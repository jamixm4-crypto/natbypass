// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/natbypass/natbypass/internal/peer"
)

type icmpSessionKey struct {
	dstIP uint32
	id    uint16
	seq   uint16
}

type icmpSessionEntry struct {
	clientVIP net.IP
	createdAt time.Time
}

type udpSessionKey struct {
	clientVIPStr string
	clientPort   uint16
	dstIPStr     string
	dstPort      uint16
}

type udpSessionEntry struct {
	conn       *net.UDPConn
	clientVIP  net.IP
	clientPort uint16
	dstIP      net.IP
	dstPort    uint16
	lastActive atomic.Int64
	closed     atomic.Bool
}

// TransitForwarder performs userspace NAT, ICMP relay, and UDP transit proxying
// on an Exit Node so that mesh clients can ping external hosts, resolve DNS,
// and access external UDP/ICMP services without relying on host OS NAT drivers (like Windows WinNAT).
type TransitForwarder struct {
	mu           sync.RWMutex
	myVIP        string
	lookupPeer   func(vipOrID string) *peer.Peer
	sendToPeer   func(destPeer *peer.Peer, packet []byte) error
	icmpConn     net.PacketConn
	icmpSessions sync.Map // map[icmpSessionKey]icmpSessionEntry
	udpSessions  sync.Map // map[udpSessionKey]*udpSessionEntry
	closed       chan struct{}
	closeOnce    sync.Once
}

// NewTransitForwarder creates and initializes a userspace transit forwarder.
func NewTransitForwarder(myVIP string, lookupPeer func(vipOrID string) *peer.Peer, sendToPeer func(destPeer *peer.Peer, packet []byte) error) *TransitForwarder {
	tf := &TransitForwarder{
		myVIP:      myVIP,
		lookupPeer: lookupPeer,
		sendToPeer: sendToPeer,
		closed:     make(chan struct{}),
	}

	// Initialize raw ICMP packet listener for transit pings
	if pc, err := net.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		tf.icmpConn = pc
		go tf.icmpListenLoop()
	}

	// Session cleanup worker
	go tf.cleanupWorker()

	return tf
}

// Close gracefully terminates the transit forwarder.
func (tf *TransitForwarder) Close() {
	tf.closeOnce.Do(func() {
		close(tf.closed)
		if tf.icmpConn != nil {
			_ = tf.icmpConn.Close()
		}
		tf.udpSessions.Range(func(key, val any) bool {
			if entry, ok := val.(*udpSessionEntry); ok && entry != nil {
				entry.closed.Store(true)
				if entry.conn != nil {
					_ = entry.conn.Close()
				}
			}
			return true
		})
	})
}

// IsTransitPacket checks whether an inbound IPv4 packet is destined for the public Internet
// (i.e. not addressed to this node, not a loopback/multicast/broadcast, and not addressed to any local mesh peer).
func (tf *TransitForwarder) IsTransitPacket(payload []byte) (bool, net.IP, net.IP) {
	if len(payload) < 20 || (payload[0]>>4) != 4 {
		return false, nil, nil
	}
	srcIP := GetSrcIP(payload)
	destIP := GetDestIP(payload)
	if srcIP == nil || destIP == nil {
		return false, nil, nil
	}

	// Ignore loopback, multicast, broadcast, link-local
	if destIP.IsLoopback() || destIP.IsMulticast() || destIP.IsUnspecified() || destIP.IsLinkLocalUnicast() {
		return false, srcIP, destIP
	}
	destStr := destIP.String()
	if destStr == "255.255.255.255" || strings.HasSuffix(destStr, ".255") {
		return false, srcIP, destIP
	}

	// Ignore if destination is this node's own virtual IP
	cleanMyVIP := strings.TrimSpace(strings.Split(tf.myVIP, "/")[0])
	if cleanMyVIP != "" && destStr == cleanMyVIP {
		return false, srcIP, destIP
	}

	// Ignore if destination is a known peer inside the mesh overlay network
	if tf.lookupPeer != nil {
		if p := tf.lookupPeer(destStr); p != nil {
			return false, srcIP, destIP
		}
	}

	// Ignore if destination matches the local mesh overlay subnet (e.g. 10.1.2.0/24 or 100.64.200.0/24)
	if cleanMyVIP != "" {
		parts := strings.Split(cleanMyVIP, ".")
		if len(parts) == 4 {
			destParts := strings.Split(destStr, ".")
			if len(destParts) == 4 && parts[0] == destParts[0] && parts[1] == destParts[1] && parts[2] == destParts[2] {
				// Same /24 mesh overlay subnet
				return false, srcIP, destIP
			}
		}
	}

	return true, srcIP, destIP
}

// HandleTransitPacket inspects an inbound packet and forwards ICMP or UDP transit traffic in userspace.
// Returns true if the packet was successfully intercepted and processed.
func (tf *TransitForwarder) HandleTransitPacket(payload []byte) bool {
	isTransit, srcIP, destIP := tf.IsTransitPacket(payload)
	if !isTransit {
		return false
	}

	ihl := int(payload[0]&0x0F) * 4
	if len(payload) < ihl {
		return false
	}
	proto := payload[9]

	switch proto {
	case 1: // ICMP
		return tf.handleTransitICMP(payload, ihl, srcIP, destIP)
	case 17: // UDP
		return tf.handleTransitUDP(payload, ihl, srcIP, destIP)
	}

	// TCP and other protocols flow to the host kernel (Wintun/WinNAT/iptables)
	return false
}

// handleTransitICMP relays outbound ICMP Echo Requests from mesh clients to the Internet.
func (tf *TransitForwarder) handleTransitICMP(payload []byte, ihl int, srcIP, destIP net.IP) bool {
	if tf.icmpConn == nil {
		return false
	}
	if len(payload) < ihl+8 {
		return false
	}
	icmpPayload := payload[ihl:]
	icmpType := icmpPayload[0]
	if icmpType != 8 { // Only intercept Echo Request (Type 8)
		return false
	}

	id := binary.BigEndian.Uint16(icmpPayload[4:6])
	seq := binary.BigEndian.Uint16(icmpPayload[6:8])
	dstU32 := ipToUint32(destIP)

	key := icmpSessionKey{
		dstIP: dstU32,
		id:    id,
		seq:   seq,
	}

	tf.icmpSessions.Store(key, icmpSessionEntry{
		clientVIP: srcIP,
		createdAt: time.Now(),
	})

	_, err := tf.icmpConn.WriteTo(icmpPayload, &net.IPAddr{IP: destIP})
	return err == nil
}

// icmpListenLoop reads ICMP responses from the Internet and routes them back to the mesh client.
func (tf *TransitForwarder) icmpListenLoop() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-tf.closed:
			return
		default:
		}

		_ = tf.icmpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, fromAddr, err := tf.icmpConn.ReadFrom(buf)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}
			select {
			case <-tf.closed:
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		if n < 8 {
			continue
		}

		// On Windows and Linux, raw ICMP packet data starts directly at buf[0] or after an IPv4 header
		icmpData := buf[:n]
		if icmpData[0]>>4 == 4 && len(icmpData) >= 20 {
			ipHdrLen := int(icmpData[0]&0x0F) * 4
			if len(icmpData) >= ipHdrLen+8 {
				icmpData = icmpData[ipHdrLen:]
			}
		}

		icmpType := icmpData[0]
		var id, seq uint16
		var fromIP net.IP

		if ipAddr, ok := fromAddr.(*net.IPAddr); ok && ipAddr != nil {
			fromIP = ipAddr.IP.To4()
		}
		if fromIP == nil {
			continue
		}

		if icmpType == 0 { // Echo Reply
			id = binary.BigEndian.Uint16(icmpData[4:6])
			seq = binary.BigEndian.Uint16(icmpData[6:8])
		} else if icmpType == 11 || icmpType == 3 { // Time Exceeded (Traceroute) or Destination Unreachable
			// Inside Time Exceeded, the payload contains the original IPv4 header + 8 bytes of original datagram
			if len(icmpData) >= 8+20+8 {
				origIPHdr := icmpData[8:]
				origIHL := int(origIPHdr[0]&0x0F) * 4
				if len(origIPHdr) >= origIHL+8 {
					origICMP := origIPHdr[origIHL:]
					id = binary.BigEndian.Uint16(origICMP[4:6])
					seq = binary.BigEndian.Uint16(origICMP[6:8])
				}
			}
		} else {
			continue
		}

		// Find the client session
		key := icmpSessionKey{
			dstIP: ipToUint32(fromIP),
			id:    id,
			seq:   seq,
		}

		val, found := tf.icmpSessions.Load(key)
		if !found && (icmpType == 11 || icmpType == 3) {
			// For traceroute TTL exceeded, the fromIP is the intermediate router,
			// while session was keyed by the target destination IP. Match by id & seq.
			tf.icmpSessions.Range(func(k, v any) bool {
				sk := k.(icmpSessionKey)
				if sk.id == id && sk.seq == seq {
					val = v
					found = true
					return false
				}
				return true
			})
		}

		if !found {
			continue
		}

		session := val.(icmpSessionEntry)
		clientVIP := session.clientVIP

		// Construct IPv4 packet: Src = fromIP, Dst = clientVIP, Proto = ICMP (1)
		ipv4Pkt := buildIPv4Packet(fromIP, clientVIP, 1, 64, icmpData)
		tf.deliverToClient(clientVIP, ipv4Pkt)
	}
}

// handleTransitUDP relays outbound UDP packets (such as DNS queries) in userspace.
func (tf *TransitForwarder) handleTransitUDP(payload []byte, ihl int, srcIP, destIP net.IP) bool {
	if len(payload) < ihl+8 {
		return false
	}
	udpHeader := payload[ihl : ihl+8]
	srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
	udpLen := int(binary.BigEndian.Uint16(udpHeader[4:6]))
	if len(payload) < ihl+udpLen || udpLen < 8 {
		return false
	}
	udpData := payload[ihl+8 : ihl+udpLen]

	key := udpSessionKey{
		clientVIPStr: srcIP.String(),
		clientPort:   srcPort,
		dstIPStr:     destIP.String(),
		dstPort:      dstPort,
	}

	val, ok := tf.udpSessions.Load(key)
	var entry *udpSessionEntry
	if ok {
		entry = val.(*udpSessionEntry)
	} else {
		// Create new outbound UDP connection
		targetAddr := &net.UDPAddr{IP: destIP, Port: int(dstPort)}
		conn, err := net.DialUDP("udp4", nil, targetAddr)
		if err != nil {
			return false
		}

		entry = &udpSessionEntry{
			conn:       conn,
			clientVIP:  srcIP,
			clientPort: srcPort,
			dstIP:      destIP,
			dstPort:    dstPort,
		}
		entry.lastActive.Store(time.Now().Unix())
		tf.udpSessions.Store(key, entry)

		// Start reader for this UDP session
		go tf.udpSessionReader(key, entry)
	}

	entry.lastActive.Store(time.Now().Unix())
	_ = entry.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := entry.conn.Write(udpData)
	return err == nil
}

// udpSessionReader listens for responses on an outbound UDP socket and forwards them back to the mesh client.
func (tf *TransitForwarder) udpSessionReader(key udpSessionKey, entry *udpSessionEntry) {
	defer func() {
		entry.closed.Store(true)
		if entry.conn != nil {
			_ = entry.conn.Close()
		}
		tf.udpSessions.Delete(key)
	}()

	buf := make([]byte, 4096)
	for {
		select {
		case <-tf.closed:
			return
		default:
		}

		if entry.closed.Load() {
			return
		}

		_ = entry.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := entry.conn.Read(buf)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				// Check inactivity
				if time.Now().Unix()-entry.lastActive.Load() > 60 {
					return
				}
				continue
			}
			return
		}

		entry.lastActive.Store(time.Now().Unix())

		// Construct IPv4 + UDP packet: Src = entry.dstIP:entry.dstPort, Dst = entry.clientVIP:entry.clientPort
		udpPacket := buildIPv4UDPPacket(entry.dstIP, entry.dstPort, entry.clientVIP, entry.clientPort, buf[:n])
		tf.deliverToClient(entry.clientVIP, udpPacket)
	}
}

// deliverToClient delivers an encapsulated IPv4 reply packet back to the client peer.
func (tf *TransitForwarder) deliverToClient(clientVIP net.IP, packet []byte) {
	if tf.lookupPeer == nil || tf.sendToPeer == nil {
		return
	}
	destPeer := tf.lookupPeer(clientVIP.String())
	if destPeer == nil {
		return
	}
	_ = tf.sendToPeer(destPeer, packet)
}

// cleanupWorker regularly removes expired ICMP sessions.
func (tf *TransitForwarder) cleanupWorker() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tf.closed:
			return
		case <-ticker.C:
			threshold := time.Now().Add(-15 * time.Second)
			tf.icmpSessions.Range(func(key, val any) bool {
				entry := val.(icmpSessionEntry)
				if entry.createdAt.Before(threshold) {
					tf.icmpSessions.Delete(key)
				}
				return true
			})
		}
	}
}

// buildIPv4Packet constructs an IPv4 packet with recalculated checksum.
func buildIPv4Packet(srcIP, dstIP net.IP, protocol byte, ttl byte, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[1] = 0    // DSCP / ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0) // Identification
	binary.BigEndian.PutUint16(pkt[6:8], 0) // Flags & Fragment Offset
	pkt[8] = ttl
	pkt[9] = protocol
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())

	cs := CalculateChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], cs)

	copy(pkt[20:], payload)
	return pkt
}

// buildIPv4UDPPacket constructs an IPv4 packet encapsulating a UDP datagram.
func buildIPv4UDPPacket(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	ipCS := CalculateChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCS)

	// UDP Header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	binary.BigEndian.PutUint16(pkt[26:28], 0) // UDP checksum optional in IPv4, 0 is valid

	// UDP Payload
	copy(pkt[28:], payload)
	return pkt
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}
