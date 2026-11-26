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
	"sync"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/peer"
)

func TestTransitForwarder_IsTransitPacket(t *testing.T) {
	myVIP := "10.1.2.113/24"
	mockPeers := map[string]*peer.Peer{
		"10.1.2.55": {
			DeviceID:  "client-dev-1",
			VirtualIP: "10.1.2.55/24",
		},
	}

	tf := &TransitForwarder{
		myVIP: myVIP,
		lookupPeer: func(vipOrID string) *peer.Peer {
			return mockPeers[vipOrID]
		},
	}

	tests := []struct {
		name      string
		srcIP     string
		destIP    string
		wantTrans bool
	}{
		{
			name:      "Transit to public DNS 1.1.1.1",
			srcIP:     "10.1.2.55",
			destIP:    "1.1.1.1",
			wantTrans: true,
		},
		{
			name:      "Transit to Google DNS 8.8.8.8",
			srcIP:     "10.1.2.55",
			destIP:    "8.8.8.8",
			wantTrans: true,
		},
		{
			name:      "Mesh local peer 10.1.2.55",
			srcIP:     "10.1.2.113",
			destIP:    "10.1.2.55",
			wantTrans: false,
		},
		{
			name:      "Self VIP 10.1.2.113",
			srcIP:     "10.1.2.55",
			destIP:    "10.1.2.113",
			wantTrans: false,
		},
		{
			name:      "Multicast 224.0.0.1",
			srcIP:     "10.1.2.55",
			destIP:    "224.0.0.1",
			wantTrans: false,
		},
		{
			name:      "Broadcast 255.255.255.255",
			srcIP:     "10.1.2.55",
			destIP:    "255.255.255.255",
			wantTrans: false,
		},
		{
			name:      "Subnet broadcast 10.1.2.255",
			srcIP:     "10.1.2.55",
			destIP:    "10.1.2.255",
			wantTrans: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := net.ParseIP(tt.srcIP)
			dst := net.ParseIP(tt.destIP)
			pkt := buildIPv4Packet(src, dst, 1, 64, []byte{8, 0, 0, 0, 0, 1, 0, 1})
			isTrans, sIP, dIP := tf.IsTransitPacket(pkt)
			if isTrans != tt.wantTrans {
				t.Errorf("IsTransitPacket() = %v, want %v (src=%v, dst=%v)", isTrans, tt.wantTrans, sIP, dIP)
			}
		})
	}
}

func TestBuildIPv4Packet(t *testing.T) {
	src := net.ParseIP("1.1.1.1")
	dst := net.ParseIP("10.1.2.55")
	payload := []byte("HelloNatBypass")

	pkt := buildIPv4Packet(src, dst, 1, 64, payload)
	if len(pkt) != 20+len(payload) {
		t.Fatalf("len(pkt) = %d, want %d", len(pkt), 20+len(payload))
	}

	// Verify IPv4 header checksum
	cs := CalculateChecksum(pkt[:20])
	if cs != 0 {
		t.Errorf("IPv4 header checksum = 0x%04x, want 0", cs)
	}

	if pkt[0] != 0x45 {
		t.Errorf("IPv4 version/IHL = 0x%02x, want 0x45", pkt[0])
	}
	if pkt[9] != 1 {
		t.Errorf("Protocol = %d, want 1", pkt[9])
	}

	extractedSrc := GetSrcIP(pkt)
	extractedDst := GetDestIP(pkt)
	if !extractedSrc.Equal(src) {
		t.Errorf("SrcIP = %v, want %v", extractedSrc, src)
	}
	if !extractedDst.Equal(dst) {
		t.Errorf("DstIP = %v, want %v", extractedDst, dst)
	}
}

func TestBuildIPv4UDPPacket(t *testing.T) {
	src := net.ParseIP("8.8.8.8")
	dst := net.ParseIP("10.1.2.55")
	payload := []byte("DNSReplyData")

	pkt := buildIPv4UDPPacket(src, 53, dst, 12345, payload)
	if len(pkt) != 20+8+len(payload) {
		t.Fatalf("len(pkt) = %d, want %d", len(pkt), 28+len(payload))
	}

	// Checksum of IPv4 header
	cs := CalculateChecksum(pkt[:20])
	if cs != 0 {
		t.Errorf("IPv4 header checksum = 0x%04x, want 0", cs)
	}

	// UDP ports
	srcPort := binary.BigEndian.Uint16(pkt[20:22])
	dstPort := binary.BigEndian.Uint16(pkt[22:24])
	if srcPort != 53 {
		t.Errorf("srcPort = %d, want 53", srcPort)
	}
	if dstPort != 12345 {
		t.Errorf("dstPort = %d, want 12345", dstPort)
	}

	// Verify UDP checksum is 0x0000 (RFC 768 no checksum for IPv4, guaranteeing zero drops in Linux/Android kernel)
	udpCS := binary.BigEndian.Uint16(pkt[26:28])
	if udpCS != 0 {
		t.Errorf("UDP checksum = 0x%04x, want 0 (RFC 768 disabled checksum)", udpCS)
	}
}

func TestTransitForwarder_DoTHandling(t *testing.T) {
	myVIP := "10.1.2.1/24"
	var deliveredPacket []byte
	var deliverMu sync.Mutex

	mockPeer := &peer.Peer{
		DeviceID:  "android-client",
		VirtualIP: "10.1.2.55/24",
	}

	tf := NewTransitForwarder(
		myVIP,
		func(vipOrID string) *peer.Peer {
			if vipOrID == "10.1.2.55" || vipOrID == "android-client" {
				return mockPeer
			}
			return nil
		},
		func(destPeer *peer.Peer, packet []byte) error {
			deliverMu.Lock()
			deliveredPacket = make([]byte, len(packet))
			copy(deliveredPacket, packet)
			deliverMu.Unlock()
			return nil
		},
	)
	defer tf.Close()

	// Simulate Android sending a TCP SYN to 1.1.1.1:853 (DNS-over-TLS)
	clientIP := net.ParseIP("10.1.2.55")
	dotServerIP := net.ParseIP("1.1.1.1")
	synPkt := buildIPv4TCPPacket(clientIP, 54321, dotServerIP, 853, 1000, 0, 0x02, 64240, nil)

	handled := tf.HandleTransitPacketWithSender(synPkt, mockPeer)
	if !handled {
		t.Fatalf("HandleTransitPacketWithSender returned false for DoT SYN packet")
	}

	// Wait for async dial completion (either SYN|ACK if reachable or RST|ACK if unreachable)
	startWait := time.Now()
	for time.Since(startWait) < 3*time.Second {
		deliverMu.Lock()
		got := deliveredPacket != nil
		deliverMu.Unlock()
		if got {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	deliverMu.Lock()
	pkt := deliveredPacket
	deliverMu.Unlock()

	if pkt != nil {
		if len(pkt) < 40 {
			t.Fatalf("Delivered packet too short: %d bytes", len(pkt))
		}
		srcIP := GetSrcIP(pkt)
		dstIP := GetDestIP(pkt)
		if !srcIP.Equal(dotServerIP) {
			t.Errorf("SrcIP = %v, want %v", srcIP, dotServerIP)
		}
		if !dstIP.Equal(clientIP) {
			t.Errorf("DstIP = %v, want %v", dstIP, clientIP)
		}
		tcpHdr := pkt[20:]
		srcPort := binary.BigEndian.Uint16(tcpHdr[0:2])
		dstPort := binary.BigEndian.Uint16(tcpHdr[2:4])
		if srcPort != 853 {
			t.Errorf("srcPort = %d, want 853", srcPort)
		}
		if dstPort != 54321 {
			t.Errorf("dstPort = %d, want 54321", dstPort)
		}
	}
}

func TestTransitForwarder_SSRFRFC1918AndSourceSpoofing(t *testing.T) {
	myVIP := "10.1.2.1/24"
	mockPeer := &peer.Peer{
		DeviceID:  "peer-a",
		VirtualIP: "10.1.2.55/24",
	}
	tf := &TransitForwarder{
		myVIP: myVIP,
		lookupPeer: func(vipOrID string) *peer.Peer {
			if vipOrID == "10.1.2.55" {
				return mockPeer
			}
			return nil
		},
	}

	// 1. Private LAN (router admin UI / host LAN) and CGNAT MUST be blocked by default
	for _, blocked := range []string{"192.168.1.1", "10.0.0.5", "172.16.0.10", "100.64.1.1", "127.0.0.1", "169.254.169.254"} {
		pkt := buildIPv4Packet(net.ParseIP("10.1.2.55"), net.ParseIP(blocked), 6, 64, make([]byte, 20))
		if isTrans, _, _ := tf.IsTransitPacket(pkt); isTrans {
			t.Errorf("IsTransitPacket allowed restricted SSRF target %s", blocked)
		}
	}

	// 2. Explicitly advertised LAN subnet becomes reachable
	tf.SetAllowedSubnets([]string{"192.168.50.0/24"})
	allowedPkt := buildIPv4Packet(net.ParseIP("10.1.2.55"), net.ParseIP("192.168.50.10"), 6, 64, make([]byte, 20))
	if isTrans, _, _ := tf.IsTransitPacket(allowedPkt); !isTrans {
		t.Errorf("IsTransitPacket rejected explicitly advertised subnet 192.168.50.10")
	}

	// 3. Source VIP spoofing by another peer MUST be rejected
	spoofPkt := buildIPv4Packet(net.ParseIP("10.1.2.99"), net.ParseIP("1.1.1.1"), 1, 64, []byte{8, 0, 0, 0, 0, 1, 0, 1})
	if tf.HandleTransitPacketWithSender(spoofPkt, mockPeer) {
		t.Errorf("HandleTransitPacketWithSender accepted spoofed source IP 10.1.2.99 from peer 10.1.2.55")
	}
}

func TestTCPWindowScaleAndSegmentPruning(t *testing.T) {
	entry := &tcpSessionEntry{
		clientVIP:    net.ParseIP("10.1.1.5"),
		clientPort:   54321,
		dstIP:        net.ParseIP("1.1.1.1"),
		dstPort:      443,
		clientWScale: 7,
	}
	entry.clientNextSeq.Store(100)

	entry.addRecentSegment(1000, make([]byte, 500))
	entry.addRecentSegment(1500, make([]byte, 500))
	entry.addRecentSegment(2000, make([]byte, 500))

	// Acknowledge up to seq 2000 -> first two segments (1000..1500, 1500..2000) must be pruned
	entry.pruneAcked(2000)
	if seg := entry.getRecentSegment(1000); seg != nil {
		t.Fatalf("expected segment 1000 to be pruned")
	}
	if seg := entry.getRecentSegment(1500); seg != nil {
		t.Fatalf("expected segment 1500 to be pruned")
	}
	oldest := entry.oldestSegment()
	if oldest == nil || oldest.seq != 2000 {
		t.Fatalf("expected oldest unacked segment seq=2000, got %+v", oldest)
	}

	// Verify RTO stall retransmit fires after >250ms unacked duration
	var delivered [][]byte
	tf := &TransitForwarder{
		lookupPeer: func(vipOrID string) *peer.Peer {
			return &peer.Peer{DeviceID: "client-dev-1", VirtualIP: "10.1.1.5/24"}
		},
		sendToPeer: func(destPeer *peer.Peer, packet []byte) error {
			delivered = append(delivered, packet)
			return nil
		},
	}
	entry.lastAckNano.Store(time.Now().Add(-350 * time.Millisecond).UnixNano())
	entry.lastRetransmitNano.Store(time.Now().Add(-350 * time.Millisecond).UnixNano())
	tf.retransmitOldestIfStalled(entry)
	if len(delivered) != 1 {
		t.Fatalf("expected 1 RTO retransmit packet, got %d", len(delivered))
	}
	// Verify second immediate call is throttled by cooldown
	tf.retransmitOldestIfStalled(entry)
	if len(delivered) != 1 {
		t.Fatalf("expected cooldown to suppress duplicate immediate retransmit, got %d", len(delivered))
	}
}
