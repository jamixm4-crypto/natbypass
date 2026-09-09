// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/pion/stun/v2"
)


// NATType describes the type of NAT in front of the device.
type NATType int

const (
	NATTypeUnknown      NATType = iota
	NATTypeFullCone             // All packets from same internal addr always use same external port
	NATTypeRestricted           // Restricted Cone вЂ” port stable but restricted by remote IP
	NATTypePortRestricted       // Port Restricted Cone
	NATTypeSymmetric            // Each destination gets different external port вЂ” typical CGNAT on LTE
)

// String returns a short label for the NAT type.
func (n NATType) String() string {
	switch n {
	case NATTypeFullCone:
		return "full_cone"
	case NATTypeRestricted:
		return "restricted"
	case NATTypePortRestricted:
		return "port_restricted"
	case NATTypeSymmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// IsSymmetric returns true when each outgoing connection gets a different external port.
// Classic UDP hole-punching is unreliable; use wide port-sweep or TCP/relay fallback.
func (n NATType) IsSymmetric() bool {
	return n == NATTypeSymmetric
}

// defaultSTUNServers — diverse list across vendors so at least one works on any operator.
// Pre-seeded with direct IPv4 addresses (including port 443) so STUN discovery requires 0ms DNS
// and successfully penetrates mobile cellular operators (LTE/5G) that filter UDP port 3478.
var defaultSTUNServers = []string{
	"162.159.207.0:3478",    // Cloudflare STUN direct IP (0ms DNS)
	"74.125.250.129:19302",  // Google STUN direct IP (0ms DNS)
	"212.53.40.43:3478",     // Sipnet Moscow direct IP (0ms DNS)
	"195.201.201.32:443",    // Nextcloud STUN port 443 (punches through cellular carrier port 3478 blocks)
	"stun.cloudflare.com:3478",
	"stun.sipnet.ru:3478",
	"stun.miwifi.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.nextcloud.com:443",
	"relay.webwormhole.io:3478",
}

type STUNClient struct {
	servers []string
}

func NewSTUNClient(servers []string) *STUNClient {
	if len(servers) == 0 {
		servers = defaultSTUNServers
	}
	return &STUNClient{
		servers: servers,
	}
}

func (s *STUNClient) GetMappedAddress(ctx context.Context) (net.IP, int, error) {
	if len(s.servers) == 0 {
		return nil, 0, errors.New("no STUN servers configured")
	}

	type stunResult struct {
		ip   net.IP
		port int
		err  error
	}

	resCh := make(chan stunResult, len(s.servers))
	probeCtx, cancelProbes := context.WithTimeout(ctx, 3*time.Second)
	defer cancelProbes()

	for _, srv := range s.servers {
		go func(server string) {
			ip, port, err := s.getMappedAddressFromServer(probeCtx, server)
			resCh <- stunResult{ip: ip, port: port, err: err}
		}(srv)
	}

	var lastErr error
	for i := 0; i < len(s.servers); i++ {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case res := <-resCh:
			if res.err == nil && res.ip != nil {
				cancelProbes() // Cancel remaining probes immediately once first responds
				return res.ip, res.port, nil
			}
			lastErr = res.err
		}
	}

	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("failed to get mapped address from all STUN servers")
}


func (s *STUNClient) getMappedAddressFromServer(ctx context.Context, server string) (net.IP, int, error) {
	addr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, 0, err
	}

	// РџСЂРёРІСЏР·С‹РІР°РµРј Рє С„РёР·РёС‡РµСЃРєРѕРјСѓ LAN-IP С‡С‚РѕР±С‹ STUN-Р·Р°РїСЂРѕСЃС‹ РЅРµ СѓС…РѕРґРёР»Рё С‡РµСЂРµР· AWG/VPN-С‚РѕРЅРЅРµР»СЊ.
	// Р’С‹Р±РёСЂР°РµРј РїРµСЂРІС‹Р№ non-loopback, non-virtual IPv4-Р°РґСЂРµСЃ (РїСЂРѕРїСѓСЃРєР°РµРј 100.64.x.x вЂ” NatBypass VIP).
	var localAddr *net.UDPAddr
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipNet.IP.To4()
				if ip4 == nil || ip4.IsLoopback() {
					continue
				}
				// РџСЂРѕРїСѓСЃРєР°РµРј РІРёСЂС‚СѓР°Р»СЊРЅС‹Р№ IP NatBypass (100.64.x.x)
				if ip4[0] == 10 && ip4[1] == 200 {
					continue
				}
				localAddr = &net.UDPAddr{IP: ip4, Port: 0}
				break
			}
			if localAddr != nil {
				break
			}
		}
	}

	conn, err := net.DialUDP("udp4", localAddr, addr)
	if err != nil {
		// Fallback: Р±РµР· РїСЂРёРІСЏР·РєРё Рє РёРЅС‚РµСЂС„РµР№СЃСѓ
		conn, err = net.DialUDP("udp4", nil, addr)
		if err != nil {
			return nil, 0, err
		}
	}
	defer conn.Close()

	c, err := stun.NewClient(conn)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var ip net.IP
	var port int
	var respErr error

	done := make(chan struct{})

	err = c.Do(message, func(res stun.Event) {
		defer close(done)
		if res.Error != nil {
			respErr = res.Error
			return
		}

		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			respErr = err
			return
		}
		ip = xorAddr.IP
		port = xorAddr.Port
	})

	if err != nil {
		return nil, 0, err
	}

	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case <-done:
		if respErr != nil {
			return nil, 0, respErr
		}
		return ip, port, nil
	}
}

var stunBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1024)
		return &b
	},
}

// STUNConsensusResult holds the outcome of multi-STUN server consensus discovery.
type STUNConsensusResult struct {
	IP        net.IP
	Port      int
	NATType   NATType
	NATDelta  int
	Endpoints []signaling.EndpointDesc
	Samples   []int
}

// DetectNATConsensus queries 3-5 diverse STUN servers in parallel from the same socket
// to classify NAT behavior, calculate port delta, and build candidate endpoints with zero-allocation buffers.
func DetectNATConsensus(ctx context.Context, sock *net.UDPConn, servers []string) (*STUNConsensusResult, error) {
	if len(servers) == 0 {
		servers = defaultSTUNServers
	}

	distinctServers := make([]string, 0, 5)
	seen := make(map[string]bool)
	for _, s := range servers {
		if !seen[s] {
			seen[s] = true
			distinctServers = append(distinctServers, s)
			if len(distinctServers) >= 5 {
				break
			}
		}
	}
	if len(distinctServers) < 2 {
		return nil, errors.New("need at least 2 STUN servers for consensus")
	}

	var activeSock *net.UDPConn
	if sock != nil {
		activeSock = sock
	} else {
		lAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		if err != nil {
			return nil, err
		}
		tempSock, err := net.ListenUDP("udp4", lAddr)
		if err != nil {
			return nil, err
		}
		defer tempSock.Close()
		activeSock = tempSock
	}

	probes := make(map[[stun.TransactionIDSize]byte]string)
	for _, srv := range distinctServers {
		srvAddr, err := net.ResolveUDPAddr("udp4", srv)
		if err != nil {
			continue
		}
		var txID [stun.TransactionIDSize]byte
		if _, err := rand.Read(txID[:]); err != nil {
			continue
		}
		msg := stun.New()
		msg.TransactionID = txID
		msg.Type = stun.BindingRequest
		msg.WriteHeader()

		if _, err := activeSock.WriteToUDP(msg.Raw, srvAddr); err == nil {
			probes[txID] = srv
		}
	}

	if len(probes) == 0 {
		return nil, errors.New("failed to send STUN binding requests to any server")
	}

	type mappedResult struct {
		server string
		ip     net.IP
		port   int
	}

	results := make([]mappedResult, 0, len(probes))
	deadline := time.Now().Add(1500 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	bufPtr := stunBufPool.Get().(*[]byte)
	defer stunBufPool.Put(bufPtr)
	buf := *bufPtr

	for len(results) < len(probes) {
		if time.Now().After(deadline) {
			break
		}
		_ = activeSock.SetReadDeadline(deadline)
		n, _, err := activeSock.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n <= 0 {
			continue
		}

		var stunMsg stun.Message
		stunMsg.Raw = buf[:n]
		if err := stunMsg.Decode(); err != nil {
			continue
		}

		srv, matched := probes[stunMsg.TransactionID]
		if !matched {
			continue // ignore unknown or spoofed Transaction ID (anti-reflection)
		}
		delete(probes, stunMsg.TransactionID)

		var mappedIP net.IP
		var mappedPort int
		var xor stun.XORMappedAddress
		if err := xor.GetFrom(&stunMsg); err == nil {
			mappedIP = xor.IP
			mappedPort = xor.Port
		} else {
			var plain stun.MappedAddress
			if err := plain.GetFrom(&stunMsg); err == nil {
				mappedIP = plain.IP
				mappedPort = plain.Port
			}
		}

		if mappedIP != nil && mappedPort > 0 {
			results = append(results, mappedResult{
				server: srv,
				ip:     mappedIP,
				port:   mappedPort,
			})
		}
	}

	if len(results) == 0 {
		return nil, errors.New("no responses received from STUN servers")
	}

	type epKey struct {
		ip   string
		port int
	}
	freq := make(map[epKey]int)
	portSamples := make([]int, 0, len(results))
	var primaryIP net.IP
	var primaryPort int
	maxCount := 0

	for _, r := range results {
		k := epKey{ip: r.ip.String(), port: r.port}
		freq[k]++
		if freq[k] > maxCount {
			maxCount = freq[k]
			primaryIP = r.ip
			primaryPort = r.port
		}
		portSamples = append(portSamples, r.port)
	}

	delta := 0
	if len(portSamples) >= 2 {
		d := portSamples[1] - portSamples[0]
		if d < 0 {
			d = -d
		}
		delta = d
	}

	var natType NATType
	if len(results) >= 3 && maxCount >= 3 {
		natType = NATTypeFullCone
		delta = 0
	} else if len(results) >= 2 && maxCount == len(results) {
		natType = NATTypeFullCone
		delta = 0
	} else if len(results) >= 2 && maxCount < len(results) {
		natType = NATTypeSymmetric
		if delta == 0 {
			delta = 1
		}
	} else {
		natType = NATTypeUnknown
	}

	endpoints := make([]signaling.EndpointDesc, 0, len(freq))
	endpoints = append(endpoints, signaling.EndpointDesc{
		Proto:    "udp",
		IP:       primaryIP.String(),
		Port:     primaryPort,
		NATType:  natType.String(),
		TTL:      20,
		Priority: 100,
	})

	for k := range freq {
		if k.ip == primaryIP.String() && k.port == primaryPort {
			continue
		}
		endpoints = append(endpoints, signaling.EndpointDesc{
			Proto:    "udp",
			IP:       k.ip,
			Port:     k.port,
			NATType:  natType.String(),
			TTL:      20,
			Priority: 80,
		})
	}

	return &STUNConsensusResult{
		IP:        primaryIP,
		Port:      primaryPort,
		NATType:   natType,
		NATDelta:  delta,
		Endpoints: endpoints,
		Samples:   portSamples,
	}, nil
}

// DetectNATType classifies the NAT type by querying diverse STUN servers
// from the same socket using consensus voting.
func DetectNATType(ctx context.Context, sock *net.UDPConn, servers []string) (NATType, error) {
	res, err := DetectNATConsensus(ctx, sock, servers)
	if err != nil {
		return NATTypeUnknown, err
	}
	return res.NATType, nil
}


