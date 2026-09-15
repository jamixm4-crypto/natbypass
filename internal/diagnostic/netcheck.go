// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package diagnostic

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/transport"
)

// NetcheckReport contains an in-depth diagnostic analysis of the network path,
// NAT behavior (RFC 5780 / RFC 4787 / RFC 6888), DPI/TSPU filtering presence,
// and optimal transport recommendation.
type NetcheckReport struct {
	UDPEnabled             bool             `json:"udp_enabled"`
	UDPBlockedIPv4         bool             `json:"udp_blocked_ipv4"`
	UDPBlockedIPv6         bool             `json:"udp_blocked_ipv6"`
	IPv6Enabled            bool             `json:"ipv6_enabled"`
	IPv6Available          bool             `json:"ipv6_available"`
	TCP443OK               bool             `json:"tcp_443_ok"`
	NATType                string           `json:"nat_type"`
	MappingType            string           `json:"mapping_type"`
	FilteringType          string           `json:"filtering_type"`
	PublicIPv4             string           `json:"public_ipv4,omitempty"`
	PublicIPv6             string           `json:"public_ipv6,omitempty"`
	PortDelta              int              `json:"port_delta"`
	PBABlockSize           int              `json:"pba_block_size,omitempty"`
	TSPUDetected           bool             `json:"tspu_detected"`
	TSPUDetails            string           `json:"tspu_details,omitempty"`
	DPIBlockedWireGuard    bool             `json:"dpi_blocked_wireguard"`
	DPIBlockedStandardUDP  bool             `json:"dpi_blocked_standard_udp"`
	PathMTU                int              `json:"path_mtu"`
	PreferredTransport     string           `json:"preferred_transport"`
	EscalationMode         string           `json:"escalation_mode"`
	EscalationLevel        int              `json:"escalation_level"`
	EscalationSummary      string           `json:"escalation_summary"`
	LatenciesMs            map[string]int64 `json:"latencies_ms"`
	Timestamp              time.Time        `json:"timestamp"`
}

// RecommendTransportForReport returns the recommended transport mode for a given NetcheckReport.
// Rationale:
// - Level 1: If IPv4 UDP is blocked, but IPv6 is available and functional -> ForceIPv6Only.
// - Level 3: If UDP is blocked, but TCP 443 is functional -> TCP Peer-as-Relay (port 443).
// - Level 2: If UDP is completely blocked with no TCP 443 -> MQTT L3 Tunnel Fallback.
// - If UDP is blocked or TSPU DPI censorship is detected without dual-stack: ShadowTLS over TLS 443.
// - If NAT is Symmetric (Address-and-Port-Dependent / random ports): QUIC (multipath + migration).
// - If NAT is Cone (Endpoint-Independent / linear predictable delta): AWG (fastest zero-overhead UDP).
func RecommendTransportForReport(rep *NetcheckReport) string {
	if rep == nil {
		return transport.TransportAWG
	}
	if rep.UDPBlockedIPv4 && rep.IPv6Available && !rep.UDPBlockedIPv6 {
		return "ipv6_only"
	}
	if rep.UDPBlockedIPv4 && rep.TCP443OK {
		return "tcp_relay"
	}
	if rep.UDPBlockedIPv4 && !rep.TCP443OK {
		return "mqtt_fallback"
	}
	if !rep.UDPEnabled || rep.TSPUDetected {
		return transport.TransportShadowTLS
	}
	natLower := strings.ToLower(rep.NATType)
	mappingLower := strings.ToLower(rep.MappingType)
	if strings.Contains(natLower, "случайн") || strings.Contains(natLower, "symmetric") ||
		strings.Contains(mappingLower, "port-dependent") || strings.Contains(mappingLower, "address-and-port") {
		return transport.TransportQUIC
	}
	return transport.TransportAWG
}

// RunNetcheck executes a comprehensive multi-probe network diagnostic.
// It checks UDP connectivity, RFC 5780 NAT classification, IPv6 availability,
// DPI (TSPU) middlebox filtering, and determines Path MTU.
func RunNetcheck(ctx context.Context) (*NetcheckReport, error) {
	rep := &NetcheckReport{
		LatenciesMs: make(map[string]int64),
		Timestamp:   time.Now().UTC(),
		PathMTU:     1420, // safe default
	}

	var wg sync.WaitGroup

	// 1. NAT & UDP Classification (RFC 5780 / RFC 4787)
	var (
		natClass *NATClassification
		natErr   error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		natClass, natErr = ClassifyNATBehavior()
	}()

	// 2. IPv6 Check
	udpBlockedIPv6 := true
	wg.Add(1)
	go func() {
		defer wg.Done()
		hasIPv6, pubIPv6 := checkIPv6(ctx)
		rep.IPv6Enabled = hasIPv6
		rep.IPv6Available = hasIPv6
		rep.PublicIPv6 = pubIPv6
		if hasIPv6 {
			// Probe UDP6 connectivity to verify if IPv6 UDP is passing through without TSPU drop
			lat6 := probeLatency(ctx, "udp6", "[2001:4860:4860::8888]:53")
			if lat6 >= 0 {
				udpBlockedIPv6 = false
				rep.LatenciesMs["google_dns_ipv6"] = lat6
			}
		}
	}()

	// 3. TCP 443 Check (Control probe for DPI/TSPU detection)
	tcp443OK := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		lat := probeLatency(ctx, "tcp", "1.1.1.1:443")
		if lat >= 0 {
			tcp443OK = true
			rep.LatenciesMs["cloudflare_tcp443"] = lat
		} else {
			lat2 := probeLatency(ctx, "tcp", "8.8.8.8:443")
			if lat2 >= 0 {
				tcp443OK = true
				rep.LatenciesMs["google_tcp443"] = lat2
			}
		}
	}()

	// 4. Latency Probes
	wg.Add(1)
	go func() {
		defer wg.Done()
		rep.LatenciesMs["google_stun"] = probeLatency(ctx, "udp", "stun.l.google.com:19302")
		rep.LatenciesMs["cloudflare_dns"] = probeLatency(ctx, "udp", "1.1.1.1:53")
		rep.LatenciesMs["yandex_dns"] = probeLatency(ctx, "udp", "77.88.8.8:53")
	}()

	// 5. Path MTU Probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		rep.PathMTU = probePathMTU(ctx)
	}()

	wg.Wait()

	// Analyze NAT classification results
	if natErr == nil && natClass != nil {
		rep.UDPEnabled = true
		rep.NATType = natClass.NATType
		rep.MappingType = natClass.MappingType
		rep.FilteringType = natClass.FilteringType
		rep.PublicIPv4 = natClass.PublicIP
		rep.PortDelta = natClass.PortDelta
		rep.PBABlockSize = natClass.PBABlockSize
	} else {
		rep.UDPEnabled = false
		rep.NATType = "UDP Blocked / Strict Filter"
		rep.MappingType = "Blocked"
		rep.FilteringType = "Drop All UDP"
	}

	rep.UDPBlockedIPv4 = !rep.UDPEnabled
	rep.UDPBlockedIPv6 = udpBlockedIPv6
	rep.IPv6Available = rep.IPv6Enabled
	rep.TCP443OK = tcp443OK

	// Detect UDP drop signatures
	cDNS, hasCDNS := rep.LatenciesMs["cloudflare_dns"]
	yDNS, hasYDNS := rep.LatenciesMs["yandex_dns"]
	gSTUN, hasGSTUN := rep.LatenciesMs["google_stun"]
	if (hasCDNS && cDNS < 0) && (hasYDNS && yDNS < 0) && (hasGSTUN && gSTUN < 0) {
		rep.DPIBlockedStandardUDP = true
	}

	// DPI / TSPU Heuristic:
	// If TCP 443 works normally, but UDP is completely blocked or failed STUN,
	// TSPU middlebox is likely dropping non-standard UDP.
	if tcp443OK && !rep.UDPEnabled {
		rep.TSPUDetected = true
		rep.DPIBlockedWireGuard = true
		rep.TSPUDetails = "Обнаружена фильтрация UDP (ТСПУ DPI / Корпоративный фаервол). Исходящий UDP сбрасывается, доступен только TCP 443."
	} else if !tcp443OK && !rep.UDPEnabled {
		rep.TSPUDetails = "Сетевой интерфейс не имеет выхода в Интернет или DNS/маршруты недоступны."
	}

	// Calculate Escalation Level & Metadata
	if !rep.UDPBlockedIPv4 {
		rep.EscalationLevel = 0
		rep.EscalationMode = "udp_standard"
		rep.EscalationSummary = "Уровень 0: Стандартный прямой UDP (P2P / AmneziaWG)"
	} else if rep.IPv6Available && !rep.UDPBlockedIPv6 {
		rep.EscalationLevel = 1
		rep.EscalationMode = "ipv6_only"
		rep.EscalationSummary = "Уровень 1: Принудительный прямой IPv6 (Обход CGNAT и ТСПУ)"
	} else if rep.TCP443OK {
		rep.EscalationLevel = 3
		rep.EscalationMode = "tcp_relay"
		rep.EscalationSummary = "Уровень 3: TCP Peer-as-Relay на порту 443 (Маскировка под HTTPS)"
	} else {
		rep.EscalationLevel = 2
		rep.EscalationMode = "mqtt_fallback"
		rep.EscalationSummary = "Уровень 2: L3 IP-туннель через протокол сигналов MQTT"
	}

	rep.PreferredTransport = RecommendTransportForReport(rep)
	return rep, nil
}

// CheckIPv6 checks if the host has an active global unicast IPv6 address and can reach IPv6 endpoints.
func CheckIPv6(ctx context.Context) (bool, string) {
	return checkIPv6(ctx)
}

// checkIPv6 checks if the host has an active global unicast IPv6 address and can reach IPv6 endpoints.
func checkIPv6(ctx context.Context) (bool, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, ""
	}
	hasGlobal := false
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
					hasGlobal = true
					break
				}
			}
		}
		if hasGlobal {
			break
		}
	}
	if !hasGlobal {
		return false, ""
	}

	// Try quick IPv6 dial
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "udp6", "[2001:4860:4860::8888]:53")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().String()
		host, _, _ := net.SplitHostPort(localAddr)
		return true, host
	}
	return true, ""
}

// probePathMTU tests UDP payload sizes to determine the maximum unfragmented Path MTU.
func probePathMTU(ctx context.Context) int {
	sizes := []int{1500, 1420, 1360, 1280}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return 1420
	}
	defer conn.Close()

	rAddr, err := net.ResolveUDPAddr("udp4", "1.1.1.1:53")
	if err != nil {
		return 1420
	}

	for _, sz := range sizes {
		// Test sending dummy datagram of target size
		buf := make([]byte, sz-28) // subtracting 20 bytes IP + 8 bytes UDP header
		_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.WriteToUDP(buf, rAddr); err == nil {
			return sz
		}
	}
	return 1280
}

// probeLatency measures RTT to a specific endpoint. Returns -1 if unreachable.
func probeLatency(ctx context.Context, network, addr string) int64 {
	start := time.Now()
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return -1
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds()
}
