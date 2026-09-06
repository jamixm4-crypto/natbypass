package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/natbypass/natbypass/internal/network"
)

// STUNResult — результат STUN-опроса
type STUNResult struct {
	Server     string
	MappedIP   net.IP
	MappedPort int
	LatencyMs  int64
	Error      string
}

// SelfTestResult — результат самодиагностики узла
type SelfTestResult struct {
	Hostname    string
	LocalIPs    []string
	STUNAddr    string      // основной mapped address "ip:port"
	NATType     string      // full_cone, restricted, symmetric, unknown
	NATDelta    int         // port delta для symmetric NAT
	ListenPort  int         // UDP порт probe listener
	STUNResults []STUNResult
}

// RunSelfTest выполняет Phase 1: STUN + NAT type detection
func RunSelfTest(ctx context.Context, cfg *ProbeConfig, listenPort int) (*SelfTestResult, error) {
	hostname, _ := os.Hostname()
	result := &SelfTestResult{Hostname: hostname, ListenPort: listenPort}

	logf("[SELF] Hostname: %s", hostname)


	// Local IPs
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				result.LocalIPs = append(result.LocalIPs, ipNet.IP.String())
			}
		}
	}
	logf("[SELF] Local IPs: %v", result.LocalIPs)

	// STUN
	logf("[STUN] Testing %d STUN servers...", len(cfg.STUNServers))

	var ports []int
	for _, server := range cfg.STUNServers {
		sr := STUNResult{Server: server}
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		client := network.NewSTUNClient([]string{server})
		ip, port, err := client.GetMappedAddress(sctx)
		cancel()
		sr.LatencyMs = time.Since(start).Milliseconds()
		if err != nil {
			sr.Error = err.Error()
			logf("[STUN] %s → ERROR: %v", server, err)
		} else {
			sr.MappedIP = ip
			sr.MappedPort = port
			ports = append(ports, port)
			if result.STUNAddr == "" {
				result.STUNAddr = fmt.Sprintf("%s:%d", ip, port)
			}
			logf("[STUN] %s → %s:%d (%dms)", server, ip, port, sr.LatencyMs)
		}
		result.STUNResults = append(result.STUNResults, sr)
	}

	// NAT type analysis
	natType, err := network.DetectNATType(ctx, nil, cfg.STUNServers)
	if err != nil {
		logf("[STUN] NAT detection error: %v", err)
		result.NATType = "unknown"
	} else {
		result.NATType = natType.String()
	}

	// Port delta for symmetric NAT
	if len(ports) >= 2 {
		delta := 0
		for i := 1; i < len(ports); i++ {
			d := ports[i] - ports[i-1]
			if d < 0 {
				d = -d
			}
			if d > delta {
				delta = d
			}
		}
		result.NATDelta = delta
		if result.NATType == "symmetric" && delta > 0 {
			logf("[STUN] NAT type: SYMMETRIC (port delta ~%d)", delta)
		} else {
			logf("[STUN] NAT type: %s", strings.ToUpper(result.NATType))
		}
	} else {
		logf("[STUN] NAT type: %s", strings.ToUpper(result.NATType))
	}

	return result, nil
}
