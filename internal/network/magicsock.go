package network

import (
	"context"
	"net"
	"sync"
	"time"
)

var isLocalSubnetHook func(net.IP) bool

func isLocalSubnet(targetIP net.IP) bool {
	if targetIP == nil {
		return false
	}
	if isLocalSubnetHook != nil {
		return isLocalSubnetHook(targetIP)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.Contains(targetIP) {
					return true
				}
			}
		}
	}
	return false
}

func classifyAddress(addrStr string) (PathType, int) {
	host := addrStr
	if h, _, err := net.SplitHostPort(addrStr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return PathTypeWAN, 3
	}
	if ip.To4() == nil {
		return PathTypeIPv6, 2
	}
	if isLocalSubnet(ip) {
		return PathTypeLAN, 1
	}
	if ip.IsPrivate() {
		return PathTypeRelay, 4
	}
	return PathTypeWAN, 2
}

// PathType represents the classification of a network transport candidate.
type PathType string

const (
	PathTypeLAN   PathType = "LAN"   // Sub-millisecond direct local network
	PathTypeIPv6  PathType = "IPv6"  // Global IPv6 direct route
	PathTypeWAN   PathType = "P2P"   // STUN-discovered hole-punched UDP WAN route
	PathTypeRelay PathType = "Relay" // Fallback encrypted TLS/WSS or signaling relay
)

// EndpointCandidate represents a single discovered route to a peer.
type EndpointCandidate struct {
	Address     string
	Type        PathType
	Latency     time.Duration
	LastSuccess time.Time
	Failures    int
	Priority    int // Lower number = higher priority
}

// PeerRouteState maintains the candidate paths and active path for a single peer.
type PeerRouteState struct {
	DeviceID       string
	Candidates     map[string]*EndpointCandidate
	ActiveEndpoint string
	ActiveType     PathType
	BestLatency    time.Duration
	mu             sync.RWMutex
}

// MagicSock implements a Tailscale-style dual-plane smart transport selector.
type MagicSock struct {
	puncher      *UDPPuncher
	peerRoutes   map[string]*PeerRouteState
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	onPathSwitch func(deviceID string, oldPath, newPath string, pType PathType)
}

// NewMagicSock creates a new smart routing socket wrapper.
func NewMagicSock(puncher *UDPPuncher, onSwitch func(deviceID string, oldPath, newPath string, pType PathType)) *MagicSock {
	ctx, cancel := context.WithCancel(context.Background())
	ms := &MagicSock{
		puncher:      puncher,
		peerRoutes:   make(map[string]*PeerRouteState),
		ctx:          ctx,
		cancel:       cancel,
		onPathSwitch: onSwitch,
	}
	go ms.maintenanceLoop()
	return ms
}

// RegisterPeerEndpoints updates all candidate endpoints for a peer.
func (ms *MagicSock) RegisterPeerEndpoints(deviceID, stunAddr, localAddr, ipv6Addr string, extraCandidates ...string) {
	ms.mu.Lock()
	pr, ok := ms.peerRoutes[deviceID]
	if !ok {
		pr = &PeerRouteState{
			DeviceID:   deviceID,
			Candidates: make(map[string]*EndpointCandidate),
		}
		ms.peerRoutes[deviceID] = pr
	}
	ms.mu.Unlock()

	pr.mu.Lock()
	defer pr.mu.Unlock()

	addCandidate := func(addr string) {
		if addr == "" {
			return
		}
		if _, exists := pr.Candidates[addr]; !exists {
			pType, priority := classifyAddress(addr)
			pr.Candidates[addr] = &EndpointCandidate{
				Address:  addr,
				Type:     pType,
				Priority: priority,
			}
		}
	}

	addCandidate(localAddr)
	addCandidate(ipv6Addr)
	addCandidate(stunAddr)
	for _, cand := range extraCandidates {
		addCandidate(cand)
	}

	if pr.ActiveEndpoint == "" {
		if stunAddr != "" {
			pr.ActiveEndpoint = stunAddr
			pr.ActiveType = PathTypeWAN
		} else if localAddr != "" {
			pType, _ := classifyAddress(localAddr)
			pr.ActiveEndpoint = localAddr
			pr.ActiveType = pType
		}
	}
}

// RecordProbeSuccess updates route metrics upon receiving an echo response.
func (ms *MagicSock) RecordProbeSuccess(deviceID, fromAddr string, rtt time.Duration) {
	ms.mu.RLock()
	pr, ok := ms.peerRoutes[deviceID]
	ms.mu.RUnlock()
	if !ok || pr == nil {
		return
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	cand, ok := pr.Candidates[fromAddr]
	if !ok {
		pType, priority := classifyAddress(fromAddr)
		cand = &EndpointCandidate{
			Address:  fromAddr,
			Type:     pType,
			Priority: priority,
		}
		pr.Candidates[fromAddr] = cand
	}

	cand.LastSuccess = time.Now()
	cand.Failures = 0
	if cand.Latency > 0 {
		cand.Latency = time.Duration(float64(cand.Latency)*0.7 + float64(rtt)*0.3)
	} else {
		cand.Latency = rtt
	}

	// Auto-promote candidate if it has strictly better priority (lower number) or lower latency within same priority
	shouldSwitch := false
	if pr.ActiveEndpoint == "" || pr.ActiveEndpoint == fromAddr {
		shouldSwitch = true
	} else if activeCand, hasActive := pr.Candidates[pr.ActiveEndpoint]; hasActive {
		if cand.Priority < activeCand.Priority {
			// Better priority path (e.g. LAN over WAN, or WAN over Relay/remote private IP) always wins
			shouldSwitch = true
		} else if cand.Priority == activeCand.Priority {
			if cand.Latency > 0 && (activeCand.Latency == 0 || cand.Latency < activeCand.Latency) {
				shouldSwitch = true
			} else if time.Since(activeCand.LastSuccess) > 5*time.Second {
				shouldSwitch = true
			}
		} else if cand.Priority > activeCand.Priority {
			// Lower priority path (e.g. remote private IP over STUN WAN) ONLY switches if STUN WAN is DEAD!
			if time.Since(activeCand.LastSuccess) > 10*time.Second {
				shouldSwitch = true
			}
		}
	} else {
		shouldSwitch = true
	}

	if shouldSwitch && pr.ActiveEndpoint != fromAddr {
		old := pr.ActiveEndpoint
		pr.ActiveEndpoint = fromAddr
		pr.ActiveType = cand.Type
		pr.BestLatency = cand.Latency
		if ms.onPathSwitch != nil {
			ms.onPathSwitch(deviceID, old, fromAddr, cand.Type)
		}
	} else if pr.ActiveEndpoint == fromAddr {
		pr.BestLatency = cand.Latency
	}
}


// RecordProbeFailure увеличивает счётчик неудач и переключает путь при 3 неудачах подряд
func (ms *MagicSock) RecordProbeFailure(deviceID, fromAddr string) {
	ms.mu.RLock()
	pr, ok := ms.peerRoutes[deviceID]
	ms.mu.RUnlock()
	if !ok || pr == nil {
		return
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	if cand, ok := pr.Candidates[fromAddr]; ok {
		cand.Failures++
		// Если 3 неудачи подряд — переключаемся на лучший альтернативный путь
		if cand.Failures >= 3 && pr.ActiveEndpoint == fromAddr {
			for addr, c := range pr.Candidates {
				if addr != fromAddr && c.LastSuccess.After(time.Now().Add(-10*time.Second)) {
					old := pr.ActiveEndpoint
					pr.ActiveEndpoint = addr
					pr.ActiveType = c.Type
					pr.BestLatency = c.Latency
					if ms.onPathSwitch != nil {
						ms.onPathSwitch(deviceID, old, addr, c.Type)
					}
					break
				}
			}
		}
	}
}

// GetActiveRoute returns the best current transmission endpoint for a peer.
func (ms *MagicSock) GetActiveRoute(deviceID string) (string, PathType, time.Duration) {
	ms.mu.RLock()
	pr, ok := ms.peerRoutes[deviceID]
	ms.mu.RUnlock()
	if !ok || pr == nil {
		return "", PathTypeRelay, 0
	}

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.ActiveEndpoint, pr.ActiveType, pr.BestLatency
}

// TriggerRoamingProbes fires smooth, jittered candidate probes without congesting network queues.
func (ms *MagicSock) TriggerRoamingProbes() {
	if ms.puncher == nil {
		return
	}
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	for _, pr := range ms.peerRoutes {
		pr.mu.RLock()
		for _, cand := range pr.Candidates {
			if cand.Address != "" {
				_ = ms.puncher.SendHolePunchProbe(cand.Address)
				time.Sleep(5 * time.Millisecond)
			}
		}
		pr.mu.RUnlock()
	}
}

// maintenanceLoop runs smooth background path health checks every 10 seconds without bufferbloat.
func (ms *MagicSock) maintenanceLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ms.ctx.Done():
			return
		case <-ticker.C:
			ms.TriggerRoamingProbes()
		}
	}
}

// Close terminates background magicsock workers.
func (ms *MagicSock) Close() {
	ms.cancel()
}