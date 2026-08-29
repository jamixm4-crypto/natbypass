package network

import (
	"context"
	"strings"
	"sync"
	"time"
)

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
func (ms *MagicSock) RegisterPeerEndpoints(deviceID, stunAddr, localAddr, ipv6Addr string) {
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

	// 1. LAN candidate
	if localAddr != "" {
		if _, exists := pr.Candidates[localAddr]; !exists {
			pr.Candidates[localAddr] = &EndpointCandidate{
				Address:  localAddr,
				Type:     PathTypeLAN,
				Priority: 1,
			}
		}
	}

	// 2. IPv6 candidate
	if ipv6Addr != "" {
		if _, exists := pr.Candidates[ipv6Addr]; !exists {
			pr.Candidates[ipv6Addr] = &EndpointCandidate{
				Address:  ipv6Addr,
				Type:     PathTypeIPv6,
				Priority: 2,
			}
		}
	}

	// 3. STUN WAN candidate
	if stunAddr != "" {
		if _, exists := pr.Candidates[stunAddr]; !exists {
			pr.Candidates[stunAddr] = &EndpointCandidate{
				Address:  stunAddr,
				Type:     PathTypeWAN,
				Priority: 3,
			}
		}
	}

	if pr.ActiveEndpoint == "" {
		if stunAddr != "" {
			pr.ActiveEndpoint = stunAddr
			pr.ActiveType = PathTypeWAN
		} else if localAddr != "" {
			pr.ActiveEndpoint = localAddr
			pr.ActiveType = PathTypeLAN
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
		pType := PathTypeWAN
		if strings.HasPrefix(fromAddr, "192.168.") || strings.HasPrefix(fromAddr, "10.") || strings.HasPrefix(fromAddr, "172.") {
			pType = PathTypeLAN
		} else if strings.Contains(fromAddr, "[") {
			pType = PathTypeIPv6
		}
		cand = &EndpointCandidate{
			Address:  fromAddr,
			Type:     pType,
			Priority: 3,
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

	// Auto-promote candidate if it has lower priority number or significantly lower latency
	shouldSwitch := false
	if pr.ActiveEndpoint == "" || pr.ActiveEndpoint == fromAddr {
		shouldSwitch = true
	} else if activeCand, hasActive := pr.Candidates[pr.ActiveEndpoint]; hasActive {
		// LAN always wins if reachable
		if cand.Type == PathTypeLAN && activeCand.Type != PathTypeLAN {
			shouldSwitch = true
		} else if cand.Priority <= activeCand.Priority && cand.Latency < activeCand.Latency {
			shouldSwitch = true
		} else if time.Since(activeCand.LastSuccess) > 15*time.Second {
			shouldSwitch = true
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

// TriggerRoamingProbes fires immediate multi-path probe bursts to all candidates across all peers.
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
			}
		}
		pr.mu.RUnlock()
	}
}

// maintenanceLoop runs background health checks and path optimization every 4 seconds.
func (ms *MagicSock) maintenanceLoop() {
	ticker := time.NewTicker(4 * time.Second)
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