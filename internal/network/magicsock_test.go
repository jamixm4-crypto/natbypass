package network

import (
	"net"
	"testing"
	"time"
)

func TestMagicSock_CandidateSwitching(t *testing.T) {
	isLocalSubnetHook = func(ip net.IP) bool {
		return ip.String() == "192.168.1.50"
	}
	defer func() { isLocalSubnetHook = nil }()

	ms := NewMagicSock(nil, func(deviceID, oldPath, newPath string, pType PathType) {
		t.Logf("Path switched for %s: %s -> %s (%s)", deviceID, oldPath, newPath, pType)
	})
	defer ms.Close()

	devID := "peer-test-1"
	ms.RegisterPeerEndpoints(devID, "95.21.40.10:47832", "192.168.1.50:47832", "[2001:db8::1]:47832")

	// Initially defaults to STUN WAN
	ep, pType, _ := ms.GetActiveRoute(devID)
	if ep != "95.21.40.10:47832" || pType != PathTypeWAN {
		t.Errorf("expected initial WAN endpoint, got %s (%s)", ep, pType)
	}

	// STUN responds with 35ms
	ms.RecordProbeSuccess(devID, "95.21.40.10:47832", 35*time.Millisecond)

	// LAN responds with 0.8ms (Priority 1) -> Must auto-switch to LAN!
	ms.RecordProbeSuccess(devID, "192.168.1.50:47832", 800*time.Microsecond)

	ep, pType, lat := ms.GetActiveRoute(devID)
	if ep != "192.168.1.50:47832" || pType != PathTypeLAN {
		t.Errorf("expected auto-switch to LAN endpoint, got %s (%s)", ep, pType)
	}
	if lat <= 0 {
		t.Errorf("expected valid latency, got %v", lat)
	}
}

func TestMagicSock_ProbeCount_TCPFallbackTriggered(t *testing.T) {
	p, err := NewUDPPuncher(0, "tcp-fallback-test", nil, nil)
	if err != nil {
		t.Fatalf("failed to create puncher: %v", err)
	}
	defer p.Close()

	triggered := make(chan struct{}, 1)
	ms := NewMagicSock(p, func(deviceID, oldPath, newPath string, pType PathType) {
		if pType == PathTypeTCP {
			select {
			case triggered <- struct{}{}:
			default:
			}
		}
	})
	defer ms.Close()

	devID := "peer-tcp-test"
	// Register a localhost endpoint so TCP dial goes somewhere testable
	ms.RegisterPeerEndpoints(devID, "127.0.0.1:0", "", "")

	// Must NOT trigger before threshold
	for i := 0; i < TCPFallbackProbeThreshold-1; i++ {
		ms.RecordProbeAttempt(devID)
	}
	if ms.hasTCPAttempted(devID) {
		t.Fatalf("TCP fallback triggered before threshold")
	}

	// The 200th probe must set tcpAttempted flag
	ms.RecordProbeAttempt(devID)
	if !ms.hasTCPAttempted(devID) {
		t.Fatalf("expected TCP fallback to be attempted after threshold")
	}
}

func TestMagicSock_HasTCPConn_False(t *testing.T) {
	p, err := NewUDPPuncher(0, "tcp-conn-test", nil, nil)
	if err != nil {
		t.Fatalf("failed to create puncher: %v", err)
	}
	defer p.Close()

	ms := NewMagicSock(p, nil)
	defer ms.Close()

	if ms.HasTCPConn("nonexistent-peer") {
		t.Fatalf("expected HasTCPConn to return false for unknown peer")
	}
}