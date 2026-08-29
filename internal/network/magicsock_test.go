package network

import (
	"testing"
	"time"
)

func TestMagicSock_CandidateSwitching(t *testing.T) {
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