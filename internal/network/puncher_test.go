package network

import (
	"testing"
	"time"
)

func TestHopPort_NoRace(t *testing.T) {
	p, err := NewUDPPuncher(0, "test-dev-1", nil, nil)
	if err != nil {
		t.Fatalf("failed to create UDPPuncher: %v", err)
	}
	defer p.Close()

	initialPort := p.LocalPort()
	if initialPort == 0 {
		t.Fatalf("expected non-zero local port")
	}

	// Hop port sequentially to verify socket teardown and recreate without race
	for i := 0; i < 3; i++ {
		newPort, err := p.HopPort()
		if err != nil {
			t.Fatalf("HopPort failed on iteration %d: %v", i, err)
		}
		if newPort == 0 {
			t.Fatalf("HopPort returned 0 port on iteration %d", i)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
