package network

import (
	"net"
	"testing"
)

func TestUDPPuncher_ReplayProtection(t *testing.T) {
	p := &UDPPuncher{}
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 47832}
	epoch := uint64(100)

	if !p.validateUDPReplay(addr, epoch, 1) {
		t.Fatal("expected initial seq 1 to be accepted")
	}
	if !p.validateUDPReplay(addr, epoch, 2) {
		t.Fatal("expected fresh seq 2 to be accepted")
	}
	if p.validateUDPReplay(addr, epoch, 2) {
		t.Fatal("expected replayed seq 2 to be rejected")
	}
	if p.validateUDPReplay(addr, epoch, 1) {
		t.Fatal("expected replayed seq 1 to be rejected")
	}
	if !p.validateUDPReplay(addr, epoch+1, 1) {
		t.Fatal("expected fresh packet in next epoch to be accepted")
	}
}
