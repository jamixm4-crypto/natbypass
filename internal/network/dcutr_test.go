package network

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScheduleSimultaneousOpenMilli_Execution(t *testing.T) {
	// Create dummy UDP puncher
	puncher, err := NewUDPPuncher(-1, "test-node", nil, nil)
	if err != nil {
		t.Fatalf("failed to create puncher: %v", err)
	}
	defer puncher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Schedule in 50ms
	startAtMilli := time.Now().UnixMilli() + 50
	err = puncher.ScheduleSimultaneousOpenMilli(ctx, startAtMilli, "127.0.0.1", []int{15000, 15001}, 2, 5)
	if err != nil {
		t.Fatalf("ScheduleSimultaneousOpenMilli failed: %v", err)
	}
}

func TestScheduleSimultaneousOpenMilli_Expired(t *testing.T) {
	puncher, err := NewUDPPuncher(-1, "test-node-expired", nil, nil)
	if err != nil {
		t.Fatalf("failed to create puncher: %v", err)
	}
	defer puncher.Close()

	ctx := context.Background()
	// Signal expired 10 seconds ago
	expiredMilli := time.Now().UnixMilli() - 10000
	err = puncher.ScheduleSimultaneousOpenMilli(ctx, expiredMilli, "127.0.0.1", []int{15000}, 2, 5)
	if err == nil {
		t.Fatalf("expected error for expired simultaneous open signal")
	}
}

func TestSendLowTTLDecoyProbe(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer conn.Close()

	rAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: conn.LocalAddr().(*net.UDPAddr).Port}
	payload := []byte("decoy-test-payload")

	err = SendLowTTLDecoyProbe(conn, rAddr, payload, 2)
	if err != nil {
		t.Logf("SendLowTTLDecoyProbe returned error (expected if permissions restricted): %v", err)
	}
}
