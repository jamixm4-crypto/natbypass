package network

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPSimultaneousOpen_EmptyTarget(t *testing.T) {
	ctx := context.Background()
	_, err := AttemptTCPSimultaneousOpen(ctx, 0, "")
	if err == nil {
		t.Fatalf("expected error for empty target address")
	}
}

func TestTCPSimultaneousOpen_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// 192.0.2.1 is TEST-NET-1 (RFC 5737), non-routable
	_, err := AttemptTCPSimultaneousOpen(ctx, 0, "192.0.2.1:54321")
	if err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestTCPDirectManager_SendReceive(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgrClient := NewTCPDirectManager(ctx)
	defer mgrClient.Close()
	mgrServer := NewTCPDirectManager(ctx)
	defer mgrServer.Close()

	receivedCh := make(chan []byte, 1)
	mgrServer.RegisterConn("peer-client", server, func(remoteAddr *net.UDPAddr, payload []byte) {
		receivedCh <- payload
	})
	mgrClient.RegisterConn("peer-server", client, nil)

	if !mgrClient.HasConn("peer-server") {
		t.Fatalf("expected client to have conn for peer-server")
	}

	testPayload := []byte("hello-natbypass-tcp-p2p-direct")
	go func() {
		_ = mgrClient.SendPacket("peer-server", testPayload)
	}()

	select {
	case recv := <-receivedCh:
		if string(recv) != string(testPayload) {
			t.Fatalf("payload mismatch: expected %s, got %s", testPayload, recv)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for TCP packet")
	}
}
