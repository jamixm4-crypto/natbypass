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

func TestTCPDirectManager_RegisterAndClose(t *testing.T) {
	ctx := context.Background()
	mgr := NewTCPDirectManager(ctx)

	if mgr.HasConn("peer-x") {
		t.Fatalf("expected no conn initially")
	}

	// Create a real loopback TCP pair
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := listener.Accept()
		connCh <- c
	}()

	clientConn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	serverConn := <-connCh
	defer serverConn.Close()

	received := make(chan []byte, 1)
	mgr.RegisterConn("peer-x", clientConn, func(addr *net.UDPAddr, payload []byte) {
		received <- payload
	})

	if !mgr.HasConn("peer-x") {
		t.Fatalf("expected HasConn true after RegisterConn")
	}

	// Send a length-prefixed frame from server side
	testData := []byte{0x45, 0x00, 0x00, 0x14} // fake IPv4 header
	frame := make([]byte, 2+len(testData))
	frame[0] = 0x00
	frame[1] = byte(len(testData))
	copy(frame[2:], testData)
	_, _ = serverConn.Write(frame)

	select {
	case pkt := <-received:
		if len(pkt) != len(testData) {
			t.Fatalf("expected %d bytes, got %d", len(testData), len(pkt))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for TCP packet")
	}

	mgr.Close()
	if mgr.HasConn("peer-x") {
		t.Fatalf("expected HasConn false after Close")
	}
}

