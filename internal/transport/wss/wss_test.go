// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package wss

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
)

func TestWSSRelay_EndToEnd(t *testing.T) {
	key := crypto.DeriveKey("mesh-network-secret-key-12345")
	wrongKey := crypto.DeriveKey("wrong-secret-key")

	server := NewWSSRelayServer(key)
	ts := httptest.NewServer(server)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Test Wrong Key Rejection
	badClient := NewWSSClient(ctx, wsURL, "bad-client", wrongKey, "", nil)
	if err := badClient.connect(); err == nil {
		t.Fatalf("expected bad client to fail authentication, but succeeded")
	}

	// 2. Test Client A and Client B bidirectional packet exchange
	recvB := make(chan []byte, 1)
	clientB := NewWSSClient(ctx, wsURL, "node-b", key, "", func(srcDevID string, payload []byte) {
		if srcDevID == "node-a" {
			recvB <- payload
		}
	})
	clientB.Start()
	defer clientB.Close()

	recvA := make(chan []byte, 1)
	clientA := NewWSSClient(ctx, wsURL, "node-a", key, "", func(srcDevID string, payload []byte) {
		if srcDevID == "node-b" {
			recvA <- payload
		}
	})
	clientA.Start()
	defer clientA.Close()

	// Wait for both clients to connect
	var connected bool
	for i := 0; i < 30; i++ {
		if clientA.IsConnected() && clientB.IsConnected() {
			connected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !connected {
		t.Fatalf("clients failed to connect to WSS relay within timeout")
	}

	// Send A -> B
	msgAToB := []byte("HELLO_FROM_NODE_A_PACKET_DATA")
	if err := clientA.SendPacket("node-b", msgAToB); err != nil {
		t.Fatalf("clientA.SendPacket failed: %v", err)
	}

	select {
	case pkt := <-recvB:
		if !bytes.Equal(pkt, msgAToB) {
			t.Fatalf("node-b received mismatch: expected %q, got %q", msgAToB, pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for packet on node-b")
	}

	// Send B -> A
	msgBToA := []byte("REPLY_FROM_NODE_B_PONG")
	if err := clientB.SendPacket("node-a", msgBToA); err != nil {
		t.Fatalf("clientB.SendPacket failed: %v", err)
	}

	select {
	case pkt := <-recvA:
		if !bytes.Equal(pkt, msgBToA) {
			t.Fatalf("node-a received mismatch: expected %q, got %q", msgBToA, pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for packet on node-a")
	}
}
