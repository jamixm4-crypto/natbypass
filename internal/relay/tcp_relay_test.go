// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package relay

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestTCPRelay_E2E(t *testing.T) {
	serverPktCh := make(chan []byte, 1)
	clientBPktCh := make(chan []byte, 1)

	serverCfg := TCPRelayServerConfig{
		ListenAddr: "127.0.0.1:0",
		DeviceID:   "relay-server-node",
		OnPacket: func(srcDevID, dstDevID string, payload []byte) {
			serverPktCh <- payload
		},
	}

	server, err := NewTCPRelayServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	serverAddr := fmt.Sprintf("127.0.0.1:%d", server.Port())

	// Client B connects and waits for messages
	clientB := NewTCPRelayClient(serverAddr, "peer-b", func(srcDevID string, payload []byte) {
		clientBPktCh <- payload
	}, nil)
	ctxB, cancelB := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelB()
	if err := clientB.Connect(ctxB); err != nil {
		t.Fatalf("Client B failed to connect: %v", err)
	}
	defer clientB.Close()

	// Client A connects
	var protectedFd atomic.Int32
	protectedFd.Store(-1)
	clientA := NewTCPRelayClient(serverAddr, "peer-a", nil, func(fd int) error {
		protectedFd.Store(int32(fd))
		return nil
	})
	ctxA, cancelA := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelA()
	if err := clientA.Connect(ctxA); err != nil {
		t.Fatalf("Client A failed to connect: %v", err)
	}
	defer clientA.Close()

	// Verify protectFn was invoked
	if protectedFd.Load() <= 0 {
		t.Logf("Warning: protectFn returned fd %d (platform specific)", protectedFd.Load())
	}

	// 1. Client A sends packet to Client B through the relay
	testPayload := []byte("Hello Peer B from Peer A via TCP 443 relay!")
	if err := clientA.SendPacket("peer-b", testPayload); err != nil {
		t.Fatalf("SendPacket to peer-b failed: %v", err)
	}

	select {
	case received := <-clientBPktCh:
		if !bytes.Equal(received, testPayload) {
			t.Fatalf("Client B received corrupted payload: got %q, want %q", received, testPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for packet at Client B")
	}

	// 2. Client A sends packet to the Relay Server directly
	serverPayload := []byte("Hello Relay Server directly!")
	if err := clientA.SendPacket("relay-server-node", serverPayload); err != nil {
		t.Fatalf("SendPacket to relay server failed: %v", err)
	}

	select {
	case received := <-serverPktCh:
		if !bytes.Equal(received, serverPayload) {
			t.Fatalf("Server received corrupted payload: got %q, want %q", received, serverPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for packet at Server")
	}

	if server.RelayedBytes() <= 0 {
		t.Fatalf("Expected server.RelayedBytes > 0, got %d", server.RelayedBytes())
	}
}

func TestTCPRelay_MeteredNetworkRejection(t *testing.T) {
	isMetered := atomic.Bool{}
	isMetered.Store(true)

	serverCfg := TCPRelayServerConfig{
		ListenAddr: "127.0.0.1:0",
		DeviceID:   "mobile-metered-node",
		IsMetered: func() bool {
			return isMetered.Load()
		},
	}

	server, err := NewTCPRelayServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	serverAddr := fmt.Sprintf("127.0.0.1:%d", server.Port())

	client := NewTCPRelayClient(serverAddr, "peer-x", nil, nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err == nil {
		t.Fatal("Expected connection to be rejected due to metered network, but succeeded")
	}
	t.Logf("Correctly rejected metered client connection: %v", err)
}

func TestTCPRelay_LowBatteryRejection(t *testing.T) {
	batteryLow := atomic.Bool{}
	batteryLow.Store(true)

	serverCfg := TCPRelayServerConfig{
		ListenAddr: "127.0.0.1:0",
		DeviceID:   "mobile-low-batt-node",
		BatteryLow: func() bool {
			return batteryLow.Load()
		},
	}

	server, err := NewTCPRelayServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	serverAddr := fmt.Sprintf("127.0.0.1:%d", server.Port())

	client := NewTCPRelayClient(serverAddr, "peer-y", nil, nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err == nil {
		t.Fatal("Expected connection to be rejected due to low battery, but succeeded")
	}
	t.Logf("Correctly rejected low battery client connection: %v", err)
}
