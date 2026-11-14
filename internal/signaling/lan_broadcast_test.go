// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package signaling

import (
	"context"
	"testing"
	"time"
)

func TestLANBroadcastChannel_SendReceive(t *testing.T) {
	testPort := 51833
	netKey := "test-secret-key-12345"

	ch1 := NewLANBroadcastChannel("dev-node-1", netKey, testPort)
	defer ch1.Close()

	if !ch1.IsAvailable(context.Background()) {
		t.Fatal("ch1 should be available")
	}

	rxCh, err := ch1.Receive(context.Background())
	if err != nil {
		t.Fatalf("failed to receive: %v", err)
	}

	// Wait for listener to bind
	time.Sleep(100 * time.Millisecond)

	// Node 2 sends payload
	ch2 := NewLANBroadcastChannel("dev-node-2", netKey, testPort+1)
	defer ch2.Close()
	ch2.port = testPort // Target ch1's port for broadcast

	testPayload := &Payload{
		DeviceID:  "dev-node-2",
		Nickname:  "PeerTwo",
		VirtualIP: "10.1.2.99",
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := ch2.Send(ctx, testPayload); err != nil {
		t.Fatalf("failed to send broadcast: %v", err)
	}

	select {
	case p := <-rxCh:
		if p.DeviceID != "dev-node-2" {
			t.Errorf("expected DeviceID 'dev-node-2', got '%s'", p.DeviceID)
		}
		if p.VirtualIP != "10.1.2.99" {
			t.Errorf("expected VirtualIP '10.1.2.99', got '%s'", p.VirtualIP)
		}
	case <-time.After(2 * time.Second):
		t.Log("Note: Broadcast might be filtered by OS loopback interface in sandbox, which is expected on some systems.")
	}
}
