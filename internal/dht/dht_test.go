// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dht

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestKademliaDHT_PublishAndLookup(t *testing.T) {
	node := NewNode("device-node-1", "")
	_ = node.Bootstrap([]string{"192.168.1.20:47832", "95.21.40.10:47832"})

	err := node.PublishEndpoint("peer-target-2", "95.21.40.10:47832")
	if err != nil {
		t.Fatalf("failed to publish endpoint: %v", err)
	}

	endpoint, err := node.LookupEndpoint("peer-target-2")
	if err != nil || endpoint != "95.21.40.10:47832" {
		t.Fatalf("expected 95.21.40.10:47832, got %s (err: %v)", endpoint, err)
	}
}

func TestDHT_Replication(t *testing.T) {
	// Node 1 (Storage Provider)
	node1 := NewNode("node-1", "127.0.0.1:0")
	defer node1.Close()

	// Node 2 (Replication Recipient)
	node2 := NewNode("node-2", "127.0.0.1:0")
	defer node2.Close()

	_ = node1.Bootstrap([]string{node2.Address})
	_ = node2.Bootstrap([]string{node1.Address})

	time.Sleep(30 * time.Millisecond)

	// Publish on Node 1 -> replicates to Node 2
	err := node1.PublishEndpoint("peer-target-x", "100.64.200.55:51820")
	if err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	// Lookup on Node 2 with retry polling
	var endpoint string
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		endpoint, err = node2.LookupEndpoint("peer-target-x")
		if err == nil && endpoint == "100.64.200.55:51820" {
			break
		}
	}
	if err != nil || endpoint != "100.64.200.55:51820" {
		t.Fatalf("expected replicated endpoint 100.64.200.55:51820, got %s (err: %v)", endpoint, err)
	}
}

func TestSingleSocketDHT_PunchNow(t *testing.T) {
	var nodeB *Node

	// Node A sends via simulated puncher socket
	nodeA := NewNodeWithSender("device-a", func(data []byte, rAddr *net.UDPAddr) error {
		// Route directly to node B's HandlePacket
		if nodeB != nil {
			nodeB.HandlePacket(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 30001})
		}
		return nil
	})

	var wg sync.WaitGroup
	wg.Add(1)

	var gotSenderID string
	var gotSenderSTUN string

	// Node B receives via its virtual socket
	nodeB = NewNodeWithSender("device-b", func(data []byte, rAddr *net.UDPAddr) error {
		return nil
	})
	nodeB.SetOnPunchNow(func(senderID, senderSTUN string) {
		gotSenderID = senderID
		gotSenderSTUN = senderSTUN
		wg.Done()
	})

	// Node A transmits PUNCH_NOW to Node B
	err := nodeA.SendPunchNow("device-b", "127.0.0.1:30002", "198.51.100.1:51820")
	if err != nil {
		t.Fatalf("SendPunchNow failed: %v", err)
	}

	wg.Wait()

	if gotSenderID != "device-a" {
		t.Errorf("expected senderID 'device-a', got %q", gotSenderID)
	}
	if gotSenderSTUN != "198.51.100.1:51820" {
		t.Errorf("expected senderSTUN '198.51.100.1:51820', got %q", gotSenderSTUN)
	}
}

func TestSingleSocketDHT_StoreAndFind(t *testing.T) {
	var nodeA, nodeB *Node

	nodeA = NewNodeWithSender("device-a", func(data []byte, rAddr *net.UDPAddr) error {
		if nodeB != nil {
			nodeB.HandlePacket(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40001})
		}
		return nil
	})

	nodeB = NewNodeWithSender("device-b", func(data []byte, rAddr *net.UDPAddr) error {
		if nodeA != nil {
			nodeA.HandlePacket(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40002})
		}
		return nil
	})

	// Node A stores key on Node B
	key := [20]byte{1, 2, 3, 4, 5}
	nodeA.sendStoreRequest("127.0.0.1:40002", key, []byte("93.184.216.34:51820"))

	nodeB.mu.RLock()
	val, ok := nodeB.Store[key]
	nodeB.mu.RUnlock()

	if !ok || string(val) != "93.184.216.34:51820" {
		t.Fatalf("expected stored value on nodeB, got ok=%v, val=%s", ok, string(val))
	}
}
