package dht

import (
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
	node1 := NewNode("node-1", "127.0.0.1:49152")
	defer node1.Close()

	// Node 2 (Replication Recipient)
	node2 := NewNode("node-2", "127.0.0.1:49153")
	defer node2.Close()

	_ = node1.Bootstrap([]string{"127.0.0.1:49153"})
	_ = node2.Bootstrap([]string{"127.0.0.1:49152"})

	time.Sleep(30 * time.Millisecond)

	// Publish on Node 1 -> replicates to Node 2
	err := node1.PublishEndpoint("peer-target-x", "100.64.200.55:51820")
	if err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Lookup on Node 2
	endpoint, err := node2.LookupEndpoint("peer-target-x")
	if err != nil || endpoint != "100.64.200.55:51820" {
		t.Fatalf("expected replicated endpoint 100.64.200.55:51820, got %s (err: %v)", endpoint, err)
	}
}
