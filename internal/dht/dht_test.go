package dht

import (
	"testing"
)

func TestKademliaDHT_PublishAndLookup(t *testing.T) {
	node := NewNode("device-node-1", "192.168.1.10:47832")
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
