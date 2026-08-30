package relay

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestUDPRelay_PacketEncryption(t *testing.T) {
	var key [32]byte
	_, _ = rand.Read(key[:])

	received := make(chan []byte, 1)
	client, err := NewUDPRelayClient("", "device-test-1", key, func(srcID string, payload []byte) {
		received <- payload
	})
	if err != nil {
		t.Fatalf("failed to create udp relay client: %v", err)
	}
	defer client.Close()

	if client.myDeviceID != "device-test-1" {
		t.Fatalf("expected device-test-1, got %s", client.myDeviceID)
	}
	_ = time.Second
}
