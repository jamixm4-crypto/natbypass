package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDoubleRatchet_PFS(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	alice, err := NewSessionState(secret)
	if err != nil {
		t.Fatalf("failed to create alice session: %v", err)
	}

	bob, err := NewSessionState(secret)
	if err != nil {
		t.Fatalf("failed to create bob session: %v", err)
	}

	// Swap keys for symmetric direction
	bob.ReceivingChain.ChainKey = alice.SendingChain.ChainKey

	msg1 := []byte("Hello, secure NatBypass mesh network!")
	enc1, err := alice.Encrypt(msg1)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	dec1, err := bob.Decrypt(enc1)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(msg1, dec1) {
		t.Fatalf("expected %s, got %s", string(msg1), string(dec1))
	}
}
