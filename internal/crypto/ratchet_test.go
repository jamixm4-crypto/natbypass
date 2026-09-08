// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

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

func TestSymmetricKDFChain_MultiMessagePFS(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	alice, err := NewSessionState(secret)
	if err != nil {
		t.Fatalf("failed to create alice session: %v", err)
	}
	bob, err := NewSessionState(secret)
	if err != nil {
		t.Fatalf("failed to create bob session: %v", err)
	}
	bob.ReceivingChain.ChainKey = make([]byte, len(alice.SendingChain.ChainKey))
	copy(bob.ReceivingChain.ChainKey, alice.SendingChain.ChainKey)

	for i := 1; i <= 5; i++ {
		msg := []byte(bytes.Repeat([]byte{byte(i)}, 100))
		ct, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("encrypt step %d failed: %v", i, err)
		}
		pt, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("decrypt step %d failed: %v", i, err)
		}
		if !bytes.Equal(msg, pt) {
			t.Fatalf("step %d payload mismatch", i)
		}
	}
}
