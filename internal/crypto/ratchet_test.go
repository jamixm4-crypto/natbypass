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
	"fmt"
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

func TestSymmetricKDFChain_PacketLossAndOutOfOrder(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 42)
	}

	alice, err := NewSessionState(secret)
	if err != nil {
		t.Fatalf("NewSessionState alice failed: %v", err)
	}
	bob, err := NewSessionState(secret)
	if err != nil {
		t.Fatalf("NewSessionState bob failed: %v", err)
	}
	bob.ReceivingChain.ChainKey = make([]byte, len(alice.SendingChain.ChainKey))
	copy(bob.ReceivingChain.ChainKey, alice.SendingChain.ChainKey)

	// Alice produces 5 messages: 0, 1, 2, 3, 4
	messages := make([][]byte, 5)
	ciphertexts := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		messages[i] = []byte(fmt.Sprintf("UDP packet payload message index %d", i))
		ct, err := alice.Encrypt(messages[i])
		if err != nil {
			t.Fatalf("encrypt %d failed: %v", i, err)
		}
		ciphertexts[i] = ct
	}

	// Bob receives out-of-order and with gaps: 0, then 3, then 1, then 2, then 4
	receiveOrder := []int{0, 3, 1, 2, 4}
	for _, idx := range receiveOrder {
		dec, err := bob.Decrypt(ciphertexts[idx])
		if err != nil {
			t.Fatalf("decrypt out-of-order message index %d failed: %v", idx, err)
		}
		if !bytes.Equal(dec, messages[idx]) {
			t.Fatalf("payload mismatch for index %d: expected %q, got %q", idx, messages[idx], dec)
		}
	}
}

func TestSymmetricKDFChain_DuplicatePacket(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 13)
	}

	alice, _ := NewSessionState(secret)
	bob, _ := NewSessionState(secret)
	bob.ReceivingChain.ChainKey = make([]byte, len(alice.SendingChain.ChainKey))
	copy(bob.ReceivingChain.ChainKey, alice.SendingChain.ChainKey)

	msg := []byte("unique payload for replay testing")
	ct, err := alice.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// First decrypt: should succeed
	dec1, err := bob.Decrypt(ct)
	if err != nil || !bytes.Equal(dec1, msg) {
		t.Fatalf("first decrypt failed: %v", err)
	}

	// Second decrypt of same ciphertext: should fail as duplicate
	_, err = bob.Decrypt(ct)
	if err == nil {
		t.Fatalf("expected duplicate packet decrypt to fail, but it succeeded")
	}
}

func TestSymmetricKDFChain_MaxSkipExceeded(t *testing.T) {
	secret := make([]byte, 32)
	alice, _ := NewSessionState(secret)
	bob, _ := NewSessionState(secret)
	bob.ReceivingChain.ChainKey = make([]byte, len(alice.SendingChain.ChainKey))
	copy(bob.ReceivingChain.ChainKey, alice.SendingChain.ChainKey)

	// Alice encrypts 70 messages (exceeding maxSkipMessages = 64)
	var lastCT []byte
	for i := 0; i < 70; i++ {
		ct, err := alice.Encrypt([]byte(fmt.Sprintf("msg %d", i)))
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		lastCT = ct
	}

	// Bob is at counter 0 and receives message 69 (gap of 69 > 64)
	_, err := bob.Decrypt(lastCT)
	if err == nil {
		t.Fatalf("expected gap > 64 to fail, but it succeeded")
	}
}

func TestStatelessHKDF_UDPLossAndReorderRecovery(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 77)
	}
	alice, _ := NewSessionState(secret)
	bob, _ := NewSessionState(secret)
	bob.ReceivingChain.ChainKey = make([]byte, len(alice.SendingChain.ChainKey))
	copy(bob.ReceivingChain.ChainKey, alice.SendingChain.ChainKey)

	// Alice produces 40 messages (indices 0..39)
	packets := make([][]byte, 40)
	for i := 0; i < 40; i++ {
		ct, err := alice.Encrypt([]byte(fmt.Sprintf("udp-packet-%d", i)))
		if err != nil {
			t.Fatalf("encrypt %d failed: %v", i, err)
		}
		packets[i] = ct
	}

	// 1. Packet 0 received
	dec0, err := bob.Decrypt(packets[0])
	if err != nil || string(dec0) != "udp-packet-0" {
		t.Fatalf("packet 0 failed: %v", err)
	}

	// 2. Heavy loss: packets 1..25 lost! Packet 26 arrives directly
	dec26, err := bob.Decrypt(packets[26])
	if err != nil || string(dec26) != "udp-packet-26" {
		t.Fatalf("packet 26 failed after loss: %v", err)
	}

	// 3. Out-of-order: packet 10 (which was previously delayed in transit) arrives now
	dec10, err := bob.Decrypt(packets[10])
	if err != nil || string(dec10) != "udp-packet-10" {
		t.Fatalf("out-of-order packet 10 failed: %v", err)
	}

	// 4. Replay attack: packet 10 replayed again -> must be rejected
	_, err = bob.Decrypt(packets[10])
	if err == nil {
		t.Fatalf("expected replay of packet 10 to fail, but succeeded")
	}

	// 5. Subsequent in-order packet 27 arrives
	dec27, err := bob.Decrypt(packets[27])
	if err != nil || string(dec27) != "udp-packet-27" {
		t.Fatalf("packet 27 failed: %v", err)
	}
}

