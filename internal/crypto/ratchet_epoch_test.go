// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package crypto

import (
	"bytes"
	"testing"
)

func TestEpochMasterKey_Determinism(t *testing.T) {
	secret := "mesh-network-secret-key-2026"
	epoch := uint64(100)

	key1 := DeriveEpochMasterKey(secret, epoch)
	key2 := DeriveEpochMasterKey(secret, epoch)

	if key1 != key2 {
		t.Fatalf("DeriveEpochMasterKey is not deterministic: %x vs %x", key1, key2)
	}

	// Different epoch must yield different key
	keyNext := DeriveEpochMasterKey(secret, epoch+1)
	if key1 == keyNext {
		t.Fatalf("Different epochs produced identical keys: %x", key1)
	}
}

func TestEpoch_EncryptDecrypt_Success(t *testing.T) {
	baseKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	epoch := uint64(500)
	message := []byte("Hello, NatBypass Mesh with Perfect Forward Secrecy!")

	encrypted, err := EncryptWithEpoch(message, baseKey, epoch)
	if err != nil {
		t.Fatalf("EncryptWithEpoch error: %v", err)
	}

	// Decrypt on same epoch
	decrypted, msgEpoch, err := DecryptWithEpoch(encrypted, baseKey, epoch)
	if err != nil {
		t.Fatalf("DecryptWithEpoch error: %v", err)
	}
	if msgEpoch != epoch {
		t.Errorf("Expected epoch %d, got %d", epoch, msgEpoch)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("Decrypted mismatch: got %s, want %s", string(decrypted), string(message))
	}
}

func TestEpoch_ToleranceWindow(t *testing.T) {
	baseKey := []byte("0123456789abcdef0123456789abcdef")
	epoch := uint64(1000)
	message := []byte("Window Tolerance Test")

	encrypted, err := EncryptWithEpoch(message, baseKey, epoch)
	if err != nil {
		t.Fatalf("EncryptWithEpoch error: %v", err)
	}

	// Receiver is 1 epoch ahead (e.g. key rotation just happened on receiver) -> MUST SUCCEED
	dec1, _, err1 := DecryptWithEpoch(encrypted, baseKey, epoch+1)
	if err1 != nil {
		t.Errorf("DecryptWithEpoch with tolerance (+1) failed: %v", err1)
	}
	if !bytes.Equal(dec1, message) {
		t.Errorf("Message mismatch")
	}

	// Receiver is 1 epoch behind (clock skew) -> MUST SUCCEED
	dec2, _, err2 := DecryptWithEpoch(encrypted, baseKey, epoch-1)
	if err2 != nil {
		t.Errorf("DecryptWithEpoch with tolerance (-1) failed: %v", err2)
	}
	if !bytes.Equal(dec2, message) {
		t.Errorf("Message mismatch")
	}

	// Receiver is 2 epochs ahead -> MUST FAIL (outside window)
	_, _, errFar := DecryptWithEpoch(encrypted, baseKey, epoch+2)
	if errFar == nil {
		t.Errorf("Expected failure for epoch out of window, but succeeded")
	}
}
