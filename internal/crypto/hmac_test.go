// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package crypto

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestHMAC_DeriveSignKey(t *testing.T) {
	key1 := DeriveSignKey("test-secret-123")
	key2 := DeriveSignKey("test-secret-123")
	key3 := DeriveSignKey("different-secret")

	if key1 != key2 {
		t.Fatalf("expected identical keys for identical secret")
	}
	if key1 == key3 {
		t.Fatalf("expected different keys for different secrets")
	}
	allZero := true
	for _, b := range key1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("derived key is all zeros")
	}
}

func TestHMAC_SignAndVerifySuccess(t *testing.T) {
	key := DeriveSignKey("mesh-room-alpha")
	payload := []byte(`{"device_id":"TEST-NODE-01","virtual_ip":"100.64.0.1"}`)

	frame := SignFrame(payload, key)
	if len(frame) != 32+8+len(payload) {
		t.Fatalf("expected frame len %d, got %d", 32+8+len(payload), len(frame))
	}

	verified, ts, err := VerifyFrame(frame, key, 30*time.Second)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if string(verified) != string(payload) {
		t.Fatalf("payload mismatch: got %s, expected %s", string(verified), string(payload))
	}
	if time.Since(time.Unix(ts, 0)) > 5*time.Second {
		t.Fatalf("timestamp skew too high: %v", ts)
	}
}

func TestHMAC_TamperRejection(t *testing.T) {
	key := DeriveSignKey("mesh-room-alpha")
	payload := []byte(`{"device_id":"TEST-NODE-01","virtual_ip":"100.64.0.1"}`)

	frame := SignFrame(payload, key)

	// Tamper signature
	tamperedSig := make([]byte, len(frame))
	copy(tamperedSig, frame)
	tamperedSig[0] ^= 0x01
	if _, _, err := VerifyFrame(tamperedSig, key, 30*time.Second); err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}

	// Tamper payload
	tamperedPayload := make([]byte, len(frame))
	copy(tamperedPayload, frame)
	tamperedPayload[len(tamperedPayload)-1] ^= 0x01
	if _, _, err := VerifyFrame(tamperedPayload, key, 30*time.Second); err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}

	// Wrong key
	wrongKey := DeriveSignKey("wrong-room")
	if _, _, err := VerifyFrame(frame, wrongKey, 30*time.Second); err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for wrong key, got %v", err)
	}
}

func TestHMAC_AntiReplay(t *testing.T) {
	key := DeriveSignKey("mesh-room-alpha")
	payload := []byte(`test-payload`)

	frame := SignFrame(payload, key)

	// Overwrite timestamp to 60 seconds ago and re-sign with older timestamp
	oldTs := time.Now().Unix() - 60
	binary.BigEndian.PutUint64(frame[32:40], uint64(oldTs))
	// re-calculate valid signature for old timestamp
	mac := SignFrame(payload, key)
	copy(frame[:32], mac[:32]) // now valid sig with old timestamp

	// With maxSkew = 30s, old frame should be rejected
	_, _, err := VerifyFrame(frame, key, 30*time.Second)
	if err != ErrFrameExpired && err != ErrInvalidSignature {
		t.Fatalf("expected ErrFrameExpired or ErrInvalidSignature, got %v", err)
	}
}

func TestHMAC_ShortFrame(t *testing.T) {
	key := DeriveSignKey("mesh-room-alpha")
	short := make([]byte, 39)
	if _, _, err := VerifyFrame(short, key, 30*time.Second); err != ErrFrameTooShort {
		t.Fatalf("expected ErrFrameTooShort, got %v", err)
	}
}
