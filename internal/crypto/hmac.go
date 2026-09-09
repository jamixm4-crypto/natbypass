// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

var (
	ErrFrameTooShort    = errors.New("signaling frame too short")
	ErrFrameExpired     = errors.New("signaling frame expired or timestamp skew too high")
	ErrInvalidSignature = errors.New("invalid HMAC signature")
)

// DeriveSignKey derives a 32-byte HMAC authentication key from a networkKey using HKDF-SHA256.
func DeriveSignKey(networkKey string) [32]byte {
	kdf := hkdf.New(sha256.New, []byte(networkKey), nil, []byte("NatBypass-Signaling-HMAC-Auth"))
	var key [32]byte
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		// Fallback to SHA256 if HKDF stream read fails
		return sha256.Sum256([]byte("NatBypass-Signaling-HMAC-Auth:" + networkKey))
	}
	return key
}

// SignFrame creates an authenticated signaling message frame:
// [Signature 32B (HMAC-SHA256)][Timestamp 8B (BigEndian)][Payload N Bytes]
// The HMAC-SHA256 signature is calculated over [Timestamp || Payload].
func SignFrame(payload []byte, signKey [32]byte) []byte {
	now := time.Now().Unix()
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(now))

	mac := hmac.New(sha256.New, signKey[:])
	mac.Write(tsBuf[:])
	mac.Write(payload)

	var sumBuf [32]byte
	sig := mac.Sum(sumBuf[:0])

	frame := make([]byte, 32+8+len(payload))
	copy(frame[0:32], sig)
	copy(frame[32:40], tsBuf[:])
	copy(frame[40:], payload)
	return frame
}

// VerifyFrame verifies the HMAC-SHA256 signature and ensures the frame timestamp
// is within maxSkew seconds of the current local clock (anti-replay).
// Uses constant-time hmac.Equal and stack-allocated hash buffer for zero allocations on MIPS.
func VerifyFrame(frame []byte, signKey [32]byte, maxSkew time.Duration) ([]byte, int64, error) {
	if len(frame) < 40 {
		return nil, 0, ErrFrameTooShort
	}

	expectedSig := frame[:32]
	tsBytes := frame[32:40]
	payload := frame[40:]

	ts := int64(binary.BigEndian.Uint64(tsBytes))
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if maxSkew > 0 && diff > int64(maxSkew.Seconds()) {
		return nil, ts, ErrFrameExpired
	}

	mac := hmac.New(sha256.New, signKey[:])
	mac.Write(tsBytes)
	mac.Write(payload)

	var sumBuf [32]byte
	computedSig := mac.Sum(sumBuf[:0])

	if !hmac.Equal(expectedSig, computedSig) {
		return nil, ts, ErrInvalidSignature
	}

	return payload, ts, nil
}
