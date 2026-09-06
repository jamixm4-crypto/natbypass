// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// WGKeyPair — пара ключей WireGuard
type WGKeyPair struct {
	PrivateKey string // base64
	PublicKey  string // base64
}

// GenerateKeyPair генерирует новую пару ключей WireGuard (Curve25519)
func GenerateKeyPair() (*WGKeyPair, error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	// Clamp private key per Curve25519 spec
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	// Compute public key via Curve25519 scalar mult
	pubKeyBytes, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("curve25519: %w", err)
	}

	return &WGKeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pubKeyBytes),
	}, nil
}

// KeyFilePath возвращает путь к файлу с приватным ключом
func KeyFilePath(hostname string) string {
	safeHost := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, hostname)
	return fmt.Sprintf("probe-%s.key", safeHost)
}

// LoadOrGenerateKeyPair загружает ключевую пару из файла или генерирует новую
func LoadOrGenerateKeyPair(hostname string) (*WGKeyPair, error) {
	keyPath := KeyFilePath(hostname)

	if data, err := os.ReadFile(keyPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) >= 2 {
			kp := &WGKeyPair{
				PrivateKey: strings.TrimSpace(lines[0]),
				PublicKey:  strings.TrimSpace(lines[1]),
			}
			// Validate base64
			if _, err := base64.StdEncoding.DecodeString(kp.PrivateKey); err == nil {
				logf("[KEY] Loaded existing keypair from %s (pub=%s...)", keyPath, kp.PublicKey[:8])
				return kp, nil
			}
		}
	}

	// Generate new keypair
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Save to file
	content := kp.PrivateKey + "\n" + kp.PublicKey + "\n"
	if err := os.WriteFile(keyPath, []byte(content), 0600); err != nil {
		// Non-fatal: warn but continue
		logf("[KEY] Warning: could not save keypair to %s: %v", keyPath, err)
	} else {
		logf("[KEY] Generated new keypair, saved to %s", filepath.Base(keyPath))
	}
	logf("[KEY] Public key: %s", kp.PublicKey)
	return kp, nil
}
