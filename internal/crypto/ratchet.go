// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// SessionState (также доступен как SymmetricKDFChain) реализует симметричную KDF-цепочку
// (Symmetric KDF Chain) для обеспечения свойства Perfect Forward Secrecy (PFS).
// На каждом сообщении сессионный ключ деривируется через стандартный HKDF-Expand (RFC 5869),
// после чего предыдущий ключ цепочки немедленно перезаписывается новым значением.
type SessionState struct {
	RootKey        []byte
	SendingChain   Chain
	ReceivingChain Chain
	MessageNumber  uint32
	mu             sync.Mutex
}

// SymmetricKDFChain — точный криптографический псевдоним для SessionState.
type SymmetricKDFChain = SessionState

// Chain представляет KDF-цепочку симметричных сессионных ключей.
type Chain struct {
	ChainKey []byte
	Counter  uint32
}

// deriveStepKeys выполняет шаг KDF-цепочки по стандарту RFC 5869 (HKDF-Expand).
// Генерирует следующий ключ цепочки (nextChainKey) и одноразовый ключ сообщения (msgKey).
func deriveStepKeys(chainKey []byte) (nextChainKey, msgKey []byte, err error) {
	nextChainKey = make([]byte, 32)
	msgKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, chainKey, []byte("NatBypass-Chain-Next-v1")), nextChainKey); err != nil {
		return nil, nil, fmt.Errorf("hkdf next chain key derivation failed: %w", err)
	}
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, chainKey, []byte("NatBypass-Msg-Key-v1")), msgKey); err != nil {
		return nil, nil, fmt.Errorf("hkdf msg key derivation failed: %w", err)
	}
	return nextChainKey, msgKey, nil
}

// NewSessionState инициализирует симметричную KDF-цепочку (PFS Session) с общим мастер-ключом.
func NewSessionState(sharedSecret []byte) (*SessionState, error) {
	if len(sharedSecret) < 32 {
		return nil, fmt.Errorf("shared secret must be at least 32 bytes")
	}

	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("NatBypass-PFS-v1"))
	rootKey := make([]byte, 32)
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)

	if _, err := io.ReadFull(kdf, rootKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(kdf, sendKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(kdf, recvKey); err != nil {
		return nil, err
	}

	return &SessionState{
		RootKey: rootKey,
		SendingChain: Chain{
			ChainKey: sendKey,
			Counter:  0,
		},
		ReceivingChain: Chain{
			ChainKey: recvKey,
			Counter:  0,
		},
	}, nil
}

// Encrypt шифрует открытый текст с одноразовой ротацией ключей через HKDF-Expand.
func (s *SessionState) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextChainKey, msgKey, err := deriveStepKeys(s.SendingChain.ChainKey)
	if err != nil {
		return nil, err
	}
	s.SendingChain.ChainKey = nextChainKey
	s.SendingChain.Counter++
	s.MessageNumber++

	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt расшифровывает сообщение с одноразовой ротацией ключей через HKDF-Expand.
func (s *SessionState) Decrypt(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextChainKey, msgKey, err := deriveStepKeys(s.ReceivingChain.ChainKey)
	if err != nil {
		return nil, err
	}
	s.ReceivingChain.ChainKey = nextChainKey
	s.ReceivingChain.Counter++

	// Создаём AEAD из message key
	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}

	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:aead.NonceSize()]
	ciphertext := data[aead.NonceSize():]

	return aead.Open(nil, nonce, ciphertext, nil)
}
