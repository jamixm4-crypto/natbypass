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
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// maxSkipMessages limits how far ahead the chain can advance for missing UDP packets.
	maxSkipMessages = 64
	// maxSkippedKeysLimit bounds the in-memory cache of skipped message keys to prevent memory leaks.
	maxSkippedKeysLimit = 256
)

// SessionState (также доступен как SymmetricKDFChain) реализует симметричную KDF-цепочку
// (Symmetric KDF Chain) для обеспечения свойства Perfect Forward Secrecy (PFS).
// На каждом сообщении сессионный ключ деривируется через стандартный HKDF-Expand (RFC 5869),
// после чего предыдущий ключ цепочки немедленно перезаписывается новым значением.
// Поддерживает кэширование пропущенных ключей (skip-list) для устойчивости к потерям пакетов в UDP.
type SessionState struct {
	RootKey        []byte
	SendingChain   Chain
	ReceivingChain Chain
	MessageNumber  uint32
	skippedKeys    map[uint32][]byte
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
		skippedKeys: make(map[uint32][]byte),
	}, nil
}

// Encrypt шифрует открытый текст с одноразовой ротацией ключей через HKDF-Expand.
// Формат возвращаемого фрейма: [MessageNumber uint32 (4 байта)][Nonce 12 байт][Ciphertext + Poly1305 Tag].
func (s *SessionState) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msgNum := s.SendingChain.Counter
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
	out := make([]byte, 4+len(nonce)+len(ciphertext))
	binary.BigEndian.PutUint32(out[:4], msgNum)
	copy(out[4:4+len(nonce)], nonce)
	copy(out[4+len(nonce):], ciphertext)
	return out, nil
}

// Decrypt расшифровывает сообщение с одноразовой ротацией ключей через HKDF-Expand.
// Поддерживает восстановление при потере и нарушении порядка доставки UDP-пакетов через кэш пропущенных ключей (skip-list).
func (s *SessionState) Decrypt(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.skippedKeys == nil {
		s.skippedKeys = make(map[uint32][]byte)
	}

	// Минимальный размер: 4 байта msgNum + 12 байт nonce + 16 байт Poly1305 auth tag
	if len(data) < 4+12+16 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (minimum 32 bytes required)", len(data))
	}

	msgNum := binary.BigEndian.Uint32(data[:4])
	nonce := data[4 : 4+12]
	ciphertext := data[4+12:]

	var msgKey []byte

	// 1. Проверяем, был ли ключ для этого сообщения уже вычислен и сохранён в skip-кэше
	if cachedKey, ok := s.skippedKeys[msgNum]; ok {
		msgKey = cachedKey
		delete(s.skippedKeys, msgNum)
	} else if msgNum < s.ReceivingChain.Counter {
		// Сообщение уже было обработано ранее либо ключ был удалён по лимиту кэша
		return nil, fmt.Errorf("duplicate or expired message: msg_num=%d, chain_counter=%d", msgNum, s.ReceivingChain.Counter)
	} else {
		// 2. msgNum >= s.ReceivingChain.Counter: сообщение из текущего шага или из будущего
		skipCount := msgNum - s.ReceivingChain.Counter
		if skipCount > maxSkipMessages {
			return nil, fmt.Errorf("message sequence gap too large: skipped %d > %d allowed", skipCount, maxSkipMessages)
		}

		// Вычисляем и кэшируем ключи для всех пропущенных промежуточных пакетов
		for s.ReceivingChain.Counter < msgNum {
			nextChainKey, skippedKey, err := deriveStepKeys(s.ReceivingChain.ChainKey)
			if err != nil {
				return nil, err
			}
			s.skippedKeys[s.ReceivingChain.Counter] = skippedKey
			s.ReceivingChain.ChainKey = nextChainKey
			s.ReceivingChain.Counter++
		}

		// Вычисляем ключ для текущего сообщения
		nextChainKey, currentKey, err := deriveStepKeys(s.ReceivingChain.ChainKey)
		if err != nil {
			return nil, err
		}
		s.ReceivingChain.ChainKey = nextChainKey
		s.ReceivingChain.Counter++
		msgKey = currentKey
	}

	// 3. Ограничиваем размер кэша пропущенных ключей во избежание утечки памяти
	if len(s.skippedKeys) > maxSkippedKeysLimit {
		var oldestKeys []uint32
		for k := range s.skippedKeys {
			oldestKeys = append(oldestKeys, k)
		}
		for _, k := range oldestKeys[:len(oldestKeys)/2] {
			delete(s.skippedKeys, k)
		}
	}

	// 4. Расшифровываем полезную нагрузку
	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}
