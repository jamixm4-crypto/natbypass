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
	// maxSkipMessages limits how far ahead the packet sequence can advance for missing UDP packets.
	maxSkipMessages = 64
)

// SessionState (также доступен как SymmetricKDFChain) реализует устойчивую к потерям UDP-пакетов
// симметричную схему шифрования (Stateless HKDF per-packet key derivation) со скользящим окном
// защиты от повторов (anti-replay sliding window по стандарту RFC 2401).
// Ключ для каждого сообщения деривируется напрямую из RootKey/ChainKey и Counter через HKDF-Expand.
type SessionState struct {
	RootKey        []byte
	SendingChain   Chain
	ReceivingChain Chain
	MessageNumber  uint32
	replayWindow   uint64 // 64-битная битовая маска скользящего окна
	replayBase     uint32 // максимальный полученный номер пакета
	hasReceived    bool   // флаг первого полученного пакета
	mu             sync.Mutex
}

// SymmetricKDFChain — точный криптографический псевдоним для SessionState.
type SymmetricKDFChain = SessionState

// Chain представляет состояние направления передачи сессионных ключей.
type Chain struct {
	ChainKey []byte
	Counter  uint32
}

// deriveMsgKeyStateless деривирует ключ для конкретного пакета напрямую из rootKey и counter.
// Это делает протокол устойчивым к потере и перестановке UDP-пакетов.
func deriveMsgKeyStateless(rootKey []byte, counter uint32) ([]byte, error) {
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, counter)

	msgKey := make([]byte, 32)
	// Используем HKDF-Expand с контекстом, включающим номер пакета
	info := append([]byte("NatBypass-Msg-Key-v2-Counter:"), counterBytes...)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, rootKey, info), msgKey); err != nil {
		return nil, err
	}
	return msgKey, nil
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

// Encrypt шифрует открытый текст с деривацией ключа для конкретного номера пакета.
// Формат возвращаемого фрейма: [MessageNumber uint32 (4 байта)][Nonce 12 байт][Ciphertext + Poly1305 Tag].
func (s *SessionState) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	msgNum := s.SendingChain.Counter
	s.SendingChain.Counter++
	s.MessageNumber++
	sendKey := s.SendingChain.ChainKey
	s.mu.Unlock()

	msgKey, err := deriveMsgKeyStateless(sendKey, msgNum)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(fmt.Sprintf("ratchet: csprng failure: %v", err))
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 4+len(nonce)+len(ciphertext))
	binary.BigEndian.PutUint32(out[:4], msgNum)
	copy(out[4:4+len(nonce)], nonce)
	copy(out[4+len(nonce):], ciphertext)
	return out, nil
}

// Decrypt расшифровывает сообщение по его номеру пакета.
// Поддерживает восстановление при потере и нарушении порядка доставки UDP-пакетов
// с защитой от Replay-атак по скользящему окну.
func (s *SessionState) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 4+12+16 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (minimum 32 bytes required)", len(data))
	}

	msgNum := binary.BigEndian.Uint32(data[:4])
	nonce := data[4 : 4+12]
	ciphertext := data[4+12:]

	s.mu.Lock()
	recvKey := s.ReceivingChain.ChainKey

	// Проверка скользящего окна защиты от Replay-атак
	if !s.hasReceived {
		if msgNum > maxSkipMessages {
			s.mu.Unlock()
			return nil, fmt.Errorf("message sequence gap too large: skipped %d > %d allowed", msgNum, maxSkipMessages)
		}
	} else {
		if msgNum > s.replayBase {
			gap := msgNum - s.replayBase
			if gap > maxSkipMessages {
				s.mu.Unlock()
				return nil, fmt.Errorf("message sequence gap too large: skipped %d > %d allowed", gap, maxSkipMessages)
			}
		} else {
			diff := s.replayBase - msgNum
			if diff >= 64 {
				s.mu.Unlock()
				return nil, fmt.Errorf("message sequence too old (seq=%d, base=%d)", msgNum, s.replayBase)
			}
			if (s.replayWindow & (uint64(1) << diff)) != 0 {
				s.mu.Unlock()
				return nil, fmt.Errorf("duplicate or replay message: seq=%d", msgNum)
			}
		}
	}
	s.mu.Unlock()

	// Деривируем ключ для msgNum напрямую из recvKey
	msgKey, err := deriveMsgKeyStateless(recvKey, msgNum)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ratchet decrypt failed: %w", err)
	}

	// Сообщение успешно верифицировано и расшифровано — продвигаем скользящее окно
	s.mu.Lock()
	if !s.hasReceived {
		s.hasReceived = true
		s.replayBase = msgNum
		s.replayWindow = 1
	} else if msgNum > s.replayBase {
		diff := msgNum - s.replayBase
		if diff < 64 {
			s.replayWindow = (s.replayWindow << diff) | 1
		} else {
			s.replayWindow = 1
		}
		s.replayBase = msgNum
	} else {
		diff := s.replayBase - msgNum
		if diff < 64 {
			s.replayWindow |= (uint64(1) << diff)
		}
	}
	s.ReceivingChain.Counter = s.replayBase + 1
	s.mu.Unlock()

	return plaintext, nil
}
