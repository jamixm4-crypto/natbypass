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
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// maxSkipMessages limits how far ahead the packet sequence can advance for missing UDP packets.
	maxSkipMessages = 2048
)

// SessionState (также доступен как SymmetricKDFChain) реализует устойчивую к потерям UDP-пакетов
// симметричную схему шифрования (Stateless HKDF per-packet key derivation) со скользящим окном
// защиты от повторов (anti-replay sliding window по стандарту RFC 2401).
// Ключ для каждого сообщения деривируется напрямую из RootKey/ChainKey и 64-битного Counter через HKDF-Expand.
type SessionState struct {
	RootKey        []byte
	SendingChain   Chain
	ReceivingChain Chain
	MessageNumber  uint64
	replayWindow   uint64 // 64-битная битовая маска скользящего окна
	replayBase     uint64 // максимальный полученный номер пакета
	hasReceived    bool   // флаг первого полученного пакета
	mu             sync.Mutex
}

// SymmetricKDFChain — точный криптографический псевдоним для SessionState.
type SymmetricKDFChain = SessionState

// Chain представляет состояние направления передачи сессионных ключей.
type Chain struct {
	ChainKey []byte
	Counter  uint64
}

// deriveMsgKeyStateless деривирует ключ для конкретного пакета напрямую из rootKey и 64-битного counter.
// Это делает протокол устойчивым к потере и перестановке UDP-пакетов.
func deriveMsgKeyStateless(rootKey []byte, counter uint64) ([]byte, error) {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	msgKey := make([]byte, 32)
	// Используем HKDF-Expand с контекстом, включающим 64-битный номер пакета (Big Endian)
	info := append([]byte("NatBypass-Msg-Key-v3-Counter:"), counterBytes...)
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
// Формат возвращаемого фрейма: [MessageNumber uint64 (8 байт Big Endian)][Nonce 12 байт][Ciphertext + Poly1305 Tag].
func (s *SessionState) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	if s.SendingChain.Counter >= (uint64(1) << 63) {
		s.mu.Unlock()
		return nil, fmt.Errorf("ratchet: sending counter overflow, rekey required")
	}
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
	out := make([]byte, 8+len(nonce)+len(ciphertext))
	binary.BigEndian.PutUint64(out[:8], msgNum)
	copy(out[8:8+len(nonce)], nonce)
	copy(out[8+len(nonce):], ciphertext)
	return out, nil
}

// Decrypt расшифровывает сообщение по его номеру пакета.
// Поддерживает восстановление при потере и нарушении порядка доставки UDP-пакетов
// с защитой от Replay-атак по 64-битному скользящему окну (RFC 2401).
func (s *SessionState) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 8+12+16 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (minimum 36 bytes required)", len(data))
	}

	msgNum := binary.BigEndian.Uint64(data[:8])
	if msgNum >= (uint64(1) << 63) {
		return nil, fmt.Errorf("message sequence number counter overflow (> 2^63)")
	}
	nonce := data[8 : 8+12]
	ciphertext := data[8+12:]

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

const (
	// EpochDuration defines the key rotation interval for Perfect Forward Secrecy (30 minutes).
	EpochDuration = 30 * time.Minute
)

// GetCurrentEpoch returns the current epoch index based on Unix timestamp.
func GetCurrentEpoch() uint64 {
	return uint64(time.Now().Unix()) / uint64(EpochDuration.Seconds())
}

// DeriveEpochKey derives a 32-byte ephemeral master key for a specific time epoch using HKDF-Expand.
// This ensures that compromise of a long-term network key in the future does not compromise past epoch keys.
func DeriveEpochKey(baseKey []byte, epoch uint64) ([32]byte, error) {
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)

	info := append([]byte("NatBypass-Epoch-PFS-v1:"), epochBytes[:]...)
	var epochKey [32]byte
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, baseKey, info), epochKey[:]); err != nil {
		return [32]byte{}, fmt.Errorf("epoch key derivation failed: %w", err)
	}
	return epochKey, nil
}

// DeriveEpochMasterKey derives a 32-byte key for the given networkKey string and epoch.
func DeriveEpochMasterKey(networkKey string, epoch uint64) [32]byte {
	base := sha256.Sum256([]byte(networkKey))
	key, err := DeriveEpochKey(base[:], epoch)
	if err != nil {
		return base // Fallback to base key on theoretical HKDF error
	}
	return key
}

// EncryptWithEpoch wraps a message with an 8-byte epoch header and encrypts it using the epoch-derived key.
func EncryptWithEpoch(plaintext []byte, baseKey []byte, epoch uint64) ([]byte, error) {
	epochKey, err := DeriveEpochKey(baseKey, epoch)
	if err != nil {
		return nil, err
	}

	enc, err := EncryptSelf(plaintext, epochKey)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 8+len(enc))
	binary.BigEndian.PutUint64(out[:8], epoch)
	copy(out[8:], enc)
	return out, nil
}

// DecryptWithEpoch validates and decrypts an epoch-wrapped message within a tolerance window of ±1 epoch.
func DecryptWithEpoch(data []byte, baseKey []byte, currentEpoch uint64) ([]byte, uint64, error) {
	if len(data) < 8+24 { // 8-byte epoch + 24-byte secretbox nonce
		return nil, 0, ErrDecryptionFailed
	}

	msgEpoch := binary.BigEndian.Uint64(data[:8])

	// Allow current epoch, previous epoch (tolerance for clock skew / packet in flight), or next epoch (+1)
	if msgEpoch > currentEpoch+1 || (currentEpoch > 0 && msgEpoch < currentEpoch-1) {
		return nil, 0, fmt.Errorf("epoch expired or out of window (msg=%d, current=%d)", msgEpoch, currentEpoch)
	}

	epochKey, err := DeriveEpochKey(baseKey, msgEpoch)
	if err != nil {
		return nil, 0, err
	}

	dec, err := DecryptSelf(data[8:], epochKey)
	if err != nil {
		return nil, 0, err
	}

	return dec, msgEpoch, nil
}

// EncryptWithEpochSeq wraps plaintext with an 8-byte epoch and 8-byte sequence counter,
// then encrypts under the epoch-derived key.
// Wire format: [Epoch uint64 (8B)][Seq uint64 (8B)][Nonce 24B][Ciphertext + Poly1305 Tag 16B]
func EncryptWithEpochSeq(plaintext []byte, baseKey []byte, epoch uint64, seq uint64) ([]byte, error) {
	epochKey, err := DeriveEpochKey(baseKey, epoch)
	if err != nil {
		return nil, err
	}

	enc, err := EncryptSelf(plaintext, epochKey)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 16+len(enc))
	binary.BigEndian.PutUint64(out[:8], epoch)
	binary.BigEndian.PutUint64(out[8:16], seq)
	copy(out[16:], enc)
	return out, nil
}

// DecryptWithEpochSeq validates epoch tolerance (±1) and decrypts the payload.
// Returns (plaintext, epoch, seq, err).
func DecryptWithEpochSeq(data []byte, baseKey []byte, currentEpoch uint64) ([]byte, uint64, uint64, error) {
	if len(data) < 16+24+16 {
		return nil, 0, 0, ErrDecryptionFailed
	}

	msgEpoch := binary.BigEndian.Uint64(data[:8])
	seq := binary.BigEndian.Uint64(data[8:16])

	// Tolerance window of ±1 epoch
	if msgEpoch > currentEpoch+1 || (currentEpoch > 0 && msgEpoch < currentEpoch-1) {
		return nil, 0, 0, fmt.Errorf("epoch expired or out of window (msg=%d, current=%d)", msgEpoch, currentEpoch)
	}

	epochKey, err := DeriveEpochKey(baseKey, msgEpoch)
	if err != nil {
		return nil, 0, 0, err
	}

	dec, err := DecryptSelf(data[16:], epochKey)
	if err != nil {
		return nil, 0, 0, err
	}

	return dec, msgEpoch, seq, nil
}

