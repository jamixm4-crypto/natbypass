package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// SessionState реализует Double Ratchet Algorithm для Perfect Forward Secrecy.
type SessionState struct {
	RootKey        []byte
	SendingChain   Chain
	ReceivingChain Chain
	MessageNumber  uint32
	mu             sync.Mutex
}

// Chain представляет KDF-цепочку симметричных сессионных ключей.
type Chain struct {
	ChainKey []byte
	Counter  uint32
}

// NewSessionState инициализирует Double Ratchet сессию с общим мастер-ключом.
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

// Encrypt шифрует открытый текст с ротацией ключей в цепочке отправки.
func (s *SessionState) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	mac := hmac.New(sha256.New, s.SendingChain.ChainKey)
	mac.Write([]byte{0x01})
	msgKey := mac.Sum(nil)

	macNext := hmac.New(sha256.New, s.SendingChain.ChainKey)
	macNext.Write([]byte{0x02})
	s.SendingChain.ChainKey = macNext.Sum(nil)
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

// Decrypt расшифровывает сообщение с ротацией ключей в цепочке приема.
func (s *SessionState) Decrypt(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ключ сообщения через HMAC-SHA256
	mac := hmac.New(sha256.New, s.ReceivingChain.ChainKey)
	mac.Write([]byte{0x01})
	msgKey := mac.Sum(nil)

	// Ротация цепочки ключей
	macNext := hmac.New(sha256.New, s.ReceivingChain.ChainKey)
	macNext.Write([]byte{0x02})
	s.ReceivingChain.ChainKey = macNext.Sum(nil)
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
