package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidKeySize   = errors.New("invalid key size")
)

func GenerateKeyPair() (publicKey, privateKey [32]byte, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	return *pub, *priv, nil
}

func Encrypt(message []byte, recipientPubKey, senderPrivKey [32]byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := box.Seal(nonce[:], message, &nonce, &recipientPubKey, &senderPrivKey)
	return encrypted, nil
}

func Decrypt(encrypted []byte, senderPubKey, recipientPrivKey [32]byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, ErrDecryptionFailed
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	decrypted, ok := box.Open(nil, encrypted[24:], &nonce, &senderPubKey, &recipientPrivKey)
	if !ok {
		return nil, ErrDecryptionFailed
	}

	return decrypted, nil
}

func KeyToHex(key [32]byte) string {
	return hex.EncodeToString(key[:])
}

func HexToKey(s string) ([32]byte, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(bytes) != 32 {
		return [32]byte{}, ErrInvalidKeySize
	}

	var key [32]byte
	copy(key[:], bytes)
	return key, nil
}

func EncryptSelf(message []byte, key [32]byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], message, &nonce, &key)
	return encrypted, nil
}

func DecryptSelf(encrypted []byte, key [32]byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, ErrDecryptionFailed
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	decrypted, ok := secretbox.Open(nil, encrypted[24:], &nonce, &key)
	if !ok {
		return nil, ErrDecryptionFailed
	}

	return decrypted, nil
}

// DeriveKey derives a 32-byte key from any secret string using SHA-256.
func DeriveKey(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}
