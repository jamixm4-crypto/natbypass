package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/crypto"
)

// loadOrGenerateKeys loads the NaCl keypair from config or generates a new one.
func loadOrGenerateKeys(cfg *config.Config) ([32]byte, [32]byte, error) {
	if cfg.Crypto.PublicKey != "" && cfg.Crypto.PrivateKey != "" {
		pub, err := crypto.HexToKey(cfg.Crypto.PublicKey)
		if err != nil {
			return [32]byte{}, [32]byte{}, fmt.Errorf("invalid public key in config: %w", err)
		}
		priv, err := crypto.HexToKey(cfg.Crypto.PrivateKey)
		if err != nil {
			return [32]byte{}, [32]byte{}, fmt.Errorf("invalid private key in config: %w", err)
		}
		return pub, priv, nil
	}

	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("failed to generate encryption keys: %w", err)
	}

	cfg.Crypto.PublicKey = crypto.KeyToHex(pub)
	cfg.Crypto.PrivateKey = crypto.KeyToHex(priv)
	return pub, priv, nil
}

// generateDeviceID derives a deterministic short device identifier from the public key.
func generateDeviceID(pubKey [32]byte) string {
	h := sha256.Sum256(pubKey[:])
	return "node-" + hex.EncodeToString(h[:4])
}

// cleanBase64Key strips whitespace and newlines from a base64 key string.
func cleanBase64Key(k string) string {
	return strings.TrimSpace(k)
}