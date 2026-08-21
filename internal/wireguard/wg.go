package wireguard

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

// KeyPair represents a WireGuard public and private key pair.
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// GenerateKeyPair generates a new WireGuard-compatible X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("ошибка генерации случайных байт: %w", err)
	}

	// Clamp the private key (WireGuard requirement)
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey[:]),
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey[:]),
	}, nil
}

// WGPeer represents a WireGuard peer configuration.
type WGPeer struct {
	PublicKey    string
	AllowedIPs   []string
	Endpoint     string
	PresharedKey string
}

// WGConfig represents a local WireGuard interface configuration.
type WGConfig struct {
	InterfaceName string
	PrivateKey    string
	Address       string
	ListenPort    int
	DNS           string
	Peers         []WGPeer
	MTU           int
}

// GenerateWGConfig generates a wg-quick compatible configuration string.
func GenerateWGConfig(cfg *WGConfig) (string, error) {
	var buf bytes.Buffer

	buf.WriteString("[Interface]\n")
	buf.WriteString(fmt.Sprintf("PrivateKey = %s\n", cfg.PrivateKey))
	if cfg.Address != "" {
		buf.WriteString(fmt.Sprintf("Address = %s\n", cfg.Address))
	}
	if cfg.ListenPort > 0 {
		buf.WriteString(fmt.Sprintf("ListenPort = %d\n", cfg.ListenPort))
	}
	if cfg.DNS != "" {
		buf.WriteString(fmt.Sprintf("DNS = %s\n", cfg.DNS))
	}
	if cfg.MTU > 0 {
		buf.WriteString(fmt.Sprintf("MTU = %d\n", cfg.MTU))
	}

	for _, peer := range cfg.Peers {
		buf.WriteString("\n[Peer]\n")
		buf.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		if peer.PresharedKey != "" {
			buf.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey))
		}
		if peer.Endpoint != "" {
			buf.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}
		if len(peer.AllowedIPs) > 0 {
			buf.WriteString("AllowedIPs = ")
			for i, ip := range peer.AllowedIPs {
				if i > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(ip)
			}
			buf.WriteString("\n")
		}
	}

	return buf.String(), nil
}

// GenerateMeshConfig builds a full mesh configuration for the current node.
func GenerateMeshConfig(myKey *KeyPair, myAddress string, peers []*WGPeer, listenPort int) (*WGConfig, error) {
	cfg := &WGConfig{
		PrivateKey: myKey.PrivateKey,
		Address:    myAddress,
		ListenPort: listenPort,
	}

	for _, p := range peers {
		if p != nil {
			cfg.Peers = append(cfg.Peers, *p)
		}
	}

	return cfg, nil
}

// SaveConfig saves the WireGuard configuration to the specified file path.
func SaveConfig(cfg *WGConfig, path string) error {
	content, err := GenerateWGConfig(cfg)
	if err != nil {
		return fmt.Errorf("ошибка генерации конфигурации: %w", err)
	}

	// 0600 is recommended for WireGuard configs containing private keys
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("ошибка сохранения конфигурации в файл: %w", err)
	}

	return nil
}
