package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

// AWGProbeParams — параметры AWG обфускации для теста
type AWGProbeParams struct {
	Jc             int    `json:"jc"`
	Jmin           int    `json:"jmin"`
	Jmax           int    `json:"jmax"`
	S1             int    `json:"s1"`
	S2             int    `json:"s2"`
	H1             uint32 `json:"h1"`
	H2             uint32 `json:"h2"`
	H3             uint32 `json:"h3"`
	H4             uint32 `json:"h4"`
	RandomTrailers bool   `json:"random_trailers"`
	DisableCookies bool   `json:"disable_cookies"`
	HeaderProtKey  string `json:"header_protection_key,omitempty"`
}

// NodeConfig — конфиг одного узла
type NodeConfig struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Country    string `json:"country"`
	Hostname   string `json:"hostname"`
	WGPubKey   string `json:"wg_pub_key"`
	VIP        string `json:"vip"`
	PrivateKey string `json:"wg_priv_key,omitempty"`
}

// ProbeConfig — общий конфиг для всех участников теста
type ProbeConfig struct {
	ProbeID         string         `json:"probe_id"`
	MQTTBroker      string         `json:"mqtt_broker"`
	MQTTTopic       string         `json:"mqtt_topic"`
	STUNServers     []string       `json:"stun_servers"`
	AWG             AWGProbeParams `json:"awg"`
	TestSubnet      string         `json:"test_subnet"`
	TestDurationSec int            `json:"test_duration_sec"`
	Nodes           []NodeConfig   `json:"nodes"`
}

// DefaultConfig создаёт конфиг по умолчанию
func DefaultConfig(probeID string) *ProbeConfig {
	return &ProbeConfig{
		ProbeID:    probeID,
		MQTTBroker: "tcp://broker.emqx.io:1883",
		MQTTTopic:  "natbypass/probe/" + probeID,
		STUNServers: []string{
			"stun.cloudflare.com:3478",
			"stun.sipnet.ru:3478",
			"stun.miwifi.com:3478",
			"stun.syncthing.net:3478",
			"stun.l.google.com:19302",
			"stun1.l.google.com:3478",
		},
		AWG: AWGProbeParams{
			Jc: 4, Jmin: 36, Jmax: 77,
			S1: 37, S2: 42,
			H1: 1937135702, H2: 3731249073,
			H3: 764002035, H4: 3695536600,
			RandomTrailers: true,
			DisableCookies: true,
			HeaderProtKey:  "auto",
		},
		TestSubnet:      "10.99.0.0/24",
		TestDurationSec: 300,
		Nodes:           []NodeConfig{},
	}
}

// LoadConfig загружает конфиг из JSON-файла
func LoadConfig(path string) (*ProbeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg ProbeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.MQTTBroker == "" {
		cfg.MQTTBroker = "tcp://broker.emqx.io:1883"
	}
	if cfg.TestDurationSec == 0 {
		cfg.TestDurationSec = 300
	}
	// Ensure high-reliability STUN servers including Russian-accessible ones (sipnet.ru, miwifi, cloudflare)
	prioritySTUNs := []string{
		"stun.cloudflare.com:3478",
		"stun.sipnet.ru:3478",
		"stun.miwifi.com:3478",
		"stun.syncthing.net:3478",
		"stun.l.google.com:19302",
		"stun1.l.google.com:3478",
	}
	seen := make(map[string]bool)
	var finalSTUNs []string
	for _, s := range prioritySTUNs {
		if !seen[s] {
			seen[s] = true
			finalSTUNs = append(finalSTUNs, s)
		}
	}
	for _, s := range cfg.STUNServers {
		if !seen[s] {
			seen[s] = true
			finalSTUNs = append(finalSTUNs, s)
		}
	}
	cfg.STUNServers = finalSTUNs
	return &cfg, nil
}

// SaveConfig сохраняет конфиг в JSON-файл
func SaveConfig(cfg *ProbeConfig, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// NodeVIP вычисляет детерминированный VIP для узла на основе его ID.
// Возвращает адрес вида 10.99.X.1 где X = hash(id) % 250 + 1
func NodeVIP(nodeID string) string {
	h := sha256.Sum256([]byte(nodeID))
	octet := int(h[0])%250 + 1
	return fmt.Sprintf("10.99.%d.1", octet)
}

// FindNode ищет узел в конфиге по ID
func (cfg *ProbeConfig) FindNode(nodeID string) *NodeConfig {
	for i := range cfg.Nodes {
		if cfg.Nodes[i].ID == nodeID {
			return &cfg.Nodes[i]
		}
	}
	return nil
}

// FindNodeByHostname ищет узел по hostname
func (cfg *ProbeConfig) FindNodeByHostname(hostname string) *NodeConfig {
	for i := range cfg.Nodes {
		if cfg.Nodes[i].Hostname == hostname {
			return &cfg.Nodes[i]
		}
	}
	return nil
}
