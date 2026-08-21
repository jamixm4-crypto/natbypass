package wireguard

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
)

// AWGParams содержит параметры обфускации протокола AmneziaWG 2.0 для обхода DPI
type AWGParams struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Jc      int    `json:"jc" yaml:"jc"`         // Количество мусорных пакетов перед хэндшейком (1..128)
	Jmin    int    `json:"jmin" yaml:"jmin"`     // Минимальный размер мусорного пакета (байты)
	Jmax    int    `json:"jmax" yaml:"jmax"`     // Максимальный размер мусорного пакета (байты)
	S1      int    `json:"s1" yaml:"s1"`         // Размер мусора в пакете инициализации (байты)
	S2      int    `json:"s2" yaml:"s2"`         // Размер мусора в пакете ответа (байты)
	H1      uint32 `json:"h1" yaml:"h1"`         // Кастомный заголовок Initiation (вместо 0x01)
	H2      uint32 `json:"h2" yaml:"h2"`         // Кастомный заголовок Response (вместо 0x02)
	H3      uint32 `json:"h3" yaml:"h3"`         // Кастомный заголовок Cookie (вместо 0x03)
	H4      uint32 `json:"h4" yaml:"h4"`         // Кастомный заголовок Transport (вместо 0x04)
}

// AWGConfig представляет конфигурацию AmneziaWG 2.0
type AWGConfig struct {
	WGConfig
	AWGParams
}

// DefaultAWGParams возвращает проверенные по умолчанию параметры AmneziaWG 2.0
func DefaultAWGParams() AWGParams {
	return AWGParams{
		Enabled: true,
		Jc:      4,
		Jmin:    40,
		Jmax:    70,
		S1:      48,
		S2:      32,
		H1:      1428571428,
		H2:      2147483647,
		H3:      857142857,
		H4:      1122334455,
	}
}

// GenerateRandomAWGParams генерирует уникальный криптографически случайный набор параметров AWG 2.0
func GenerateRandomAWGParams() AWGParams {
	jc, _ := rand.Int(rand.Reader, big.NewInt(6))
	jmin, _ := rand.Int(rand.Reader, big.NewInt(30))
	jmax, _ := rand.Int(rand.Reader, big.NewInt(60))
	s1, _ := rand.Int(rand.Reader, big.NewInt(80))
	s2, _ := rand.Int(rand.Reader, big.NewInt(80))

	h1 := randomUint32()
	h2 := randomUint32()
	h3 := randomUint32()
	h4 := randomUint32()

	return AWGParams{
		Enabled: true,
		Jc:      int(jc.Int64()) + 3,       // 3..8
		Jmin:    int(jmin.Int64()) + 40,    // 40..70
		Jmax:    int(jmax.Int64()) + 71,    // 71..130
		S1:      int(s1.Int64()) + 20,      // 20..100
		S2:      int(s2.Int64()) + 20,      // 20..100
		H1:      h1,
		H2:      h2,
		H3:      h3,
		H4:      h4,
	}
}

func randomUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	val := binary.BigEndian.Uint32(b[:])
	if val < 1000 {
		val += 1000
	}
	return val
}

// GenerateAWGConfig генерирует конфигурационный файл AmneziaWG 2.0 (.conf)
func GenerateAWGConfig(cfg *AWGConfig) (string, error) {
	var buf bytes.Buffer

	buf.WriteString("# ============================================================\n")
	buf.WriteString("# AmneziaWG 2.0 (AWG) Mesh Configuration with DPI Obfuscation\n")
	buf.WriteString("# Generated automatically by NatBypass\n")
	buf.WriteString("# ============================================================\n\n")

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

	// AWG 2.0 Obfuscation headers and junk parameters
	if cfg.AWGParams.Enabled {
		buf.WriteString(fmt.Sprintf("Jc = %d\n", cfg.AWGParams.Jc))
		buf.WriteString(fmt.Sprintf("Jmin = %d\n", cfg.AWGParams.Jmin))
		buf.WriteString(fmt.Sprintf("Jmax = %d\n", cfg.AWGParams.Jmax))
		buf.WriteString(fmt.Sprintf("S1 = %d\n", cfg.AWGParams.S1))
		buf.WriteString(fmt.Sprintf("S2 = %d\n", cfg.AWGParams.S2))
		buf.WriteString(fmt.Sprintf("H1 = %d\n", cfg.AWGParams.H1))
		buf.WriteString(fmt.Sprintf("H2 = %d\n", cfg.AWGParams.H2))
		buf.WriteString(fmt.Sprintf("H3 = %d\n", cfg.AWGParams.H3))
		buf.WriteString(fmt.Sprintf("H4 = %d\n", cfg.AWGParams.H4))
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
		buf.WriteString("PersistentKeepalive = 25\n")
	}

	return buf.String(), nil
}

// SaveAWGConfig сохраняет конфигурацию AmneziaWG 2.0 в файл
func SaveAWGConfig(cfg *AWGConfig, path string) error {
	content, err := GenerateAWGConfig(cfg)
	if err != nil {
		return fmt.Errorf("ошибка генерации AWG конфигурации: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("ошибка сохранения файла AWG: %w", err)
	}
	return nil
}