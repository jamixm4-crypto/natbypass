// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// AmneziaWG protocol parameters and obfuscation mechanisms (H1..H4, S1..S4, Jc, Jmin, Jmax)
// are developed by the AmneziaWG team (https://github.com/amnezia-vpn/amneziawg-go).
// Original WireGuard protocol created by Jason A. Donenfeld (https://www.wireguard.com).

package wireguard

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/hkdf"
)

// AWGVersion определяет версию протокола AmneziaWG
type AWGVersion string

const (
	AWGVersion20 AWGVersion = "2.0"
	AWGVersion31 AWGVersion = "3.1"
)

// AWGParams содержит все параметры обфускации протокола AmneziaWG 3.1
type AWGParams struct {
	// Версия протокола
	Version AWGVersion `json:"version" yaml:"version"`
	Enabled bool       `json:"enabled" yaml:"enabled"`

	// ═══ AWG 2.0 Совместимость ═══
	Jc int `json:"jc" yaml:"jc"`         // Junk-train: количество junk-пакетов
	Jmin int `json:"jmin" yaml:"jmin"` // Минимальный размер junk-пакета
	Jmax int `json:"jmax" yaml:"jmax"` // Максимальный размер junk-пакета
	S1 int `json:"s1" yaml:"s1"`         // Prefix для Init
	S2 int `json:"s2" yaml:"s2"`         // Prefix для Response
	S3 int `json:"s3" yaml:"s3"`         // Prefix для Cookie (новый в 3.1)
	S4 int `json:"s4" yaml:"s4"`         // Prefix для Data (новый в 3.1)
	H1 uint32 `json:"h1" yaml:"h1"`     // Custom header Initiation
	H2 uint32 `json:"h2" yaml:"h2"`     // Custom header Response
	H3 uint32 `json:"h3" yaml:"h3"`     // Custom header Cookie
	H4 uint32 `json:"h4" yaml:"h4"`     // Custom header Transport

	// ═══ AWG 3.1: Header Protection ═══
	HeaderProtectionKey     [32]byte `json:"header_protection_key" yaml:"header_protection_key"`
	HeaderProtectionEnabled bool     `json:"header_protection_enabled" yaml:"header_protection_enabled"`

	// ═══ AWG 3.1: Content Padding ═══
	ContentPaddingAdditionMin int `json:"content_padding_min" yaml:"content_padding_min"`
	ContentPaddingAdditionMax int `json:"content_padding_max" yaml:"content_padding_max"`

	// ═══ AWG 3.1: Custom Timings (ranges) ═══
	RekeyAfterTimeMin       int `json:"rekey_after_time_min" yaml:"rekey_after_time_min"`
	RekeyAfterTimeMax       int `json:"rekey_after_time_max" yaml:"rekey_after_time_max"`
	RekeyTimeoutMin         int `json:"rekey_timeout_min" yaml:"rekey_timeout_min"`
	RekeyTimeoutMax         int `json:"rekey_timeout_max" yaml:"rekey_timeout_max"`
	RejectAfterTimeMin      int `json:"reject_after_time_min" yaml:"reject_after_time_min"`
	RejectAfterTimeMax      int `json:"reject_after_time_max" yaml:"reject_after_time_max"`
	KeepaliveTimeoutMin     int `json:"keepalive_timeout_min" yaml:"keepalive_timeout_min"`
	KeepaliveTimeoutMax     int `json:"keepalive_timeout_max" yaml:"keepalive_timeout_max"`
	MaxHandshakeAttemptsMin int `json:"max_handshake_attempts_min" yaml:"max_handshake_attempts_min"`
	MaxHandshakeAttemptsMax int `json:"max_handshake_attempts_max" yaml:"max_handshake_attempts_max"`

	// ═══ AWG 3.1: Packet Modification ═══
	RandomTrailers bool `json:"random_trailers" yaml:"random_trailers"`
	DisableCookies bool `json:"disable_cookies" yaml:"disable_cookies"`

	// ═══ AWG 3.1: CPS Packets (I1-I5) ═══
	I1 string `json:"i1" yaml:"i1"`
	I2 string `json:"i2" yaml:"i2"`
	I3 string `json:"i3" yaml:"i3"`
	I4 string `json:"i4" yaml:"i4"`
	I5 string `json:"i5" yaml:"i5"`
}

// AWGConfig представляет конфигурацию AmneziaWG
type AWGConfig struct {
	WGConfig
	AWGParams
}

// GenerateAWG20LegacyParams возвращает параметры совместимости со старым AWG 2.0
func GenerateAWG20LegacyParams() AWGParams {
	return AWGParams{
		Version: AWGVersion20,
		Enabled: true,
		Jc:      4,
		Jmin:    40,
		Jmax:    70,
		S1:      48,
		S2:      32,
		S3:      0,
		S4:      0,
		H1:      1428571428,
		H2:      2147483647,
		H3:      857142857,
		H4:      1122334455,
	}
}

// DefaultAWGParams возвращает параметры по умолчанию для всей системы (AWG 3.1 Strict против блокировок ТСПУ)
func DefaultAWGParams() AWGParams {
	return GenerateAWG31StrictParams()
}

// GenerateAWG31BalancedParams генерирует сбалансированные параметры AWG 3.1
func GenerateAWG31BalancedParams() AWGParams {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in GenerateAWG31BalancedParams: %v", err))
	}

	return AWGParams{
		Version: AWGVersion31,
		Enabled: true,

		// Junk-train (расширенный)
		Jc:   5,
		Jmin: 40,
		Jmax: 70,

		// Prefixes (рекомендуется одинаковые при RandomTrailers)
		S1: 20,
		S2: 20,
		S3: 20,
		S4: 20,

		// При Header Protection: H1=1, H2=2, H3=3, H4=4
		H1: 1,
		H2: 2,
		H3: 3,
		H4: 4,

		// Header Protection
		HeaderProtectionKey:     key,
		HeaderProtectionEnabled: true,

		// Content Padding
		ContentPaddingAdditionMin: 0,
		ContentPaddingAdditionMax: 50,

		// Custom Timings (ranges)
		RekeyAfterTimeMin:       120,
		RekeyAfterTimeMax:       180,
		RekeyTimeoutMin:         5,
		RekeyTimeoutMax:         15,
		RejectAfterTimeMin:      180,
		RejectAfterTimeMax:      240,
		KeepaliveTimeoutMin:     10,
		KeepaliveTimeoutMax:     25,
		MaxHandshakeAttemptsMin: 3,
		MaxHandshakeAttemptsMax: 7,

		// Packet Modification
		RandomTrailers: true,
		DisableCookies: false, // Balanced: оставляем cookies

		// CPS Packets (опционально)
		I1: "",
		I2: "",
		I3: "",
		I4: "",
		I5: "",
	}
}

// GenerateAWG31StrictParams генерирует максимальную обфускацию против ТСПУ / DPI
func GenerateAWG31StrictParams() AWGParams {
	params := GenerateAWG31BalancedParams()

	// Strict: отключаем cookies (защита от active probing)
	params.DisableCookies = true

	// Strict: усиленный junk-train против ТСПУ (Jc = 4..5, Jmax = 120 для разрушения сигнатур WireGuard)
	params.Jc = 5
	params.Jmin = 40
	params.Jmax = 120

	// Strict: больший content padding
	params.ContentPaddingAdditionMax = 100

	// Strict: более широкий диапазон таймеров
	params.KeepaliveTimeoutMin = 5
	params.KeepaliveTimeoutMax = 30
	params.RekeyAfterTimeMin = 90
	params.RekeyAfterTimeMax = 240

	// Strict: добавляем CPS packets
	params.I1 = "quic_initial"
	params.I2 = "dns_query"

	return params
}

// DeriveAWGParamsFromKey derives deterministic AWG 3.1 parameters from a shared network key.
// Ensures all nodes in the mesh automatically have matching H1..H4, S1..S2, and HeaderProtectionKey.
func DeriveAWGParamsFromKey(networkKey string) AWGParams {
	params := GenerateAWG31StrictParams()
	if networkKey == "" {
		return params
	}

	// Derive 64 bytes using HKDF-SHA256 from networkKey
	hkdfReader := hkdf.New(sha256.New, []byte(networkKey), []byte("natbypass-awg-salt-v1"), []byte("natbypass-awg-31-mesh"))
	var derived [64]byte
	if _, err := io.ReadFull(hkdfReader, derived[:]); err != nil {
		panic(fmt.Sprintf("wireguard: critical hkdf failure in DeriveAWGParamsFromKey: %v", err))
	}

	// 1. Header Protection Key (32 bytes)
	copy(params.HeaderProtectionKey[:], derived[0:32])
	params.HeaderProtectionEnabled = true

	// 2. Deterministic H1..H4
	params.H1 = binary.BigEndian.Uint32(derived[32:36])
	params.H2 = binary.BigEndian.Uint32(derived[36:40])
	params.H3 = binary.BigEndian.Uint32(derived[40:44])
	params.H4 = binary.BigEndian.Uint32(derived[44:48])

	// Ensure headers are non-zero and distinct
	if params.H1 < 1000 {
		params.H1 += 1000
	}
	if params.H2 < 1000 {
		params.H2 += 2000
	}
	if params.H3 < 1000 {
		params.H3 += 3000
	}
	if params.H4 < 1000 {
		params.H4 += 4000
	}

	// 3. S1..S4 (prefixes)
	params.S1 = 20 + int(derived[48]%40)
	params.S2 = 20 + int(derived[49]%40)
	params.S3 = params.S1
	params.S4 = params.S2

	// 4. Jc, Jmin, Jmax
	params.Jc = 4 + int(derived[50]%4)
	params.Jmin = 40 + int(derived[51]%30)
	params.Jmax = params.Jmin + 30 + int(derived[52]%40)

	return params
}

func randomUint32() uint32 {
	var b [4]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in randomUint32: %v", err))
	}
	val := binary.BigEndian.Uint32(b[:])
	if val < 1000 {
		val += 1000
	}
	return val
}

// GenerateRandomWGPort генерирует криптографически стойкий случайный UDP-порт в диапазоне 25700..49000
// для исключения конфликтов сервисов и обхода сигнатурных блокировок ТСПУ/DPI.
func GenerateRandomWGPort() int {
	minPort := 25700
	maxPort := 49000
	delta := big.NewInt(int64(maxPort - minPort + 1))
	n, err := rand.Int(rand.Reader, delta)
	if err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in GenerateRandomWGPort: %v", err))
	}
	return minPort + int(n.Int64())
}

// GenerateRandomAWGParams генерирует случайные валидные параметры AWG
func GenerateRandomAWGParams() AWGParams {
	jcBig, err := rand.Int(rand.Reader, big.NewInt(5))
	if err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in GenerateRandomAWGParams: %v", err))
	}
	jc := int(jcBig.Int64()) + 3 // 3..7

	jminBig, err := rand.Int(rand.Reader, big.NewInt(30))
	if err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in GenerateRandomAWGParams: %v", err))
	}
	jmin := int(jminBig.Int64()) + 30 // 30..60

	jmaxExtraBig, err := rand.Int(rand.Reader, big.NewInt(60))
	if err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in GenerateRandomAWGParams: %v", err))
	}
	jmaxExtra := int(jmaxExtraBig.Int64()) + 30 // 30..90
	jmax := jmin + jmaxExtra                   // 60..150

	s1Big, err := rand.Int(rand.Reader, big.NewInt(80))
	if err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in GenerateRandomAWGParams: %v", err))
	}
	s1 := int(s1Big.Int64()) + 20

	s2Big, err := rand.Int(rand.Reader, big.NewInt(80))
	if err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in GenerateRandomAWGParams: %v", err))
	}
	s2 := int(s2Big.Int64()) + 20

	return AWGParams{
		Version: AWGVersion31,
		Enabled: true,
		Jc:      jc,
		Jmin:    jmin,
		Jmax:    jmax,
		S1:      s1,
		S2:      s2,
		S3:      s1,
		S4:      s2,
		H1:      randomUint32(),
		H2:      randomUint32(),
		H3:      randomUint32(),
		H4:      randomUint32(),
	}
}

// GetRecommendedMTU returns the recommended MTU for a given AWG preset.
// For "anti_tspu", it returns 1280 to eliminate the standard WireGuard MTU (1420) signature,
// matching the standard minimum IPv6/tunnel MTU. For other presets, it returns 1420.
func GetRecommendedMTU(preset string) int {
	if preset == "anti_tspu" {
		return 1280
	}
	return 1420
}

// GetAWGParamsByPreset возвращает параметры по имени пресета
func GetAWGParamsByPreset(preset string) AWGParams {
	switch preset {
	case "awg31_strict":
		return GenerateAWG31StrictParams()
	case "awg31_balanced":
		return GenerateAWG31BalancedParams()
	case "awg20_legacy":
		return GenerateAWG20LegacyParams()
	case "anti_tspu":
		// Anti-TSPU: AWG 2.0 с нетипичными параметрами против сигнатур ТСПУ
		params := GenerateAWG20LegacyParams()
		params.Jc = 5
		params.Jmin = 40
		params.Jmax = 120
		params.S1 = 56
		params.S2 = 100
		params.H1 = randomUint32()
		params.H2 = randomUint32()
		params.H3 = randomUint32()
		params.H4 = randomUint32()
		return params
	default:
		return GenerateAWG31StrictParams()
	}
}

// GenerateAWGConfig генерирует конфигурационный файл AmneziaWG
func GenerateAWGConfig(cfg *AWGConfig) (string, error) {
	var buf bytes.Buffer

	buf.WriteString("# ============================================================\n")
	if cfg.AWGParams.Version == AWGVersion31 {
		buf.WriteString("# AmneziaWG 3.1 Mesh Configuration (Advanced Anti-DPI / TSPU)\n")
		buf.WriteString("# Behavioral obfuscation: Header Protection + Custom Timings\n")
	} else {
		buf.WriteString("# AmneziaWG 2.0 Mesh Configuration (Legacy Compatibility)\n")
	}
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

	if cfg.AWGParams.Enabled {
		// ═══ Общие параметры (2.0 и 3.1) ═══
		buf.WriteString(fmt.Sprintf("Jc = %d\n", cfg.AWGParams.Jc))
		buf.WriteString(fmt.Sprintf("Jmin = %d\n", cfg.AWGParams.Jmin))
		buf.WriteString(fmt.Sprintf("Jmax = %d\n", cfg.AWGParams.Jmax))
		buf.WriteString(fmt.Sprintf("S1 = %d\n", cfg.AWGParams.S1))
		buf.WriteString(fmt.Sprintf("S2 = %d\n", cfg.AWGParams.S2))

		// S3, S4 — новые в 3.1
		if cfg.AWGParams.Version == AWGVersion31 {
			buf.WriteString(fmt.Sprintf("S3 = %d\n", cfg.AWGParams.S3))
			buf.WriteString(fmt.Sprintf("S4 = %d\n", cfg.AWGParams.S4))
		}

		// ═══ Header Protection (AWG 3.1) ═══
		if cfg.AWGParams.HeaderProtectionEnabled {
			buf.WriteString(fmt.Sprintf("HeaderProtectionKey = %s\n",
				hex.EncodeToString(cfg.AWGParams.HeaderProtectionKey[:])))
			// При Header Protection: стандартные заголовки
			buf.WriteString("H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n")
		} else {
			// Без Header Protection: кастомные заголовки
			buf.WriteString(fmt.Sprintf("H1 = %d\n", cfg.AWGParams.H1))
			buf.WriteString(fmt.Sprintf("H2 = %d\n", cfg.AWGParams.H2))
			buf.WriteString(fmt.Sprintf("H3 = %d\n", cfg.AWGParams.H3))
			buf.WriteString(fmt.Sprintf("H4 = %d\n", cfg.AWGParams.H4))
		}

		// ═══ AWG 3.1: Custom Timings ═══
		if cfg.AWGParams.Version == AWGVersion31 {
			if cfg.AWGParams.RekeyAfterTimeMin > 0 {
				buf.WriteString(fmt.Sprintf("RekeyAfterTime = %d-%d\n",
					cfg.AWGParams.RekeyAfterTimeMin, cfg.AWGParams.RekeyAfterTimeMax))
			}
			if cfg.AWGParams.RekeyTimeoutMin > 0 {
				buf.WriteString(fmt.Sprintf("RekeyTimeout = %d-%d\n",
					cfg.AWGParams.RekeyTimeoutMin, cfg.AWGParams.RekeyTimeoutMax))
			}
			if cfg.AWGParams.RejectAfterTimeMin > 0 {
				buf.WriteString(fmt.Sprintf("RejectAfterTime = %d-%d\n",
					cfg.AWGParams.RejectAfterTimeMin, cfg.AWGParams.RejectAfterTimeMax))
			}
			if cfg.AWGParams.KeepaliveTimeoutMin > 0 {
				buf.WriteString(fmt.Sprintf("KeepaliveTimeout = %d-%d\n",
					cfg.AWGParams.KeepaliveTimeoutMin, cfg.AWGParams.KeepaliveTimeoutMax))
			}
			if cfg.AWGParams.MaxHandshakeAttemptsMin > 0 {
				buf.WriteString(fmt.Sprintf("MaxHandshakeAttempts = %d-%d\n",
					cfg.AWGParams.MaxHandshakeAttemptsMin, cfg.AWGParams.MaxHandshakeAttemptsMax))
			}

			// ═══ AWG 3.1: Packet Modification ═══
			if cfg.AWGParams.RandomTrailers {
				buf.WriteString("RandomTrailers = on\n")
			}
			if cfg.AWGParams.DisableCookies {
				buf.WriteString("DisableCookies = on\n")
			}
			if cfg.AWGParams.ContentPaddingAdditionMin > 0 || cfg.AWGParams.ContentPaddingAdditionMax > 0 {
				buf.WriteString(fmt.Sprintf("ContentPaddingAddition = %d-%d\n",
					cfg.AWGParams.ContentPaddingAdditionMin, cfg.AWGParams.ContentPaddingAdditionMax))
			}

			// ═══ AWG 3.1: CPS Packets ═══
			if cfg.AWGParams.I1 != "" {
				buf.WriteString(fmt.Sprintf("I1 = %s\n", cfg.AWGParams.I1))
			}
			if cfg.AWGParams.I2 != "" {
				buf.WriteString(fmt.Sprintf("I2 = %s\n", cfg.AWGParams.I2))
			}
			if cfg.AWGParams.I3 != "" {
				buf.WriteString(fmt.Sprintf("I3 = %s\n", cfg.AWGParams.I3))
			}
			if cfg.AWGParams.I4 != "" {
				buf.WriteString(fmt.Sprintf("I4 = %s\n", cfg.AWGParams.I4))
			}
			if cfg.AWGParams.I5 != "" {
				buf.WriteString(fmt.Sprintf("I5 = %s\n", cfg.AWGParams.I5))
			}
		}
	}

	// ═══ Peers ═══
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
		// PersistentKeepalive: использовать диапазон из KeepaliveTimeout если задан
		if cfg.AWGParams.KeepaliveTimeoutMin > 0 {
			buf.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", cfg.AWGParams.KeepaliveTimeoutMin))
		} else {
			buf.WriteString("PersistentKeepalive = 25\n")
		}
	}

	return buf.String(), nil
}

// SaveAWGConfig сохраняет сгенерированный конфигурационный файл на диск
func SaveAWGConfig(cfg *AWGConfig, path string) error {
	content, err := GenerateAWGConfig(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

// GenerateRandomMTU генерирует случайный MTU в диапазоне 1280–1379 для предотвращения
// фингерпринтинга длины пакетов системами ТСПУ/DPI.
func GenerateRandomMTU() int {
	var b [1]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(fmt.Sprintf("wireguard: csprng failure in GenerateRandomMTU: %v", err))
	}
	return 1280 + int(b[0]%101) // 1280-1380
}
