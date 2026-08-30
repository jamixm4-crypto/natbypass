package wireguard

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
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

// DefaultAWGParams возвращает параметры совместимости с AWG 2.0
func DefaultAWGParams() AWGParams {
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

// GenerateAWG31BalancedParams генерирует сбалансированные параметры AWG 3.1
func GenerateAWG31BalancedParams() AWGParams {
	var key [32]byte
	_, _ = rand.Read(key[:])

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

// GenerateAWG31StrictParams генерирует максимальную обфускацию для РФ/Китая
func GenerateAWG31StrictParams() AWGParams {
	params := GenerateAWG31BalancedParams()

	// Strict: отключаем cookies (защита от active probing)
	params.DisableCookies = true

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

func randomUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	val := binary.BigEndian.Uint32(b[:])
	if val < 1000 {
		val += 1000
	}
	return val
}

// GenerateRandomAWGParams генерирует случайные валидные параметры AWG
func GenerateRandomAWGParams() AWGParams {
	jcBig, _ := rand.Int(rand.Reader, big.NewInt(6))
	jminBig, _ := rand.Int(rand.Reader, big.NewInt(50))
	jmaxExtra, _ := rand.Int(rand.Reader, big.NewInt(100))
	s1Big, _ := rand.Int(rand.Reader, big.NewInt(100))
	s2Big, _ := rand.Int(rand.Reader, big.NewInt(100))

	jc := int(jcBig.Int64()) + 2
	jmin := int(jminBig.Int64()) + 20
	jmax := jmin + int(jmaxExtra.Int64()) + 30
	s1 := int(s1Big.Int64()) + 20
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

// GetAWGParamsByPreset возвращает параметры по имени пресета
func GetAWGParamsByPreset(preset string) AWGParams {
	switch preset {
	case "awg31_strict":
		return GenerateAWG31StrictParams()
	case "awg31_balanced":
		return GenerateAWG31BalancedParams()
	case "awg20_legacy":
		return DefaultAWGParams()
	case "anti_tspu":
		// Anti-TSPU: AWG 2.0 с нетипичными параметрами
		params := DefaultAWGParams()
		params.Jc = 5
		params.S2 = 100
		params.H1 = randomUint32()
		params.H2 = randomUint32()
		params.H3 = randomUint32()
		params.H4 = randomUint32()
		return params
	default:
		return GenerateAWG31BalancedParams()
	}
}

// GenerateAWGConfig генерирует конфигурационный файл AmneziaWG
func GenerateAWGConfig(cfg *AWGConfig) (string, error) {
	var buf bytes.Buffer

	buf.WriteString("# ============================================================\n")
	if cfg.AWGParams.Version == AWGVersion31 {
		buf.WriteString("# AmneziaWG 3.1 Mesh Configuration (Anti-DPI Russia/China)\n")
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
