package wireguard

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestAWG_PresetsAndConfigGeneration(t *testing.T) {
	t.Run("AWG20_Legacy_Preset", func(t *testing.T) {
		p := GetAWGParamsByPreset("awg20_legacy")
		if p.Version != AWGVersion20 {
			t.Errorf("expected AWGVersion20, got %s", p.Version)
		}
		if p.Jc != 4 || p.S1 != 48 || p.S2 != 32 {
			t.Errorf("unexpected legacy params: %+v", p)
		}

		cfg := &AWGConfig{
			WGConfig: WGConfig{
				PrivateKey: "aW52YWxpZGtleTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
				Address:    "10.200.0.2/24",
				ListenPort: 51820,
				Peers: []WGPeer{
					{
						PublicKey:  "cHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=",
						Endpoint:   "95.21.40.10:51820",
						AllowedIPs: []string{"10.200.0.0/24"},
					},
				},
			},
			AWGParams: p,
		}

		confStr, err := GenerateAWGConfig(cfg)
		if err != nil {
			t.Fatalf("GenerateAWGConfig failed: %v", err)
		}

		if !strings.Contains(confStr, "AmneziaWG 2.0") {
			t.Errorf("expected header with 2.0, got: %s", confStr)
		}
		if !strings.Contains(confStr, "Jc = 4") || !strings.Contains(confStr, "S1 = 48") {
			t.Errorf("missing Jc/S1 in config:\n%s", confStr)
		}
		if strings.Contains(confStr, "HeaderProtectionKey") {
			t.Errorf("legacy config should not have HeaderProtectionKey")
		}
	})

	t.Run("AWG31_Balanced_Preset", func(t *testing.T) {
		p := GetAWGParamsByPreset("awg31_balanced")
		if p.Version != AWGVersion31 {
			t.Errorf("expected AWGVersion31, got %s", p.Version)
		}
		if !p.HeaderProtectionEnabled || len(p.HeaderProtectionKey) != 32 {
			t.Errorf("expected HeaderProtectionEnabled=true with 32-byte key")
		}
		if !p.RandomTrailers {
			t.Errorf("expected RandomTrailers=true")
		}

		cfg := &AWGConfig{
			WGConfig: WGConfig{
				PrivateKey: "aW52YWxpZGtleTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
				Address:    "10.200.0.2/24",
				ListenPort: 443,
			},
			AWGParams: p,
		}

		confStr, err := GenerateAWGConfig(cfg)
		if err != nil {
			t.Fatalf("GenerateAWGConfig failed: %v", err)
		}

		if !strings.Contains(confStr, "AmneziaWG 3.1") {
			t.Errorf("expected header with 3.1, got: %s", confStr)
		}
		if !strings.Contains(confStr, "HeaderProtectionKey = "+hex.EncodeToString(p.HeaderProtectionKey[:])) {
			t.Errorf("missing HeaderProtectionKey in config:\n%s", confStr)
		}
		if !strings.Contains(confStr, "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4") {
			t.Errorf("expected standard H1-H4 with Header Protection, got:\n%s", confStr)
		}
		if !strings.Contains(confStr, "RekeyAfterTime = 120-180") {
			t.Errorf("missing RekeyAfterTime in config:\n%s", confStr)
		}
		if !strings.Contains(confStr, "RandomTrailers = on") {
			t.Errorf("missing RandomTrailers in config:\n%s", confStr)
		}
	})

	t.Run("AWG31_Strict_Preset_Russia_China", func(t *testing.T) {
		p := GetAWGParamsByPreset("awg31_strict")
		if p.Version != AWGVersion31 {
			t.Errorf("expected AWGVersion31, got %s", p.Version)
		}
		if !p.DisableCookies {
			t.Errorf("expected DisableCookies=true in strict mode")
		}
		if p.I1 != "quic_initial" || p.I2 != "dns_query" {
			t.Errorf("expected CPS packets I1/I2, got I1=%s, I2=%s", p.I1, p.I2)
		}

		cfg := &AWGConfig{
			WGConfig: WGConfig{
				PrivateKey: "aW52YWxpZGtleTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
				Address:    "10.200.0.5/24",
			},
			AWGParams: p,
		}

		confStr, err := GenerateAWGConfig(cfg)
		if err != nil {
			t.Fatalf("GenerateAWGConfig failed: %v", err)
		}

		if !strings.Contains(confStr, "DisableCookies = on") {
			t.Errorf("missing DisableCookies in config:\n%s", confStr)
		}
		if !strings.Contains(confStr, "I1 = quic_initial") || !strings.Contains(confStr, "I2 = dns_query") {
			t.Errorf("missing I1/I2 in config:\n%s", confStr)
		}
	})

	t.Run("Anti_TSPU_Preset", func(t *testing.T) {
		p := GetAWGParamsByPreset("anti_tspu")
		if p.Jc != 5 || p.S2 != 100 {
			t.Errorf("expected Jc=5, S2=100 for anti_tspu preset, got Jc=%d, S2=%d", p.Jc, p.S2)
		}
	})
}
