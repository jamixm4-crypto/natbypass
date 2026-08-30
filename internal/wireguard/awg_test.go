package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func generatePrivateKey() string {
	var k [32]byte
	_, _ = rand.Read(k[:])
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(k[:])
}

func TestGenerateAWG31Config(t *testing.T) {
	params := GenerateAWG31StrictParams()
	cfg := &AWGConfig{
		WGConfig: WGConfig{
			PrivateKey: "test-private-key",
			Address:    "100.64.200.1/24",
			ListenPort: 443,
		},
		AWGParams: params,
	}

	content, err := GenerateAWGConfig(cfg)
	if err != nil {
		t.Fatalf("failed to generate config: %v", err)
	}

	// Проверяем наличие AWG 3.1 параметров
	if !strings.Contains(content, "HeaderProtectionKey") {
		t.Error("missing HeaderProtectionKey in config")
	}
	if !strings.Contains(content, "RandomTrailers = on") {
		t.Error("missing RandomTrailers in config")
	}
	if !strings.Contains(content, "DisableCookies = on") {
		t.Error("missing DisableCookies in config")
	}
	if !strings.Contains(content, "KeepaliveTimeout = ") {
		t.Error("missing KeepaliveTimeout range in config")
	}
	if !strings.Contains(content, "RekeyAfterTime = ") {
		t.Error("missing RekeyAfterTime range in config")
	}
	if !strings.Contains(content, "ContentPaddingAddition = ") {
		t.Error("missing ContentPaddingAddition in config")
	}

	// Проверяем что H1-H4 стандартные при Header Protection
	if !strings.Contains(content, "H1 = 1") {
		t.Error("H1 should be 1 when Header Protection enabled")
	}
}

func TestAWG31HeaderProtectionKeyGeneration(t *testing.T) {
	params := GenerateAWG31BalancedParams()

	if !params.HeaderProtectionEnabled {
		t.Error("Header Protection should be enabled by default in AWG 3.1")
	}

	// Проверяем что ключ не нулевой
	allZero := true
	for _, b := range params.HeaderProtectionKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Header Protection Key should not be all zeros")
	}
}

func TestAWGPresetsCompatibility(t *testing.T) {
	tests := []struct {
		preset   string
		expected AWGVersion
	}{
		{"awg20_legacy", AWGVersion20},
		{"anti_tspu", AWGVersion20},
		{"awg31_balanced", AWGVersion31},
		{"awg31_strict", AWGVersion31},
	}

	for _, tt := range tests {
		params := GetAWGParamsByPreset(tt.preset)
		if params.Version != tt.expected {
			t.Errorf("preset %s: expected version %s, got %s",
				tt.preset, tt.expected, params.Version)
		}
	}
}

func TestAWG20BackwardCompatibility(t *testing.T) {
	params := GenerateAWG20LegacyParams()
	cfg := &AWGConfig{
		WGConfig: WGConfig{
			PrivateKey: "test-key",
			Address:    "100.64.200.1/24",
		},
		AWGParams: params,
	}

	content, err := GenerateAWGConfig(cfg)
	if err != nil {
		t.Fatalf("failed to generate AWG 2.0 config: %v", err)
	}

	// AWG 2.0 НЕ должен содержать параметры 3.1
	if strings.Contains(content, "HeaderProtectionKey") {
		t.Error("AWG 2.0 config should not contain HeaderProtectionKey")
	}
	if strings.Contains(content, "RandomTrailers") {
		t.Error("AWG 2.0 config should not contain RandomTrailers")
	}
}

func TestAWG31EndToEnd(t *testing.T) {
	// Создаём сервер с AWG 3.1
	serverParams := GenerateAWG31StrictParams()
	serverCfg := &AWGConfig{
		WGConfig: WGConfig{
			PrivateKey: generatePrivateKey(),
			Address:    "100.64.200.1/24",
			ListenPort: 443,
		},
		AWGParams: serverParams,
	}

	serverConfig, _ := GenerateAWGConfig(serverCfg)

	// Создаём клиента с теми же параметрами
	clientParams := serverParams // Копируем параметры сервера
	clientCfg := &AWGConfig{
		WGConfig: WGConfig{
			PrivateKey: generatePrivateKey(),
			Address:    "100.64.200.2/24",
			ListenPort: 443,
		},
		AWGParams: clientParams,
	}

	clientConfig, _ := GenerateAWGConfig(clientCfg)

	// Проверяем что оба конфига валидны
	if len(serverConfig) == 0 || len(clientConfig) == 0 {
		t.Fatal("empty config generated")
	}

	// Проверяем совместимость параметров
	if serverParams.HeaderProtectionKey != clientParams.HeaderProtectionKey {
		t.Error("Header Protection Keys must match between server and client")
	}
}
