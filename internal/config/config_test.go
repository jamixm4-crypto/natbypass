package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptConfigData(t *testing.T) {
	plainYAML := []byte("app:\n  name: \"NatBypass\"\n  device_name: \"test-node\"\n  publish_interval: 10\n")

	enc, err := EncryptConfigData(plainYAML)
	if err != nil {
		t.Fatalf("EncryptConfigData failed: %v", err)
	}

	// Plain data should pass through DecryptConfigData unmodified
	decPlain, err := DecryptConfigData(plainYAML)
	if err != nil {
		t.Fatalf("DecryptConfigData on plain data failed: %v", err)
	}
	if string(decPlain) != string(plainYAML) {
		t.Errorf("DecryptConfigData on plain data modified content: got %q, want %q", string(decPlain), string(plainYAML))
	}

	// Encrypted data should be successfully decrypted back to plain data
	dec, err := DecryptConfigData(enc)
	if err != nil {
		t.Fatalf("DecryptConfigData failed: %v", err)
	}
	if string(dec) != string(plainYAML) {
		t.Errorf("Decrypted content mismatch: got %q, want %q", string(dec), string(plainYAML))
	}
}

func TestSaveAndLoadPlainConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &Config{
		App: AppConfig{
			Name:            "NatBypass",
			DeviceName:      "my-test-device",
			PublishInterval: 10,
			SaveLogsToDisk:  false,
			ShowDiagnostics: false,
		},
		Network: NetworkConfig{
			AllowExitNode:     false,
			AdvertisedSubnets: []string{"192.168.1.0/24"},
		},
	}

	if err := Save(cfg, cfgPath, false); err != nil {
		t.Fatalf("Save(plain) failed: %v", err)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), HeaderEncryptedConfig) {
		t.Errorf("Plain config file should not have encrypted header")
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(plain) failed: %v", err)
	}

	if loaded.App.DeviceName != "my-test-device" {
		t.Errorf("App.DeviceName = %q, want %q", loaded.App.DeviceName, "my-test-device")
	}
	if loaded.App.PublishInterval != 10 {
		t.Errorf("App.PublishInterval = %d, want 10", loaded.App.PublishInterval)
	}
	if loaded.App.SaveLogsToDisk != false {
		t.Errorf("App.SaveLogsToDisk = %v, want false", loaded.App.SaveLogsToDisk)
	}
	if loaded.App.ShowDiagnostics != false {
		t.Errorf("App.ShowDiagnostics = %v, want false", loaded.App.ShowDiagnostics)
	}
	if loaded.Network.AllowExitNode != false {
		t.Errorf("Network.AllowExitNode = %v, want false", loaded.Network.AllowExitNode)
	}
	if len(loaded.Network.AdvertisedSubnets) != 1 || loaded.Network.AdvertisedSubnets[0] != "192.168.1.0/24" {
		t.Errorf("Network.AdvertisedSubnets = %v, want [192.168.1.0/24]", loaded.Network.AdvertisedSubnets)
	}
}

func TestSaveAndLoadEncryptedConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &Config{
		App: AppConfig{
			Name:            "NatBypass",
			DeviceName:      "secure-node",
			PublishInterval: 10,
			SaveLogsToDisk:  false,
			ShowDiagnostics: false,
		},
		Network: NetworkConfig{
			AllowExitNode: false,
		},
	}

	if err := Save(cfg, cfgPath, true); err != nil {
		t.Fatalf("Save(encrypt) failed: %v", err)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(encrypted) failed: %v", err)
	}

	if loaded.App.DeviceName != "secure-node" {
		t.Errorf("App.DeviceName = %q, want %q", loaded.App.DeviceName, "secure-node")
	}
	if loaded.App.PublishInterval != 10 {
		t.Errorf("App.PublishInterval = %d, want 10", loaded.App.PublishInterval)
	}
	if loaded.App.SaveLogsToDisk != false {
		t.Errorf("App.SaveLogsToDisk = %v, want false", loaded.App.SaveLogsToDisk)
	}
	if loaded.App.ShowDiagnostics != false {
		t.Errorf("App.ShowDiagnostics = %v, want false", loaded.App.ShowDiagnostics)
	}
	if loaded.Network.AllowExitNode != false {
		t.Errorf("Network.AllowExitNode = %v, want false", loaded.Network.AllowExitNode)
	}
	_ = raw
}

func TestDefaultConfigValues(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "empty.yaml")

	if err := os.WriteFile(cfgPath, []byte("app:\n  name: \"NatBypass\"\n"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(empty) failed: %v", err)
	}

	if loaded.App.PublishInterval != 10 {
		t.Errorf("Default PublishInterval = %d, want 10", loaded.App.PublishInterval)
	}
	if loaded.App.SaveLogsToDisk != false {
		t.Errorf("Default SaveLogsToDisk = %v, want false", loaded.App.SaveLogsToDisk)
	}
	if loaded.App.ShowDiagnostics != false {
		t.Errorf("Default ShowDiagnostics = %v, want false", loaded.App.ShowDiagnostics)
	}
	if loaded.Network.AllowExitNode != false {
		t.Errorf("Default AllowExitNode = %v, want false", loaded.Network.AllowExitNode)
	}
}
