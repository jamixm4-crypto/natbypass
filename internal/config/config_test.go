// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

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

func TestPathTraversalRejected(t *testing.T) {
	traversalPaths := []string{
		"../../etc/shadow",
		"../../Windows/win.ini",
		"..\\..\\Windows\\System32\\calc.exe",
		"foo/../../bar/config.yaml",
		"../config.yaml",
	}

	for _, p := range traversalPaths {
		_, err := Load(p)
		if err == nil {
			t.Errorf("expected path traversal error for %q, but got nil", p)
		} else if !strings.Contains(err.Error(), "path traversal rejected") {
			t.Errorf("expected 'path traversal rejected' in error for %q, got: %v", p, err)
		}
	}
}

func TestDeterministicSubnetDerivation(t *testing.T) {
	// 1. Same seed must produce identical subnet
	sub1 := DeriveSubnetFromSeed("my-secret-topic-key-123")
	sub2 := DeriveSubnetFromSeed("my-secret-topic-key-123")
	if sub1 != sub2 {
		t.Errorf("DeriveSubnetFromSeed not deterministic: %s != %s", sub1, sub2)
	}
	if !strings.HasSuffix(sub1, ".0/24") {
		t.Errorf("DeriveSubnetFromSeed invalid format: %s", sub1)
	}

	// 2. Different seeds should produce different subnets
	sub3 := DeriveSubnetFromSeed("another-secret-topic-key-456")
	if sub1 == sub3 {
		t.Errorf("DeriveSubnetFromSeed collision on different seeds: %s", sub1)
	}

	// 3. Profile with explicit Subnet takes precedence
	profExplicit := &Profile{
		Subnet:    "10.50.60.0/24",
		VirtualIP: "10.50.60.5/24",
		MQTTTopic: "some-topic",
	}
	if got := DeriveSubnetFromProfile(profExplicit); got != "10.50.60.0/24" {
		t.Errorf("DeriveSubnetFromProfile with explicit Subnet: got %s, want 10.50.60.0/24", got)
	}

	// 4. Profile without Subnet but with VirtualIP derives from VirtualIP
	profVIP := &Profile{
		VirtualIP: "10.77.88.99/24",
		MQTTTopic: "some-topic",
	}
	if got := DeriveSubnetFromProfile(profVIP); got != "10.77.88.0/24" {
		t.Errorf("DeriveSubnetFromProfile with VirtualIP: got %s, want 10.77.88.0/24", got)
	}

	// 5. Profile with only Topic derives deterministically from Topic
	profTopic := &Profile{
		MQTTTopic: "mesh-team-secret",
	}
	gotTopicSubnet := DeriveSubnetFromProfile(profTopic)
	expectedTopicSubnet := DeriveSubnetFromSeed("mesh-team-secret")
	if gotTopicSubnet != expectedTopicSubnet {
		t.Errorf("DeriveSubnetFromProfile with Topic: got %s, want %s", gotTopicSubnet, expectedTopicSubnet)
	}

	// 6. Profile prefix helper
	prefix := DeriveSubnetPrefixFromProfile(profExplicit)
	if prefix != "10.50.60" {
		t.Errorf("DeriveSubnetPrefixFromProfile: got %s, want 10.50.60", prefix)
	}
}

func TestSubnetMismatchWarning(t *testing.T) {
	// Matching subnet - no warning
	if warn := SubnetMismatchWarning("10.50.60.5", "10.50.60.0/24"); warn != "" {
		t.Errorf("expected empty warning for matching VIP, got: %s", warn)
	}
	if warn := SubnetMismatchWarning("10.50.60.5/24", "10.50.60.0/24"); warn != "" {
		t.Errorf("expected empty warning for matching VIP with mask, got: %s", warn)
	}

	// Mismatched subnet - must return warning
	warn := SubnetMismatchWarning("10.1.1.5", "10.1.2.0/24")
	if warn == "" {
		t.Errorf("expected warning for mismatched VIP, got empty string")
	}
	if !strings.Contains(warn, "10.1.1.5") || !strings.Contains(warn, "10.1.2.0/24") {
		t.Errorf("warning missing expected IP/subnet info: %s", warn)
	}
}

func TestGetMeshSubnets(t *testing.T) {
	prof := &Profile{Subnet: "10.20.30.0/24"}
	subnets := GetMeshSubnets(prof)
	if len(subnets) != 2 {
		t.Fatalf("expected 2 subnets, got %d: %v", len(subnets), subnets)
	}
	if subnets[0] != "10.20.30.0/24" || subnets[1] != "100.64.200.0/24" {
		t.Errorf("unexpected subnets: %v", subnets)
	}
}
