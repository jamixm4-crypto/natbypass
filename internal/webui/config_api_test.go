// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
)

func TestConfigAPISerializationAndPersistence(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.yaml")

	initialCfg := &config.Config{
		App: config.AppConfig{
			Name:            "NatBypass",
			DeviceName:      "TestDevice",
			SaveLogsToDisk:  true,
			ShowDiagnostics: true,
			PublishInterval: 12,
		},
		WebUI: config.WebUIConfig{
			Enabled: true,
			Port:    8080,
		},
		Network: config.NetworkConfig{
			Address: "10.0.0.1",
			UDPPort: 47832,
		},
	}
	if err := config.Save(initialCfg, cfgPath, false); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	reg := peer.NewRegistry()
	sig := signaling.NewFallbackManager(nil)
	server := NewServer(8080, "", "", reg, sig)
	server.SetConfigPath(cfgPath)
	server.cfg = initialCfg

	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", server.handleConfig)
	mux.HandleFunc("/api/settings/save", server.handleSettingsSave)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. GET /api/config and verify lowercase json fields
	resp, err := http.Get(ts.URL + "/api/config")
	if err != nil {
		t.Fatalf("GET /api/config failed: %v", err)
	}
	defer resp.Body.Close()

	var getResult struct {
		Ok   bool `json:"ok"`
		Data struct {
			App struct {
				DeviceName      string `json:"device_name"`
				SaveLogsToDisk  bool   `json:"save_logs_to_disk"`
				ShowDiagnostics bool   `json:"show_diagnostics"`
				PublishInterval int    `json:"publish_interval"`
			} `json:"app"`
			Network struct {
				Address string `json:"address"`
				UDPPort int    `json:"udp_port"`
			} `json:"network"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&getResult); err != nil {
		t.Fatalf("Failed to decode GET /api/config response: %v", err)
	}

	if !getResult.Ok {
		t.Errorf("Expected ok=true, got false")
	}
	if getResult.Data.App.DeviceName != "TestDevice" {
		t.Errorf("Expected device_name 'TestDevice', got '%s'", getResult.Data.App.DeviceName)
	}
	if !getResult.Data.App.SaveLogsToDisk {
		t.Errorf("Expected save_logs_to_disk=true, got false")
	}
	if !getResult.Data.App.ShowDiagnostics {
		t.Errorf("Expected show_diagnostics=true, got false")
	}
	if getResult.Data.Network.UDPPort != 47832 {
		t.Errorf("Expected udp_port=47832, got %d", getResult.Data.Network.UDPPort)
	}

	// 2. POST /api/settings/save to update settings
	savePayload := map[string]interface{}{
		"device_name":        "UpdatedDevice",
		"publish_interval":   15,
		"save_logs_to_disk":  false,
		"show_diagnostics":   true,
		"virtual_ip":         "10.0.0.2",
	}
	bodyBytes, _ := json.Marshal(savePayload)
	postResp, err := http.Post(ts.URL+"/api/settings/save", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("POST /api/settings/save failed: %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", postResp.StatusCode)
	}

	// 3. GET /api/config again (simulating page reload F5)
	reloadResp, err := http.Get(ts.URL + "/api/config")
	if err != nil {
		t.Fatalf("Reload GET /api/config failed: %v", err)
	}
	defer reloadResp.Body.Close()

	var reloadResult struct {
		Ok   bool `json:"ok"`
		Data struct {
			App struct {
				DeviceName      string `json:"device_name"`
				SaveLogsToDisk  bool   `json:"save_logs_to_disk"`
				ShowDiagnostics bool   `json:"show_diagnostics"`
				PublishInterval int    `json:"publish_interval"`
			} `json:"app"`
		} `json:"data"`
	}
	if err := json.NewDecoder(reloadResp.Body).Decode(&reloadResult); err != nil {
		t.Fatalf("Failed to decode reload response: %v", err)
	}

	if reloadResult.Data.App.DeviceName != "UpdatedDevice" {
		t.Errorf("Expected device_name 'UpdatedDevice', got '%s'", reloadResult.Data.App.DeviceName)
	}
	if reloadResult.Data.App.SaveLogsToDisk != false {
		t.Errorf("Expected save_logs_to_disk=false, got %v", reloadResult.Data.App.SaveLogsToDisk)
	}
	if reloadResult.Data.App.ShowDiagnostics != true {
		t.Errorf("Expected show_diagnostics=true, got %v", reloadResult.Data.App.ShowDiagnostics)
	}

	// Also verify config file on disk directly
	savedCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Failed to load saved config from disk: %v", err)
	}
	if savedCfg.App.DeviceName != "UpdatedDevice" {
		t.Errorf("Expected disk DeviceName 'UpdatedDevice', got '%s'", savedCfg.App.DeviceName)
	}
	if savedCfg.App.SaveLogsToDisk != false {
		t.Errorf("Expected disk SaveLogsToDisk=false, got %v", savedCfg.App.SaveLogsToDisk)
	}
	if savedCfg.App.ShowDiagnostics != true {
		t.Errorf("Expected disk ShowDiagnostics=true, got %v", savedCfg.App.ShowDiagnostics)
	}

	_ = os.RemoveAll(tempDir)
}
