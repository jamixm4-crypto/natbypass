// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/peer"
)

func TestMeshTopologyEndpoint(t *testing.T) {
	reg := peer.NewRegistry()
	reg.Upsert(&peer.Peer{
		DeviceID:          "remote-peer-1",
		DeviceName:        "Laptop-Remote",
		VirtualIP:         "10.1.1.2/24",
		Online:            true,
		DirectP2P:         true,
		Transport:         "quic",
		PingMs:            25,
		LossPercent:       0,
		StandbyRelayReady: true,
		LastSeen:          time.Now(),
	})

	srv := &Server{
		registry:   reg,
		deviceName: "Local-Server",
		version:    "1.9.226-beta3",
		state: &AppState{
			DeviceID:  "self-node",
			VirtualIP: "10.1.1.1/24",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mesh/topology", nil)
	w := httptest.NewRecorder()

	srv.handleMeshTopology(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var resp struct {
		Ok   bool         `json:"ok"`
		Data MeshTopology `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if !resp.Ok {
		t.Fatalf("Expected ok: true")
	}

	topo := resp.Data
	if topo.SelfID != "self-node" {
		t.Errorf("Expected SelfID 'self-node', got %s", topo.SelfID)
	}

	if len(topo.Nodes) != 2 {
		t.Fatalf("Expected 2 nodes (self + 1 peer), got %d", len(topo.Nodes))
	}

	if len(topo.Edges) != 1 {
		t.Fatalf("Expected 1 edge, got %d", len(topo.Edges))
	}

	edge := topo.Edges[0]
	if edge.From != "self-node" || edge.To != "remote-peer-1" {
		t.Errorf("Edge mismatch: from %s to %s", edge.From, edge.To)
	}
	if edge.Transport != "quic" {
		t.Errorf("Expected transport 'quic', got %s", edge.Transport)
	}
	if !edge.StandbyRelayReady {
		t.Errorf("Expected StandbyRelayReady true")
	}
	if edge.PathType != "direct" {
		t.Errorf("Expected PathType 'direct', got %s", edge.PathType)
	}
}

func TestTelemetryEndpoint(t *testing.T) {
	reg := peer.NewRegistry()
	reg.Upsert(&peer.Peer{
		DeviceID:          "p1",
		Online:            true,
		DirectP2P:         true,
		StandbyRelayReady: true,
		LastSeen:          time.Now(),
	})
	reg.Upsert(&peer.Peer{
		DeviceID:          "p2",
		Online:            true,
		DirectP2P:         false,
		StandbyRelayReady: false,
		LastSeen:          time.Now(),
	})

	srv := &Server{
		registry: reg,
		version:  "1.9.226-beta3",
		state: &AppState{
			DeviceID: "local-node",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry", nil)
	w := httptest.NewRecorder()

	srv.handleTelemetry(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var resp struct {
		Ok   bool          `json:"ok"`
		Data TelemetryData `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if !resp.Ok {
		t.Fatalf("Expected ok: true")
	}

	telem := resp.Data
	if telem.TotalPeers != 2 {
		t.Errorf("Expected 2 peers, got %d", telem.TotalPeers)
	}
	if telem.DirectP2PCount != 1 {
		t.Errorf("Expected 1 direct peer, got %d", telem.DirectP2PCount)
	}
	if telem.RelayCount != 1 {
		t.Errorf("Expected 1 relay peer, got %d", telem.RelayCount)
	}
	if telem.StandbyReadyCount != 1 {
		t.Errorf("Expected 1 standby ready, got %d", telem.StandbyReadyCount)
	}
}
