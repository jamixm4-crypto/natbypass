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

	"github.com/natbypass/natbypass/internal/diagnostic"
)

func TestNetcheckEndpoint(t *testing.T) {
	srv := &Server{
		deviceName: "Local-Server",
		version:    "1.9.226-beta3",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics/netcheck", nil)
	w := httptest.NewRecorder()

	srv.handleDiagnosticsNetcheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Ok   bool                      `json:"ok"`
		Data *diagnostic.NetcheckReport `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if !resp.Ok {
		t.Errorf("Expected ok=true, got %v", resp.Ok)
	}
	if resp.Data == nil {
		t.Fatal("Expected non-nil NetcheckReport data")
	}
	if resp.Data.PathMTU < 1280 {
		t.Errorf("Expected PathMTU >= 1280, got %d", resp.Data.PathMTU)
	}
}
