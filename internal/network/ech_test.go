// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"context"
	"crypto/tls"
	"testing"
)

func TestExtractECHFromData(t *testing.T) {
	record := "1 . alpn=h2 ech=AEX+DQBBNgAgACBc25Kn75BoPMkgzYKg/dXgaMCgmHg8eHg37zltEo7pFgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= ipv4hint=1.1.1.1"
	ech, err := ExtractECHFromData(record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ech) < 10 {
		t.Errorf("expected decoded ECH length > 10, got %d", len(ech))
	}
}

func TestECHManager_FallbackAndCache(t *testing.T) {
	mgr := NewECHManager()
	ctx := context.Background()

	// Should return default fallback for known or default domain
	ech, err := mgr.GetECHConfigList(ctx, "cloudflare.com")
	if err != nil {
		t.Fatalf("expected fallback ECH config, got err: %v", err)
	}
	if len(ech) == 0 {
		t.Fatal("expected non-empty ECH config")
	}

	// Verify caching
	echCached, err := mgr.GetECHConfigList(ctx, "cloudflare.com")
	if err != nil || len(echCached) != len(ech) {
		t.Errorf("cache retrieval failed")
	}
}

func TestApplyDefaultECH(t *testing.T) {
	tlsConf := &tls.Config{
		ServerName: "cloudflare.com",
	}

	applied := ApplyDefaultECH(tlsConf, "cloudflare.com")
	if !applied {
		t.Fatal("expected ApplyDefaultECH to succeed")
	}

	if len(tlsConf.EncryptedClientHelloConfigList) == 0 {
		t.Error("expected EncryptedClientHelloConfigList to be non-empty")
	}
	if tlsConf.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion=TLS1.3, got %x", tlsConf.MinVersion)
	}
}
