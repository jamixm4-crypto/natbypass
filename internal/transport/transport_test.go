// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package transport

import (
	"testing"
)

func TestDefaultRegistry(t *testing.T) {
	reg := DefaultRegistry()
	if reg == nil {
		t.Fatal("expected non-nil default registry")
	}

	awg, ok := reg.Get("awg")
	if !ok || awg == nil {
		t.Error("expected awg transport to be registered")
	}
	if awg.Features().Protocol != "udp" {
		t.Errorf("expected protocol udp, got %s", awg.Features().Protocol)
	}

	quic, ok := reg.Get("quic")
	if !ok || quic == nil {
		t.Error("expected quic transport to be registered")
	}

	shadowtls, ok := reg.Get("shadowtls")
	if !ok || shadowtls == nil {
		t.Error("expected shadowtls transport to be registered")
	}

	wss, ok := reg.Get("wss")
	if !ok || wss == nil {
		t.Error("expected wss transport to be registered")
	}

	list := reg.List()
	if len(list) < 4 {
		t.Errorf("expected at least 4 registered transports, got %d", len(list))
	}

	// Verify priority sorting
	for i := 1; i < len(list); i++ {
		if list[i].Features().Priority < list[i-1].Features().Priority {
			t.Errorf("transports not sorted by priority: %d < %d", list[i].Features().Priority, list[i-1].Features().Priority)
		}
	}
}

func TestCustomTransportRegistration(t *testing.T) {
	reg := NewRegistry()
	custom := NewBaseTransport("custom_mesh", TransportFeatures{
		Name:         "Custom Mesh",
		Protocol:     "udp",
		Encrypted:    true,
		Obfuscated:   true,
		Multiplexing: true,
		Priority:     10,
	})

	reg.Register(custom)
	got, ok := reg.Get("custom_mesh")
	if !ok || got.Name() != "custom_mesh" {
		t.Errorf("failed to retrieve registered transport")
	}
}
