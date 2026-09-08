// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"testing"
	"time"
)

func TestTrafficShaper_Configuration(t *testing.T) {
	shaper := NewTrafficShaper(true)
	if !shaper.IsEnabled() {
		t.Fatalf("expected shaper to be enabled")
	}

	shaper.SetEnabled(false)
	if shaper.IsEnabled() {
		t.Fatalf("expected shaper to be disabled")
	}

	shaper.SetEnabled(true)
	if shaper.jitterMin != 5*time.Millisecond || shaper.maxFrameSize != 1350 {
		t.Fatalf("invalid default shaper parameters: %+v", shaper)
	}
}

func TestTrafficShaper_AdaptivePadding(t *testing.T) {
	shaper := NewTrafficShaper(true)

	// Small packet: 60 bytes (e.g. ping/DNS)
	padLen := shaper.AdaptivePadding(60)
	if padLen <= 0 || 60+padLen > 1350 {
		t.Fatalf("unexpected padLen for small packet: %d", padLen)
	}

	payload := make([]byte, 60)
	payload[0] = 0x45 // IPv4
	padded := shaper.ApplyAdaptivePadding(payload)
	if len(padded) <= len(payload) {
		t.Fatalf("expected padded length > %d, got %d", len(payload), len(padded))
	}

	// Large packet near MTU: 1350 bytes -> padLen should be 0
	padLarge := shaper.AdaptivePadding(1350)
	if padLarge != 0 {
		t.Fatalf("expected 0 padding for 1350B packet, got %d", padLarge)
	}
}
