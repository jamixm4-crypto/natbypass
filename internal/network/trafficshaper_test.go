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
