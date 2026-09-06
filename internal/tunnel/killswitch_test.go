// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"testing"
)

func TestKillSwitch_Lifecycle(t *testing.T) {
	ks := NewKillSwitch()
	if ks.IsEnabled() {
		t.Fatalf("expected kill switch to be disabled initially")
	}

	if err := ks.Enable("test-tun0"); err != nil {
		t.Fatalf("failed to enable kill switch: %v", err)
	}

	if !ks.IsEnabled() {
		t.Fatalf("expected kill switch to be enabled")
	}

	if err := ks.Disable(); err != nil {
		t.Fatalf("failed to disable kill switch: %v", err)
	}

	if ks.IsEnabled() {
		t.Fatalf("expected kill switch to be disabled after Disable()")
	}
}

func TestKillSwitch_AutoRecovery(t *testing.T) {
	ks := NewKillSwitch()
	_ = ks.Enable("nb0")
	if !ks.IsEnabled() {
		t.Fatalf("expected kill switch to be enabled")
	}

	_ = ks.Disable()
	if ks.IsEnabled() {
		t.Fatalf("expected kill switch to be disabled")
	}
}
