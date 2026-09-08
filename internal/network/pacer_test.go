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

func TestAdaptivePacer_RTT_EWMA(t *testing.T) {
	pacer := NewAdaptivePacer()

	pacer.RecordAck(50 * time.Millisecond)
	srtt := pacer.SmoothedRTT()
	if srtt <= 0 {
		t.Fatalf("expected srtt > 0, got %v", srtt)
	}

	pacer.RecordAck(100 * time.Millisecond)
	srtt2 := pacer.SmoothedRTT()
	if srtt2 <= srtt {
		t.Fatalf("expected srtt to increase towards 100ms, got %v <= %v", srtt2, srtt)
	}
}

func TestAdaptivePacer_LossScaling(t *testing.T) {
	pacer := NewAdaptivePacer()

	// Initially zero loss
	if mult := pacer.KeepAliveMultiplier(); mult != 1.0 {
		t.Fatalf("expected 1.0 multiplier initially, got %f", mult)
	}

	// Simulate heavy loss
	for i := 0; i < 100; i++ {
		pacer.RecordSent(1000)
		if i < 40 {
			pacer.RecordLoss()
		}
	}
	pacer.ForceEvaluateWindow()

	if pacer.LossRate() < 0.20 {
		t.Fatalf("expected loss rate >= 0.20, got %f", pacer.LossRate())
	}
	if mult := pacer.KeepAliveMultiplier(); mult <= 1.0 {
		t.Fatalf("expected keepalive multiplier > 1.0 under loss, got %f", mult)
	}

	// Verify pacing execution doesn't panic
	pacer.Pace()
}
