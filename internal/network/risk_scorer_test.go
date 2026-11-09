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

func TestRiskScorer_NormalConditions(t *testing.T) {
	rs := NewRiskScorer()
	for i := 0; i < 10; i++ {
		rs.RecordProbeResult(true, 25*time.Millisecond)
	}

	score := rs.Score()
	if score > 0.20 {
		t.Errorf("expected low score under normal conditions, got %f", score)
	}
	if rs.Level() != RiskLow {
		t.Errorf("expected RiskLow, got %s", rs.Level())
	}
	if rs.ShouldRotateMask() {
		t.Errorf("expected ShouldRotateMask to be false under normal conditions")
	}
}

func TestRiskScorer_HighRiskEscalation(t *testing.T) {
	rs := NewRiskScorer()

	// Simulate sudden DPI filtering: consecutive drops + RTT inflation + RST
	for i := 0; i < 6; i++ {
		rs.RecordProbeResult(false, 0)
	}
	rs.RecordRST()

	score := rs.Score()
	if score < 0.70 {
		t.Errorf("expected high risk score >= 0.70, got %f", score)
	}
	if rs.Level() != RiskHigh {
		t.Errorf("expected RiskHigh, got %s", rs.Level())
	}
	if !rs.ShouldRotateMask() {
		t.Errorf("expected ShouldRotateMask to be true under high DPI interference")
	}
}
