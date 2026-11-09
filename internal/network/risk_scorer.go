// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"sync"
	"time"
)

// RiskLevel classifies the DPI / middlebox interference threat level on a connection.
type RiskLevel string

const (
	// RiskLow represents clean, uninhibited packet delivery (< 0.35).
	RiskLow RiskLevel = "low"

	// RiskModerate indicates emerging anomalies, packet drop bursts, or jitter inflation (0.35 - 0.70).
	RiskModerate RiskLevel = "moderate"

	// RiskHigh indicates active DPI interference, TCP RST injections, or heavy stateful throttling (>= 0.70).
	RiskHigh RiskLevel = "high"
)

// RiskScorer monitors link telemetry and computes a heuristic DPI detection risk score.
// Inspired by aivpn (Neural Resonance / micro-scoring) and NetworkML behavioral traffic profiling.
type RiskScorer struct {
	mu              sync.RWMutex
	consecutiveLoss int
	probeTimeouts   int
	rttMin          time.Duration
	rttCurrent      time.Duration
	lastRstDetected time.Time
	lastScore       float64
	lastUpdated     time.Time
}

// NewRiskScorer creates an initialized DPI risk scorer.
func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		rttMin:      20 * time.Millisecond,
		rttCurrent:  20 * time.Millisecond,
		lastUpdated: time.Now(),
	}
}

// RecordProbeResult records the outcome of a datagram transmission or probe round-trip.
func (rs *RiskScorer) RecordProbeResult(success bool, rtt time.Duration) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.lastUpdated = time.Now()

	if !success {
		rs.consecutiveLoss++
		rs.probeTimeouts++
		return
	}

	rs.consecutiveLoss = 0
	if rtt > 0 {
		rs.rttCurrent = rtt
		if rs.rttMin == 0 || rtt < rs.rttMin {
			rs.rttMin = rtt
		}
	}
	if rs.probeTimeouts > 0 {
		rs.probeTimeouts--
	}
}

// RecordRST marks an abnormal TCP reset injection or middlebox teardown event.
func (rs *RiskScorer) RecordRST() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.lastRstDetected = time.Now()
	rs.lastUpdated = time.Now()
}

// Score evaluates the current link telemetry and returns a normalized DPI detection risk score [0.0, 1.0].
func (rs *RiskScorer) Score() float64 {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	var score float64

	// 1. Consecutive datagram loss pressure (up to 0.40 score)
	if rs.consecutiveLoss >= 5 {
		score += 0.40
	} else if rs.consecutiveLoss > 0 {
		score += float64(rs.consecutiveLoss) * 0.08
	}

	// 2. Probe timeouts count (up to 0.25 score)
	if rs.probeTimeouts >= 3 {
		score += 0.25
	} else if rs.probeTimeouts > 0 {
		score += float64(rs.probeTimeouts) * 0.08
	}

	// 3. RTT inflation ratio (DPI queue buffer-bloat / throttling inspection delay)
	if rs.rttMin > 0 && rs.rttCurrent > 0 {
		ratio := float64(rs.rttCurrent) / float64(rs.rttMin)
		if ratio >= 3.0 {
			score += 0.25
		} else if ratio >= 1.8 {
			score += 0.12
		}
	}

	// 4. Recent TCP RST injection (< 60s ago is a strong tell of active DPI)
	if !rs.lastRstDetected.IsZero() && time.Since(rs.lastRstDetected) < 60*time.Second {
		score += 0.35
	}

	// Decay over time if no new failures occurred
	if time.Since(rs.lastUpdated) > 30*time.Second {
		score *= 0.5
	}

	if score > 1.0 {
		score = 1.0
	}
	rs.lastScore = score
	return score
}

// Level returns the categorical risk level based on the computed score.
func (rs *RiskScorer) Level() RiskLevel {
	s := rs.Score()
	if s >= 0.70 {
		return RiskHigh
	}
	if s >= 0.35 {
		return RiskModerate
	}
	return RiskLow
}

// ShouldRotateMask returns true if active DPI suppression is detected and
// obfuscation mask rotation or transport escalation is recommended.
func (rs *RiskScorer) ShouldRotateMask() bool {
	return rs.Score() >= 0.70
}
