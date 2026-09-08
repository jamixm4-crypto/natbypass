// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"sync"
	"sync/atomic"
	"time"
)

// AdaptivePacer provides BBR-inspired rate pacing, loss smoothing, and probe interval adaptation.
// When DPI active filtering / throttling or network congestion causes packet loss,
// the pacer smooths packet transmission bursts and increases keepalive intervals,
// preventing sudden connection drops.
type AdaptivePacer struct {
	mu           sync.RWMutex
	srtt         time.Duration // Smoothed RTT (EWMA)
	rttMin       time.Duration // Minimum RTT observed (RTprop)
	rttMinSeenAt time.Time
	sentCount    uint64
	lossCount    uint64
	lastWindow   time.Time
	currentLoss  float64       // 0.0 to 1.0 (loss rate in current window)
	maxBurst     int           // Maximum packets sent before pacing yield
	burstCounter int
}

// NewAdaptivePacer creates a new adaptive congestion control and pacing engine.
func NewAdaptivePacer() *AdaptivePacer {
	return &AdaptivePacer{
		srtt:         20 * time.Millisecond,
		rttMin:       20 * time.Millisecond,
		rttMinSeenAt: time.Now(),
		lastWindow:   time.Now(),
		maxBurst:     8,
	}
}

// RecordAck updates RTT estimates using Exponentially Weighted Moving Average (EWMA).
func (p *AdaptivePacer) RecordAck(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.srtt == 0 {
		p.srtt = rtt
		p.rttMin = rtt
		p.rttMinSeenAt = time.Now()
		return
	}

	// EWMA: 85% previous, 15% new sample
	p.srtt = time.Duration(float64(p.srtt)*0.85 + float64(rtt)*0.15)

	if rtt < p.rttMin || time.Since(p.rttMinSeenAt) > 30*time.Second {
		p.rttMin = rtt
		p.rttMinSeenAt = time.Now()
	}
}

// RecordSent increments transmitted packet count.
func (p *AdaptivePacer) RecordSent(pktLen int) {
	atomic.AddUint64(&p.sentCount, 1)
}

// RecordLoss notes an unacknowledged or dropped packet.
func (p *AdaptivePacer) RecordLoss() {
	atomic.AddUint64(&p.lossCount, 1)
	p.evaluateWindow()
}

// evaluateWindow periodically recalculates loss rate over a sliding 3-second interval.
func (p *AdaptivePacer) evaluateWindow() {
	p.mu.RLock()
	lastWin := p.lastWindow
	p.mu.RUnlock()

	if time.Since(lastWin) < 3*time.Second {
		return
	}
	p.ForceEvaluateWindow()
}

// ForceEvaluateWindow immediately recalculates loss rate.
func (p *AdaptivePacer) ForceEvaluateWindow() {
	p.mu.Lock()
	defer p.mu.Unlock()

	sent := atomic.SwapUint64(&p.sentCount, 0)
	lost := atomic.SwapUint64(&p.lossCount, 0)
	p.lastWindow = time.Now()

	if sent > 0 {
		p.currentLoss = float64(lost) / float64(sent+lost)
	} else if lost > 0 {
		p.currentLoss = 0.5
	} else {
		p.currentLoss = 0.0
	}
}

// Pace introduces micro-delays between packet bursts when congestion or DPI throttling is active.
func (p *AdaptivePacer) Pace() {
	p.mu.Lock()
	loss := p.currentLoss
	p.burstCounter++
	burstMax := p.maxBurst
	p.mu.Unlock()

	if loss <= 0.05 {
		// Clean network: yield every maxBurst packets
		if p.burstCounter >= burstMax {
			p.mu.Lock()
			p.burstCounter = 0
			p.mu.Unlock()
			time.Sleep(100 * time.Microsecond)
		}
		return
	}

	// Active congestion / DPI drop detected (> 5% loss):
	// Pace packets proportionally to loss rate (0.5ms - 5ms delay)
	if p.burstCounter >= 2 {
		p.mu.Lock()
		p.burstCounter = 0
		p.mu.Unlock()
		paceDelay := time.Duration(float64(time.Millisecond) * (1.0 + loss*8.0))
		if paceDelay > 6*time.Millisecond {
			paceDelay = 6 * time.Millisecond
		}
		time.Sleep(paceDelay)
	}
}

// KeepAliveMultiplier calculates a scaling factor (1.0 - 3.0) for keepalive intervals.
// Under high loss, keepalive frequency is relaxed to avoid provoking aggressive firewall drop thresholds.
func (p *AdaptivePacer) KeepAliveMultiplier() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch {
	case p.currentLoss > 0.30:
		return 3.0 // 3x slower keepalives
	case p.currentLoss > 0.15:
		return 2.0 // 2x slower keepalives
	case p.currentLoss > 0.05:
		return 1.4
	default:
		return 1.0
	}
}

// LossRate returns current observed loss rate (0.0 to 1.0).
func (p *AdaptivePacer) LossRate() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentLoss
}

// SmoothedRTT returns current EWMA RTT.
func (p *AdaptivePacer) SmoothedRTT() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.srtt
}
