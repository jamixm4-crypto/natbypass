// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package transport

import (
	"sync"
	"time"
)

// LinkMetrics contains real-time latency, drop, and connection state metrics for a peer.
type LinkMetrics struct {
	RTT         time.Duration
	LossPercent int
	ConsecDrops int
	DirectUDP   bool
	DirectTCP   bool
	Jitter      time.Duration
}

// TransportSelector dynamically selects the best transport for each peer based on link quality.
// It incorporates a hysteresis hold-down timer to avoid flapping between transports.
type TransportSelector struct {
	mu             sync.RWMutex
	currentByPeer  map[string]string
	switchedAt     map[string]time.Time
	hysteresisHold time.Duration
}

// NewTransportSelector initializes a dynamic transport selector with a given flapping hold-down duration.
func NewTransportSelector(holdDuration time.Duration) *TransportSelector {
	if holdDuration <= 0 {
		holdDuration = 15 * time.Second
	}
	return &TransportSelector{
		currentByPeer:  make(map[string]string),
		switchedAt:     make(map[string]time.Time),
		hysteresisHold: holdDuration,
	}
}

// SelectTransport evaluates metrics and returns the optimal transport identifier ("awg", "quic", "shadowtls", "wss").
func (s *TransportSelector) SelectTransport(peerID string, metrics LinkMetrics) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	current := s.currentByPeer[peerID]
	if current == "" {
		current = "awg"
	}

	target := "awg"

	// 1. Catastrophic degradation or UDP block:
	if metrics.LossPercent >= 50 || metrics.ConsecDrops >= 5 || (!metrics.DirectUDP && !metrics.DirectTCP) {
		if metrics.DirectTCP {
			target = "shadowtls"
		} else {
			target = "wss"
		}
	} else if metrics.LossPercent >= 10 || metrics.ConsecDrops >= 2 || metrics.Jitter > 50*time.Millisecond {
		// 2. Moderate packet loss or high jitter: QUIC provides loss recovery and anti-DPI HTTP/3 framing
		if metrics.DirectUDP {
			target = "quic"
		} else if metrics.DirectTCP {
			target = "shadowtls"
		} else {
			target = "wss"
		}
	} else {
		// 3. Healthy link: AWG provides lowest CPU and memory overhead
		if metrics.DirectUDP {
			target = "awg"
		} else if metrics.DirectTCP {
			target = "shadowtls"
		} else {
			target = "wss"
		}
	}

	// Immediate switch if link is hard down (drops >= 3)
	if target != current && metrics.ConsecDrops >= 3 {
		s.currentByPeer[peerID] = target
		s.switchedAt[peerID] = now
		return target
	}

	// Otherwise, apply hysteresis to prevent rapid flapping
	if target != current {
		lastSwitch := s.switchedAt[peerID]
		if !lastSwitch.IsZero() && now.Sub(lastSwitch) < s.hysteresisHold {
			return current // hold current transport
		}
		s.currentByPeer[peerID] = target
		s.switchedAt[peerID] = now
		return target
	}

	return current
}

// GetCurrent returns the currently active transport for peerID.
func (s *TransportSelector) GetCurrent(peerID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	curr, ok := s.currentByPeer[peerID]
	if !ok || curr == "" {
		return "awg"
	}
	return curr
}
