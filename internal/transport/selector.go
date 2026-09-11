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
	RTT          time.Duration
	LossPercent  int
	ConsecDrops  int
	DirectUDP    bool
	DirectTCP    bool
	DirectWebRTC bool
	MeshRelay    bool
	Jitter       time.Duration
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

// SelectTransport evaluates metrics and returns the optimal transport identifier:
// "awg" (Tier 1), "quic" (Tier 1 lossy), "shadowtls" (Tier 2), "webrtc" (Tier 3), "mesh_relay" (Tier 4), "wss" (Tier 5).
func (s *TransportSelector) SelectTransport(peerID string, metrics LinkMetrics) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	current := s.currentByPeer[peerID]
	if current == "" {
		current = "awg"
	}

	target := "awg"

	// 5-Tier Connection Ladder:
	// Tier 1: Direct UDP (AWG when healthy, QUIC on moderate loss/jitter)
	// Tier 2: Direct TCP (ShadowTLS 3.1)
	// Tier 3: Direct WebRTC (Pion Data Channels)
	// Tier 4: P2P Multi-Hop Mesh Relay
	// Tier 5: Central Relay (WSS or MQTT)
	if metrics.DirectUDP && metrics.LossPercent < 50 && metrics.ConsecDrops < 5 {
		if metrics.LossPercent >= 10 || metrics.ConsecDrops >= 2 || metrics.Jitter > 50*time.Millisecond {
			target = "quic"
		} else {
			target = "awg"
		}
	} else if metrics.DirectTCP {
		target = "shadowtls"
	} else if metrics.DirectWebRTC {
		target = "webrtc"
	} else if metrics.MeshRelay {
		target = "mesh_relay"
	} else {
		target = "wss"
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
