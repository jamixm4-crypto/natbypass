// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package transport

import (
	"testing"
	"time"
)

func TestTransportSelector_HealthyLinkPrefersAWG(t *testing.T) {
	sel := NewTransportSelector(100 * time.Millisecond)
	m := LinkMetrics{
		RTT:         30 * time.Millisecond,
		LossPercent: 0,
		ConsecDrops: 0,
		DirectUDP:   true,
		DirectTCP:   true,
		Jitter:      2 * time.Millisecond,
	}

	chosen := sel.SelectTransport("peer-1", m)
	if chosen != "awg" {
		t.Fatalf("Expected 'awg' on healthy link, got %s", chosen)
	}
}

func TestTransportSelector_ModerateLossSwitchesToQUIC(t *testing.T) {
	sel := NewTransportSelector(100 * time.Millisecond)
	mHealthy := LinkMetrics{DirectUDP: true, LossPercent: 0}
	sel.SelectTransport("peer-1", mHealthy)

	// Simulate sudden loss
	mLossy := LinkMetrics{
		DirectUDP:   true,
		LossPercent: 15,
		ConsecDrops: 3, // hard trigger to bypass hysteresis
	}

	chosen := sel.SelectTransport("peer-1", mLossy)
	if chosen != "quic" {
		t.Fatalf("Expected switch to 'quic' on 15%% loss, got %s", chosen)
	}
}

func TestTransportSelector_UDPBlockedSwitchesToShadowTLS(t *testing.T) {
	sel := NewTransportSelector(100 * time.Millisecond)
	mBlocked := LinkMetrics{
		DirectUDP:   false,
		DirectTCP:   true,
		LossPercent: 100,
		ConsecDrops: 5,
	}

	chosen := sel.SelectTransport("peer-1", mBlocked)
	if chosen != "shadowtls" {
		t.Fatalf("Expected 'shadowtls' when UDP is blocked but TCP is direct, got %s", chosen)
	}
}

func TestTransportSelector_AllDirectBlockedSwitchesToWSS(t *testing.T) {
	sel := NewTransportSelector(100 * time.Millisecond)
	mRelay := LinkMetrics{
		DirectUDP:   false,
		DirectTCP:   false,
		LossPercent: 100,
		ConsecDrops: 5,
	}

	chosen := sel.SelectTransport("peer-1", mRelay)
	if chosen != "wss" {
		t.Fatalf("Expected 'wss' when all direct paths blocked, got %s", chosen)
	}
}

func TestTransportSelector_HysteresisPreventsFlapping(t *testing.T) {
	sel := NewTransportSelector(5 * time.Second) // 5s hysteresis
	mHealthy := LinkMetrics{DirectUDP: true, LossPercent: 0}
	sel.SelectTransport("peer-1", mHealthy)

	// Mild loss (12%), ConsecDrops=1 (soft trigger)
	mMildLoss := LinkMetrics{DirectUDP: true, LossPercent: 12, ConsecDrops: 1}
	// Initial switch allowed
	chosen1 := sel.SelectTransport("peer-1", mMildLoss)
	if chosen1 != "quic" {
		t.Fatalf("Expected initial switch to 'quic', got %s", chosen1)
	}

	// Immediately link recovers to 0% loss, but hysteresis hold should prevent instant flip-flop back
	chosen2 := sel.SelectTransport("peer-1", mHealthy)
	if chosen2 != "quic" {
		t.Fatalf("Expected hysteresis to hold 'quic', got %s", chosen2)
	}
}

func TestTransportSelector_WebRTCFallback(t *testing.T) {
	sel := NewTransportSelector(100 * time.Millisecond)
	mWebRTC := LinkMetrics{
		DirectUDP:    false,
		DirectTCP:    false,
		DirectWebRTC: true,
		LossPercent:  100,
		ConsecDrops:  5,
	}

	chosen := sel.SelectTransport("peer-rtc", mWebRTC)
	if chosen != "webrtc" {
		t.Fatalf("Expected 'webrtc' when UDP and TCP are down but WebRTC connected, got %s", chosen)
	}
}

func TestTransportSelector_MeshRelayFallback(t *testing.T) {
	sel := NewTransportSelector(100 * time.Millisecond)
	mMesh := LinkMetrics{
		DirectUDP:    false,
		DirectTCP:    false,
		DirectWebRTC: false,
		MeshRelay:    true,
		LossPercent:  100,
		ConsecDrops:  5,
	}

	chosen := sel.SelectTransport("peer-mesh", mMesh)
	if chosen != "mesh_relay" {
		t.Fatalf("Expected 'mesh_relay' when direct routes down but mesh relay exists, got %s", chosen)
	}
}

