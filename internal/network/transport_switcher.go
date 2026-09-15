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
)

// TransportMode represents the active data-plane transport escalation level.
type TransportMode string

const (
	// TransportModeUDP is standard multi-tier UDP traversal (Direct P2P, Port Prediction, Coordinated, AWG 3.1).
	TransportModeUDP TransportMode = "udp"

	// TransportModeIPv6 is strict UDP over IPv6-only (Level 1 escalation).
	// Used when IPv4 UDP is blocked by TSPU/middlebox but global IPv6 is functional.
	TransportModeIPv6 TransportMode = "ipv6_only"

	// TransportModeTCPRelay is TCP/WSS Peer-as-Relay over port 443 (Level 3 escalation).
	// Used when all UDP is blocked, but TCP 443 is open and relay-capable peers are available.
	TransportModeTCPRelay TransportMode = "tcp_relay"

	// TransportModeMQTT is L3 encapsulation over MQTT signaling brokers (Level 2 escalation / DECISIONS.md #5).
	// Used as universal emergency fallback when UDP is blocked and direct TCP peer relay is unavailable.
	TransportModeMQTT TransportMode = "mqtt_relay"
)

// NetcheckResult captures the essential findings of an RFC 5780 / DPI network assessment.
type NetcheckResult struct {
	UDPBlockedIPv4 bool   `json:"udp_blocked_ipv4"`
	UDPBlockedIPv6 bool   `json:"udp_blocked_ipv6"`
	IPv6Available  bool   `json:"ipv6_available"`
	TCP443OK       bool   `json:"tcp_443_ok"`
	TSPUDetected   bool   `json:"tspu_detected"`
	NATType        string `json:"nat_type"`
	PublicIPv4     string `json:"public_ipv4,omitempty"`
	PublicIPv6     string `json:"public_ipv6,omitempty"`
}

// TransportSwitcher evaluates network reachability and switches global transport mode automatically.
type TransportSwitcher struct {
	mu                 sync.RWMutex
	currentMode        TransportMode
	lastResult         NetcheckResult
	forceIPv6Only      atomic.Bool
	disableUDPProbes   atomic.Bool
	enableMQTTFallback atomic.Bool
	onModeChange       func(oldMode, newMode TransportMode)
}

// NewTransportSwitcher creates a default TransportSwitcher initialized in standard UDP mode.
func NewTransportSwitcher() *TransportSwitcher {
	return &TransportSwitcher{
		currentMode: TransportModeUDP,
	}
}

// SetOnModeChange registers a callback invoked whenever the transport mode changes.
func (s *TransportSwitcher) SetOnModeChange(fn func(oldMode, newMode TransportMode)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onModeChange = fn
}

// CurrentMode returns the active transport mode.
func (s *TransportSwitcher) CurrentMode() TransportMode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentMode
}

// LastResult returns the most recent NetcheckResult evaluated by the switcher.
func (s *TransportSwitcher) LastResult() NetcheckResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastResult
}

// IsForceIPv6Only returns true if IPv4 UDP is bypassed in favor of direct IPv6.
func (s *TransportSwitcher) IsForceIPv6Only() bool {
	return s.forceIPv6Only.Load()
}

// IsDisableUDPProbes returns true if UDP hole punching and probes are shut off to save battery/bandwidth.
func (s *TransportSwitcher) IsDisableUDPProbes() bool {
	return s.disableUDPProbes.Load()
}

// IsEnableMQTTFallback returns true if L3 data-plane should be routed over MQTT.
func (s *TransportSwitcher) IsEnableMQTTFallback() bool {
	return s.enableMQTTFallback.Load()
}

// ForceIPv6Only manually enforces Level 1 IPv6-only transport.
func (s *TransportSwitcher) ForceIPv6Only() {
	s.forceIPv6Only.Store(true)
	s.disableUDPProbes.Store(false)
	s.enableMQTTFallback.Store(false)
	s.setMode(TransportModeIPv6)
}

// DisableUDPProbes manually shuts down UDP hole punching probes.
func (s *TransportSwitcher) DisableUDPProbes() {
	s.disableUDPProbes.Store(true)
}

// EnableMQTTFallback manually enforces Level 2 MQTT L3 tunneling.
func (s *TransportSwitcher) EnableMQTTFallback() {
	s.enableMQTTFallback.Store(true)
	s.disableUDPProbes.Store(true)
	s.setMode(TransportModeMQTT)
}

// ResetToUDP resets the transport switcher back to standard dual-stack UDP mode.
func (s *TransportSwitcher) ResetToUDP() {
	s.forceIPv6Only.Store(false)
	s.disableUDPProbes.Store(false)
	s.enableMQTTFallback.Store(false)
	s.setMode(TransportModeUDP)
}

// Evaluate evaluates a NetcheckResult and transitions to the optimal escalation mode.
// Escalation Ladder:
// 1. Level 0: If UDP on IPv4 is NOT blocked -> TransportModeUDP (standard AWG/P2P).
// 2. Level 1: If UDP on IPv4 is blocked, but IPv6 is available & not blocked -> TransportModeIPv6.
// 3. Level 3: If all UDP is blocked, but TCP 443 is accessible -> TransportModeTCPRelay.
// 4. Level 2: If UDP is blocked and direct TCP relay unavailable -> TransportModeMQTT (universal fallback).
func (s *TransportSwitcher) Evaluate(res NetcheckResult) TransportMode {
	s.mu.Lock()
	s.lastResult = res
	s.mu.Unlock()

	var targetMode TransportMode

	if !res.UDPBlockedIPv4 && !res.TSPUDetected {
		// Level 0: Standard UDP path
		s.forceIPv6Only.Store(false)
		s.disableUDPProbes.Store(false)
		s.enableMQTTFallback.Store(false)
		targetMode = TransportModeUDP
	} else if res.IPv6Available && !res.UDPBlockedIPv6 {
		// Level 1: Dual-stack IPv6 bypass
		s.forceIPv6Only.Store(true)
		s.disableUDPProbes.Store(false)
		s.enableMQTTFallback.Store(false)
		targetMode = TransportModeIPv6
	} else if res.TCP443OK {
		// Level 3: TCP/WSS Peer-as-Relay on 443
		s.forceIPv6Only.Store(false)
		s.disableUDPProbes.Store(true)
		s.enableMQTTFallback.Store(false)
		targetMode = TransportModeTCPRelay
	} else {
		// Level 2: Universal MQTT L3 fallback
		s.forceIPv6Only.Store(false)
		s.disableUDPProbes.Store(true)
		s.enableMQTTFallback.Store(true)
		targetMode = TransportModeMQTT
	}

	s.setMode(targetMode)
	return targetMode
}

func (s *TransportSwitcher) setMode(newMode TransportMode) {
	s.mu.Lock()
	oldMode := s.currentMode
	if oldMode == newMode {
		s.mu.Unlock()
		return
	}
	s.currentMode = newMode
	cb := s.onModeChange
	s.mu.Unlock()

	if cb != nil {
		cb(oldMode, newMode)
	}
}
