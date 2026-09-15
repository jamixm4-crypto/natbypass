// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"sync"
	"testing"
)

func TestTransportSwitcher_Evaluate_StandardUDP(t *testing.T) {
	switcher := NewTransportSwitcher()
	res := NetcheckResult{
		UDPBlockedIPv4: false,
		UDPBlockedIPv6: false,
		IPv6Available:  true,
		TCP443OK:       true,
		TSPUDetected:   false,
		NATType:        "full_cone",
	}

	mode := switcher.Evaluate(res)
	if mode != TransportModeUDP {
		t.Fatalf("Expected TransportModeUDP, got %s", mode)
	}
	if switcher.IsForceIPv6Only() {
		t.Errorf("Expected IsForceIPv6Only=false")
	}
	if switcher.IsDisableUDPProbes() {
		t.Errorf("Expected IsDisableUDPProbes=false")
	}
	if switcher.IsEnableMQTTFallback() {
		t.Errorf("Expected IsEnableMQTTFallback=false")
	}
}

func TestTransportSwitcher_Evaluate_Level1_IPv6Only(t *testing.T) {
	switcher := NewTransportSwitcher()
	// Real scenario: Mobile carrier drops IPv4 UDP with TSPU, but IPv6 is functional
	res := NetcheckResult{
		UDPBlockedIPv4: true,
		UDPBlockedIPv6: false,
		IPv6Available:  true,
		TCP443OK:       true,
		TSPUDetected:   true,
		NATType:        "Drop All UDP",
	}

	mode := switcher.Evaluate(res)
	if mode != TransportModeIPv6 {
		t.Fatalf("Expected TransportModeIPv6, got %s", mode)
	}
	if !switcher.IsForceIPv6Only() {
		t.Errorf("Expected IsForceIPv6Only=true")
	}
	if switcher.IsDisableUDPProbes() {
		t.Errorf("Expected IsDisableUDPProbes=false (IPv6 probes must remain enabled)")
	}
	if switcher.IsEnableMQTTFallback() {
		t.Errorf("Expected IsEnableMQTTFallback=false")
	}
}

func TestTransportSwitcher_Evaluate_Level3_TCPRelay(t *testing.T) {
	switcher := NewTransportSwitcher()
	// Real scenario: IPv4 UDP dropped, no global IPv6 (IPv4-only SIM), but TCP 443 open
	res := NetcheckResult{
		UDPBlockedIPv4: true,
		UDPBlockedIPv6: true,
		IPv6Available:  false,
		TCP443OK:       true,
		TSPUDetected:   true,
		NATType:        "Drop All UDP",
	}

	mode := switcher.Evaluate(res)
	if mode != TransportModeTCPRelay {
		t.Fatalf("Expected TransportModeTCPRelay, got %s", mode)
	}
	if switcher.IsForceIPv6Only() {
		t.Errorf("Expected IsForceIPv6Only=false")
	}
	if !switcher.IsDisableUDPProbes() {
		t.Errorf("Expected IsDisableUDPProbes=true (UDP probes must be shut off to save battery)")
	}
	if switcher.IsEnableMQTTFallback() {
		t.Errorf("Expected IsEnableMQTTFallback=false")
	}
}

func TestTransportSwitcher_Evaluate_Level2_MQTTFallback(t *testing.T) {
	switcher := NewTransportSwitcher()
	// Worst case: UDP completely blocked, TCP 443 blocked / unavailable
	res := NetcheckResult{
		UDPBlockedIPv4: true,
		UDPBlockedIPv6: true,
		IPv6Available:  false,
		TCP443OK:       false,
		TSPUDetected:   true,
		NATType:        "Drop All UDP",
	}

	mode := switcher.Evaluate(res)
	if mode != TransportModeMQTT {
		t.Fatalf("Expected TransportModeMQTT, got %s", mode)
	}
	if !switcher.IsDisableUDPProbes() {
		t.Errorf("Expected IsDisableUDPProbes=true")
	}
	if !switcher.IsEnableMQTTFallback() {
		t.Errorf("Expected IsEnableMQTTFallback=true")
	}
}

func TestTransportSwitcher_ManualOverrides(t *testing.T) {
	switcher := NewTransportSwitcher()

	switcher.ForceIPv6Only()
	if switcher.CurrentMode() != TransportModeIPv6 || !switcher.IsForceIPv6Only() {
		t.Errorf("ForceIPv6Only failed")
	}

	switcher.EnableMQTTFallback()
	if switcher.CurrentMode() != TransportModeMQTT || !switcher.IsEnableMQTTFallback() || !switcher.IsDisableUDPProbes() {
		t.Errorf("EnableMQTTFallback failed")
	}

	switcher.ResetToUDP()
	if switcher.CurrentMode() != TransportModeUDP || switcher.IsForceIPv6Only() || switcher.IsDisableUDPProbes() || switcher.IsEnableMQTTFallback() {
		t.Errorf("ResetToUDP failed")
	}
}

func TestTransportSwitcher_OnModeChange(t *testing.T) {
	switcher := NewTransportSwitcher()

	var mu sync.Mutex
	var transitions [][2]TransportMode

	switcher.SetOnModeChange(func(oldMode, newMode TransportMode) {
		mu.Lock()
		transitions = append(transitions, [2]TransportMode{oldMode, newMode})
		mu.Unlock()
	})

	switcher.Evaluate(NetcheckResult{
		UDPBlockedIPv4: true,
		IPv6Available:  true,
		TSPUDetected:   true,
	})

	switcher.Evaluate(NetcheckResult{
		UDPBlockedIPv4: true,
		IPv6Available:  false,
		TCP443OK:       true,
		TSPUDetected:   true,
	})

	mu.Lock()
	defer mu.Unlock()
	if len(transitions) != 2 {
		t.Fatalf("Expected 2 transitions, got %d", len(transitions))
	}
	if transitions[0][0] != TransportModeUDP || transitions[0][1] != TransportModeIPv6 {
		t.Errorf("Transition 1 mismatch: %v", transitions[0])
	}
	if transitions[1][0] != TransportModeIPv6 || transitions[1][1] != TransportModeTCPRelay {
		t.Errorf("Transition 2 mismatch: %v", transitions[1])
	}
}
