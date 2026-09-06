// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// AmneziaWG protocol parameters and obfuscation mechanisms (H1..H4, S1..S4, Jc, Jmin, Jmax)
// are developed by the AmneziaWG team (https://github.com/amnezia-vpn/amneziawg-go).
// Original WireGuard protocol created by Jason A. Donenfeld (https://www.wireguard.com).

package main

import (
	"context"
	"fmt"
)

// AWGHandshakeResult — результат попытки AWG handshake
type AWGHandshakeResult struct {
	Success    bool
	Attempts   int
	TimeMs     int64
	Error      string
	Skipped    bool   // true если тест пропущен (нет прав/инструментов)
	SkipReason string
}

// AWGPingResult — результат ICMP ping через AWG туннель
type AWGPingResult struct {
	Sent     int
	Received int
	LossPct  float64
	MinMs    int64
	AvgMs    int64
	MaxMs    int64
	Error    string
}

// DPIProbeResult — результат DPI fingerprint probe
type DPIProbeResult struct {
	PlainWGSuccess   bool   // plain WireGuard (без AWG) прошёл
	AWGSuccess       bool   // AWG с текущими H прошёл
	AWGRandomSuccess bool   // AWG с random H прошёл
	BlockedByDPI     bool
	Notes            string
}

// RelayTestResult — результат relay теста
type RelayTestResult struct {
	Success bool
	ViaNode string
	AvgMs   int64
	LossPct float64
	Error   string
}

// TestAWGHandshake пытается установить AWG handshake с пиром.
// Требует административных привилегий и наличия wg/wintun.
// На системах без поддержки возвращает Skipped=true.
func TestAWGHandshake(ctx context.Context, cfg *ProbeConfig, myNodeID string, myKP *WGKeyPair, peer *PeerInfo) *AWGHandshakeResult {
	result := &AWGHandshakeResult{}
	logf("[AWG-HS] %s → %s: testing AWG handshake", myNodeID, peer.NodeID)

	// Check if we have the peer's public key
	if peer.PubKey == "" {
		result.Skipped = true
		result.SkipReason = "peer public key not available"
		logf("[AWG-HS] Skipped: no peer public key")
		return result
	}

	// Perform raw WireGuard Initiation packet detection
	success, ms, err := testWireGuardHandshakeRaw(ctx, cfg, myNodeID, myKP, peer, false)
	result.Attempts = 3
	result.TimeMs = ms
	if err != nil {
		result.Error = err.Error()
		result.Success = false
	} else {
		result.Success = success
	}

	if result.Success {
		logf("[AWG-HS] %s → %s: SUCCESS (%dms)", myNodeID, peer.NodeID, ms)
	} else {
		logf("[AWG-HS] %s → %s: FAIL - %s", myNodeID, peer.NodeID, result.Error)
	}
	return result
}

// TestAWGPing — ping через AWG туннель (только если handshake успешен)
func TestAWGPing(ctx context.Context, peer *PeerInfo, count int) *AWGPingResult {
	result := &AWGPingResult{Sent: count}
	// TODO: реализовать через userspace WG или wgctrl
	result.LossPct = 100
	result.Error = "AWG ping not yet implemented (requires userspace WG)"
	return result
}

// TestDPIProbe проверяет, блокируется ли WireGuard/AWG DPI-системами
func TestDPIProbe(ctx context.Context, cfg *ProbeConfig, myNodeID string, myKP *WGKeyPair, peer *PeerInfo) *DPIProbeResult {
	result := &DPIProbeResult{}
	logf("[DPI] %s → %s: DPI fingerprint probe", myNodeID, peer.NodeID)

	// Test 1: plain WireGuard (Jc=0)
	plainSuccess, _, _ := testWireGuardHandshakeRaw(ctx, cfg, myNodeID, myKP, peer, true)
	result.PlainWGSuccess = plainSuccess
	if plainSuccess {
		logf("[DPI] Plain WireGuard: OK")
	} else {
		logf("[DPI] Plain WireGuard: FAIL")
	}

	// Test 2: AWG with current H params
	awgSuccess, _, _ := testWireGuardHandshakeRaw(ctx, cfg, myNodeID, myKP, peer, false)
	result.AWGSuccess = awgSuccess
	if awgSuccess {
		logf("[DPI] AWG (current H): OK")
	} else {
		logf("[DPI] AWG (current H): FAIL")
	}

	// Determine if DPI-blocked
	if !plainSuccess && !awgSuccess {
		result.BlockedByDPI = true
		result.Notes = "WireGuard полностью заблокирован. UDP проходит, но WG/AWG handshake нет → ТСПУ/DPI"
	} else if !awgSuccess && plainSuccess {
		result.Notes = "AWG блокируется, но plain WG проходит — возможно DPI fingerprint по AWG-специфичным полям"
	}

	return result
}

// TestRelayPath проверяет relay-путь через третий узел
func TestRelayPath(ctx context.Context, myNodeID string, target *PeerInfo, relayPeers []*PeerInfo) *RelayTestResult {
	result := &RelayTestResult{}
	logf("[RELAY] Testing relay paths for %s → %s", myNodeID, target.NodeID)
	// TODO: полный relay тест через signaling
	result.Error = "relay test not yet implemented"
	return result
}

// testWireGuardHandshakeRaw посылает raw WG Initiation пакет и ждёт Response.
// plainMode=true — без AWG обфускации (стандартный WG).
// Текущая реализация — stub для MVP.
func testWireGuardHandshakeRaw(ctx context.Context, cfg *ProbeConfig, myNodeID string, myKP *WGKeyPair, peer *PeerInfo, plainMode bool) (bool, int64, error) {
	// This is a complex implementation requiring full WireGuard crypto.
	// MVP stub: return not-implemented
	_ = plainMode
	_ = cfg
	_ = myNodeID
	_ = myKP
	_ = peer
	return false, 0, fmt.Errorf("raw WG handshake test not yet implemented (requires userspace WG)")
}
