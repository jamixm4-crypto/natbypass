// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// PairResult — результат теста одной пары узлов
type PairResult struct {
	From         string
	To           string
	UDPPunch     *UDPPunchResult
	AWGHandshake *AWGHandshakeResult
	AWGPing      *AWGPingResult
	TCPTests     []TCPTestResult
	DPIProbe     *DPIProbeResult
	RelayTest    *RelayTestResult
	Verdict      string
	Notes        string
}

// ProbeReport — полный отчёт
type ProbeReport struct {
	ProbeID     string                 `json:"probe_id"`
	Timestamp   time.Time              `json:"timestamp"`
	DurationSec int                    `json:"duration_sec"`
	MyNodeID    string                 `json:"my_node_id"`
	SelfTest    *SelfTestResult        `json:"self_test"`
	Nodes       []*PeerInfo            `json:"nodes"`
	Pairs       map[string]*PairResult `json:"pairs"`
}

// DetermineVerdict анализирует результаты пары и выдаёт вердикт
func DetermineVerdict(r *PairResult) (verdict, notes string) {
	if r.AWGHandshake != nil && r.AWGHandshake.Success {
		if r.AWGPing != nil && r.AWGPing.LossPct < 50 {
			verdict = "p2p_ok"
			notes = fmt.Sprintf("AWG P2P работает: ping avg=%dms loss=%.0f%%", r.AWGPing.AvgMs, r.AWGPing.LossPct)
		} else {
			verdict = "p2p_handshake_ok_ping_unstable"
			notes = "AWG handshake успешен, но пинг нестабилен (высокий loss)"
		}
		return
	}

	if r.UDPPunch != nil && r.UDPPunch.Success && r.AWGHandshake != nil && !r.AWGHandshake.Success {
		if r.DPIProbe != nil {
			if !r.DPIProbe.PlainWGSuccess && !r.DPIProbe.AWGSuccess {
				verdict = "udp_ok_wg_blocked"
				notes = "UDP проходит, но WireGuard handshake блокируется. Вероятно ТСПУ/DPI фильтрует WG-паттерн"
			} else if r.DPIProbe.AWGRandomSuccess {
				verdict = "awg_fingerprint_blocked"
				notes = "Текущие H1-H4 блокируются DPI, random H работают — нужно сменить параметры"
			} else {
				verdict = "awg_handshake_fail"
				notes = "UDP punch OK, но AWG handshake не проходит"
			}
		} else {
			verdict = "awg_handshake_fail"
			notes = "UDP punch OK, но AWG handshake не проходит"
		}
		return
	}

	if r.UDPPunch != nil && !r.UDPPunch.Success {
		verdict = "udp_blocked"
		notes = "Raw UDP заблокирован. Проверьте файрвол или провайдера"
		return
	}

	if r.RelayTest != nil && r.RelayTest.Success {
		verdict = "relay_only"
		notes = fmt.Sprintf("Только relay через %s: %dms avg", r.RelayTest.ViaNode, r.RelayTest.AvgMs)
		return
	}

	verdict = "unknown"
	notes = "Недостаточно данных для определения причины"
	return
}

// PrintReport выводит отчёт в консоль
func PrintReport(report *ProbeReport) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf(" NatBypass Probe — Report: %s\n", report.ProbeID)
	fmt.Printf(" Node: %s | Duration: %ds | Peers: %d\n",
		report.MyNodeID, report.DurationSec, len(report.Nodes))
	fmt.Println(strings.Repeat("=", 70))

	// Self-test
	if st := report.SelfTest; st != nil {
		fmt.Printf("\n[SELF] %s | STUN: %s | NAT: %s",
			st.Hostname, st.STUNAddr, strings.ToUpper(st.NATType))
		if st.NATDelta > 0 {
			fmt.Printf(" (delta=%d)", st.NATDelta)
		}
		fmt.Println()
	}

	// Peers
	if len(report.Nodes) > 0 {
		fmt.Println("\nDISCOVERED NODES:")
		for _, p := range report.Nodes {
			fmt.Printf("  %-12s %-20s %-25s %-15s %s\n",
				p.NodeID, p.Label, p.STUNAddr, p.NATType, p.VIP)
		}
	}

	// Pairs
	if len(report.Pairs) > 0 {
		fmt.Println("\nTEST RESULTS:")
		for key, pair := range report.Pairs {
			verdict, notes := DetermineVerdict(pair)
			pair.Verdict = verdict
			pair.Notes = notes

			icon := "[FAIL]"
			if strings.HasPrefix(verdict, "p2p_ok") {
				icon = "[ OK ]"
			} else if strings.HasPrefix(verdict, "relay") {
				icon = "[RLAY]"
			}

			fmt.Printf("  %s %s:\n         %s\n", icon, key, notes)
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("-", 70))
}

// SaveJSONReport сохраняет отчёт в JSON-файл
func SaveJSONReport(report *ProbeReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
