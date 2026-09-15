// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// CarrierASNRule defines port allocation behavior and prediction viability for a given operator ASN.
type CarrierASNRule struct {
	Carrier          string `json:"carrier"`
	PortAllocation   string `json:"port_allocation"` // "sequential" | "fixed_step" | "small_jitter" | "pba" | "random"
	DefaultDelta     int    `json:"default_delta"`
	SweepRadius      int    `json:"sweep_radius"`
	PredictionViable bool   `json:"prediction_viable"`
}

var (
	dynamicRulesMu sync.RWMutex
	dynamicRules   = make(map[string]CarrierASNRule)
	saveFileMu     sync.Mutex
)

// knownCarrierASNs contains empirical NAT traversal characteristics for major Russian, CIS, and European cellular operators.
var knownCarrierASNs = map[string]CarrierASNRule{
	// MegaFon / Yota (AS31133, AS25159, AS25513)
	"AS31133": {Carrier: "MegaFon/Yota", PortAllocation: "sequential", DefaultDelta: 1, SweepRadius: 5, PredictionViable: true},
	"AS25159": {Carrier: "MegaFon", PortAllocation: "sequential", DefaultDelta: 2, SweepRadius: 6, PredictionViable: true},
	"AS25513": {Carrier: "MegaFon-Corp", PortAllocation: "sequential", DefaultDelta: 2, SweepRadius: 6, PredictionViable: true},

	// MTS (AS8359)
	"AS8359": {Carrier: "MTS", PortAllocation: "fixed_step", DefaultDelta: 2, SweepRadius: 8, PredictionViable: true},

	// Beeline / VimpelCom (AS16345, AS3216, AS8402)
	"AS16345": {Carrier: "Beeline", PortAllocation: "pba", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},
	"AS3216":  {Carrier: "Beeline", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 12, PredictionViable: true},
	"AS8402":  {Carrier: "Beeline-Corbina", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},

	// Tele2 / Rostelecom / T2 (AS42610, AS12389, AS41668)
	"AS42610": {Carrier: "Tele2/T2", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},
	"AS12389": {Carrier: "Rostelecom", PortAllocation: "fixed_step", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},
	"AS41668": {Carrier: "Tele2-Macro", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},

	// Regional CIS & RU Carriers
	"AS39949": {Carrier: "Motiv-Telecom", PortAllocation: "sequential", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},
	"AS25490": {Carrier: "Tattelecom/Letai", PortAllocation: "fixed_step", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},
	"AS15895": {Carrier: "Kyivstar", PortAllocation: "fixed_step", DefaultDelta: 2, SweepRadius: 8, PredictionViable: true},
	"AS21497": {Carrier: "Vodafone-UA", PortAllocation: "sequential", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},
	"AS34356": {Carrier: "lifecell", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},
	"AS28760": {Carrier: "A1-Belarus", PortAllocation: "sequential", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},
	"AS25106": {Carrier: "MTS-Belarus", PortAllocation: "fixed_step", DefaultDelta: 2, SweepRadius: 8, PredictionViable: true},
	"AS34244": {Carrier: "Beeline-KZ", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},
	"AS48716": {Carrier: "Kcell-KZ", PortAllocation: "fixed_step", DefaultDelta: 2, SweepRadius: 8, PredictionViable: true},
	"AS43765": {Carrier: "Tele2-KZ", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},
	"AS28910": {Carrier: "Ucell-UZ", PortAllocation: "sequential", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},
	"AS8193":  {Carrier: "Uztelecom", PortAllocation: "fixed_step", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},

	// European Carriers
	"AS3215":  {Carrier: "Orange", PortAllocation: "sequential", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},
	"AS3209":  {Carrier: "Vodafone-DE", PortAllocation: "fixed_step", DefaultDelta: 2, SweepRadius: 8, PredictionViable: true},
	"AS3320":  {Carrier: "Deutsche-Telekom", PortAllocation: "fixed_step", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},
	"AS12322": {Carrier: "Free-Mobile", PortAllocation: "pba", DefaultDelta: 1, SweepRadius: 12, PredictionViable: true},

	// T-Mobile (AS21928, AS12271) - Known RFC 4787 Random CGNAT
	"AS21928": {Carrier: "T-Mobile", PortAllocation: "random", DefaultDelta: 0, SweepRadius: 0, PredictionViable: false},
	"AS12271": {Carrier: "T-Mobile", PortAllocation: "random", DefaultDelta: 0, SweepRadius: 0, PredictionViable: false},
}

// LookupCarrierASN returns the CGNAT rule for a given ASN (e.g. "AS31133" or "31133").
// Dynamic learned rules have higher precedence over hardcoded static rules.
func LookupCarrierASN(asn string) (CarrierASNRule, bool) {
	clean := strings.ToUpper(strings.TrimSpace(asn))
	if clean == "" || clean == "UNKNOWN" {
		return CarrierASNRule{}, false
	}
	if !strings.HasPrefix(clean, "AS") {
		clean = "AS" + clean
	}

	dynamicRulesMu.RLock()
	dynRule, dynOk := dynamicRules[clean]
	dynamicRulesMu.RUnlock()
	if dynOk {
		return dynRule, true
	}

	rule, ok := knownCarrierASNs[clean]
	return rule, ok
}

// UpdateCarrierASN updates or registers a dynamic CGNAT rule in memory.
func UpdateCarrierASN(asn string, rule CarrierASNRule) {
	clean := strings.ToUpper(strings.TrimSpace(asn))
	if clean == "" || clean == "UNKNOWN" {
		return
	}
	if !strings.HasPrefix(clean, "AS") {
		clean = "AS" + clean
	}

	dynamicRulesMu.Lock()
	dynamicRules[clean] = rule
	dynamicRulesMu.Unlock()
}

// RecordPeerObservation learns from a peer beacon or probe report (ASN + NATDelta).
// If the ASN is valid and delta > 0, it dynamically creates or refines a rule in the cache.
// If cacheFilePath is non-empty, the updated cache is saved to disk asynchronously.
func RecordPeerObservation(asn string, delta int, cacheFilePath string) bool {
	if delta <= 0 || delta > 32 {
		return false
	}
	clean := strings.ToUpper(strings.TrimSpace(asn))
	if clean == "" || clean == "UNKNOWN" {
		return false
	}
	if !strings.HasPrefix(clean, "AS") {
		clean = "AS" + clean
	}

	existing, found := LookupCarrierASN(clean)
	if found && !existing.PredictionViable {
		// Do not override an explicitly non-viable random CGNAT
		return false
	}

	alloc := "fixed_step"
	if delta == 1 {
		alloc = "sequential"
	}
	radius := delta * 4
	if radius < 6 {
		radius = 6
	} else if radius > 16 {
		radius = 16
	}

	carrierName := "Learned (" + clean + ")"
	if found && existing.Carrier != "" && !strings.HasPrefix(existing.Carrier, "Learned") {
		carrierName = existing.Carrier
	}

	newRule := CarrierASNRule{
		Carrier:          carrierName,
		PortAllocation:   alloc,
		DefaultDelta:     delta,
		SweepRadius:      radius,
		PredictionViable: true,
	}

	dynamicRulesMu.Lock()
	changed := true
	if cur, ok := dynamicRules[clean]; ok {
		if cur.DefaultDelta == delta && cur.SweepRadius == radius {
			changed = false
		}
	}
	if changed {
		dynamicRules[clean] = newRule
	}
	dynamicRulesMu.Unlock()

	if changed && cacheFilePath != "" {
		go func() {
			_ = SaveASNRulesCache(cacheFilePath)
		}()
	}
	return changed
}

// LoadASNRulesCache loads persisted dynamic ASN rules from a JSON file.
func LoadASNRulesCache(filePath string) error {
	if filePath == "" {
		return nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var loaded map[string]CarrierASNRule
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}

	dynamicRulesMu.Lock()
	defer dynamicRulesMu.Unlock()
	for k, v := range loaded {
		clean := strings.ToUpper(strings.TrimSpace(k))
		if !strings.HasPrefix(clean, "AS") {
			clean = "AS" + clean
		}
		dynamicRules[clean] = v
	}
	return nil
}

// SaveASNRulesCache saves all dynamic ASN rules to a JSON file atomically.
func SaveASNRulesCache(filePath string) error {
	if filePath == "" {
		return nil
	}
	saveFileMu.Lock()
	defer saveFileMu.Unlock()

	dynamicRulesMu.RLock()
	clone := make(map[string]CarrierASNRule, len(dynamicRules))
	for k, v := range dynamicRules {
		clone[k] = v
	}
	dynamicRulesMu.RUnlock()

	if len(clone) == 0 {
		return nil
	}

	data, err := json.MarshalIndent(clone, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := fmt.Sprintf("%s.%d.tmp", filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	_ = os.Remove(filePath)
	return os.Rename(tmpFile, filePath)
}

// ClearDynamicASNRules clears all learned dynamic rules in memory.
func ClearDynamicASNRules() {
	dynamicRulesMu.Lock()
	dynamicRules = make(map[string]CarrierASNRule)
	dynamicRulesMu.Unlock()
}

// IsPredictionViable checks whether port prediction should be attempted.
// Prevents battery and network drain from wide random port-spraying when CGNAT is completely random.
func IsPredictionViable(asn string, samples []int, prof CGNATProfile, fallbackDelta int) (bool, int) {
	// 1. If explicit rule says random, immediately reject
	if rule, found := LookupCarrierASN(asn); found {
		if !rule.PredictionViable {
			return false, 0
		}
		if rule.SweepRadius > 0 {
			return true, rule.SweepRadius
		}
	}

	// 2. If profile indicates PBA block, prediction within block is viable
	if prof.BlockSize > 0 {
		return true, prof.BlockSize
	}

	// 3. If sequential with small delta, viable
	if prof.IsSequential && prof.Delta > 0 && prof.Delta <= 16 {
		return true, prof.Delta * 4
	}

	// 4. If fallback delta is small (1..16), viable
	if fallbackDelta > 0 && fallbackDelta <= 16 {
		return true, fallbackDelta * 4
	}

	// 5. If port variance across samples is large and non-sequential, reject wide spray
	if len(samples) >= 3 && !prof.IsSequential && !prof.ParityPreserved {
		return false, 0
	}

	// Default fallback: small conservative sweep radius of 8 ports
	return true, 8
}

// GenerateAdaptivePredictPorts generates an optimized list of candidate target ports
// based on the remote peer's base port, measured NAT delta, and operator ASN.
func GenerateAdaptivePredictPorts(basePort int, measuredDelta int, asn string) []int {
	if basePort <= 0 || basePort > 65535 {
		return nil
	}

	// 1. Look up known carrier rule by ASN
	rule, found := LookupCarrierASN(asn)
	if found && !rule.PredictionViable {
		// Carrier uses RFC 4787 Random port allocation (e.g. T-Mobile).
		// Wide port sweeps will fail and exhaust mobile battery. Punch only the exact base port.
		return []int{basePort}
	}

	// 2. Determine effective step / delta
	step := 1
	if measuredDelta > 0 && measuredDelta <= 32 {
		step = measuredDelta
	} else if found && rule.DefaultDelta > 0 {
		step = rule.DefaultDelta
	}

	seen := make(map[int]bool)
	var ports []int

	addPort := func(p int) {
		if p >= 1024 && p <= 65535 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}

	// Always include the exact base port first
	addPort(basePort)

	// 3. Port allocation strategies
	alloc := ""
	if found {
		alloc = rule.PortAllocation
	}

	switch alloc {
	case "sequential", "fixed_step":
		// Sequential/fixed-step CGNATs (MegaFon, MTS, Rostelecom) allocate forward
		// on consecutive outbound UDP flows. Sweep predominantly forward.
		for i := 1; i <= 5; i++ {
			addPort(basePort + i*step)
		}
		// One step backward just in case packet ordering or race occurred
		addPort(basePort - step)

	case "small_jitter", "pba":
		// Small jitter around base port (Tele2, Beeline)
		radius := 6
		if found && rule.SweepRadius > 0 {
			radius = rule.SweepRadius
			if radius > 12 {
				radius = 12
			}
		}
		for i := 1; i <= radius; i++ {
			addPort(basePort + i)
			addPort(basePort - i)
		}

	default:
		// Fallback when ASN is unknown:
		if measuredDelta > 0 && measuredDelta <= 16 {
			for i := 1; i <= 4; i++ {
				addPort(basePort + i*measuredDelta)
			}
			addPort(basePort - measuredDelta)
		} else {
			// Small symmetric fanout [-2, -1, +1, +2]
			for _, off := range []int{1, -1, 2, -2} {
				addPort(basePort + off)
			}
		}
	}

	return ports
}

// IsPredictedPort returns true if fromAddr and stunAddr share the same public host IP
// but have different ports, indicating a port-predicted symmetric NAT hole-punch.
func IsPredictedPort(fromAddr, stunAddr string) bool {
	if fromAddr == "" || stunAddr == "" {
		return false
	}
	fHost, fPort, err1 := net.SplitHostPort(fromAddr)
	sHost, sPort, err2 := net.SplitHostPort(stunAddr)
	if err1 != nil || err2 != nil {
		return false
	}
	return fHost == sHost && fPort != sPort
}
