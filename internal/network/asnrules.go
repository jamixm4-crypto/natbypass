// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"strings"
)

// CarrierASNRule defines port allocation behavior and prediction viability for a given operator ASN.
type CarrierASNRule struct {
	Carrier          string
	PortAllocation   string // "sequential" | "fixed_step" | "small_jitter" | "pba" | "random"
	DefaultDelta     int
	SweepRadius      int
	PredictionViable bool
}

// knownCarrierASNs contains empirical NAT traversal characteristics for major Russian and CIS cellular operators.
var knownCarrierASNs = map[string]CarrierASNRule{
	// MegaFon (AS31133, AS25159)
	"AS31133": {Carrier: "MegaFon/Yota", PortAllocation: "sequential", DefaultDelta: 1, SweepRadius: 5, PredictionViable: true},
	"AS25159": {Carrier: "MegaFon", PortAllocation: "sequential", DefaultDelta: 2, SweepRadius: 6, PredictionViable: true},

	// MTS (AS8359, AS25159)
	"AS8359": {Carrier: "MTS", PortAllocation: "fixed_step", DefaultDelta: 2, SweepRadius: 8, PredictionViable: true},

	// Beeline / VimpelCom (AS16345, AS3216)
	"AS16345": {Carrier: "Beeline", PortAllocation: "pba", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},
	"AS3216":  {Carrier: "Beeline", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 12, PredictionViable: true},

	// Tele2 / Rostelecom (AS42610, AS12389)
	"AS42610": {Carrier: "Tele2", PortAllocation: "small_jitter", DefaultDelta: 1, SweepRadius: 10, PredictionViable: true},
	"AS12389": {Carrier: "Rostelecom", PortAllocation: "fixed_step", DefaultDelta: 1, SweepRadius: 6, PredictionViable: true},

	// T-Mobile (AS21928, AS12271) - Known RFC 4787 Random CGNAT
	"AS21928": {Carrier: "T-Mobile", PortAllocation: "random", DefaultDelta: 0, SweepRadius: 0, PredictionViable: false},
	"AS12271": {Carrier: "T-Mobile", PortAllocation: "random", DefaultDelta: 0, SweepRadius: 0, PredictionViable: false},
}

// LookupCarrierASN returns the CGNAT rule for a given ASN (e.g. "AS31133" or "31133").
func LookupCarrierASN(asn string) (CarrierASNRule, bool) {
	clean := strings.ToUpper(strings.TrimSpace(asn))
	if clean == "" || clean == "UNKNOWN" {
		return CarrierASNRule{}, false
	}
	if !strings.HasPrefix(clean, "AS") {
		clean = "AS" + clean
	}
	rule, ok := knownCarrierASNs[clean]
	return rule, ok
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
