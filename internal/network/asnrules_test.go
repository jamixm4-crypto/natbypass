// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"path/filepath"
	"testing"
)

func TestASNRules_LookupStatic(t *testing.T) {
	rule, found := LookupCarrierASN("AS31133")
	if !found {
		t.Fatalf("expected AS31133 to be found in knownCarrierASNs")
	}
	if rule.Carrier != "MegaFon/Yota" || rule.DefaultDelta != 1 {
		t.Errorf("unexpected rule for AS31133: %+v", rule)
	}

	// Test without "AS" prefix
	rule2, found2 := LookupCarrierASN("8359")
	if !found2 {
		t.Fatalf("expected 8359 to be resolved to AS8359")
	}
	if rule2.Carrier != "MTS" || rule2.DefaultDelta != 2 {
		t.Errorf("unexpected rule for MTS: %+v", rule2)
	}
}

func TestASNRules_DynamicRecordAndPersistence(t *testing.T) {
	ClearDynamicASNRules()
	defer ClearDynamicASNRules()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "test_asn_cache.json")

	// Dynamic observation for unknown carrier AS99999
	changed := RecordPeerObservation("AS99999", 4, cacheFile)
	if !changed {
		t.Fatalf("expected RecordPeerObservation to record new ASN")
	}

	// Save explicitly
	if err := SaveASNRulesCache(cacheFile); err != nil {
		t.Fatalf("SaveASNRulesCache failed: %v", err)
	}

	// Lookup dynamically learned rule
	dynRule, found := LookupCarrierASN("AS99999")
	if !found {
		t.Fatalf("expected dynamically learned AS99999 to be found")
	}
	if dynRule.DefaultDelta != 4 || dynRule.PortAllocation != "fixed_step" {
		t.Errorf("unexpected dynamic rule: %+v", dynRule)
	}

	// Clear memory and reload from disk
	ClearDynamicASNRules()
	_, foundAfterClear := LookupCarrierASN("AS99999")
	if foundAfterClear {
		t.Fatalf("expected dynamic rules to be empty after clear")
	}

	if err := LoadASNRulesCache(cacheFile); err != nil {
		t.Fatalf("LoadASNRulesCache failed: %v", err)
	}

	reloadedRule, foundReloaded := LookupCarrierASN("AS99999")
	if !foundReloaded {
		t.Fatalf("expected AS99999 to be found after loading from cache file")
	}
	if reloadedRule.DefaultDelta != 4 {
		t.Errorf("expected DefaultDelta 4, got %d", reloadedRule.DefaultDelta)
	}

	// Ensure random CGNAT (T-Mobile) cannot be overridden
	if changedRandom := RecordPeerObservation("AS21928", 2, cacheFile); changedRandom {
		t.Errorf("expected Random CGNAT rule for AS21928 NOT to be overridden")
	}
}

func TestASNRules_AdaptivePortsWithDynamicRule(t *testing.T) {
	ClearDynamicASNRules()
	defer ClearDynamicASNRules()

	UpdateCarrierASN("AS55555", CarrierASNRule{
		Carrier:          "CustomCarrier",
		PortAllocation:   "sequential",
		DefaultDelta:     3,
		SweepRadius:      6,
		PredictionViable: true,
	})

	ports := GenerateAdaptivePredictPorts(50000, 0, "AS55555")
	if len(ports) < 2 {
		t.Fatalf("expected predicted ports, got %v", ports)
	}
	if ports[0] != 50000 {
		t.Errorf("first port should be base port, got %d", ports[0])
	}
	// With delta 3 and sequential, next should be 50003
	if ports[1] != 50003 {
		t.Errorf("expected second port 50003, got %d", ports[1])
	}
}
