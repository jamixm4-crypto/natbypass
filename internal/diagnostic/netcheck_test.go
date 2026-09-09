// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package diagnostic

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/transport"
)

func TestRecommendTransportForReport(t *testing.T) {
	// Case 1: Healthy UDP, Full Cone / EIM -> prefers AWG
	rep1 := &NetcheckReport{
		UDPEnabled:  true,
		NATType:     "Full Cone / Restricted Cone NAT",
		MappingType: "Endpoint-Independent Mapping (EIM)",
	}
	if rec := RecommendTransportForReport(rep1); rec != transport.TransportAWG {
		t.Errorf("Expected %s, got %s", transport.TransportAWG, rec)
	}

	// Case 2: Symmetric NAT with random ports -> prefers QUIC
	rep2 := &NetcheckReport{
		UDPEnabled:  true,
		NATType:     "Symmetric NAT / CGNAT (Случайные порты)",
		MappingType: "Address-Dependent Mapping (Случайный порт)",
	}
	if rec := RecommendTransportForReport(rep2); rec != transport.TransportQUIC {
		t.Errorf("Expected %s, got %s", transport.TransportQUIC, rec)
	}

	// Case 3: UDP Blocked / TSPU Censorship -> prefers ShadowTLS
	rep3 := &NetcheckReport{
		UDPEnabled:   false,
		TSPUDetected: true,
		NATType:      "UDP Blocked / Strict Filter",
	}
	if rec := RecommendTransportForReport(rep3); rec != transport.TransportShadowTLS {
		t.Errorf("Expected %s, got %s", transport.TransportShadowTLS, rec)
	}
}

func TestNetcheckReport_JSONSerialization(t *testing.T) {
	rep := &NetcheckReport{
		UDPEnabled:         true,
		IPv6Enabled:        false,
		NATType:            "Full Cone / Restricted Cone NAT",
		MappingType:        "Endpoint-Independent Mapping (EIM)",
		FilteringType:      "Address/Port Restricted",
		PublicIPv4:         "198.51.100.42",
		PathMTU:            1420,
		PreferredTransport: transport.TransportAWG,
		LatenciesMs: map[string]int64{
			"google_stun": 25,
		},
		Timestamp: time.Now().UTC(),
	}

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed NetcheckReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if parsed.PublicIPv4 != rep.PublicIPv4 || parsed.PreferredTransport != rep.PreferredTransport {
		t.Errorf("Parsed mismatch: %+v vs %+v", parsed, rep)
	}
}

func TestRunNetcheck_QuickCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rep, err := RunNetcheck(ctx)
	if err != nil {
		t.Fatalf("RunNetcheck failed: %v", err)
	}
	if rep == nil {
		t.Fatal("Expected non-nil report")
	}
	if rep.PathMTU < 1280 {
		t.Errorf("Expected PathMTU >= 1280, got %d", rep.PathMTU)
	}
	if rep.PreferredTransport == "" {
		t.Error("Expected non-empty PreferredTransport")
	}
}
