// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package signaling

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
)

func TestPayloadMarshalUnmarshal_AWG(t *testing.T) {
	awg := &AWGParams{
		Jc:   4,
		Jmin: 40,
		Jmax: 70,
		S1:   48,
		S2:   32,
		H1:   "1428571428",
		H2:   "2147483647",
		H3:   "857142857",
		H4:   "1122334455",
	}

	orig := &Payload{
		DeviceID:         "device-123",
		Nickname:         "node-alpha",
		DeviceName:       "node-alpha",
		VirtualIP:        "100.64.200.2",
		PublicKey:        "abcdef123456",
		PublicIP:         "1.2.3.4",
		LocalAddr:        "192.168.1.100:51820",
		STUNAddr:         "1.2.3.4:51820",
		WGPubKey:         "wgpub123",
		WGPort:           51820,
		Timestamp:        time.Now().Truncate(time.Millisecond),
		IsExitNode:       true,
		AdvertisedRoutes: []string{"192.168.1.0/24"},
		AWG:              awg,
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Payload
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.AWG == nil {
		t.Fatalf("Expected AWG to be non-nil")
	}

	if !reflect.DeepEqual(parsed.AWG, orig.AWG) {
		t.Errorf("AWG mismatch: got %+v, want %+v", parsed.AWG, orig.AWG)
	}
	if parsed.DeviceID != orig.DeviceID {
		t.Errorf("DeviceID mismatch: got %s, want %s", parsed.DeviceID, orig.DeviceID)
	}
}

func TestPayloadUnmarshal_PascalCase_CamelCase_AWG(t *testing.T) {
	// PascalCase JSON
	pascalJSON := `{
		"DeviceID": "dev-pascal",
		"Nickname": "PascalNode",
		"VirtualIP": "100.64.200.5",
		"PublicIP": "203.0.113.1",
		"LocalAddr": "192.168.0.5:51820",
		"STUNAddr": "203.0.113.1:51820",
		"WGPubKey": "wg-key-pascal",
		"WGPort": 51820,
		"IsExitNode": true,
		"AdvertisedRoutes": ["10.0.0.0/8"],
		"AWG": {
			"Jc": 4,
			"Jmin": 40,
			"Jmax": 70,
			"S1": 48,
			"S2": 32,
			"H1": "1428571428",
			"H2": "2147483647",
			"H3": "857142857",
			"H4": "1122334455"
		}
	}`

	var p1 Payload
	if err := json.Unmarshal([]byte(pascalJSON), &p1); err != nil {
		t.Fatalf("Unmarshal PascalCase failed: %v", err)
	}

	if p1.DeviceID != "dev-pascal" {
		t.Errorf("DeviceID mismatch: got %s", p1.DeviceID)
	}
	if p1.AWG == nil {
		t.Fatalf("Expected AWG to be non-nil in PascalCase payload")
	}
	expectedAWG := &AWGParams{
		Jc:   4,
		Jmin: 40,
		Jmax: 70,
		S1:   48,
		S2:   32,
		H1:   "1428571428",
		H2:   "2147483647",
		H3:   "857142857",
		H4:   "1122334455",
	}
	if !reflect.DeepEqual(p1.AWG, expectedAWG) {
		t.Errorf("AWG mismatch from PascalCase: got %+v, want %+v", p1.AWG, expectedAWG)
	}

	// Mixed / Numeric Headers / camelCase
	mixedJSON := `{
		"device_id": "dev-mixed",
		"AWG": {
			"jc": 7,
			"jMin": 50,
			"jMax": 90,
			"s1": 60,
			"s2": 40,
			"h1": 1428571428,
			"h2": 2147483647,
			"h3": 857142857,
			"h4": 1122334455
		}
	}`

	var p2 Payload
	if err := json.Unmarshal([]byte(mixedJSON), &p2); err != nil {
		t.Fatalf("Unmarshal mixed JSON failed: %v", err)
	}

	if p2.AWG == nil {
		t.Fatalf("Expected AWG to be non-nil in mixed payload")
	}
	expectedMixedAWG := &AWGParams{
		Jc:   7,
		Jmin: 50,
		Jmax: 90,
		S1:   60,
		S2:   40,
		H1:   "1428571428",
		H2:   "2147483647",
		H3:   "857142857",
		H4:   "1122334455",
	}
	if !reflect.DeepEqual(p2.AWG, expectedMixedAWG) {
		t.Errorf("AWG mismatch from mixed: got %+v, want %+v", p2.AWG, expectedMixedAWG)
	}
}

func TestPayloadEncryptDecrypt_AWG(t *testing.T) {
	pub1, priv1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("KeyPair 1 generation failed: %v", err)
	}
	pub2, priv2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("KeyPair 2 generation failed: %v", err)
	}

	origPayload := &Payload{
		DeviceID:  "dev-secure",
		VirtualIP: "100.64.200.10",
		AWG: &AWGParams{
			Jc:   5,
			Jmin: 42,
			Jmax: 75,
			S1:   50,
			S2:   35,
			H1:   "999999",
			H2:   "888888",
			H3:   "777777",
			H4:   "666666",
		},
	}

	encrypted, err := EncryptPayload(origPayload, pub2, priv1)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}
	if len(encrypted.Encrypted) == 0 {
		t.Fatalf("Expected non-empty encrypted data")
	}

	decrypted, err := DecryptPayload(encrypted, pub1, priv2)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if decrypted.AWG == nil {
		t.Fatalf("Expected AWG to be decrypted")
	}
	if !reflect.DeepEqual(decrypted.AWG, origPayload.AWG) {
		t.Errorf("Decrypted AWG mismatch: got %+v, want %+v", decrypted.AWG, origPayload.AWG)
	}
}

func TestPayload_EndpointsAndCoordination(t *testing.T) {
	orig := &Payload{
		DeviceID:  "node-endpoints",
		VirtualIP: "100.64.0.5",
		Endpoints: []EndpointDesc{
			{
				Proto:    "udp",
				IP:       "198.51.100.1",
				Port:     47832,
				NATType:  "full_cone",
				TTL:      20,
				Priority: 100,
			},
			{
				Proto:    "udp",
				IP:       "198.51.100.1",
				Port:     47833,
				NATType:  "symmetric",
				TTL:      20,
				Priority: 80,
			},
		},
		Coordination: &PunchCoordinationSignal{
			Action:      "punch",
			SessionID:   "session-xyz",
			Target:      "node-target",
			Sender:      "node-endpoints",
			StartAt:     1773000000,
			TargetPorts: []int{47832, 47833, 47834},
			BurstCount:  8,
			IntervalMs:  15,
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Payload
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(parsed.Endpoints))
	}
	if parsed.Endpoints[0].Port != 47832 || parsed.Endpoints[0].NATType != "full_cone" {
		t.Fatalf("unexpected endpoint 0: %+v", parsed.Endpoints[0])
	}

	if parsed.Coordination == nil {
		t.Fatalf("expected coordination to be non-nil")
	}
	if parsed.Coordination.Action != "punch" || parsed.Coordination.BurstCount != 8 {
		t.Fatalf("unexpected coordination signal: %+v", parsed.Coordination)
	}
}


