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

func TestHMACSignAndDecryptPayload(t *testing.T) {
	networkKey := "300d425a69b19128ed78ea994d30be44"
	signKey := crypto.DeriveSignKey(networkKey)

	original := &Payload{
		DeviceID:   "node-remote-daemon",
		Nickname:   "MarNet Keen",
		VirtualIP:  "10.1.1.5",
		PublicKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		STUNAddr:   "198.51.100.1:47832",
		LocalAddr:  "192.168.1.1:47832",
		Platform:   "KeeneticOS",
		IsKeenetic: true,
		Version:    "v1.9.226-beta13",
		Timestamp:  time.Now(),
	}

	// 1. Daemon encrypts payload with NetworkKey
	encryptedPayload, err := EncryptPayloadWithKey(original, networkKey)
	if err != nil {
		t.Fatalf("EncryptPayloadWithKey failed: %v", err)
	}

	// 2. Daemon marshals to JSON and signs frame with SignFrame
	jsonData, err := json.Marshal(encryptedPayload)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	signedFrame := crypto.SignFrame(jsonData, signKey)

	// 3. GUI receives frame: verifies with signKey and 300s skew
	verifiedInner, _, err := crypto.VerifyFrame(signedFrame, signKey, 300*time.Second)
	if err != nil {
		t.Fatalf("VerifyFrame failed: %v", err)
	}

	// 4. GUI unmarshals inner JSON
	var receivedPayload Payload
	if err := json.Unmarshal(verifiedInner, &receivedPayload); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if receivedPayload.DeviceID != "node-remote-daemon" {
		t.Errorf("expected DeviceID 'node-remote-daemon', got %s", receivedPayload.DeviceID)
	}

	// 5. GUI decrypts payload with NetworkKey
	decrypted, err := DecryptPayloadWithKey(&receivedPayload, networkKey)
	if err != nil {
		t.Fatalf("DecryptPayloadWithKey failed: %v", err)
	}

	if decrypted.DeviceID != original.DeviceID {
		t.Errorf("DeviceID mismatch: got %s, want %s", decrypted.DeviceID, original.DeviceID)
	}
	if decrypted.Nickname != "MarNet Keen" {
		t.Errorf("Nickname mismatch: got %s, want %s", decrypted.Nickname, original.Nickname)
	}
	if decrypted.VirtualIP != "10.1.1.5" {
		t.Errorf("VirtualIP mismatch: got %s, want %s", decrypted.VirtualIP, original.VirtualIP)
	}
	if decrypted.STUNAddr != "198.51.100.1:47832" {
		t.Errorf("STUNAddr mismatch: got %s, want %s", decrypted.STUNAddr, original.STUNAddr)
	}
}

type mockMQTTMessage struct {
	payload []byte
}

func (m *mockMQTTMessage) Duplicate() bool   { return false }
func (m *mockMQTTMessage) Qos() byte         { return 0 }
func (m *mockMQTTMessage) Retained() bool    { return false }
func (m *mockMQTTMessage) Topic() string     { return "test/topic" }
func (m *mockMQTTMessage) MessageID() uint16 { return 0 }
func (m *mockMQTTMessage) Payload() []byte   { return m.payload }
func (m *mockMQTTMessage) Ack()              {}

func TestSignatureBypass_RejectedWhenKeyActive(t *testing.T) {
	networkKey := "secure-mesh-key-9988"
	signKey := crypto.DeriveSignKey(networkKey)

	ch := &MQTTChannel{
		dedup: NewPacketDedup(),
	}
	ch.SetNetworkKey(networkKey)

	outCh := make(chan *Payload, 10)
	ch.outMu.Lock()
	ch.outChans = append(ch.outChans, outCh)
	ch.outMu.Unlock()

	// 1. Attacker attempts Signature Bypass: sends raw JSON starting with '{'
	rawJSON := []byte(`{"deviceID":"attacker-node","nickname":"Evil Node","virtual_ip":"10.99.0.1"}`)
	ch.handleIncoming(&mockMQTTMessage{payload: rawJSON})

	select {
	case p := <-outCh:
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Plaintext JSON was accepted when NetworkKey was active! Got payload: %+v", p)
	case <-time.After(50 * time.Millisecond):
		// Expected: dropped
	}

	// 2. Attacker sends tampered / invalid HMAC frame
	fakeFrame := make([]byte, 50)
	fakeFrame[0] = 0xAA // binary
	ch.handleIncoming(&mockMQTTMessage{payload: fakeFrame})

	select {
	case p := <-outCh:
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Invalid HMAC frame was accepted! Got payload: %+v", p)
	case <-time.After(50 * time.Millisecond):
		// Expected: dropped
	}

	// 3. Legitimate peer sends valid HMAC-signed frame
	legitJSON := []byte(`{"deviceID":"legit-node","nickname":"Friendly Node","virtual_ip":"10.99.0.2"}`)
	validSignedFrame := crypto.SignFrame(legitJSON, signKey)
	ch.handleIncoming(&mockMQTTMessage{payload: validSignedFrame})

	select {
	case p := <-outCh:
		if p.DeviceID != "legit-node" {
			t.Errorf("expected DeviceID 'legit-node', got '%s'", p.DeviceID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Valid HMAC-signed frame was unexpectedly dropped")
	}

	// 4. Test Tunnel Payload: Raw packet must be rejected when NetworkKey is active
	tunnelReceived := make(chan []byte, 1)
	ch.tunnelMu.Lock()
	ch.tunnelHandler = func(pkt []byte) {
		tunnelReceived <- pkt
	}
	ch.tunnelMu.Unlock()

	// Attacker sends raw IPv4 packet (starts with 0x45)
	rawIP := make([]byte, 28)
	rawIP[0] = 0x45 // IPv4 header
	ch.handleTunnelPayload(rawIP)

	select {
	case pkt := <-tunnelReceived:
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Raw unauthenticated tunnel packet was accepted! Got: %x", pkt)
	case <-time.After(50 * time.Millisecond):
		// Expected: dropped
	}

	// Legitimate peer sends signed tunnel packet
	signedIP := crypto.SignFrame(rawIP, signKey)
	ch.handleTunnelPayload(signedIP)

	select {
	case pkt := <-tunnelReceived:
		if len(pkt) != len(rawIP) || pkt[0] != 0x45 {
			t.Errorf("Tunnel packet corrupted: got %x, want %x", pkt, rawIP)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Valid signed tunnel packet was unexpectedly dropped")
	}
}



