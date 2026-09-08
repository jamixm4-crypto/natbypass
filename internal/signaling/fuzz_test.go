// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package signaling

import (
	"encoding/json"
	"testing"
)

// FuzzPayloadUnmarshal tests robustness of JSON unmarshaling and field decoding for all signal types.
func FuzzPayloadUnmarshal(f *testing.F) {
	// Seed corpus
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"device_id":"test-1","virtual_ip":"10.1.1.5/24","public_key":"abc"}`))
	f.Add([]byte(`{"rendezvous":{"phase":"init","session_id":"s1","sender_device_id":"d1","sender_stun":"1.2.3.4:5678"}}`))
	f.Add([]byte(`{"sym_punch":{"target_device_id":"d2","my_stun_addr":"1.1.1.1:1111","hop_hint":4444}}`))
	f.Add([]byte(`{"remote_diag":{"action":"request_diag","target_id":"all"}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Payload
		if err := json.Unmarshal(data, &p); err == nil {
			// Check invariant: DirectP2P and ActiveEndpoint are never adopted from unmarshaled payload
			if p.DirectP2P {
				t.Errorf("DirectP2P must never be true after unmarshal")
			}
			if p.Rendezvous != nil {
				_ = p.Rendezvous.Phase
				_ = p.Rendezvous.SenderSTUN
			}
			if p.SymPunch != nil {
				_ = p.SymPunch.MySTUNAddr
			}
			if p.RemoteDiag != nil {
				_ = p.RemoteDiag.Action
			}
		}
	})
}

// FuzzPayloadDecryption tests robustness of symmetric key decryption against corrupt or manipulated ciphertexts.
func FuzzPayloadDecryption(f *testing.F) {
	testKey := "master-secret-key-12345"

	f.Add([]byte{})
	f.Add([]byte("not-a-valid-ciphertext"))
	f.Add([]byte{0x00, 0x01, 0x02, 0x03, 0x04})

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &Payload{
			DeviceID:  "fuzz-node",
			Encrypted: data,
		}
		// DecryptPayloadWithKey should gracefully return error, never panic
		_, _ = DecryptPayloadWithKey(p, testKey)
	})
}
