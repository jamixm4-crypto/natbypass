// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/pion/stun/v3"
)

// FuzzParseQUICChameleonProbe tests robustness of QUIC Chameleon probe parser against arbitrary payload.
func FuzzParseQUICChameleonProbe(f *testing.F) {
	var dummyKey [32]byte
	copy(dummyKey[:], []byte("01234567890123456789012345678901"))

	// Seed corpus with valid and edge-case samples
	f.Add([]byte{})
	f.Add([]byte{0xC0, 0x00, 0x00, 0x00, 0x01})
	f.Add(bytes.Repeat([]byte{0xFF}, 64))

	validProbe, err := BuildQUICChameleonProbe(constants.PingPrefix+"test-peer:12345", dummyKey)
	if err == nil && len(validProbe) > 0 {
		f.Add(validProbe)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure parser never panics on corrupt, truncated, or malicious data
		_, _ = ParseQUICChameleonProbe(data, dummyKey)
	})
}

// FuzzInboundPacketStructure tests processing of raw UDP datagram framing.
func FuzzInboundPacketStructure(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(constants.KeepAlivePayload))
	f.Add([]byte(constants.PingPrefix + "dev1:12345"))
	f.Add([]byte(constants.PongPrefix + "dev1:12345:100"))

	// Padded tunnel packet format
	header := []byte(constants.TunPaddedHeader)
	var pktLen [2]byte
	binary.BigEndian.PutUint16(pktLen[:], 20)
	dummyIPv4 := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 1, 1, 1, 10, 1, 1, 2}
	f.Add(append(append(header, pktLen[:]...), dummyIPv4...))

	f.Fuzz(func(t *testing.T, data []byte) {
		// 1. Check STUN detector
		_ = stun.IsMessage(data)

		// 2. Check Padded TUN Header parsing
		if len(data) > constants.TunPaddedHeaderSize+2 && string(data[:constants.TunPaddedHeaderSize]) == constants.TunPaddedHeader {
			realLen := int(binary.BigEndian.Uint16(data[constants.TunPaddedHeaderSize : constants.TunPaddedHeaderSize+2]))
			if realLen > 0 && constants.TunPaddedHeaderSize+2+realLen <= len(data) {
				rawPayload := data[constants.TunPaddedHeaderSize+2 : constants.TunPaddedHeaderSize+2+realLen]
				if len(rawPayload) >= 20 && rawPayload[0]>>4 == 4 {
					_ = net.IPv4(rawPayload[12], rawPayload[13], rawPayload[14], rawPayload[15])
				}
			}
		}
	})
}

// FuzzFingerprintCGNAT tests robustness of CGNAT port sequence analysis.
func FuzzFingerprintCGNAT(f *testing.F) {
	f.Add([]byte{0x04, 0xD2, 0x04, 0xD3, 0x04, 0xD4}) // 1234, 1235, 1236

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 || len(data)%2 != 0 {
			return
		}
		var samples []int
		for i := 0; i < len(data); i += 2 {
			p := int(binary.BigEndian.Uint16(data[i : i+2]))
			if p > 0 && p <= 65535 {
				samples = append(samples, p)
			}
		}
		if len(samples) >= 2 {
			prof := FingerprintCGNAT(samples)
			_ = prof.IsSequential
			var p UDPPuncher
			_ = p.CandidatePortsAdvanced(1000, samples, prof, 1)
		}
	})
}
