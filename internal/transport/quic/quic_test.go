// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package quic

import (
	"bytes"
	"testing"
)

func TestQUIC_BuildAndParse(t *testing.T) {
	var testKey [32]byte
	copy(testKey[:], []byte("01234567890123456789012345678901"))

	originalPayload := []byte("TEST_IP_PACKET_OVER_QUIC_TRANSPORT")
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	pktNum := uint16(42)

	// 1. Build 1-RTT Short Header packet
	packet, err := BuildQUICDataPacket(dcid, pktNum, originalPayload, testKey)
	if err != nil {
		t.Fatalf("BuildQUICDataPacket failed: %v", err)
	}

	// Verify RFC 9000 header bits
	if (packet[0] & 0xC0) != 0x40 {
		t.Fatalf("invalid RFC 9000 Short Header byte: 0x%X", packet[0])
	}

	// 2. Parse and unpack
	decrypted, parsedPN, parsedDCID, err := ParseQUICDataPacket(packet, testKey)
	if err != nil {
		t.Fatalf("ParseQUICDataPacket failed: %v", err)
	}

	if !bytes.Equal(decrypted, originalPayload) {
		t.Fatalf("payload mismatch: expected %q, got %q", originalPayload, decrypted)
	}
	if parsedPN != pktNum {
		t.Fatalf("packet number mismatch: expected %d, got %d", pktNum, parsedPN)
	}
	if !bytes.Equal(parsedDCID, dcid) {
		t.Fatalf("DCID mismatch: expected %v, got %v", dcid, parsedDCID)
	}
}

func TestQUIC_SessionMigration(t *testing.T) {
	var testKey [32]byte
	copy(testKey[:], []byte("01234567890123456789012345678901"))

	sess := NewSession("peer-mobile", "192.168.1.100:47832", testKey)
	if sess.RemoteAddr() != "192.168.1.100:47832" {
		t.Fatalf("invalid initial remote addr")
	}

	// Simulate Wi-Fi to Cellular handover
	migrated := sess.HandleMigration("178.120.50.2:55432")
	if !migrated {
		t.Fatalf("expected migration to be detected")
	}
	if sess.RemoteAddr() != "178.120.50.2:55432" {
		t.Fatalf("remote addr not updated after migration")
	}

	// Subsequent packet on same cellular IP -> no migration event
	if sess.HandleMigration("178.120.50.2:55432") {
		t.Fatalf("expected no migration for identical IP")
	}
}
