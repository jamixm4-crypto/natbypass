// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"bytes"
	"testing"
)

func TestMultiHop_EncodeDecode(t *testing.T) {
	src := "node-alpha"
	dst := "node-bravo"
	payload := []byte("encrypted-ip-payload-data-here")

	encoded, err := EncodeMultiHopPacket(src, dst, 4, 0x00, payload)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if !IsMultiHopPacket(encoded) {
		t.Fatal("Expected IsMultiHopPacket to be true")
	}

	decoded, err := DecodeMultiHopPacket(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.SrcID != src || decoded.DstID != dst || decoded.TTL != 4 {
		t.Fatalf("Mismatch: %+v", decoded)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("Payload mismatch: %s vs %s", decoded.Payload, payload)
	}
}

func TestMultiHopRouter_LocalDelivery(t *testing.T) {
	deliveredSrc := ""
	var deliveredPayload []byte

	router := NewMultiHopRouter("node-self",
		func(dstID string, packet []byte) error {
			t.Fatal("Forward should not be called for local destination")
			return nil
		},
		func(srcID string, payload []byte) error {
			deliveredSrc = srcID
			deliveredPayload = payload
			return nil
		},
	)

	packet, err := EncodeMultiHopPacket("node-remote", "node-self", 3, 0x00, []byte("hello-mesh"))
	if err != nil {
		t.Fatal(err)
	}

	if err := router.Route(packet); err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	if deliveredSrc != "node-remote" || string(deliveredPayload) != "hello-mesh" {
		t.Fatalf("Delivery incorrect: src=%s payload=%s", deliveredSrc, deliveredPayload)
	}

	fwd, del, drop := router.Stats()
	if fwd != 0 || del != 1 || drop != 0 {
		t.Fatalf("Stats incorrect: fwd=%d del=%d drop=%d", fwd, del, drop)
	}
}

func TestMultiHopRouter_TransitForwarding(t *testing.T) {
	forwardedDst := ""
	var forwardedData []byte

	// Node Charlie routes traffic between Alpha and Bravo
	router := NewMultiHopRouter("node-charlie",
		func(dstID string, packet []byte) error {
			forwardedDst = dstID
			forwardedData = packet
			return nil
		},
		func(srcID string, payload []byte) error {
			t.Fatal("Deliver should not be called on transit hop")
			return nil
		},
	)

	initialTTL := uint8(4)
	packet, err := EncodeMultiHopPacket("node-alpha", "node-bravo", initialTTL, 0x00, []byte("cross-border-vpn"))
	if err != nil {
		t.Fatal(err)
	}

	if err := router.Route(packet); err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	if forwardedDst != "node-bravo" {
		t.Fatalf("Expected forwardedDst node-bravo, got %s", forwardedDst)
	}

	// Verify TTL was decremented in place to 3
	dec, err := DecodeMultiHopPacket(forwardedData)
	if err != nil {
		t.Fatal(err)
	}
	if dec.TTL != 3 {
		t.Fatalf("Expected decremented TTL 3, got %d", dec.TTL)
	}

	fwd, del, drop := router.Stats()
	if fwd != 1 || del != 0 || drop != 0 {
		t.Fatalf("Stats incorrect: fwd=%d del=%d drop=%d", fwd, del, drop)
	}
}

func TestMultiHopRouter_TTLZeroLoopPrevention(t *testing.T) {
	router := NewMultiHopRouter("node-charlie", nil, nil)

	// Packet with TTL=1 arriving at transit hop must be dropped to prevent loops
	packet, err := EncodeMultiHopPacket("node-alpha", "node-bravo", 1, 0x00, []byte("looping-packet"))
	if err != nil {
		t.Fatal(err)
	}

	err = router.Route(packet)
	if err == nil {
		t.Fatal("Expected TTL expired error")
	}

	_, _, drop := router.Stats()
	if drop != 1 {
		t.Fatalf("Expected 1 dropped loop, got %d", drop)
	}
}
