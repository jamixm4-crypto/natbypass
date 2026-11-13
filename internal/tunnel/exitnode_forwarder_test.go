// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/natbypass/natbypass/internal/peer"
)

func TestTransitForwarder_IsTransitPacket(t *testing.T) {
	myVIP := "10.1.2.113/24"
	mockPeers := map[string]*peer.Peer{
		"10.1.2.55": {
			DeviceID:  "client-dev-1",
			VirtualIP: "10.1.2.55/24",
		},
	}

	tf := &TransitForwarder{
		myVIP: myVIP,
		lookupPeer: func(vipOrID string) *peer.Peer {
			return mockPeers[vipOrID]
		},
	}

	tests := []struct {
		name      string
		srcIP     string
		destIP    string
		wantTrans bool
	}{
		{
			name:      "Transit to public DNS 1.1.1.1",
			srcIP:     "10.1.2.55",
			destIP:    "1.1.1.1",
			wantTrans: true,
		},
		{
			name:      "Transit to Google DNS 8.8.8.8",
			srcIP:     "10.1.2.55",
			destIP:    "8.8.8.8",
			wantTrans: true,
		},
		{
			name:      "Mesh local peer 10.1.2.55",
			srcIP:     "10.1.2.113",
			destIP:    "10.1.2.55",
			wantTrans: false,
		},
		{
			name:      "Self VIP 10.1.2.113",
			srcIP:     "10.1.2.55",
			destIP:    "10.1.2.113",
			wantTrans: false,
		},
		{
			name:      "Multicast 224.0.0.1",
			srcIP:     "10.1.2.55",
			destIP:    "224.0.0.1",
			wantTrans: false,
		},
		{
			name:      "Broadcast 255.255.255.255",
			srcIP:     "10.1.2.55",
			destIP:    "255.255.255.255",
			wantTrans: false,
		},
		{
			name:      "Subnet broadcast 10.1.2.255",
			srcIP:     "10.1.2.55",
			destIP:    "10.1.2.255",
			wantTrans: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := net.ParseIP(tt.srcIP)
			dst := net.ParseIP(tt.destIP)
			pkt := buildIPv4Packet(src, dst, 1, 64, []byte{8, 0, 0, 0, 0, 1, 0, 1})
			isTrans, sIP, dIP := tf.IsTransitPacket(pkt)
			if isTrans != tt.wantTrans {
				t.Errorf("IsTransitPacket() = %v, want %v (src=%v, dst=%v)", isTrans, tt.wantTrans, sIP, dIP)
			}
		})
	}
}

func TestBuildIPv4Packet(t *testing.T) {
	src := net.ParseIP("1.1.1.1")
	dst := net.ParseIP("10.1.2.55")
	payload := []byte("HelloNatBypass")

	pkt := buildIPv4Packet(src, dst, 1, 64, payload)
	if len(pkt) != 20+len(payload) {
		t.Fatalf("len(pkt) = %d, want %d", len(pkt), 20+len(payload))
	}

	// Verify IPv4 header checksum
	cs := CalculateChecksum(pkt[:20])
	if cs != 0 {
		t.Errorf("IPv4 header checksum = 0x%04x, want 0", cs)
	}

	if pkt[0] != 0x45 {
		t.Errorf("IPv4 version/IHL = 0x%02x, want 0x45", pkt[0])
	}
	if pkt[9] != 1 {
		t.Errorf("Protocol = %d, want 1", pkt[9])
	}

	extractedSrc := GetSrcIP(pkt)
	extractedDst := GetDestIP(pkt)
	if !extractedSrc.Equal(src) {
		t.Errorf("SrcIP = %v, want %v", extractedSrc, src)
	}
	if !extractedDst.Equal(dst) {
		t.Errorf("DstIP = %v, want %v", extractedDst, dst)
	}
}

func TestBuildIPv4UDPPacket(t *testing.T) {
	src := net.ParseIP("8.8.8.8")
	dst := net.ParseIP("10.1.2.55")
	payload := []byte("DNSReplyData")

	pkt := buildIPv4UDPPacket(src, 53, dst, 12345, payload)
	if len(pkt) != 20+8+len(payload) {
		t.Fatalf("len(pkt) = %d, want %d", len(pkt), 28+len(payload))
	}

	// Checksum of IPv4 header
	cs := CalculateChecksum(pkt[:20])
	if cs != 0 {
		t.Errorf("IPv4 header checksum = 0x%04x, want 0", cs)
	}

	// UDP ports
	srcPort := binary.BigEndian.Uint16(pkt[20:22])
	dstPort := binary.BigEndian.Uint16(pkt[22:24])
	if srcPort != 53 {
		t.Errorf("srcPort = %d, want 53", srcPort)
	}
	if dstPort != 12345 {
		t.Errorf("dstPort = %d, want 12345", dstPort)
	}
}
