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

	// Verify UDP checksum using standard 1's complement algorithm over pseudo-header + UDP datagram
	var pseudoSum uint32
	pseudoSum += uint32(binary.BigEndian.Uint16(src.To4()[0:2]))
	pseudoSum += uint32(binary.BigEndian.Uint16(src.To4()[2:4]))
	pseudoSum += uint32(binary.BigEndian.Uint16(dst.To4()[0:2]))
	pseudoSum += uint32(binary.BigEndian.Uint16(dst.To4()[2:4]))
	pseudoSum += uint32(17) // Proto UDP
	pseudoSum += uint32(8 + len(payload))
	for i := 20; i < len(pkt)-1; i += 2 {
		pseudoSum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	if len(payload)%2 != 0 {
		pseudoSum += uint32(pkt[len(pkt)-1]) << 8
	}
	for pseudoSum > 0xFFFF {
		pseudoSum = (pseudoSum & 0xFFFF) + (pseudoSum >> 16)
	}
	if ^uint16(pseudoSum) != 0 {
		t.Errorf("UDP checksum verification failed: 0x%04x, want 0", ^uint16(pseudoSum))
	}
}

func TestTransitForwarder_DoTRejection(t *testing.T) {
	myVIP := "10.1.2.1/24"
	var deliveredPacket []byte

	mockPeer := &peer.Peer{
		DeviceID:  "android-client",
		VirtualIP: "10.1.2.55/24",
	}

	tf := NewTransitForwarder(
		myVIP,
		func(vipOrID string) *peer.Peer {
			if vipOrID == "10.1.2.55" || vipOrID == "android-client" {
				return mockPeer
			}
			return nil
		},
		func(destPeer *peer.Peer, packet []byte) error {
			deliveredPacket = make([]byte, len(packet))
			copy(deliveredPacket, packet)
			return nil
		},
	)
	defer tf.Close()

	// Simulate Android sending a TCP SYN to 1.1.1.1:853 (DNS-over-TLS)
	clientIP := net.ParseIP("10.1.2.55")
	dotServerIP := net.ParseIP("1.1.1.1")
	synPkt := buildIPv4TCPPacket(clientIP, 54321, dotServerIP, 853, 1000, 0, 0x02, 64240, nil)

	handled := tf.HandleTransitPacketWithSender(synPkt, mockPeer)
	if !handled {
		t.Fatalf("HandleTransitPacketWithSender returned false for DoT SYN packet")
	}

	if deliveredPacket == nil {
		t.Fatalf("Expected immediate TCP RST packet to be delivered, got nil")
	}

	// Verify the delivered packet is a TCP RST (flags 0x14)
	if len(deliveredPacket) < 40 {
		t.Fatalf("Delivered packet too short: %d bytes", len(deliveredPacket))
	}

	srcIP := GetSrcIP(deliveredPacket)
	dstIP := GetDestIP(deliveredPacket)
	if !srcIP.Equal(dotServerIP) {
		t.Errorf("RST SrcIP = %v, want %v", srcIP, dotServerIP)
	}
	if !dstIP.Equal(clientIP) {
		t.Errorf("RST DstIP = %v, want %v", dstIP, clientIP)
	}

	tcpHdr := deliveredPacket[20:]
	srcPort := binary.BigEndian.Uint16(tcpHdr[0:2])
	dstPort := binary.BigEndian.Uint16(tcpHdr[2:4])
	if srcPort != 853 {
		t.Errorf("RST srcPort = %d, want 853", srcPort)
	}
	if dstPort != 54321 {
		t.Errorf("RST dstPort = %d, want 54321", dstPort)
	}

	flags := tcpHdr[13]
	if flags != 0x14 { // RST|ACK
		t.Errorf("RST flags = 0x%02x, want 0x14 (RST|ACK)", flags)
	}
}
