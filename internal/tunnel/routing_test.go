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
)

func TestParseSubnetCIDR(t *testing.T) {
	tests := []struct {
		cidr        string
		expectedIP  string
		expectedMask string
		expectErr   bool
	}{
		{
			cidr:        "192.168.1.0/24",
			expectedIP:  "192.168.1.0",
			expectedMask: "255.255.255.0",
			expectErr:   false,
		},
		{
			cidr:        "10.0.0.0/8",
			expectedIP:  "10.0.0.0",
			expectedMask: "255.0.0.0",
			expectErr:   false,
		},
		{
			cidr:        "172.16.5.12/16",
			expectedIP:  "172.16.0.0",
			expectedMask: "255.255.0.0",
			expectErr:   false,
		},
		{
			cidr:        "192.168.100.50/32",
			expectedIP:  "192.168.100.50",
			expectedMask: "255.255.255.255",
			expectErr:   false,
		},
		{
			cidr:      "invalid",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		ip, mask, err := parseSubnetCIDR(tt.cidr)
		if tt.expectErr {
			if err == nil {
				t.Errorf("parseSubnetCIDR(%q) expected error, got nil", tt.cidr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSubnetCIDR(%q) unexpected error: %v", tt.cidr, err)
			continue
		}
		if ip != tt.expectedIP {
			t.Errorf("parseSubnetCIDR(%q) IP = %v, want %v", tt.cidr, ip, tt.expectedIP)
		}
		if mask != tt.expectedMask {
			t.Errorf("parseSubnetCIDR(%q) Mask = %v, want %v", tt.cidr, mask, tt.expectedMask)
		}
	}
}

func TestIsParasiticOrBroadcast(t *testing.T) {
	myVIP := "10.1.1.5"

	buildIPv4Packet := func(src, dst net.IP, proto byte, dstPort uint16) []byte {
		pkt := make([]byte, 28)
		pkt[0] = 0x45 // IPv4, IHL=5
		pkt[9] = proto
		copy(pkt[12:16], src.To4())
		copy(pkt[16:20], dst.To4())
		if proto == 17 && dstPort > 0 { // UDP
			binary.BigEndian.PutUint16(pkt[22:24], dstPort)
		}
		return pkt
	}

	tests := []struct {
		name     string
		src      string
		dst      string
		proto    byte
		port     uint16
		expected bool
	}{
		{"Valid mesh unicast", "10.1.1.5", "10.1.1.6", 1, 0, false},
		{"Valid TCP data", "10.1.1.5", "10.1.1.7", 6, 80, false},
		{"Multicast 224.0.0.252 (LLMNR)", "10.1.1.5", "224.0.0.252", 17, 5355, true},
		{"Multicast 239.255.255.250 (SSDP)", "10.1.1.5", "239.255.255.250", 17, 1900, true},
		{"Global broadcast 255.255.255.255", "10.1.1.5", "255.255.255.255", 17, 51820, true},
		{"Subnet broadcast .255", "10.1.1.5", "10.1.1.255", 17, 47832, true},
		{"Subnet network .0", "10.1.1.5", "10.1.1.0", 1, 0, true},
		{"Link-local unicast 169.254.1.1", "10.1.1.5", "169.254.1.1", 1, 0, true},
		{"Loopback 127.0.0.1", "10.1.1.5", "127.0.0.1", 1, 0, true},
		{"Self loopback (myVIP)", "10.1.1.5", "10.1.1.5", 1, 0, true},
		{"NetBIOS Name Service noise", "10.1.1.5", "10.1.1.20", 17, 137, true},
		{"mDNS noise", "10.1.1.5", "10.1.1.20", 17, 5353, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := buildIPv4Packet(net.ParseIP(tt.src), net.ParseIP(tt.dst), tt.proto, tt.port)
			got := IsParasiticOrBroadcast(pkt, myVIP)
			if got != tt.expected {
				t.Errorf("IsParasiticOrBroadcast(%s -> %s, proto %d, port %d) = %v; want %v",
					tt.src, tt.dst, tt.proto, tt.port, got, tt.expected)
			}
		})
	}
}

func TestClampTCPMSS(t *testing.T) {
	buildTCPSYN := func(src, dst net.IP, mss uint16) []byte {
		// 20 bytes IP + 24 bytes TCP (20 header + 4 MSS option)
		pkt := make([]byte, 44)
		pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
		binary.BigEndian.PutUint16(pkt[2:4], 44)
		pkt[9] = 6 // TCP
		copy(pkt[12:16], src.To4())
		copy(pkt[16:20], dst.To4())

		// TCP header at offset 20
		binary.BigEndian.PutUint16(pkt[20:22], 12345) // Src port
		binary.BigEndian.PutUint16(pkt[22:24], 80)    // Dst port
		pkt[20+12] = (6 << 4)                         // Data offset = 6 (24 bytes)
		pkt[20+13] = 0x02                             // SYN flag

		// MSS option at offset 40 (Kind=2, Len=4)
		pkt[40] = 2
		pkt[41] = 4
		binary.BigEndian.PutUint16(pkt[42:44], mss)

		return pkt
	}

	src := net.ParseIP("10.1.1.5")
	dst := net.ParseIP("10.1.1.6")

	t.Run("Clamp larger MSS to 1240", func(t *testing.T) {
		pkt := buildTCPSYN(src, dst, 1460)
		modified := ClampTCPMSS(pkt, 1240)
		if !modified {
			t.Fatalf("expected ClampTCPMSS to return true for MSS=1460 > 1240")
		}
		newMSS := binary.BigEndian.Uint16(pkt[42:44])
		if newMSS != 1240 {
			t.Errorf("expected clamped MSS=1240, got %d", newMSS)
		}
		// Verify TCP checksum is non-zero
		csum := binary.BigEndian.Uint16(pkt[36:38])
		if csum == 0 {
			t.Errorf("expected non-zero TCP checksum after clamping")
		}
	})

	t.Run("Do not modify smaller MSS", func(t *testing.T) {
		pkt := buildTCPSYN(src, dst, 1200)
		modified := ClampTCPMSS(pkt, 1240)
		if modified {
			t.Fatalf("expected ClampTCPMSS to return false for MSS=1200 <= 1240")
		}
		mss := binary.BigEndian.Uint16(pkt[42:44])
		if mss != 1200 {
			t.Errorf("expected unchanged MSS=1200, got %d", mss)
		}
	})
}

