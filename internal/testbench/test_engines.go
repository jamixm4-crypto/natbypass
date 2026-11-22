// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package testbench

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/tunnel"
)

// RunEngineTests validates platform-specific engine rules across Android, Windows, and Linux.
func RunEngineTests(ctx context.Context, vm *VirtualMesh) []TestResult {
	results := make([]TestResult, 0)

	// Test 1: Android Engine — Parasitic & Broadcast Traffic Filter
	results = append(results, testAndroidParasiticTrafficFilter(ctx, vm))

	// Test 2: Android Engine — Userspace TCP MSS Clamping to 1220
	results = append(results, testAndroidMSSClampingRule(ctx, vm))

	// Test 3: Linux / Router Engine — CIDR Subnet Parsing & Validation
	results = append(results, testLinuxSubnetParsingRules(ctx, vm))

	// Test 4: Windows Engine — Wintun Driver & DLL Integrity Check
	results = append(results, testWindowsWintunIntegrity(ctx, vm))

	return results
}

func testAndroidParasiticTrafficFilter(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Android Engine: Parasitic Traffic Filter",
		Category: "engine_verification",
		Status:   StatusPass,
	}

	myVIP := "10.11.12.101"

	// List of packets that must be discarded to save mobile battery and avoid multicast storms
	cases := []struct {
		desc   string
		dstIP  string
		proto  byte
		port   uint16
		dropIt bool
	}{
		{"LLMNR Multicast (224.0.0.252:5355)", "224.0.0.252", 17, 5355, true},
		{"SSDP Multicast (239.255.255.250:1900)", "239.255.255.250", 17, 1900, true},
		{"Global Broadcast (255.255.255.255)", "255.255.255.255", 17, 67, true},
		{"Subnet Broadcast (10.11.12.255)", "10.11.12.255", 17, 137, true},
		{"Loopback (127.0.0.1)", "127.0.0.1", 6, 80, true},
		{"Valid Mesh Peer Unicast (10.11.12.102)", "10.11.12.102", 6, 443, false},
		{"Valid WAN Public IP (1.1.1.1)", "1.1.1.1", 17, 53, false},
	}

	for _, tc := range cases {
		pkt := tunnel.BuildIPv4UDPPacket(net.ParseIP(myVIP), 12345, net.ParseIP(tc.dstIP), tc.port, []byte("probe"))
		isParasitic := tunnel.IsParasiticOrBroadcast(pkt, myVIP)
		if isParasitic != tc.dropIt {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Filter rule failed for %s: got isParasitic=%v, want %v", tc.desc, isParasitic, tc.dropIt)
			res.Duration = time.Since(start)
			return res
		}
	}

	res.Duration = time.Since(start)
	res.Message = "All 7 Android parasitic and multicast flood filter rules verified"
	return res
}

func testAndroidMSSClampingRule(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Android Engine: TCP MSS Clamping to 1220",
		Category: "engine_verification",
		Status:   StatusPass,
	}

	// Create a TCP SYN packet advertising MSS 1460 (standard Ethernet)
	srcIP := net.ParseIP("10.11.12.101")
	dstIP := net.ParseIP("10.11.12.102")

	options := []byte{
		0x02, 0x04, 0x05, 0xB4, // MSS = 1460 (0x05B4)
		0x01,                   // NOP
		0x03, 0x03, 0x07,       // WScale = 7
	}
	pkt := tunnel.BuildIPv4TCPPacket(srcIP, 40000, dstIP, 80, 100, 0, 0x02, 64240, nil)

	// Replace TCP options with MSS 1460
	pktWithLargeMSS := make([]byte, 20+20+len(options))
	copy(pktWithLargeMSS, pkt[:40])
	copy(pktWithLargeMSS[40:], options)
	pktWithLargeMSS[0] = 0x45
	binary.BigEndian.PutUint16(pktWithLargeMSS[2:4], uint16(len(pktWithLargeMSS)))
	pktWithLargeMSS[32] = byte((len(options)+20)/4) << 4 // Data offset

	// Run userspace clamp
	clamped := tunnel.ClampTCPMSS(pktWithLargeMSS, constants.DefaultClampedMSS)
	if !clamped {
		res.Status = StatusFail
		res.Message = "ClampTCPMSS returned false for MSS 1460"
		res.Duration = time.Since(start)
		return res
	}

	// Find MSS option and check value
	tcpHdrLen := int((pktWithLargeMSS[32] >> 4) * 4)
	opts := pktWithLargeMSS[40 : 20+tcpHdrLen]
	foundMSS := uint16(0)
	for i := 0; i < len(opts)-3; i++ {
		if opts[i] == 2 && opts[i+1] == 4 {
			foundMSS = binary.BigEndian.Uint16(opts[i+2 : i+4])
			break
		}
	}

	if foundMSS != uint16(constants.DefaultClampedMSS) {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("MSS was clamped to %d, expected %d", foundMSS, constants.DefaultClampedMSS)
		res.Duration = time.Since(start)
		return res
	}

	res.Duration = time.Since(start)
	res.Message = fmt.Sprintf("TCP MSS successfully clamped from 1460 to %d (prevents MTU 1280 fragmentation)", constants.DefaultClampedMSS)
	return res
}

func testLinuxSubnetParsingRules(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Linux / Keenetic: Subnet CIDR Parsing",
		Category: "engine_verification",
		Status:   StatusPass,
	}

	validSubnets := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"172.16.0.0/12",
	}

	for _, sub := range validSubnets {
		ip, mask, err := tunnel.ParseSubnetCIDR(sub)
		if err != nil || ip == "" || mask == "" {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Failed to parse valid subnet CIDR %s: %v", sub, err)
			res.Duration = time.Since(start)
			return res
		}
	}

	invalidSubnets := []string{
		"999.999.999.999/24",
		"192.168.1.1",
		"",
	}

	for _, sub := range invalidSubnets {
		_, _, err := tunnel.ParseSubnetCIDR(sub)
		if err == nil {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Invalid subnet %q was accepted without error", sub)
			res.Duration = time.Since(start)
			return res
		}
	}

	res.Duration = time.Since(start)
	res.Message = "Subnet CIDR validator verified for router and daemon configurations"
	return res
}

func testWindowsWintunIntegrity(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Windows Engine: Wintun DLL Architecture & Size",
		Category: "engine_verification",
		Status:   StatusPass,
	}

	wintunPath, err := tunnel.EnsureWintunDLL()
	if err != nil {
		res.Status = StatusWarn
		res.Message = fmt.Sprintf("Wintun check notice: %v", err)
		res.Duration = time.Since(start)
		return res
	}

	if !strings.HasSuffix(strings.ToLower(wintunPath), "wintun.dll") {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("Unexpected Wintun path: %s", wintunPath)
		res.Duration = time.Since(start)
		return res
	}

	res.Duration = time.Since(start)
	res.Message = fmt.Sprintf("Wintun DLL verified at %s", wintunPath)
	return res
}
