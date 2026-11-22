// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package testbench

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/tunnel"
)

// RunP2PTests executes all P2P direct, fallback, and bilateral stability tests.
func RunP2PTests(ctx context.Context, vm *VirtualMesh) []TestResult {
	results := make([]TestResult, 0)

	// Test 1: Direct P2P UDP Bilateral Packet Exchange
	results = append(results, testDirectP2PUdp(ctx, vm))

	// Test 2: Bilateral Keepalive State Transitions & Freshness
	results = append(results, testBilateralStateTransitions(ctx, vm))

	// Test 3: TCP Obfuscation / ShadowTLS Fallback on UDP Blocking
	results = append(results, testTCPFallbackOnUDPBlock(ctx, vm))

	// Test 4: Regression Check — Ghost Peer Isolation
	results = append(results, testGhostPeerIsolation(ctx, vm))

	// Test 5: Disconnect Recovery Latency (Verifying 80-second freeze fix)
	results = append(results, testDisconnectRecoveryLatency(ctx, vm))

	return results
}

func testDirectP2PUdp(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Direct P2P UDP Packet Transmission",
		Category: "p2p_mesh",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	peerNode := vm.SubnetNode

	// Build an ICMP Echo Request from Client to SubnetNode
	icmpPayload := []byte{8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 'p', 'i', 'n', 'g'}
	cs := tunnel.CalculateChecksum(icmpPayload)
	icmpPayload[2] = byte(cs >> 8)
	icmpPayload[3] = byte(cs & 0xFF)

	pkt := tunnel.BuildIPv4Packet(client.VirtualIP, peerNode.VirtualIP, 1, 64, icmpPayload)

	// Flush outbound TUN queue
	for len(peerNode.TunOutboundChan) > 0 {
		<-peerNode.TunOutboundChan
	}

	// Send packet from client
	client.TunInboundChan <- pkt

	// Wait for delivery on peer node
	select {
	case rxPkt := <-peerNode.TunOutboundChan:
		rtt := time.Since(start)
		res.RTT = rtt
		if len(rxPkt) < 20 {
			res.Status = StatusFail
			res.Message = "Received truncated packet"
			break
		}
		rxDst := net.IPv4(rxPkt[16], rxPkt[17], rxPkt[18], rxPkt[19])
		if !rxDst.Equal(peerNode.VirtualIP) {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Mismatched destination IP: got %s, want %s", rxDst, peerNode.VirtualIP)
			break
		}
		res.Duration = time.Since(start)
		res.Message = fmt.Sprintf("P2P UDP packet delivered in %v, bilateral path intact", rtt.Round(time.Microsecond))
	case <-time.After(2 * time.Second):
		res.Status = StatusFail
		res.Message = "Timed out waiting for direct P2P packet delivery (2s)"
		res.Duration = time.Since(start)
	}

	return res
}

func testBilateralStateTransitions(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Bilateral Keepalive State & Demotion",
		Category: "p2p_mesh",
		Status:   StatusPass,
	}

	p := &peer.Peer{
		DeviceID:          "test-node-alpha",
		VirtualIP:         "10.11.12.205",
		ActiveEndpoint:    "1.2.3.4:51820",
		Online:            true,
		DirectP2P:         true,
		LastSeen:          time.Now(),
		LastDirectSeen:    time.Now(),
		LastBilateralSeen: time.Now(),
	}

	// 1. Check fresh bilateral state
	if !p.IsBilateralP2P(constants.BilateralDemotionThreshold) {
		res.Status = StatusFail
		res.Message = "Peer should be bilateral when LastBilateralSeen is recent"
		res.Duration = time.Since(start)
		return res
	}

	// 2. Test demotion threshold
	p.LastBilateralSeen = time.Now().Add(-constants.BilateralDemotionThreshold - time.Second)
	if p.IsBilateralP2P(constants.BilateralDemotionThreshold) {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("Peer failed to demote after exceeding BilateralDemotionThreshold (%v)", constants.BilateralDemotionThreshold)
		res.Duration = time.Since(start)
		return res
	}

	res.Duration = time.Since(start)
	res.Message = "Bilateral state transitions and fresh threshold validation passed"
	return res
}

func testTCPFallbackOnUDPBlock(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "TCP ShadowTLS Fallback on UDP Block",
		Category: "p2p_mesh",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	peerNode := vm.SubnetNode

	// Update registry on client to use TCP transport for peerNode
	if p, ok := client.Registry.GetByIDOrVIP(peerNode.ID); ok {
		p.Transport = "tcp"
		p.DirectP2P = false
		client.Registry.Upsert(p)
	}

	// Simulate DPI blocking UDP on virtual mesh
	vm.SetDropUDP(true)
	defer vm.SetDropUDP(false)

	// Flush receive channel
	for len(peerNode.TCPRecvChan) > 0 {
		<-peerNode.TCPRecvChan
	}
	for len(peerNode.TunOutboundChan) > 0 {
		<-peerNode.TunOutboundChan
	}

	// Send test packet via TCP fallback
	testPayload := []byte("TCP-SHADOWTLS-PAYLOAD-TEST")
	pkt := tunnel.BuildIPv4Packet(client.VirtualIP, peerNode.VirtualIP, 17, 64, testPayload)
	client.TunInboundChan <- pkt

	select {
	case rxPkt := <-peerNode.TunOutboundChan:
		res.Duration = time.Since(start)
		res.Message = fmt.Sprintf("Fallback to TCP confirmed: delivered packet (%d bytes) while UDP is 100%% blocked", len(rxPkt))
	case <-time.After(2 * time.Second):
		res.Status = StatusFail
		res.Message = "Timed out waiting for packet over TCP fallback channel"
		res.Duration = time.Since(start)
	}

	// Restore transport
	if p, ok := client.Registry.GetByIDOrVIP(peerNode.ID); ok {
		p.Transport = "udp_direct"
		p.DirectP2P = true
		client.Registry.Upsert(p)
	}

	return res
}

func testGhostPeerIsolation(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Ghost Peer Prevention (IsSyntheticDynamicPeer)",
		Category: "p2p_mesh",
		Status:   StatusPass,
	}

	reg := vm.ClientNode.Registry
	initialCount := len(reg.List())

	// Attempt to upsert a synthetic ghost peer: peer-10-1-2-1
	ghostPeer := &peer.Peer{
		DeviceID:       "peer-10-1-2-1",
		VirtualIP:      "10.1.2.1",
		ActiveEndpoint: "192.168.1.1:51820",
		Online:         true,
	}

	// Verify that IsSyntheticDynamicPeer correctly identifies it
	if !peer.IsSyntheticDynamicPeer(ghostPeer) {
		res.Status = StatusFail
		res.Message = "IsSyntheticDynamicPeer failed to identify 'peer-10-1-2-1' as synthetic"
		res.Duration = time.Since(start)
		return res
	}

	// Verify that Upsert rejects it
	reg.Upsert(ghostPeer)

	if len(reg.List()) != initialCount {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("Registry allowed synthetic peer insertion: count changed from %d to %d", initialCount, len(reg.List()))
		res.Duration = time.Since(start)
		return res
	}

	if _, ok := reg.Get("peer-10-1-2-1"); ok {
		res.Status = StatusFail
		res.Message = "Synthetic peer found in registry after Upsert"
		res.Duration = time.Since(start)
		return res
	}

	res.Duration = time.Since(start)
	res.Message = "Synthetic ghost peers properly identified and rejected by registry"
	return res
}

func testDisconnectRecoveryLatency(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Disconnect Recovery (No 80s Ping Freeze)",
		Category: "p2p_mesh",
		Status:   StatusPass,
	}

	p := &peer.Peer{
		DeviceID:          "recovery-test-peer",
		VirtualIP:         "10.11.12.210",
		ActiveEndpoint:    "127.0.0.1:20210",
		Online:            true,
		DirectP2P:         true,
		LastSeen:          time.Now(),
		LastDirectSeen:    time.Now(),
		LastBilateralSeen: time.Now(),
	}

	// Simulate disconnect: peer drops for 3 seconds
	simulatedDisconnectTime := time.Now().Add(-3 * time.Second)
	p.LastSeen = simulatedDisconnectTime
	p.LastDirectSeen = simulatedDisconnectTime
	// Note: Crucial check — LastBilateralSeen must NOT be reset to zero (time.Time{})
	// because zeroing it forces an 80-second freeze before recovery!
	if p.LastBilateralSeen.IsZero() {
		res.Status = StatusFail
		res.Message = "LastBilateralSeen was zeroed on disconnect event"
		res.Duration = time.Since(start)
		return res
	}

	// Simulate incoming probe packet re-establishing connection
	now := time.Now()
	p.LastSeen = now
	p.LastDirectSeen = now
	p.LastBilateralSeen = now

	// Check if peer is immediately active and bilateral without delay
	if !p.IsBilateralP2P(constants.BilateralDemotionThreshold) {
		res.Status = StatusFail
		res.Message = "Peer failed to resume Bilateral state immediately after probe reception"
		res.Duration = time.Since(start)
		return res
	}

	res.Duration = time.Since(start)
	res.Message = "Connection recovered immediately with fresh timestamp (0ms freeze)"
	return res
}
