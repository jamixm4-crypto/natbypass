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

	"github.com/natbypass/natbypass/internal/tunnel"
)

// RunSubnetTests validates subnet advertisement, LPM routing, and isolation.
func RunSubnetTests(ctx context.Context, vm *VirtualMesh) []TestResult {
	results := make([]TestResult, 0)

	// Test 1: LPM Routing Precedence (Subnet Route vs Exit Node)
	results = append(results, testSubnetLPMPrecedence(ctx, vm))

	// Test 2: Subnet Bidirectional Packet Exchange (Echo)
	results = append(results, testSubnetBidirectionalTransit(ctx, vm))

	// Test 3: Subnet Non-Overlapping Fallback Isolation
	results = append(results, testSubnetNonOverlappingIsolation(ctx, vm))

	return results
}

func testSubnetLPMPrecedence(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Subnet LPM Precedence (Route vs Exit Node)",
		Category: "subnet_routing",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	exitNode := vm.ExitNode
	subnetNode := vm.SubnetNode

	// Configure client with both: an active Exit Node AND Subnet Route
	client.SelectedExitNode = exitNode.ID

	// Target IP is inside the advertised subnet 192.168.100.0/24
	targetSubnetIP := net.ParseIP("192.168.100.42")
	pkt := tunnel.BuildIPv4Packet(client.VirtualIP, targetSubnetIP, 17, 64, []byte("SUBNET-DATA"))

	// Flush queues
	for len(subnetNode.TunOutboundChan) > 0 {
		<-subnetNode.TunOutboundChan
	}
	for len(exitNode.UDPRecvChan) > 0 {
		<-exitNode.UDPRecvChan
	}

	// Send packet from client
	client.TunInboundChan <- pkt

	// Verify that subnetNode received it, NOT exitNode!
	select {
	case rxPkt := <-subnetNode.TunOutboundChan:
		rtt := time.Since(start)
		res.RTT = rtt
		res.Duration = rtt
		dstIP := net.IPv4(rxPkt[16], rxPkt[17], rxPkt[18], rxPkt[19])
		if !dstIP.Equal(targetSubnetIP) {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Mismatched packet destination: got %s, want %s", dstIP, targetSubnetIP)
			return res
		}

		// Double-check exitNode didn't receive it
		if len(exitNode.UDPRecvChan) > 0 {
			res.Status = StatusFail
			res.Message = "LPM Violation: Subnet packet was erroneously leaked to Exit Node!"
			return res
		}

		res.Message = fmt.Sprintf("LPM route matched successfully in %v (delivered to %s, exit node bypassed)", rtt.Round(time.Microsecond), subnetNode.Name)
	case <-time.After(2 * time.Second):
		res.Status = StatusFail
		res.Message = "Timed out waiting for subnet packet delivery on subnet gateway"
		res.Duration = time.Since(start)
	}

	return res
}

func testSubnetBidirectionalTransit(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Subnet Bidirectional Round-Trip Transit",
		Category: "subnet_routing",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	subnetNode := vm.SubnetNode

	targetSubnetIP := net.ParseIP("192.168.100.77")

	// 1. Client sends request to target in subnet
	reqPayload := []byte("PING-REQ-SUBNET")
	reqPkt := tunnel.BuildIPv4Packet(client.VirtualIP, targetSubnetIP, 1, 64, reqPayload)

	for len(client.TunOutboundChan) > 0 {
		<-client.TunOutboundChan
	}
	for len(subnetNode.TunOutboundChan) > 0 {
		<-subnetNode.TunOutboundChan
	}

	client.TunInboundChan <- reqPkt

	// 2. SubnetNode receives packet from mesh and simulates LAN host responding
	select {
	case <-subnetNode.TunOutboundChan:
		// SubnetNode crafts reply from LAN host back to client VIP
		respPayload := []byte("PONG-RESP-SUBNET")
		respPkt := tunnel.BuildIPv4Packet(targetSubnetIP, client.VirtualIP, 1, 64, respPayload)

		// SubnetNode injects reply into its TunInboundChan
		subnetNode.TunInboundChan <- respPkt

		// 3. Client receives reply
		select {
		case clientRx := <-client.TunOutboundChan:
			rtt := time.Since(start)
			res.RTT = rtt
			res.Duration = rtt
			srcIP := net.IPv4(clientRx[12], clientRx[13], clientRx[14], clientRx[15])
			if !srcIP.Equal(targetSubnetIP) {
				res.Status = StatusFail
				res.Message = fmt.Sprintf("Response source mismatch: got %s, want %s", srcIP, targetSubnetIP)
				return res
			}
			res.Message = fmt.Sprintf("Full subnet round-trip completed in %v (%s <-> %s)", rtt.Round(time.Microsecond), client.VirtualIP, targetSubnetIP)
		case <-time.After(2 * time.Second):
			res.Status = StatusFail
			res.Message = "Timed out waiting for subnet response on client TUN"
			res.Duration = time.Since(start)
		}
	case <-time.After(2 * time.Second):
		res.Status = StatusFail
		res.Message = "Subnet gateway did not receive client packet"
		res.Duration = time.Since(start)
	}

	return res
}

func testSubnetNonOverlappingIsolation(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "Non-Advertised Subnet Fallback Isolation",
		Category: "subnet_routing",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	exitNode := vm.ExitNode
	subnetNode := vm.SubnetNode

	client.SelectedExitNode = exitNode.ID

	// Target IP is outside the advertised 192.168.100.0/24 subnet (e.g. 192.168.200.99)
	unadvertisedIP := net.ParseIP("192.168.200.99")
	pkt := tunnel.BuildIPv4Packet(client.VirtualIP, unadvertisedIP, 17, 64, []byte("FALLBACK-TEST"))

	exitRxBefore := exitNode.RxPackets.Load()
	subnetRxBefore := subnetNode.RxPackets.Load()

	client.TunInboundChan <- pkt

	// It must fall through to Exit Node, and NOT be grabbed by SubnetNode!
	timeout := time.After(2 * time.Second)
	deliveredToExit := false
	for !deliveredToExit {
		select {
		case <-timeout:
			res.Status = StatusFail
			res.Message = "Timed out waiting for fallback packet at exit node"
			res.Duration = time.Since(start)
			return res
		default:
			if subnetNode.RxPackets.Load() > subnetRxBefore {
				res.Status = StatusFail
				res.Message = "Isolation failure: Unadvertised subnet packet erroneously accepted by subnet gateway"
				res.Duration = time.Since(start)
				return res
			}
			if exitNode.RxPackets.Load() > exitRxBefore {
				deliveredToExit = true
			} else {
				time.Sleep(5 * time.Millisecond)
			}
		}
	}

	res.Duration = time.Since(start)
	res.Message = "Unadvertised route cleanly fell back to Exit Node without leaking into subnet"
	return res
}
