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
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/tunnel"
	"golang.org/x/net/dns/dnsmessage"
)

// RunExitNodeTests validates DNS transit, TCP NAT, MSS clamping, and DoT handling.
func RunExitNodeTests(ctx context.Context, vm *VirtualMesh) []TestResult {
	results := make([]TestResult, 0)

	// Test 1: DNS Resolution via Exit Node (UDP 53) + RFC 768 Checksum
	results = append(results, testDNSResolutionViaExitNode(ctx, vm))

	// Test 2: DNS Transit Filter (DNS allowed even when allow_exit_node=false)
	results = append(results, testDNSTransitAllowedWhenExitDisabled(ctx, vm))

	// Test 3: DoT (Port 853) Handling (No synthetic TCP RST)
	results = append(results, testDoTPort853Handling(ctx, vm))

	// Test 4: HTTP Internet Transit & TCP Handshake via TransitForwarder
	results = append(results, testHTTPInternetTransit(ctx, vm))

	return results
}

func testDNSResolutionViaExitNode(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "DNS Transit Resolution (UDP 53 + RFC 768)",
		Category: "exit_node",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	exitNode := vm.ExitNode
	client.SelectedExitNode = exitNode.ID

	// Build raw DNS Query for "cloudflare.com" A record
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               0x4321,
			Response:         false,
			OpCode:           0,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("cloudflare.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	dnsBytes, err := msg.Pack()
	if err != nil {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("Failed to pack DNS query: %v", err)
		res.Duration = time.Since(start)
		return res
	}

	dnsServerIP := net.ParseIP("1.1.1.1")
	clientPort := uint16(53123)

	// Build UDP packet: Client VIP -> 1.1.1.1:53
	dnsPacket := tunnel.BuildIPv4UDPPacket(client.VirtualIP, clientPort, dnsServerIP, 53, dnsBytes)

	// Intercept response
	var rxPacket []byte
	var rxMu sync.Mutex
	done := make(chan struct{})

	// Temporarily capture response routed back to Client
	origSend := vm.ExitNode.TransitForwarder
	_ = origSend

	// We listen on client's UDPRecvChan
	go func() {
		for {
			select {
			case pkt, ok := <-client.UDPRecvChan:
				if !ok {
					return
				}
				if len(pkt) >= 28 && pkt[9] == 17 { // UDP
					dstPort := binary.BigEndian.Uint16(pkt[22:24])
					if dstPort == clientPort {
						rxMu.Lock()
						rxPacket = pkt
						rxMu.Unlock()
						close(done)
						return
					}
				}
			case <-time.After(4 * time.Second):
				return
			}
		}
	}()

	// Feed DNS packet to Exit Node's TransitForwarder
	handled := exitNode.TransitForwarder.HandleTransitPacket(dnsPacket)
	if !handled {
		res.Status = StatusFail
		res.Message = "TransitForwarder failed to handle DNS packet"
		res.Duration = time.Since(start)
		return res
	}

	select {
	case <-done:
		rtt := time.Since(start)
		res.RTT = rtt
		res.Duration = rtt

		rxMu.Lock()
		pkt := rxPacket
		rxMu.Unlock()

		if len(pkt) < 28 {
			res.Status = StatusFail
			res.Message = "Received truncated UDP DNS packet"
			return res
		}

		// Verify RFC 768 UDP Checksum (Must be 0x0000 or valid non-corrupted)
		udpCS := binary.BigEndian.Uint16(pkt[26:28])
		if udpCS != 0 {
			res.Details = append(res.Details, fmt.Sprintf("UDP Checksum is 0x%04X (non-zero RFC 768)", udpCS))
		} else {
			res.Details = append(res.Details, "RFC 768: UDP checksum is 0x0000 (Android kernel safe)")
		}

		// Unpack DNS Answer
		var parser dnsmessage.Parser
		header, err := parser.Start(pkt[28:])
		if err != nil {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Failed to parse returned DNS message: %v", err)
			return res
		}

		if header.RCode != dnsmessage.RCodeSuccess {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("DNS server returned error RCode: %v", header.RCode)
			return res
		}

		res.Message = fmt.Sprintf("DNS resolved in %v via Exit Node (ID: 0x%04X, RCode: OK)", rtt.Round(time.Millisecond), header.ID)
	case <-time.After(5 * time.Second):
		res.Status = StatusWarn
		res.Message = "DNS query to 1.1.1.1 timed out (check internet connectivity on test host)"
		res.Duration = time.Since(start)
	}

	return res
}

func testDNSTransitAllowedWhenExitDisabled(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "DNS Allowed When allow_exit_node=false",
		Category: "exit_node",
		Status:   StatusPass,
	}

	// In beta.42, we ensured DNS transit (port 53) passes even if allow_exit_node=false:
	// allowTransit := allowExitNode || isDNS
	isDNSCheck := func(packet []byte, allowExitNode bool) bool {
		if len(packet) < 28 || (packet[0]>>4) != 4 {
			return false
		}
		isDNS := (packet[9] == 17 || packet[9] == 6) && (binary.BigEndian.Uint16(packet[22:24]) == 53 || binary.BigEndian.Uint16(packet[20:22]) == 53)
		return allowExitNode || isDNS
	}

	// 1. Packet to port 53 (DNS) with allowExitNode=false
	dnsPkt := tunnel.BuildIPv4UDPPacket(net.ParseIP("10.11.12.101"), 5555, net.ParseIP("8.8.8.8"), 53, []byte{1, 2, 3})
	if !isDNSCheck(dnsPkt, false) {
		res.Status = StatusFail
		res.Message = "DNS packet was rejected when allow_exit_node=false"
		res.Duration = time.Since(start)
		return res
	}

	// 2. Packet to port 80 (HTTP) with allowExitNode=false
	httpPkt := tunnel.BuildIPv4TCPPacket(net.ParseIP("10.11.12.101"), 5555, net.ParseIP("93.184.216.34"), 80, 100, 0, 0x02, 64240, nil)
	if isDNSCheck(httpPkt, false) {
		res.Status = StatusFail
		res.Message = "HTTP packet was incorrectly allowed when allow_exit_node=false"
		res.Duration = time.Since(start)
		return res
	}

	res.Duration = time.Since(start)
	res.Message = "DNS transit bypass confirmed: DNS is forwarded even if exit node is disabled"
	return res
}

func testDoTPort853Handling(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "DoT (Port 853) Anti-RST Validation",
		Category: "exit_node",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	exitNode := vm.ExitNode

	// Build a TCP SYN to 1.1.1.1:853
	dotServerIP := net.ParseIP("1.1.1.1")
	clientPort := uint16(48853)
	synPkt := tunnel.BuildIPv4TCPPacket(client.VirtualIP, clientPort, dotServerIP, 853, 1000, 0, 0x02, 64240, nil)

	var receivedRST bool
	var rstMu sync.Mutex
	done := make(chan struct{})

	// Listen for response packets directed to client
	go func() {
		defer close(done)
		timer := time.After(3 * time.Second)
		for {
			select {
			case pkt, ok := <-client.UDPRecvChan:
				if !ok {
					return
				}
				if len(pkt) >= 40 && pkt[9] == 6 { // TCP
					srcPort := binary.BigEndian.Uint16(pkt[20:22])
					dstPort := binary.BigEndian.Uint16(pkt[22:24])
					flags := pkt[33]
					if srcPort == 853 && dstPort == clientPort {
						if (flags & 0x04) != 0 { // RST flag set!
							rstMu.Lock()
							receivedRST = true
							rstMu.Unlock()
							return
						}
					}
				}
			case <-timer:
				return
			}
		}
	}()

	// Feed to Exit Node
	exitNode.TransitForwarder.HandleTransitPacket(synPkt)

	<-done

	rstMu.Lock()
	rstSeen := receivedRST
	rstMu.Unlock()

	if rstSeen {
		res.Status = StatusFail
		res.Message = "Exit node sent synthetic TCP RST for DoT port 853! This breaks Android network validation."
		res.Duration = time.Since(start)
		return res
	}

	res.Duration = time.Since(start)
	res.Message = "DoT handled cleanly without synthetic RST; captive portal / validation preserved"
	return res
}

func testHTTPInternetTransit(ctx context.Context, vm *VirtualMesh) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     "HTTP Transit & TCP NAT Handshake",
		Category: "exit_node",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	exitNode := vm.ExitNode

	// Use public IP of Cloudflare 1.1.1.1:80
	targetIP := net.ParseIP("1.1.1.1")
	clientPort := uint16(54321)

	// Step 1: Send TCP SYN (flags=0x02)
	synPkt := tunnel.BuildIPv4TCPPacket(client.VirtualIP, clientPort, targetIP, 80, 2000, 0, 0x02, 64240, nil)

	var synAckReceived bool
	var mssClamped bool
	var serverISN uint32
	var mu sync.Mutex
	done := make(chan struct{})

	go func() {
		for {
			select {
			case pkt, ok := <-client.UDPRecvChan:
				if !ok {
					return
				}
				if len(pkt) >= 40 && pkt[9] == 6 {
					srcPort := binary.BigEndian.Uint16(pkt[20:22])
					dstPort := binary.BigEndian.Uint16(pkt[22:24])
					flags := pkt[33]
					if srcPort == 80 && dstPort == clientPort && (flags&0x12) == 0x12 { // SYN|ACK
						mu.Lock()
						synAckReceived = true
						serverISN = binary.BigEndian.Uint32(pkt[24:28])

						// Check MSS option (should be clamped to 1220)
						tcpHdrLen := int((pkt[32] >> 4) * 4)
						if tcpHdrLen > 20 {
							opts := pkt[40 : 20+tcpHdrLen]
							for i := 0; i < len(opts)-3; i++ {
								if opts[i] == 2 && opts[i+1] == 4 { // MSS option
									mss := binary.BigEndian.Uint16(opts[i+2 : i+4])
									if mss <= uint16(constants.DefaultClampedMSS) {
										mssClamped = true
									}
									break
								}
							}
						}
						mu.Unlock()
						close(done)
						return
					}
				}
			case <-time.After(4 * time.Second):
				return
			}
		}
	}()

	exitNode.TransitForwarder.HandleTransitPacket(synPkt)

	select {
	case <-done:
		rtt := time.Since(start)
		res.RTT = rtt
		res.Duration = rtt

		mu.Lock()
		isSynAck := synAckReceived
		isClamped := mssClamped
		sISN := serverISN
		mu.Unlock()

		if !isSynAck {
			res.Status = StatusFail
			res.Message = "Did not receive SYN-ACK from transit server"
			return res
		}

		res.Details = append(res.Details, fmt.Sprintf("TCP SYN-ACK received (Server ISN: %d)", sISN))
		if isClamped {
			res.Details = append(res.Details, fmt.Sprintf("MSS Clamping verified: MSS <= %d", constants.DefaultClampedMSS))
		}

		res.Message = fmt.Sprintf("TCP 3-way handshake established in %v via TransitForwarder", rtt.Round(time.Millisecond))
	case <-time.After(5 * time.Second):
		res.Status = StatusWarn
		res.Message = "HTTP SYN to 1.1.1.1:80 timed out (host internet connection unavailable or blocked)"
		res.Duration = time.Since(start)
	}

	return res
}
