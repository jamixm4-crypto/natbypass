// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package testbench

import (
	"context"
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/natbypass/natbypass/internal/tunnel"
)

// RunSpeedTests executes synthetic high-volume throughput and latency benchmarks.
func RunSpeedTests(ctx context.Context, vm *VirtualMesh, testSizeMB int) []TestResult {
	if testSizeMB <= 0 {
		testSizeMB = 10 // Default 10MB
	}

	results := make([]TestResult, 0)

	// Test 1: Bulk Throughput Benchmark (Full MTU 1280 bytes)
	results = append(results, testBulkThroughput(ctx, vm, testSizeMB))

	// Test 2: High-Rate Packet Burst (Small packets 128 bytes - PPS & Latency)
	results = append(results, testSmallPacketBurst(ctx, vm, 5000))

	return results
}

func testBulkThroughput(ctx context.Context, vm *VirtualMesh, targetMB int) TestResult {
	res := TestResult{
		Name:     fmt.Sprintf("Bulk Tunnel Throughput (%d MB, MTU 1280)", targetMB),
		Category: "throughput_speed",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	peerNode := vm.SubnetNode

	packetSize := 1280
	payloadSize := packetSize - 20 - 8 // IPv4 (20) + UDP (8) = 1252 bytes
	totalBytesTarget := uint64(targetMB) * 1024 * 1024
	totalPacketsTarget := int(totalBytesTarget / uint64(packetSize))

	rawPayload := make([]byte, payloadSize)
	_, _ = rand.Read(rawPayload)

	var (
		recvBytes   atomic.Uint64
		recvPackets atomic.Uint64
		stopRecv    atomic.Bool
	)

	// Memory benchmark snapshot before test
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	// Consumer goroutine on receiving node
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stopRecv.Load() {
			select {
			case pkt, ok := <-peerNode.TunOutboundChan:
				if !ok {
					return
				}
				recvBytes.Add(uint64(len(pkt)))
				recvPackets.Add(1)
				if recvBytes.Load() >= totalBytesTarget {
					return
				}
			case <-time.After(50 * time.Millisecond):
				if stopRecv.Load() {
					return
				}
			}
		}
	}()

	// Producer loop on client node
	sentPackets := 0
	sentBytes := uint64(0)
	sendStart := time.Now()

	for sentPackets < totalPacketsTarget {
		pkt := tunnel.BuildIPv4UDPPacket(client.VirtualIP, 50000, peerNode.VirtualIP, 50001, rawPayload)

		select {
		case client.TunInboundChan <- pkt:
			sentPackets++
			sentBytes += uint64(len(pkt))
		case <-time.After(100 * time.Millisecond):
			// Backpressure if queue saturated
		}
	}

	// Wait up to 5 seconds for in-flight packets to arrive
	waitStart := time.Now()
	for recvBytes.Load() < sentBytes && time.Since(waitStart) < 3*time.Second {
		time.Sleep(5 * time.Millisecond)
	}

	stopRecv.Store(true)
	wg.Wait()
	duration := time.Since(sendStart)

	runtime.ReadMemStats(&memAfter)

	finalRecvBytes := recvBytes.Load()
	finalRecvPackets := int(recvPackets.Load())

	mbps := (float64(finalRecvBytes) * 8.0) / (duration.Seconds() * 1000 * 1000)
	pps := float64(finalRecvPackets) / duration.Seconds()
	lossPct := 0.0
	if sentPackets > 0 {
		lossPct = float64(sentPackets-finalRecvPackets) / float64(sentPackets) * 100.0
		if lossPct < 0 {
			lossPct = 0
		}
	}

	res.Duration = duration
	res.ThroughputMbps = mbps
	res.PacketLoss = lossPct
	res.PacketsSent = sentPackets
	res.PacketsRecv = finalRecvPackets
	res.BytesSent = sentBytes
	res.BytesRecv = finalRecvBytes

	allocDiffMB := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / (1024 * 1024)

	res.Details = append(res.Details, fmt.Sprintf("Data Transferred: %.2f MB in %v", float64(finalRecvBytes)/(1024*1024), duration.Round(time.Millisecond)))
	res.Details = append(res.Details, fmt.Sprintf("Processing Rate: %.0f packets/sec (PPS)", pps))
	res.Details = append(res.Details, fmt.Sprintf("Memory Allocation: %.2f MB allocated during test", allocDiffMB))

	if mbps < 50.0 {
		res.Status = StatusWarn
		res.Message = fmt.Sprintf("Throughput lower than expected (%.2f Mbps). Potential queue contention.", mbps)
	} else {
		res.Message = fmt.Sprintf("Sustained %.2f Mbps throughput with %.1f%% packet loss", mbps, lossPct)
	}

	return res
}

func testSmallPacketBurst(ctx context.Context, vm *VirtualMesh, packetCount int) TestResult {
	res := TestResult{
		Name:     fmt.Sprintf("Small Packet Burst (%d pkts, 128B)", packetCount),
		Category: "throughput_speed",
		Status:   StatusPass,
	}

	client := vm.ClientNode
	peerNode := vm.SubnetNode

	payload := make([]byte, 100) // 100 bytes payload + 28 bytes IP/UDP = 128B packet
	_, _ = rand.Read(payload)

	var (
		recvCount atomic.Uint64
		stopRecv  atomic.Bool
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stopRecv.Load() {
			select {
			case _, ok := <-peerNode.TunOutboundChan:
				if !ok {
					return
				}
				recvCount.Add(1)
				if int(recvCount.Load()) >= packetCount {
					return
				}
			case <-time.After(50 * time.Millisecond):
				if stopRecv.Load() {
					return
				}
			}
		}
	}()

	sendStart := time.Now()
	sent := 0
	for i := 0; i < packetCount; i++ {
		pkt := tunnel.BuildIPv4UDPPacket(client.VirtualIP, 44444, peerNode.VirtualIP, 44445, payload)
		select {
		case client.TunInboundChan <- pkt:
			sent++
		case <-time.After(50 * time.Millisecond):
		}
	}

	waitStart := time.Now()
	for int(recvCount.Load()) < sent && time.Since(waitStart) < 2*time.Second {
		time.Sleep(5 * time.Millisecond)
	}

	stopRecv.Store(true)
	wg.Wait()
	duration := time.Since(sendStart)

	recved := int(recvCount.Load())
	pps := float64(recved) / duration.Seconds()
	lossPct := float64(sent-recved) / float64(sent) * 100.0

	res.Duration = duration
	res.PacketsSent = sent
	res.PacketsRecv = recved
	res.PacketLoss = lossPct

	res.Details = append(res.Details, fmt.Sprintf("Burst Rate: %.0f packets/sec (Duration: %v)", pps, duration.Round(time.Millisecond)))
	res.Details = append(res.Details, fmt.Sprintf("Packets Delivered: %d / %d (Loss: %.1f%%)", recved, sent, lossPct))

	if lossPct > 2.0 {
		res.Status = StatusWarn
		res.Message = fmt.Sprintf("High small-packet loss under burst: %.1f%% dropped", lossPct)
	} else {
		res.Message = fmt.Sprintf("Burst processed cleanly at %.0f PPS (Loss: %.1f%%)", pps, lossPct)
	}

	return res
}
