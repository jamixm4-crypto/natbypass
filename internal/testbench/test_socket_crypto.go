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
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/tunnel"
)

// RunSocketCryptoTests executes real OS socket and real cryptographic pipeline benchmarks.
func RunSocketCryptoTests(ctx context.Context, testSizeMB int) []TestResult {
	if testSizeMB <= 0 {
		testSizeMB = 10
	}

	results := make([]TestResult, 0)

	// Test 1: Real OS UDP Sockets (Kernel Winsock syscalls, unencrypted baseline)
	results = append(results, testRealOSSocketThroughput(ctx, testSizeMB, false))

	// Test 2: Real OS UDP Sockets WITH Full End-to-End Encryption (ChaCha20-Poly1305 + HKDF + Anti-Replay)
	results = append(results, testRealOSSocketThroughput(ctx, testSizeMB, true))

	// Test 3: Standalone Crypto Engine Micro-Benchmark (Poly1305 MAC + ChaCha20 cipher speed)
	results = append(results, testCryptoEngineMicrobench(ctx, 10000))

	return results
}

func testRealOSSocketThroughput(ctx context.Context, targetMB int, encrypt bool) TestResult {
	modeLabel := "Raw OS UDP Socket (Winsock Syscalls)"
	if encrypt {
		modeLabel = "Encrypted OS UDP Socket (ChaCha20-Poly1305 + Winsock)"
	}

	res := TestResult{
		Name:     fmt.Sprintf("%s (%d MB)", modeLabel, targetMB),
		Category: "real_hardware_network",
		Status:   StatusPass,
	}

	// 1. Create real OS kernel UDP sockets on localhost
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("Failed to bind OS server UDP socket: %v", err)
		return res
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		res.Status = StatusFail
		res.Message = fmt.Sprintf("Failed to bind OS client UDP socket: %v", err)
		return res
	}
	defer clientConn.Close()

	// Set realistic OS socket buffer sizes (1MB)
	_ = serverConn.SetReadBuffer(2 * 1024 * 1024)
	_ = clientConn.SetWriteBuffer(2 * 1024 * 1024)

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// 2. Setup real cryptographic sessions if encryption enabled
	var aliceSession, bobSession *crypto.SessionState
	if encrypt {
		sharedSecret := make([]byte, 32)
		_, _ = rand.Read(sharedSecret)
		aliceSession, err = crypto.NewSessionState(sharedSecret)
		if err != nil {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Failed to create Alice crypto session: %v", err)
			return res
		}
		bobSession, err = crypto.NewSessionState(sharedSecret)
		if err != nil {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Failed to create Bob crypto session: %v", err)
			return res
		}
		// Link Alice's SendingChain to Bob's ReceivingChain
		bobSession.ReceivingChain.ChainKey = make([]byte, len(aliceSession.SendingChain.ChainKey))
		copy(bobSession.ReceivingChain.ChainKey, aliceSession.SendingChain.ChainKey)
	}

	packetSize := 1280
	payloadSize := packetSize - 20 - 8 // IPv4 (20) + UDP (8) = 1252 bytes
	totalBytesTarget := uint64(targetMB) * 1024 * 1024
	totalPacketsTarget := int(totalBytesTarget / uint64(packetSize))

	rawPayload := make([]byte, payloadSize)
	_, _ = rand.Read(rawPayload)

	var (
		recvBytes   atomic.Uint64
		recvPackets atomic.Uint64
		decryptFail atomic.Uint64
		stopRecv    atomic.Bool
	)

	// Receiver loop on real OS UDP socket
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for !stopRecv.Load() {
			_ = serverConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, _, readErr := serverConn.ReadFromUDP(buf)
			if readErr != nil {
				continue
			}
			if n == 0 {
				continue
			}

			if encrypt {
				decrypted, decErr := bobSession.Decrypt(buf[:n])
				if decErr != nil {
					decryptFail.Add(1)
					continue
				}
				recvBytes.Add(uint64(len(decrypted)))
			} else {
				recvBytes.Add(uint64(n))
			}
			recvPackets.Add(1)

			if recvBytes.Load() >= totalBytesTarget {
				return
			}
		}
	}()

	// Sender loop using real OS WriteToUDP syscall
	srcIP := net.ParseIP("10.11.12.101")
	dstIP := net.ParseIP("10.11.12.102")

	sendStart := time.Now()
	sentPackets := 0
	sentBytes := uint64(0)

	for sentPackets < totalPacketsTarget {
		pkt := tunnel.BuildIPv4UDPPacket(srcIP, 45000, dstIP, 45001, rawPayload)

		var wireData []byte
		if encrypt {
			var encErr error
			wireData, encErr = aliceSession.Encrypt(pkt)
			if encErr != nil {
				res.Status = StatusFail
				res.Message = fmt.Sprintf("Encryption error: %v", encErr)
				return res
			}
		} else {
			wireData = pkt
		}

		_, writeErr := clientConn.WriteToUDP(wireData, serverAddr)
		if writeErr == nil {
			sentPackets++
			sentBytes += uint64(len(pkt))
		}
	}

	// Drain period
	waitStart := time.Now()
	for recvBytes.Load() < sentBytes && time.Since(waitStart) < 3*time.Second {
		time.Sleep(5 * time.Millisecond)
	}

	stopRecv.Store(true)
	wg.Wait()
	duration := time.Since(sendStart)

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

	res.Details = append(res.Details, fmt.Sprintf("Transport: Real OS Sockets (%s -> %s)", clientConn.LocalAddr(), serverAddr))
	res.Details = append(res.Details, fmt.Sprintf("Data Transferred: %.2f MB in %v", float64(finalRecvBytes)/(1024*1024), duration.Round(time.Millisecond)))
	res.Details = append(res.Details, fmt.Sprintf("Throughput: %.2f Mbps | Processing Rate: %.0f PPS", mbps, pps))
	if encrypt {
		res.Details = append(res.Details, fmt.Sprintf("Decryption Failures: %d (0 expected)", decryptFail.Load()))
	}

	res.Message = fmt.Sprintf("Real OS socket throughput: %.2f Mbps with %.1f%% packet loss", mbps, lossPct)
	return res
}

func testCryptoEngineMicrobench(ctx context.Context, iterations int) TestResult {
	start := time.Now()
	res := TestResult{
		Name:     fmt.Sprintf("Crypto Engine Microbenchmark (%d packets)", iterations),
		Category: "real_hardware_network",
		Status:   StatusPass,
	}

	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)

	alice, _ := crypto.NewSessionState(sharedSecret)
	bob, _ := crypto.NewSessionState(sharedSecret)
	bob.ReceivingChain.ChainKey = make([]byte, len(alice.SendingChain.ChainKey))
	copy(bob.ReceivingChain.ChainKey, alice.SendingChain.ChainKey)

	packet := make([]byte, 1280) // 1280 bytes MTU
	_, _ = rand.Read(packet)

	// Measure encryption time
	encStart := time.Now()
	ciphertexts := make([][]byte, iterations)
	for i := 0; i < iterations; i++ {
		ct, err := alice.Encrypt(packet)
		if err != nil {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Encrypt failed at iteration %d: %v", i, err)
			return res
		}
		ciphertexts[i] = ct
	}
	encDuration := time.Since(encStart)

	// Measure decryption time
	decStart := time.Now()
	for i := 0; i < iterations; i++ {
		pt, err := bob.Decrypt(ciphertexts[i])
		if err != nil {
			res.Status = StatusFail
			res.Message = fmt.Sprintf("Decrypt failed at iteration %d: %v", i, err)
			return res
		}
		if len(pt) != len(packet) {
			res.Status = StatusFail
			res.Message = "Decrypted length mismatch"
			return res
		}
	}
	decDuration := time.Since(decStart)

	totalMB := (float64(iterations) * 1280.0) / (1024 * 1024)
	cryptoMbps := (totalMB * 8.0) / encDuration.Seconds()

	encPerPktUs := float64(encDuration.Microseconds()) / float64(iterations)
	decPerPktUs := float64(decDuration.Microseconds()) / float64(iterations)

	res.Duration = time.Since(start)
	res.ThroughputMbps = cryptoMbps

	res.Details = append(res.Details, fmt.Sprintf("Payload: %d packets of 1280 bytes (%.2f MB total)", iterations, totalMB))
	res.Details = append(res.Details, fmt.Sprintf("Encryption Speed: %.2f µs/packet (%.2f Mbps)", encPerPktUs, cryptoMbps))
	res.Details = append(res.Details, fmt.Sprintf("Decryption Speed: %.2f µs/packet", decPerPktUs))
	res.Details = append(res.Details, fmt.Sprintf("Single-Core CPU Limit: max ~%.0f packets/sec per thread", 1000000.0/(encPerPktUs+decPerPktUs)))

	res.Message = fmt.Sprintf("Crypto engine benchmarked at %.2f Mbps (%.2f µs enc / %.2f µs dec per packet on %s/%s)",
		cryptoMbps, encPerPktUs, decPerPktUs, runtime.GOOS, runtime.GOARCH)

	return res
}
