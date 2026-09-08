// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package shadowtls

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
)

func TestBuildClientHello_Structure(t *testing.T) {
	key := crypto.DeriveKey("test-network-secret-key-123456789")
	sni := "gateway.icloud.com"

	chPkt, err := BuildClientHello(sni, key)
	if err != nil {
		t.Fatalf("BuildClientHello failed: %v", err)
	}

	if len(chPkt) < 100 {
		t.Fatalf("ClientHello record unexpectedly small: %d bytes", len(chPkt))
	}

	// Byte 0 must be 0x16 (RecordHandshake)
	if chPkt[0] != RecordHandshake {
		t.Fatalf("expected RecordHandshake (0x16), got 0x%02x", chPkt[0])
	}

	// Bytes 1..2 must be 0x03 0x01 (VersionTLS10 record layer for middlebox compatibility)
	if chPkt[1] != 0x03 || chPkt[2] != 0x01 {
		t.Fatalf("expected TLS 1.0 record layer (0x0301), got 0x%02x%02x", chPkt[1], chPkt[2])
	}

	// Handshake type at offset 5 must be 0x01 (ClientHello)
	if chPkt[5] != HandshakeClientHello {
		t.Fatalf("expected HandshakeClientHello (0x01), got 0x%02x", chPkt[5])
	}

	// SNI string must exist within record
	if !bytes.Contains(chPkt, []byte(sni)) {
		t.Fatalf("ClientHello does not contain SNI '%s'", sni)
	}
}

func tcpLoopbackPair() (net.Conn, net.Conn, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()

	var serverConn net.Conn
	var acceptErr error
	done := make(chan struct{})
	go func() {
		serverConn, acceptErr = ln.Accept()
		close(done)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	<-done
	if acceptErr != nil {
		_ = clientConn.Close()
		return nil, nil, acceptErr
	}
	return clientConn, serverConn, nil
}

func TestHandshake_SuccessAndTransmission(t *testing.T) {
	key := crypto.DeriveKey("shared-mesh-secret-key-999999999")
	sni := "www.microsoft.com"

	clientConn, serverConn, err := tcpLoopbackPair()
	if err != nil {
		t.Fatalf("tcpLoopbackPair failed: %v", err)
	}
	defer clientConn.Close()
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var serverErr, clientErr error
	var serverTLS, clientTLS *ShadowTLSConn

	go func() {
		defer wg.Done()
		serverTLS, serverErr = ServerHandshake(serverConn, key, 3*time.Second)
	}()

	go func() {
		defer wg.Done()
		clientTLS, _, clientErr = ClientHandshake(clientConn, sni, key, 3*time.Second)
	}()

	wg.Wait()

	if serverErr != nil {
		t.Fatalf("ServerHandshake failed: %v", serverErr)
	}
	if clientErr != nil {
		t.Fatalf("ClientHandshake failed: %v", clientErr)
	}

	// Test bidirectional encrypted packet transmission with dynamic padding
	testPayload := []byte("GET /tunnel-ping HTTP/1.1\r\nHost: 10.1.1.1\r\n\r\n")

	// Client -> Server
	if err := clientTLS.WritePacket(testPayload); err != nil {
		t.Fatalf("clientTLS.WritePacket failed: %v", err)
	}

	recvOnServer, err := serverTLS.ReadPacket()
	if err != nil {
		t.Fatalf("serverTLS.ReadPacket failed: %v", err)
	}
	if !bytes.Equal(recvOnServer, testPayload) {
		t.Fatalf("server received payload mismatch: expected %q, got %q", testPayload, recvOnServer)
	}

	// Server -> Client reply
	replyPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPONG")
	if err := serverTLS.WritePacket(replyPayload); err != nil {
		t.Fatalf("serverTLS.WritePacket failed: %v", err)
	}

	recvOnClient, err := clientTLS.ReadPacket()
	if err != nil {
		t.Fatalf("clientTLS.ReadPacket failed: %v", err)
	}
	if !bytes.Equal(recvOnClient, replyPayload) {
		t.Fatalf("client received payload mismatch: expected %q, got %q", replyPayload, recvOnClient)
	}
}

func TestHandshake_WrongKeyRejection_ActiveProbing(t *testing.T) {
	keyAlice := crypto.DeriveKey("key-alice-valid")
	keyAttacker := crypto.DeriveKey("key-attacker-probe")

	clientConn, serverConn, err := tcpLoopbackPair()
	if err != nil {
		t.Fatalf("tcpLoopbackPair failed: %v", err)
	}
	defer clientConn.Close()
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var serverErr, clientErr error

	go func() {
		defer wg.Done()
		_, serverErr = ServerHandshake(serverConn, keyAlice, 2*time.Second)
	}()

	go func() {
		defer wg.Done()
		_, _, clientErr = ClientHandshake(clientConn, "gateway.icloud.com", keyAttacker, 2*time.Second)
	}()

	wg.Wait()

	// Server MUST reject with error, successfully protecting against active probing
	if serverErr == nil {
		t.Fatalf("expected ServerHandshake to fail due to wrong HMAC key, but succeeded!")
	}
	if clientErr == nil {
		t.Fatalf("expected ClientHandshake to fail, but succeeded!")
	}
}

func TestHandshake_SimultaneousOpen_CollisionResolution(t *testing.T) {
	key := crypto.DeriveKey("mesh-secret-key")
	sni := "gateway.icloud.com"

	connA, connB, err := tcpLoopbackPair()
	if err != nil {
		t.Fatalf("tcpLoopbackPair failed: %v", err)
	}
	defer connA.Close()
	defer connB.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var roleA, roleB bool
	var errA, errB error
	var tlsA, tlsB *ShadowTLSConn

	// Both sides run ClientHandshake simultaneously (simulating TCP Simultaneous Open)
	go func() {
		defer wg.Done()
		tlsA, roleA, errA = ClientHandshake(connA, sni, key, 3*time.Second)
	}()

	go func() {
		defer wg.Done()
		tlsB, roleB, errB = ClientHandshake(connB, sni, key, 3*time.Second)
	}()

	wg.Wait()

	if errA != nil {
		t.Fatalf("Peer A Simultaneous Open handshake failed: %v", errA)
	}
	if errB != nil {
		t.Fatalf("Peer B Simultaneous Open handshake failed: %v", errB)
	}

	// Exactly one peer must win the tie-break and become Server
	if roleA == roleB {
		t.Fatalf("Expected exactly one peer to become Server, but got roleA=%v, roleB=%v", roleA, roleB)
	}

	// Test encrypted communication between the two simultaneous open peers
	msg := []byte("SIMULTANEOUS_OPEN_VERIFIED")
	if roleA { // Peer A is Server
		if err := tlsB.WritePacket(msg); err != nil {
			t.Fatalf("tlsB.WritePacket failed: %v", err)
		}
		got, err := tlsA.ReadPacket()
		if err != nil {
			t.Fatalf("tlsA.ReadPacket failed: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("payload mismatch: expected %q, got %q", msg, got)
		}
	} else { // Peer B is Server
		if err := tlsA.WritePacket(msg); err != nil {
			t.Fatalf("tlsA.WritePacket failed: %v", err)
		}
		got, err := tlsB.ReadPacket()
		if err != nil {
			t.Fatalf("tlsB.ReadPacket failed: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("payload mismatch: expected %q, got %q", msg, got)
		}
	}
}

func TestShadowTLS_HandshakeStateEnforcement(t *testing.T) {
	key := crypto.DeriveKey("test-handshake-state-key")
	clientConn, serverConn, err := tcpLoopbackPair()
	if err != nil {
		t.Fatalf("tcpLoopbackPair failed: %v", err)
	}
	defer clientConn.Close()
	defer serverConn.Close()

	// Create unverified connection without handshake
	unverified := NewUnverifiedShadowTLSConn(clientConn, key)
	if unverified.IsHandshakeComplete() {
		t.Fatalf("expected unverified connection to have handshakeDone=false")
	}

	// Attempting to write application data (0x17) must fail immediately
	err = unverified.WritePacket([]byte("premature packet"))
	if !errors.Is(err, ErrHandshakeNotComplete) {
		t.Fatalf("expected ErrHandshakeNotComplete, got: %v", err)
	}

	// Attempting to read application data must also fail
	_, err = unverified.ReadPacket()
	if !errors.Is(err, ErrHandshakeNotComplete) {
		t.Fatalf("expected ErrHandshakeNotComplete, got: %v", err)
	}

	// After marking complete, state machine allows operations
	unverified.MarkHandshakeComplete()
	if !unverified.IsHandshakeComplete() {
		t.Fatalf("expected handshakeDone=true after MarkHandshakeComplete")
	}
}

func TestExtractSNI(t *testing.T) {
	key := crypto.DeriveKey("test-sni-extraction-key")
	targetSNI := "secure.apple.com"

	chPkt, err := BuildClientHello(targetSNI, key)
	if err != nil {
		t.Fatalf("BuildClientHello failed: %v", err)
	}

	// Skip 5 bytes record header to get ClientHello body
	body := chPkt[5:]
	extracted := ExtractSNI(body)
	if extracted != targetSNI {
		t.Fatalf("expected extracted SNI %q, got %q", targetSNI, extracted)
	}
}

