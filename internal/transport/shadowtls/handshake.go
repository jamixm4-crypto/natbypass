// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package shadowtls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// DefaultSNI is the default host name used in TLS 1.3 SNI extension
	DefaultSNI = "gateway.icloud.com"

	// Record Content Types (RFC 8446)
	RecordChangeCipherSpec = 0x14
	RecordHandshake        = 0x16
	RecordApplicationData  = 0x17

	// Handshake Types
	HandshakeClientHello = 0x01
	HandshakeServerHello = 0x02

	// TLS Versions
	VersionTLS10 = 0x0301
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// Extension Types
	ExtServerName         = 0x0000
	ExtSupportedGroups    = 0x000a
	ExtSignatureAlgorithm = 0x000d
	ExtSupportedVersions  = 0x002b
	ExtKeyShare           = 0x0033
)

var (
	ErrInvalidTLSHandshake = errors.New("shadowtls: invalid TLS 1.3 record")
	ErrAuthFailed          = errors.New("shadowtls: peer authentication failed (HMAC mismatch)")
	ErrTimeout             = errors.New("shadowtls: handshake timed out")
)

// computeHMAC generates a 16-byte HMAC tag over data with key
func computeHMAC(key [32]byte, data []byte) []byte {
	h := hmac.New(sha256.New, key[:])
	h.Write(data)
	return h.Sum(nil)[:16]
}

// BuildClientHello constructs a byte-perfect TLS 1.3 ClientHello with embedded HMAC authentication.
func BuildClientHello(sni string, networkKey [32]byte) ([]byte, error) {
	if sni == "" {
		sni = DefaultSNI
	}

	var clientRandom [32]byte
	if _, err := io.ReadFull(rand.Reader, clientRandom[:]); err != nil {
		return nil, err
	}

	// Embed HMAC authentication in legacy session ID (RFC 8446 middlebox compatibility)
	// sessionID = [16 bytes HMAC(networkKey, clientRandom)] + [16 bytes random nonce]
	var sessionID [32]byte
	authTag := computeHMAC(networkKey, clientRandom[:])
	copy(sessionID[:16], authTag)
	if _, err := io.ReadFull(rand.Reader, sessionID[16:]); err != nil {
		return nil, err
	}

	// Extensions payload
	extBuf := new(bytes.Buffer)

	// 1. SNI Extension
	sniLen := len(sni)
	extBuf.Write([]byte{0x00, 0x00}) // ExtServerName
	binary.Write(extBuf, binary.BigEndian, uint16(sniLen+5))
	binary.Write(extBuf, binary.BigEndian, uint16(sniLen+3))
	extBuf.WriteByte(0x00) // HostName type
	binary.Write(extBuf, binary.BigEndian, uint16(sniLen))
	extBuf.WriteString(sni)

	// 2. Supported Versions Extension (TLS 1.3)
	extBuf.Write([]byte{0x00, 0x2b}) // ExtSupportedVersions
	extBuf.Write([]byte{0x00, 0x03, 0x02, 0x03, 0x04})

	// 3. Supported Groups Extension (X25519, secp256r1)
	extBuf.Write([]byte{0x00, 0x0a}) // ExtSupportedGroups
	extBuf.Write([]byte{0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17})

	// 4. Key Share Extension (X25519 mock public key)
	extBuf.Write([]byte{0x00, 0x33}) // ExtKeyShare
	var keyShareData [32]byte
	if _, err := io.ReadFull(rand.Reader, keyShareData[:]); err != nil {
		return nil, fmt.Errorf("shadowtls csprng key share failure: %w", err)
	}
	binary.Write(extBuf, binary.BigEndian, uint16(36)) // ext len
	binary.Write(extBuf, binary.BigEndian, uint16(34)) // client_shares len
	extBuf.Write([]byte{0x00, 0x1d})                   // X25519
	binary.Write(extBuf, binary.BigEndian, uint16(32)) // key len
	extBuf.Write(keyShareData[:])

	// ClientHello Body
	chBody := new(bytes.Buffer)
	binary.Write(chBody, binary.BigEndian, uint16(VersionTLS12)) // Legacy version 0x0303
	chBody.Write(clientRandom[:])                               // 32 bytes Random
	chBody.WriteByte(32)                                         // Session ID Length
	chBody.Write(sessionID[:])                                   // 32 bytes Session ID

	// Cipher Suites (TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384)
	chBody.Write([]byte{0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02})
	chBody.Write([]byte{0x01, 0x00}) // Compression method: null

	// Extensions length + payload
	binary.Write(chBody, binary.BigEndian, uint16(extBuf.Len()))
	chBody.Write(extBuf.Bytes())

	// Handshake Layer: Type 0x01 (ClientHello) + 3 bytes length
	hsBody := chBody.Bytes()
	hsLen := len(hsBody)
	hsPkt := make([]byte, 4+hsLen)
	hsPkt[0] = HandshakeClientHello
	hsPkt[1] = byte(hsLen >> 16)
	hsPkt[2] = byte(hsLen >> 8)
	hsPkt[3] = byte(hsLen)
	copy(hsPkt[4:], hsBody)

	// Record Layer: Type 0x16 + Version 0x0301 + 2 bytes length
	recLen := len(hsPkt)
	fullRec := make([]byte, 5+recLen)
	fullRec[0] = RecordHandshake
	fullRec[1] = 0x03
	fullRec[2] = 0x01
	binary.BigEndian.PutUint16(fullRec[3:5], uint16(recLen))
	copy(fullRec[5:], hsPkt)

	return fullRec, nil
}

// BuildServerHello constructs a byte-perfect TLS 1.3 ServerHello response.
func BuildServerHello(clientRandom [32]byte, clientSessionID [32]byte, networkKey [32]byte) ([]byte, error) {
	var serverRandom [32]byte
	// Server mutual authentication: HMAC over client random + "server"
	authTag := computeHMAC(networkKey, append(clientRandom[:], []byte("server")...))
	copy(serverRandom[:16], authTag)
	if _, err := io.ReadFull(rand.Reader, serverRandom[16:]); err != nil {
		return nil, err
	}

	// Extensions (SupportedVersions 0x0304 + KeyShare)
	extBuf := new(bytes.Buffer)
	extBuf.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}) // SupportedVersions TLS 1.3

	extBuf.Write([]byte{0x00, 0x33}) // KeyShare
	var sKeyShare [32]byte
	if _, err := io.ReadFull(rand.Reader, sKeyShare[:]); err != nil {
		return nil, fmt.Errorf("shadowtls server csprng key share failure: %w", err)
	}
	binary.Write(extBuf, binary.BigEndian, uint16(36))
	extBuf.Write([]byte{0x00, 0x1d})                   // X25519
	binary.Write(extBuf, binary.BigEndian, uint16(32)) // Key len
	extBuf.Write(sKeyShare[:])

	// ServerHello Body
	shBody := new(bytes.Buffer)
	binary.Write(shBody, binary.BigEndian, uint16(VersionTLS12))
	shBody.Write(serverRandom[:])
	shBody.WriteByte(32)
	shBody.Write(clientSessionID[:])
	shBody.Write([]byte{0x13, 0x03}) // Selected: TLS_CHACHA20_POLY1305_SHA256
	shBody.WriteByte(0x00)           // Compression: null
	binary.Write(shBody, binary.BigEndian, uint16(extBuf.Len()))
	shBody.Write(extBuf.Bytes())

	// Handshake Layer: Type 0x02 (ServerHello) + 3 bytes length
	hsBytes := shBody.Bytes()
	hsLen := len(hsBytes)
	hsPkt := make([]byte, 4+hsLen)
	hsPkt[0] = HandshakeServerHello
	hsPkt[1] = byte(hsLen >> 16)
	hsPkt[2] = byte(hsLen >> 8)
	hsPkt[3] = byte(hsLen)
	copy(hsPkt[4:], hsBytes)

	// Record Layer 1: Handshake (ServerHello)
	rec1Len := len(hsPkt)
	rec1 := make([]byte, 5+rec1Len)
	rec1[0] = RecordHandshake
	rec1[1] = 0x03
	rec1[2] = 0x03
	binary.BigEndian.PutUint16(rec1[3:5], uint16(rec1Len))
	copy(rec1[5:], hsPkt)

	// Record Layer 2: ChangeCipherSpec (RFC 8446 middlebox compatibility mode)
	// 0x14 0x03 0x03 0x00 0x01 0x01
	rec2 := []byte{RecordChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01}

	return append(rec1, rec2...), nil
}

// ClientHandshake performs client-side ShadowTLS handshake over existing TCP connection.
// It returns (isServerRole, err). When a TCP Simultaneous Open collision is detected (both sides sent
// ClientHello simultaneously), a deterministic tie-break determines which side acts as Server.
func ClientHandshake(conn net.Conn, sni string, networkKey [32]byte, timeout time.Duration) (bool, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	chPkt, err := BuildClientHello(sni, networkKey)
	if err != nil {
		return false, err
	}

	// Extract clientRandom and authTag for later server verification
	var clientRandom [32]byte
	copy(clientRandom[:], chPkt[11:43])

	if _, err := conn.Write(chPkt); err != nil {
		return false, fmt.Errorf("failed to send ClientHello: %w", err)
	}

	// Read response Record Header (5 bytes)
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false, fmt.Errorf("failed to read ServerHello header: %w", err)
	}
	if hdr[0] != RecordHandshake {
		return false, ErrInvalidTLSHandshake
	}
	recLen := binary.BigEndian.Uint16(hdr[3:5])
	if recLen < 38 || recLen > 8192 {
		return false, ErrInvalidTLSHandshake
	}

	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return false, fmt.Errorf("failed to read handshake response body: %w", err)
	}

	// 1. Standard Client path: Server responded with ServerHello (HandshakeServerHello = 0x02)
	if body[0] == HandshakeServerHello {
		if len(body) < 38 {
			return false, ErrInvalidTLSHandshake
		}
		serverRandom := body[6:38]
		expectedAuth := computeHMAC(networkKey, append(clientRandom[:], []byte("server")...))
		if !hmac.Equal(serverRandom[:16], expectedAuth) {
			return false, ErrAuthFailed
		}

		// Read optional ChangeCipherSpec (6 bytes: 0x14 0x03 0x03 0x00 0x01 0x01)
		ccsHdr := make([]byte, 6)
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := io.ReadFull(conn, ccsHdr); err == nil && n == 6 && ccsHdr[0] == RecordChangeCipherSpec {
			// ChangeCipherSpec successfully consumed
		}
		_ = conn.SetDeadline(time.Time{})
		return false, nil // We are Client
	}

	// 2. TCP Simultaneous Open collision resolution: Both sides sent ClientHello (HandshakeClientHello = 0x01)!
	if body[0] == HandshakeClientHello {
		if len(body) < 70 {
			return false, ErrInvalidTLSHandshake
		}
		var remoteClientRandom [32]byte
		copy(remoteClientRandom[:], body[6:38])

		sessIDLen := int(body[38])
		if sessIDLen != 32 || len(body) < 39+32 {
			return false, ErrInvalidTLSHandshake
		}
		var remoteSessionID [32]byte
		copy(remoteSessionID[:], body[39:39+32])

		// Validate remote peer's HMAC token
		expectedTag := computeHMAC(networkKey, remoteClientRandom[:])
		if !hmac.Equal(remoteSessionID[:16], expectedTag) {
			return false, ErrAuthFailed
		}

		// Tie-break: compare our clientRandom vs remoteClientRandom
		cmp := bytes.Compare(clientRandom[:], remoteClientRandom[:])
		if cmp > 0 {
			// WE WIN: We transition to SERVER role!
			shResp, err := BuildServerHello(remoteClientRandom, remoteSessionID, networkKey)
			if err != nil {
				return false, err
			}
			if _, err := conn.Write(shResp); err != nil {
				return false, fmt.Errorf("failed to write ServerHello in simultaneous open: %w", err)
			}
			return true, nil // We act as Server
		} else {
			// WE LOSE: We remain CLIENT role and wait for ServerHello from the winner
			_ = conn.SetDeadline(time.Now().Add(timeout))
			sHdr := make([]byte, 5)
			if _, err := io.ReadFull(conn, sHdr); err != nil {
				return false, fmt.Errorf("failed to read ServerHello from simultaneous open peer: %w", err)
			}
			if sHdr[0] != RecordHandshake {
				return false, ErrInvalidTLSHandshake
			}
			sRecLen := binary.BigEndian.Uint16(sHdr[3:5])
			if sRecLen < 38 || sRecLen > 4096 {
				return false, ErrInvalidTLSHandshake
			}
			sBody := make([]byte, sRecLen)
			if _, err := io.ReadFull(conn, sBody); err != nil {
				return false, fmt.Errorf("failed to read ServerHello body from simultaneous open peer: %w", err)
			}
			if sBody[0] != HandshakeServerHello || len(sBody) < 38 {
				return false, ErrInvalidTLSHandshake
			}
			serverRandom := sBody[6:38]
			expectedAuth := computeHMAC(networkKey, append(clientRandom[:], []byte("server")...))
			if !hmac.Equal(serverRandom[:16], expectedAuth) {
				return false, ErrAuthFailed
			}
			// Read optional ChangeCipherSpec
			ccsHdr := make([]byte, 6)
			_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = io.ReadFull(conn, ccsHdr)
			_ = conn.SetDeadline(time.Time{})
			return false, nil // We remain Client
		}
	}

	return false, ErrInvalidTLSHandshake
}

// ServerHandshake handles incoming connection on server side, validates HMAC, and responds.
func ServerHandshake(conn net.Conn, networkKey [32]byte, timeout time.Duration) error {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("failed to read ClientHello header: %w", err)
	}
	if hdr[0] != RecordHandshake {
		return ErrInvalidTLSHandshake
	}
	recLen := binary.BigEndian.Uint16(hdr[3:5])
	if recLen < 40 || recLen > 8192 {
		return ErrInvalidTLSHandshake
	}

	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return fmt.Errorf("failed to read ClientHello body: %w", err)
	}
	if body[0] != HandshakeClientHello || len(body) < 70 {
		return ErrInvalidTLSHandshake
	}

	// clientRandom starts at offset 6 in body
	var clientRandom [32]byte
	copy(clientRandom[:], body[6:38])

	// sessionID length at offset 38, sessionID at offset 39
	sessIDLen := int(body[38])
	if sessIDLen != 32 || len(body) < 39+32 {
		return ErrInvalidTLSHandshake
	}
	var sessionID [32]byte
	copy(sessionID[:], body[39:39+32])

	// Validate HMAC authentication token
	expectedTag := computeHMAC(networkKey, clientRandom[:])
	if !hmac.Equal(sessionID[:16], expectedTag) {
		return ErrAuthFailed
	}

	// Respond with valid ServerHello + ChangeCipherSpec
	shResp, err := BuildServerHello(clientRandom, sessionID, networkKey)
	if err != nil {
		return err
	}
	if _, err := conn.Write(shResp); err != nil {
		return fmt.Errorf("failed to write ServerHello response: %w", err)
	}

	return nil
}
