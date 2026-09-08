// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package quic

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
)

const (
	// QUICShortHeader is the RFC 9000 1-RTT Short Header marker:
	// Form=0 (Short), FixedBit=1, Spin=0, Reserved=0, KeyPhase=0, PN_Length=1 (2-byte packet number)
	QUICShortHeader = 0x41

	// DCIDLen is the standard length for Destination Connection ID (RFC 9000)
	DCIDLen = 8
)

var (
	ErrPacketTooShort   = errors.New("quic: packet too short for short header")
	ErrInvalidHeader    = errors.New("quic: not a valid 1-RTT short header")
	ErrDecryptionFailed = errors.New("quic: failed to decrypt payload")
)

// BuildQUICDataPacket wraps a raw IP/tunnel packet into an authentic RFC 9000 1-RTT Short Header packet.
// The resulting UDP datagram matches the wire-level signature of legitimate HTTP/3 / QUIC traffic.
func BuildQUICDataPacket(dcid []byte, pktNum uint16, payload []byte, cKey [32]byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("quic: empty payload")
	}

	encPayload, err := crypto.EncryptSelf(payload, cKey)
	if err != nil {
		return nil, fmt.Errorf("quic encryption error: %w", err)
	}

	totalLen := 1 + DCIDLen + 2 + len(encPayload)
	buf := make([]byte, totalLen)

	// 1. Short Header Byte (0x41)
	buf[0] = QUICShortHeader

	// 2. Destination Connection ID (DCID: 8 bytes)
	if len(dcid) >= DCIDLen {
		copy(buf[1:1+DCIDLen], dcid[:DCIDLen])
	} else {
		_, _ = rand.Read(buf[1 : 1+DCIDLen])
	}

	// 3. Packet Number (2 bytes)
	binary.BigEndian.PutUint16(buf[1+DCIDLen:1+DCIDLen+2], pktNum)

	// 4. Encrypted Application Data / Payload
	copy(buf[1+DCIDLen+2:], encPayload)

	return buf, nil
}

// ParseQUICDataPacket verifies and unpacks an incoming RFC 9000 1-RTT Short Header packet.
// Returns decrypted payload, packet number, and DCID.
func ParseQUICDataPacket(packet []byte, cKey [32]byte) (payload []byte, pktNum uint16, dcid []byte, err error) {
	if len(packet) < 1+DCIDLen+2+20 { // Header (11 bytes) + Min AEAD overhead / payload (20 bytes)
		return nil, 0, nil, ErrPacketTooShort
	}

	// Check Short Header marker: bit 7 must be 0 (Short Header), bit 6 must be 1 (Fixed Bit)
	if (packet[0] & 0xC0) != 0x40 {
		return nil, 0, nil, ErrInvalidHeader
	}

	extractedDCID := packet[1 : 1+DCIDLen]
	extractedPN := binary.BigEndian.Uint16(packet[1+DCIDLen : 1+DCIDLen+2])
	rawPayload := packet[1+DCIDLen+2:]

	dec, decErr := crypto.DecryptSelf(rawPayload, cKey)
	if decErr != nil || len(dec) == 0 {
		return nil, 0, nil, ErrDecryptionFailed
	}

	return dec, extractedPN, extractedDCID, nil
}

// Session represents an active peer-to-peer QUIC transport session with connection migration support.
type Session struct {
	mu           sync.RWMutex
	peerID       string
	dcid         [DCIDLen]byte
	cKey         [32]byte
	remoteAddr   string
	pktNumSeq    uint32
	lastSeen     time.Time
	migratedFrom string
}

// NewSession creates a new QUIC transport session for a remote peer.
func NewSession(peerID string, remoteAddr string, cKey [32]byte) *Session {
	var dcid [DCIDLen]byte
	_, _ = rand.Read(dcid[:])

	return &Session{
		peerID:     peerID,
		dcid:       dcid,
		cKey:       cKey,
		remoteAddr: remoteAddr,
		lastSeen:   time.Now(),
	}
}

// Encapsulate formats an outbound packet for this session.
func (s *Session) Encapsulate(payload []byte) ([]byte, error) {
	nextPN := uint16(atomic.AddUint32(&s.pktNumSeq, 1))
	s.mu.RLock()
	dcid := s.dcid
	cKey := s.cKey
	s.mu.RUnlock()

	return BuildQUICDataPacket(dcid[:], nextPN, payload, cKey)
}

// HandleMigration records seamless connection migration when a peer's IP changes (e.g. Wi-Fi <-> Cellular).
func (s *Session) HandleMigration(newAddr string) bool {
	if newAddr == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastSeen = time.Now()
	if s.remoteAddr != newAddr {
		s.migratedFrom = s.remoteAddr
		s.remoteAddr = newAddr
		return true // connection migration event occurred
	}
	return false
}

// RemoteAddr returns the current active endpoint.
func (s *Session) RemoteAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.remoteAddr
}
