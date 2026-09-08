// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package shadowtls

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/natbypass/natbypass/internal/crypto"
)

var (
	ErrRecordTooShort  = errors.New("shadowtls: TLS record too short")
	ErrInvalidRecord   = errors.New("shadowtls: record is not TLS Application Data")
	ErrPayloadTooLarge = errors.New("shadowtls: payload exceeds maximum TLS record size")
)

// ShadowTLSConn wraps an underlying net.Conn in TLS 1.3 Application Data record framing.
type ShadowTLSConn struct {
	net.Conn
	key     [32]byte
	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewShadowTLSConn creates a new framed TLS 1.3 connection.
func NewShadowTLSConn(rawConn net.Conn, key [32]byte) *ShadowTLSConn {
	return &ShadowTLSConn{
		Conn:    rawConn,
		key:     key,
		readBuf: nil,
	}
}

// WritePacket encapsulates an IP/tunnel packet into an encrypted TLS 1.3 Application Data record
// with dynamic padding (16-48 bytes) to camouflage packet size distributions against DPI.
func (c *ShadowTLSConn) WritePacket(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if len(payload) > 16384 {
		return ErrPayloadTooLarge
	}

	// 1. Calculate dynamic random padding (16..48 bytes)
	var padRand [1]byte
	if _, err := io.ReadFull(rand.Reader, padRand[:]); err != nil {
		return fmt.Errorf("shadowtls csprng failure: %w", err)
	}
	padLen := 16 + int(padRand[0]%33)

	realLen := uint16(len(payload))
	plainPkt := make([]byte, 2+len(payload)+padLen)
	binary.BigEndian.PutUint16(plainPkt[:2], realLen)
	copy(plainPkt[2:], payload)
	if _, err := io.ReadFull(rand.Reader, plainPkt[2+len(payload):]); err != nil {
		return fmt.Errorf("shadowtls padding csprng failure: %w", err)
	}

	// 2. Encrypt payload using ChaCha20-Poly1305 (NaCl SecretBox / EncryptSelf)
	encPayload, err := crypto.EncryptSelf(plainPkt, c.key)
	if err != nil {
		return fmt.Errorf("shadowtls encrypt failed: %w", err)
	}

	// 3. Frame as TLS 1.3 Application Data Record (RFC 8446 Section 5.1)
	// Header: 0x17 (Application Data) + 0x03 0x03 (TLS 1.2/1.3) + 2 bytes length
	recLen := len(encPayload)
	rec := make([]byte, 5+recLen)
	rec[0] = RecordApplicationData
	rec[1] = 0x03
	rec[2] = 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(recLen))
	copy(rec[5:], encPayload)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = c.Conn.Write(rec)
	return err
}

// ReadPacket reads one complete TLS 1.3 Application Data record, decrypts it,
// strips padding, and returns the original inner packet.
func (c *ShadowTLSConn) ReadPacket() ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, hdr); err != nil {
		return nil, err
	}

	// Verify TLS Application Data record header
	if hdr[0] != RecordApplicationData {
		return nil, ErrInvalidRecord
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 40 || recLen > 18000 {
		return nil, ErrRecordTooShort
	}

	encBuf := make([]byte, recLen)
	if _, err := io.ReadFull(c.Conn, encBuf); err != nil {
		return nil, err
	}

	dec, err := crypto.DecryptSelf(encBuf, c.key)
	if err != nil {
		return nil, fmt.Errorf("shadowtls decrypt failed: %w", err)
	}

	if len(dec) < 2 {
		return nil, ErrRecordTooShort
	}

	realLen := int(binary.BigEndian.Uint16(dec[:2]))
	if realLen <= 0 || 2+realLen > len(dec) {
		return nil, ErrInvalidRecord
	}

	pkt := make([]byte, realLen)
	copy(pkt, dec[2:2+realLen])
	return pkt, nil
}

// Read implements standard net.Conn byte stream interface over framed TLS records
func (c *ShadowTLSConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		pkt, err := c.ReadPacket()
		if err != nil {
			return 0, err
		}
		c.readBuf = pkt
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write implements standard net.Conn byte stream interface by framing writes
func (c *ShadowTLSConn) Write(b []byte) (int, error) {
	if err := c.WritePacket(b); err != nil {
		return 0, err
	}
	return len(b), nil
}
