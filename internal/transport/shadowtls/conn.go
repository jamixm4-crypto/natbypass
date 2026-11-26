// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package shadowtls

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
)

var (
	ErrRecordTooShort       = errors.New("shadowtls: TLS record too short")
	ErrInvalidRecord        = errors.New("shadowtls: record framing invalid")
	ErrPayloadTooLarge      = errors.New("shadowtls: payload exceeds maximum TLS record size")
	ErrHandshakeNotComplete = errors.New("shadowtls: TLS 1.3 handshake must complete before sending application data")
)

// ShadowTLSConn wraps an underlying authenticated TLS 1.3 connection (*tls.Conn).
// It provides packet framing with dynamic random padding (16..48 bytes) over the TLS stream,
// camouflaging packet size distributions against DPI/TSPU while delegating all encryption,
// authentication, and TLS record framing to Go's standard library crypto/tls (RFC 8446).
type ShadowTLSConn struct {
	net.Conn
	key           [32]byte
	br            *bufio.Reader
	readBuf       []byte
	handshakeDone bool
	readMu        sync.Mutex
	writeMu       sync.Mutex
}

var shadowFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

// NewShadowTLSConn creates a new framed TLS 1.3 connection.
// Presumes the TLS 1.3 handshake has already completed over conn.
func NewShadowTLSConn(conn net.Conn, key [32]byte) *ShadowTLSConn {
	return &ShadowTLSConn{
		Conn:          conn,
		key:           key,
		br:            bufio.NewReaderSize(conn, 65536),
		readBuf:       nil,
		handshakeDone: true,
	}
}

// NewUnverifiedShadowTLSConn creates a connection requiring explicit handshake completion.
func NewUnverifiedShadowTLSConn(rawConn net.Conn, key [32]byte) *ShadowTLSConn {
	return &ShadowTLSConn{
		Conn:          rawConn,
		key:           key,
		br:            bufio.NewReaderSize(rawConn, 65536),
		readBuf:       nil,
		handshakeDone: false,
	}
}

// MarkHandshakeComplete marks the connection as having verified and completed the TLS 1.3 handshake.
func (c *ShadowTLSConn) MarkHandshakeComplete() {
	c.handshakeDone = true
}

// IsHandshakeComplete returns whether the TLS 1.3 handshake is complete.
func (c *ShadowTLSConn) IsHandshakeComplete() bool {
	return c.handshakeDone
}

// NewClientConn performs client-side TLS 1.3 mutual authentication handshake and returns an authenticated ShadowTLSConn.
func NewClientConn(rawConn net.Conn, sni string, key [32]byte, timeout time.Duration) (*ShadowTLSConn, bool, error) {
	return ClientHandshake(rawConn, sni, key, timeout)
}

// NewServerConn performs server-side TLS 1.3 mutual authentication handshake and returns an authenticated ShadowTLSConn.
func NewServerConn(rawConn net.Conn, key [32]byte, timeout time.Duration) (*ShadowTLSConn, error) {
	return ServerHandshake(rawConn, key, DefaultSNI, timeout)
}

// NewServerConnWithSNI performs server-side TLS 1.3 handshake with custom SNI decoy fallback.
func NewServerConnWithSNI(rawConn net.Conn, key [32]byte, sni string, timeout time.Duration) (*ShadowTLSConn, error) {
	return ServerHandshake(rawConn, key, sni, timeout)
}

// WritePacket encapsulates an IP/tunnel packet into an encrypted TLS 1.3 Application Data stream
// with dynamic padding (16-48 bytes) to camouflage packet size distributions against DPI.
// All encryption is performed by Go's standard crypto/tls layer in RFC 8446 AEAD records.
func (c *ShadowTLSConn) WritePacket(payload []byte) error {
	if !c.handshakeDone {
		return ErrHandshakeNotComplete
	}
	if len(payload) == 0 {
		return nil
	}
	if len(payload) > 16384 {
		return ErrPayloadTooLarge
	}

	// 1. Calculate dynamic random padding (16..48 bytes) with zero syscalls
	var padRand [1]byte
	crypto.FastJitterBytes(padRand[:])
	padLen := 16 + int(padRand[0]%33)

	realLen := uint16(len(payload))
	totalLen := 2 + len(payload) + padLen
	if totalLen > 32768 {
		return ErrPayloadTooLarge
	}

	// 2. Build framed payload: [uint16 totalLen][uint16 realLen][payload][random padding]
	frameLen := 2 + totalLen
	var pooledPtr *[]byte
	var frame []byte
	if frameLen <= 2048 {
		pooledPtr = shadowFramePool.Get().(*[]byte)
		frame = (*pooledPtr)[:frameLen]
	} else {
		frame = make([]byte, frameLen)
	}
	binary.BigEndian.PutUint16(frame[0:2], uint16(totalLen))
	binary.BigEndian.PutUint16(frame[2:4], realLen)
	copy(frame[4:4+len(payload)], payload)
	crypto.FastJitterBytes(frame[4+len(payload):])

	c.writeMu.Lock()
	// Write directly to c.Conn (*tls.Conn). Go's standard library crypto/tls encrypts
	// the frame into genuine TLS 1.3 Application Data records with AEAD and sequence numbers.
	_, err := c.Conn.Write(frame)
	c.writeMu.Unlock()
	if pooledPtr != nil {
		shadowFramePool.Put(pooledPtr)
	}
	return err
}

// ReadPacket reads one framed packet from the TLS 1.3 stream, decrypts it via crypto/tls,
// strips padding, and returns the original inner packet.
func (c *ShadowTLSConn) ReadPacket() ([]byte, error) {
	if !c.handshakeDone {
		return nil, ErrHandshakeNotComplete
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.br == nil {
		c.br = bufio.NewReaderSize(c.Conn, 65536)
	}

	var lenHdr [2]byte
	if _, err := io.ReadFull(c.br, lenHdr[:]); err != nil {
		return nil, err
	}
	totalLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	if totalLen < 18 || totalLen > 32768 {
		return nil, ErrRecordTooShort
	}

	var pooledPtr *[]byte
	var frame []byte
	if totalLen <= 2048 {
		pooledPtr = shadowFramePool.Get().(*[]byte)
		frame = (*pooledPtr)[:totalLen]
	} else {
		frame = make([]byte, totalLen)
	}
	if _, err := io.ReadFull(c.br, frame); err != nil {
		if pooledPtr != nil {
			shadowFramePool.Put(pooledPtr)
		}
		return nil, err
	}

	realLen := int(binary.BigEndian.Uint16(frame[:2]))
	if realLen <= 0 || 2+realLen > totalLen {
		if pooledPtr != nil {
			shadowFramePool.Put(pooledPtr)
		}
		return nil, ErrInvalidRecord
	}

	pkt := make([]byte, realLen)
	copy(pkt, frame[2:2+realLen])
	if pooledPtr != nil {
		shadowFramePool.Put(pooledPtr)
	}
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
