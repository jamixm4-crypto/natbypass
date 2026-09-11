// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

const (
	// MultiHopMagic is the 2-byte header identifier for multi-hop P2P mesh relay packets ("NH").
	MultiHopMagic0 = 0x4E
	MultiHopMagic1 = 0x48

	// DefaultMaxTTL is the initial time-to-live for a multi-hop relayed packet.
	DefaultMaxTTL = 5

	// MinMultiHopHeaderSize: Magic(2) + TTL(1) + Flags(1) + SrcLen(1) + DstLen(1) = 6 bytes
	MinMultiHopHeaderSize = 6
)

var (
	ErrNotMultiHop   = errors.New("not a multi-hop packet")
	ErrPacketTooShort = errors.New("packet too short for multi-hop header")
	ErrTTLZero       = errors.New("multi-hop TTL expired (loop prevention)")
	ErrDeviceIDTooLong = errors.New("deviceID exceeds maximum length 64")
)

// MultiHopPacket represents a routed P2P mesh envelope.
// The payload remains end-to-end encrypted between SrcID and DstID.
type MultiHopPacket struct {
	TTL     uint8
	Flags   uint8
	SrcID   string
	DstID   string
	Payload []byte
}

// EncodeMultiHopPacket serializes a multi-hop envelope.
func EncodeMultiHopPacket(srcID, dstID string, ttl uint8, flags uint8, payload []byte) ([]byte, error) {
	if len(srcID) > 64 || len(dstID) > 64 {
		return nil, ErrDeviceIDTooLong
	}
	if ttl == 0 {
		ttl = DefaultMaxTTL
	}

	srcLen := len(srcID)
	dstLen := len(dstID)
	totalLen := MinMultiHopHeaderSize + srcLen + dstLen + len(payload)

	buf := make([]byte, totalLen)
	buf[0] = MultiHopMagic0
	buf[1] = MultiHopMagic1
	buf[2] = ttl
	buf[3] = flags
	buf[4] = uint8(srcLen)
	buf[5] = uint8(dstLen)

	offset := 6
	copy(buf[offset:], srcID)
	offset += srcLen
	copy(buf[offset:], dstID)
	offset += dstLen
	copy(buf[offset:], payload)

	return buf, nil
}

// DecodeMultiHopPacket parses a raw multi-hop envelope.
func DecodeMultiHopPacket(data []byte) (*MultiHopPacket, error) {
	if len(data) < MinMultiHopHeaderSize {
		return nil, ErrPacketTooShort
	}
	if data[0] != MultiHopMagic0 || data[1] != MultiHopMagic1 {
		return nil, ErrNotMultiHop
	}

	ttl := data[2]
	flags := data[3]
	srcLen := int(data[4])
	dstLen := int(data[5])

	headerLen := MinMultiHopHeaderSize + srcLen + dstLen
	if len(data) < headerLen {
		return nil, ErrPacketTooShort
	}

	offset := 6
	srcID := string(data[offset : offset+srcLen])
	offset += srcLen
	dstID := string(data[offset : offset+dstLen])
	offset += dstLen
	payload := data[offset:]

	return &MultiHopPacket{
		TTL:     ttl,
		Flags:   flags,
		SrcID:   srcID,
		DstID:   dstID,
		Payload: payload,
	}, nil
}

// IsMultiHopPacket quickly checks if a packet has the MultiHop magic prefix.
func IsMultiHopPacket(data []byte) bool {
	return len(data) >= MinMultiHopHeaderSize && data[0] == MultiHopMagic0 && data[1] == MultiHopMagic1
}

// MultiHopRouter handles multi-hop routing, transit forwarding, and local delivery.
type MultiHopRouter struct {
	// Atomic telemetry metrics MUST be first for 64-bit alignment on 32-bit MIPS/ARM/386
	forwardedCount uint64
	deliveredCount uint64
	droppedLoops   uint64

	selfDeviceID string
	forwardFunc  func(dstID string, packet []byte) error
	deliverFunc  func(srcID string, payload []byte) error
	mu           sync.RWMutex
}

// NewMultiHopRouter creates a router instance for the local node.
func NewMultiHopRouter(
	selfDeviceID string,
	forwardFunc func(dstID string, packet []byte) error,
	deliverFunc func(srcID string, payload []byte) error,
) *MultiHopRouter {
	return &MultiHopRouter{
		selfDeviceID: selfDeviceID,
		forwardFunc:  forwardFunc,
		deliverFunc:  deliverFunc,
	}
}

// SetDeliverFunc safely updates the packet delivery function for packets destined to this node.
func (r *MultiHopRouter) SetDeliverFunc(fn func(srcID string, payload []byte) error) {
	r.mu.Lock()
	r.deliverFunc = fn
	r.mu.Unlock()
}

// Route processes an incoming packet.
// - If destination is local node: strips header and delivers payload locally.
// - If destination is remote: decrements TTL in place and forwards to next hop.
func (r *MultiHopRouter) Route(data []byte) error {
	pkt, err := DecodeMultiHopPacket(data)
	if err != nil {
		return err
	}

	// Case 1: Destination is THIS node
	if pkt.DstID == r.selfDeviceID {
		atomic.AddUint64(&r.deliveredCount, 1)
		r.mu.RLock()
		deliv := r.deliverFunc
		r.mu.RUnlock()
		if deliv != nil {
			return deliv(pkt.SrcID, pkt.Payload)
		}
		return nil
	}

	// Case 2: Intermediate transit hop (Node C forwarding A -> B)
	if pkt.TTL <= 1 {
		atomic.AddUint64(&r.droppedLoops, 1)
		return fmt.Errorf("%w: TTL=%d for dst=%s", ErrTTLZero, pkt.TTL, pkt.DstID)
	}

	// Zero-allocation TTL decrement in place
	data[2]--
	atomic.AddUint64(&r.forwardedCount, 1)

	r.mu.RLock()
	fwd := r.forwardFunc
	r.mu.RUnlock()
	if fwd != nil {
		return fwd(pkt.DstID, data)
	}
	return nil
}

// Stats returns the router's current telemetry counters.
func (r *MultiHopRouter) Stats() (forwarded, delivered, droppedLoops uint64) {
	return atomic.LoadUint64(&r.forwardedCount),
		atomic.LoadUint64(&r.deliveredCount),
		atomic.LoadUint64(&r.droppedLoops)
}
