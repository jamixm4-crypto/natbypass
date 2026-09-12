//go:build linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"net"
	"syscall"
)

// SendLowTTLDecoyProbe sends a decoy probe packet with a deliberately low IP TTL (1-3)
// towards the in-path TSPU/DPI inspection engine. The decoy packet reaches the DPI middlebox,
// influencing its state-machine, but expires before reaching the remote peer.
// The socket TTL is immediately restored to standard 64 after transmission.
func SendLowTTLDecoyProbe(conn *net.UDPConn, rAddr *net.UDPAddr, payload []byte, ttl int) error {
	if conn == nil || rAddr == nil || len(payload) == 0 {
		return nil
	}
	if ttl <= 0 || ttl > 64 {
		ttl = 2
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		_, writeErr := conn.WriteToUDP(payload, rAddr)
		return writeErr
	}

	var sockErr error
	_ = rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})

	_, writeErr := conn.WriteToUDP(payload, rAddr)

	// Restore default TTL = 64
	_ = rawConn.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 64)
	})

	if sockErr != nil {
		return sockErr
	}
	return writeErr
}
