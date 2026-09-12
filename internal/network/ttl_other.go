//go:build !linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"net"
)

// SendLowTTLDecoyProbe is a standard write fallback on non-Linux operating systems.
func SendLowTTLDecoyProbe(conn *net.UDPConn, rAddr *net.UDPAddr, payload []byte, ttl int) error {
	if conn == nil || rAddr == nil || len(payload) == 0 {
		return nil
	}
	_, err := conn.WriteToUDP(payload, rAddr)
	return err
}
