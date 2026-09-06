//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"syscall"
)

func setSocketReusePort(c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		// SO_REUSEADDR on Windows allows rebinding port
		opErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return opErr
}
