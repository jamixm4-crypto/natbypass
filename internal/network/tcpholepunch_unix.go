//go:build !windows

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
		if err1 := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err1 != nil {
			opErr = err1
			return
		}
		// SO_REUSEPORT (0xf on Linux/BSD)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0xf, 1)
	})
	if err != nil {
		return err
	}
	return opErr
}
