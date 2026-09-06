//go:build linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mobile

import "syscall"

// setTunNonblock переводит TUN fd в non-blocking режим (Linux/Android).
// Это позволяет tf.Read() возвращать EAGAIN вместо блокировки навсегда,
// что необходимо для корректного завершения TUN read goroutine при отключении.
func setTunNonblock(fd int) error {
	return syscall.SetNonblock(fd, true)
}
