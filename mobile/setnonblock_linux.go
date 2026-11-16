//go:build linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mobile

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setTunNonblock переводит TUN fd в non-blocking режим (Linux/Android).
// Это позволяет tf.Read() возвращать EAGAIN вместо блокировки навсегда,
// что необходимо для корректного завершения TUN read goroutine при отключении.
func setTunNonblock(fd int) error {
	return syscall.SetNonblock(fd, true)
}

func closeTunFd(fd int) {
	if fd > 0 {
		_ = syscall.Close(fd)
	}
}

// waitTunReadable ожидает готовности дескриптора TUN для чтения через poll() ядра Linux.
// Это обеспечивает субмиллисекундную реакцию на появление пакетов (<0.1 мс вместо искусственного time.Sleep),
// полностью устраняя искусственное ограничение пропускной способности TCP (ACK throttling),
// и одновременно гарантирует 0% расхода CPU в моменты простоя туннеля.
func waitTunReadable(fd int, timeoutMs int) bool {
	if fd <= 0 {
		return false
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP}}
	n, err := unix.Poll(pfd, timeoutMs)
	return err == nil && n > 0 && (pfd[0].Revents&unix.POLLIN != 0)
}
