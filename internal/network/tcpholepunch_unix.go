//go:build !windows

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
