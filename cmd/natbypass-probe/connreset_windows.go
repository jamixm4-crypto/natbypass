//go:build windows

package main

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const SIO_UDP_CONNRESET = 0x9800000C

func DisableUDPConnReset(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rawConn.Control(func(fd uintptr) {
		var bytesReturned uint32
		newVal := uint32(0)
		_ = windows.WSAIoctl(
			windows.Handle(fd),
			SIO_UDP_CONNRESET,
			(*byte)(unsafe.Pointer(&newVal)),
			uint32(unsafe.Sizeof(newVal)),
			nil,
			0,
			&bytesReturned,
			nil,
			0,
		)
	})
}
