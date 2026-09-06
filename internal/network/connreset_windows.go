//go:build windows

package network

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const SIO_UDP_CONNRESET = 0x9800000C

// DisableUDPConnReset disables the SIO_UDP_CONNRESET socket option on Windows.
// By default, Windows returns WSAECONNRESET (error 10054) on the next recvfrom() if a previously
// sent UDP packet caused an ICMP Port Unreachable. Disabling this is standard practice for UDP hole punching.
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
