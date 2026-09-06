//go:build !windows

package network

import "net"

// DisableUDPConnReset is a no-op on non-Windows platforms.
func DisableUDPConnReset(conn *net.UDPConn) {}
