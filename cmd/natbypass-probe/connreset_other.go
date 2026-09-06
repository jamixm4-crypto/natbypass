//go:build !windows

package main

import "net"

func DisableUDPConnReset(conn *net.UDPConn) {}
