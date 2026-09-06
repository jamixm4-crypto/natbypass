//go:build !windows

package network

import "net"

func getWindowsDefaultGateway() net.IP {
	return nil
}
