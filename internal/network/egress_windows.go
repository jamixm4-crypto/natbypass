//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"net"
	"os/exec"
	"strings"
	"syscall"
)

func getWindowsDefaultGateway() net.IP {
	psScript := `(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notlike '*NatBypass*' -and $_.InterfaceAlias -notlike '*Wintun*' } | Sort-Object RouteMetric | Select-Object -First 1).NextHop`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if out, err := cmd.Output(); err == nil {
		str := strings.TrimSpace(string(out))
		if ip := net.ParseIP(str); ip != nil && !ip.IsUnspecified() {
			return ip.To4()
		}
	}
	return nil
}
