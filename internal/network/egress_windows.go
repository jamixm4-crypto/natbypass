//go:build windows

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
