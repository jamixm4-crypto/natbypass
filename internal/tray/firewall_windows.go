//go:build windows

package tray

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// EnsureFirewallRule ensures a Windows Firewall allow rule exists for the WebUI TCP port.
func EnsureFirewallRule(port int) error {
	ruleName := "NatBypass WebUI"

	// 1. Check if rule already exists
	checkCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := checkCmd.CombinedOutput()
	if err == nil && strings.Contains(string(out), ruleName) {
		return nil
	}

	// 2. Add rule: allow inbound TCP
	addCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=in",
		"action=allow",
		"protocol=TCP",
		"localport="+strconv.Itoa(port),
	)
	addCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add firewall rule: %w", err)
	}
	return nil
}