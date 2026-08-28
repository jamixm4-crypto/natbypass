//go:build windows

package tray

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// EnsureFirewallRule ensures a Windows Firewall allow rule exists specifically for the NatBypass executable.
func EnsureFirewallRule(port int) error {
	ruleName := "NatBypass"
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// 1. Check if rule already exists
	checkCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := checkCmd.CombinedOutput()
	if err == nil && strings.Contains(string(out), ruleName) {
		return nil
	}

	// 2. Add rule: allow inbound for our specific program
	addCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=in",
		"action=allow",
		"program="+exePath,
		"enable=yes",
	)
	addCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add firewall rule: %w", err)
	}
	return nil
}