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

	// 1. Check if rule already exists; if yes, ensure edge=yes is enabled
	checkCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := checkCmd.CombinedOutput()
	if err == nil && strings.Contains(string(out), ruleName) {
		setCmd := exec.Command("netsh", "advfirewall", "firewall", "set", "rule",
			"name="+ruleName,
			"new",
			"edge=yes",
		)
		setCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = setCmd.Run()
	} else {
		// 2. Add rule: allow inbound for our specific program with edge traversal
		addCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=allow",
			"program="+exePath,
			"edge=yes",
			"enable=yes",
		)
		addCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := addCmd.Run(); err != nil {
			return fmt.Errorf("failed to add firewall rule: %w", err)
		}
	}

	// 3. Port rule with EdgeTraversal (edge=yes)
	if port > 0 {
		portRule := fmt.Sprintf("NatBypass-P2P-%d", port)
		pCheck := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+portRule)
		pCheck.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		pOut, pErr := pCheck.CombinedOutput()
		if pErr != nil || !strings.Contains(string(pOut), portRule) {
			pAdd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+portRule,
				"dir=in",
				"action=allow",
				"protocol=UDP",
				fmt.Sprintf("localport=%d", port),
				"edge=yes",
				"enable=yes",
			)
			pAdd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			_ = pAdd.Run()
		} else {
			pSet := exec.Command("netsh", "advfirewall", "firewall", "set", "rule",
				"name="+portRule,
				"new",
				"edge=yes",
			)
			pSet.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			_ = pSet.Run()
		}
	}
	return nil
}