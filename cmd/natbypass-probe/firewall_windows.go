//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func EnsureProbeFirewallRule(port int) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	ruleName := "NatBypass-Probe"

	checkCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := checkCmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), ruleName) {
		addCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=allow",
			"program="+exePath,
			"enable=yes",
		)
		addCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = addCmd.Run()
	}

	if port > 0 {
		portRule := fmt.Sprintf("NatBypass-Probe-UDP-%d", port)
		portCheck := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+portRule)
		portCheck.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		pOut, pErr := portCheck.CombinedOutput()
		if pErr != nil || !strings.Contains(string(pOut), portRule) {
			portAdd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+portRule,
				"dir=in",
				"action=allow",
				"protocol=UDP",
				fmt.Sprintf("localport=%d", port),
				"enable=yes",
			)
			portAdd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			_ = portAdd.Run()
		}
	}
	logf("[FW] Ensured Windows Defender Firewall allows inbound UDP for port %d", port)
}
