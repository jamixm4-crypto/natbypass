//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

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

	// 1. Program rule with EdgeTraversal (edge=yes)
	checkCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := checkCmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), ruleName) {
		addCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=allow",
			"program="+exePath,
			"edge=yes",
			"enable=yes",
		)
		addCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = addCmd.Run()
	} else {
		// Update existing rule to enable NAT edge traversal
		setCmd := exec.Command("netsh", "advfirewall", "firewall", "set", "rule",
			"name="+ruleName,
			"new",
			"edge=yes",
		)
		setCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = setCmd.Run()
	}

	// 2. Port rule with EdgeTraversal (edge=yes)
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
				"edge=yes",
				"enable=yes",
			)
			portAdd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			_ = portAdd.Run()
		} else {
			setPortCmd := exec.Command("netsh", "advfirewall", "firewall", "set", "rule",
				"name="+portRule,
				"new",
				"edge=yes",
			)
			setPortCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			_ = setPortCmd.Run()
		}
	}
	logf("[FW] Ensured Windows Defender Firewall allows inbound UDP with NAT Edge Traversal for port %d", port)
}
