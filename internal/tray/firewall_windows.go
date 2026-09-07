//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tray

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// EnsureFirewallRule ensures Windows Firewall allow rules exist for the NatBypass executable,
// the active UDP puncher port, standard stealth ports (443, 47832), ICMPv4, and the Wintun adapter.
func EnsureFirewallRule(port int) error {
	ruleName := "NatBypass"
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// 1. Program rule: allow inbound for our specific program with edge traversal and all profiles
	checkCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := checkCmd.CombinedOutput()
	if err == nil && strings.Contains(string(out), ruleName) {
		setCmd := exec.Command("netsh", "advfirewall", "firewall", "set", "rule",
			"name="+ruleName,
			"new",
			"profile=any",
			"edge=yes",
		)
		setCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = setCmd.Run()
	} else {
		addCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=allow",
			"program="+exePath,
			"profile=any",
			"edge=yes",
			"enable=yes",
		)
		addCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = addCmd.Run()
	}

	// 2. Specific UDP Port rules with EdgeTraversal (edge=yes) and profile=any
	// Always ensure standard ports 443 and 47832 are permitted
	ensurePortRule("NatBypass-UDP-443", 443)
	ensurePortRule("NatBypass-UDP-47832", 47832)

	// If a custom or dynamically bound port is specified, ensure rule exists
	if port > 0 && port != 443 && port != 47832 {
		portRule := fmt.Sprintf("NatBypass-P2P-%d", port)
		ensurePortRule(portRule, port)
	}

	// 3. Ensure ICMPv4 echo requests are allowed through Firewall
	ensureICMPRule()

	// 4. Ensure NatBypass Wintun interface adapter traffic is allowed
	ensureAdapterRule()

	return nil
}

func ensurePortRule(ruleName string, port int) {
	pCheck := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	pCheck.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	pOut, pErr := pCheck.CombinedOutput()
	if pErr != nil || !strings.Contains(string(pOut), ruleName) {
		pAdd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=allow",
			"protocol=UDP",
			fmt.Sprintf("localport=%d", port),
			"profile=any",
			"edge=yes",
			"enable=yes",
		)
		pAdd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = pAdd.Run()
	} else {
		pSet := exec.Command("netsh", "advfirewall", "firewall", "set", "rule",
			"name="+ruleName,
			"new",
			"profile=any",
			"edge=yes",
		)
		pSet.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = pSet.Run()
	}
}

func ensureICMPRule() {
	ruleName := "NatBypass-ICMPv4"
	check := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	check.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := check.CombinedOutput()
	if err != nil || !strings.Contains(string(out), ruleName) {
		add := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=allow",
			"protocol=icmpv4:8,any",
			"profile=any",
			"enable=yes",
		)
		add.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = add.Run()
	}
}

func ensureAdapterRule() {
	ruleName := "NatBypass Adapter All"
	check := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	check.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := check.CombinedOutput()
	if err != nil || !strings.Contains(string(out), ruleName) {
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			`New-NetFirewallRule -DisplayName 'NatBypass Adapter All' -Name 'NatBypass Adapter All' -Direction Inbound -Action Allow -InterfaceAlias 'NatBypass' -Profile Any -ErrorAction SilentlyContinue`)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}
}