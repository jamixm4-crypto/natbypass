//go:build !windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package diagnostic

import (
	"os"
	"os/exec"
)

func CheckIsAdmin() bool {
	return os.Geteuid() == 0
}

func CheckWintunDriver() DiagnosticItem {
	return DiagnosticItem{
		Name:    "Драйвер TUN/TAP",
		Passed:  true,
		Elapsed: 0,
		Message: "✓ В Linux/Unix используется ядерный модуль /dev/net/tun",
	}
}

func CheckNetshAndFirewall() DiagnosticItem {
	return DiagnosticItem{
		Name:    "Маршрутизация / Netlink",
		Passed:  true,
		Elapsed: 0,
		Message: "✓ В Linux маршрутизация выполняется через ядро (ip route / iptables)",
	}
}

func CheckWebView2Runtime() DiagnosticItem {
	return DiagnosticItem{
		Name:    "Web UI Runtime",
		Passed:  true,
		Elapsed: 0,
		Message: "✓ В Linux веб-панель управления открывается через встроенный HTTP-сервер",
	}
}

func setSysProcAttr(cmd *exec.Cmd) {
}

