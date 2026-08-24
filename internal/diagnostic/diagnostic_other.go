//go:build !windows

package diagnostic

import (
	"os"
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
