//go:build windows

package diagnostic

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/natbypass/natbypass/internal/tunnel"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func CheckIsAdmin() bool {
	var token windows.Token
	h := windows.CurrentProcess()
	err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func CheckWintunDriver() DiagnosticItem {
	start := time.Now()
	testAdapterName := fmt.Sprintf("NatBypassDiag_%d", time.Now().Unix()%10000)
	dev, err := tunnel.CreateAdapter(testAdapterName, "10.200.250.1")
	if err != nil {
		return DiagnosticItem{
			Name:    "Драйвер Wintun / NDIS Адаптер",
			Passed:  false,
			Elapsed: time.Since(start),
			Message: fmt.Sprintf("❌ Ошибка инициализации Wintun: %v", err),
			Details: "Возможные причины: антивирус блокирует установку драйвера, поврежден wintun.dll или завис предыдущий сетевой адаптер в диспетчере устройств.",
		}
	}
	_ = dev.Close()

	return DiagnosticItem{
		Name:    "Драйвер Wintun / NDIS Адаптер",
		Passed:  true,
		Elapsed: time.Since(start),
		Message: "✓ Драйвер Wintun успешно загружен, тестовый виртуальный сетевой адаптер создан и закрыт без ошибок",
	}
}

func CheckNetshAndFirewall() DiagnosticItem {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "show", "subinterfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	elapsed := time.Since(start)

	if err != nil || ctx.Err() != nil {
		return DiagnosticItem{
			Name:    "Быстродействие Netsh / Маршрутизация",
			Passed:  false,
			Elapsed: elapsed,
			Message: "❌ Утилита netsh зависает или заблокирована политиками безопасности Windows",
			Details: fmt.Sprintf("Ошибка: %v. Проверьте службы Windows Network Location Awareness (NLA) и DHCP Client.", err),
		}
	}

	return DiagnosticItem{
		Name:    "Быстродействие Netsh / Маршрутизация",
		Passed:  true,
		Elapsed: elapsed,
		Message: fmt.Sprintf("✓ Netsh отвечает быстро (%d ms), стек сетевой маршрутизации Windows исправен", elapsed.Milliseconds()),
		Details: string(out[:min(len(out), 200)]),
	}
}

func CheckWebView2Runtime() DiagnosticItem {
	start := time.Now()
	regPaths := []string{
		`SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`,
		`SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`,
	}

	var version string
	for _, p := range regPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.QUERY_VALUE)
		if err == nil {
			v, _, err := k.GetStringValue("pv")
			k.Close()
			if err == nil && v != "" && v != "0.0.0.0" {
				version = v
				break
			}
		}
	}

	elapsed := time.Since(start)
	if version != "" {
		return DiagnosticItem{
			Name:    "Microsoft Edge WebView2 Runtime",
			Passed:  true,
			Elapsed: elapsed,
			Message: fmt.Sprintf("✓ WebView2 Runtime установлен (версия %s)", version),
		}
	}

	return DiagnosticItem{
		Name:    "Microsoft Edge WebView2 Runtime",
		Passed:  true,
		Elapsed: elapsed,
		Message: "⚠️ WebView2 Runtime не найден. Графический интерфейс автоматически откроется в системном браузере (Fallback).",
		Details: "Для встроенного окна установите 'Microsoft Edge WebView2 Evergreen Runtime' с сайта Microsoft.",
	}
}
