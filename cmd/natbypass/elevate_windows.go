//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/natbypass/natbypass/internal/diagnostic"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

// ensureAdminOnWindows проверяет права администратора.
// Если прав нет — просто предупреждает в лог.
// TUN-адаптер без прав не поднимется, но MQTT и WebUI работают без прав.
func ensureAdminOnWindows() {
	if !diagnostic.CheckIsAdmin() {
		log.Warn().Msg("⚠️ Запущено без прав администратора. Виртуальный сетевой интерфейс (TUN) требует прав администратора. Остальные функции (WebUI, MQTT, P2P) работают в обычном режиме.")
		return
	}
	// Если запущен с правами администратора — тихо создаем правило брандмауэра для UDP hole-punch (порт 47832)
	go ensureFirewallRule()
}

// ensureFirewallRule создаёт правило Windows Firewall для входящего UDP на порту 47832 (без дубликатов)
func ensureFirewallRule() {
	const ruleName = "NatBypass UDP P2P (47832)"
	checkCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := checkCmd.Run(); err == nil {
		return // Правило уже существует
	}
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName, "dir=in", "action=allow", "protocol=UDP", "localport=47832",
		"description=NatBypass UDP hole-punch P2P port", "enable=yes", "profile=any")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Run(); err == nil {
		log.Info().Msg("✅ Правило Windows Firewall для UDP 47832 (P2P Direct) создано")
	}
}

// relaunchAsAdmin перезапускает текущий процесс с правами администратора через ShellExecuteEx (UAC-диалог).
// Вызывается если TUN не удалось создать и пользователь хочет поднять интерфейс.
func relaunchAsAdmin() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}

	verb, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exe)

	type SHELLEXECUTEINFO struct {
		cbSize         uint32
		fMask          uint32
		hwnd           uintptr
		lpVerb         *uint16
		lpFile         *uint16
		lpParameters   *uint16
		lpDirectory    *uint16
		nShow          int32
		hInstApp       uintptr
		lpIDList       uintptr
		lpClass        *uint16
		hkeyClass      uintptr
		dwHotKey       uint32
		hIconOrMonitor uintptr
		hProcess       uintptr
	}

	sei := &SHELLEXECUTEINFO{
		fMask:   0x00000040, // SEE_MASK_NOCLOSEPROCESS
		lpVerb:  verb,
		lpFile:  exePtr,
		nShow:   1,
	}
	sei.cbSize = uint32(unsafe.Sizeof(*sei))

	shell32 := windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteEx := shell32.NewProc("ShellExecuteExW")
	ret, _, _ := procShellExecuteEx.Call(uintptr(unsafe.Pointer(sei)))
	return ret != 0
}

