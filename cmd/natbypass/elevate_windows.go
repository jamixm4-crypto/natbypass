//go:build windows

package main

import (
	"os"
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
	}
	// Создаём правило брандмауэра для UDP hole-punch (port 47832) в фоне
	go ensureFirewallRule()
}

// ensureFirewallRule создаёт правило Windows Firewall для входящего UDP на порту 47832
// (порт UDP puncher). Без этого правила Windows Firewall блокирует входящие UDP-пробы
// от других устройств, и статус соединения всегда остаётся Relay вместо Direct P2P.
// Запускаем netsh через ShellExecuteEx с verb "runas" — UAC-диалог только один раз.
func ensureFirewallRule() {
	const ruleName = "NatBypass UDP P2P (47832)"

	// Сначала проверяем — возможно правило уже есть
	checkCmd := "cmd.exe"
	checkArgs, _ := windows.UTF16PtrFromString("/C netsh advfirewall firewall show rule name=\"" + ruleName + "\" >nul 2>&1")
	checkFile, _ := windows.UTF16PtrFromString(checkCmd)

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

	// Тихая проверка без диалога (обычные права)
	seiCheck := &SHELLEXECUTEINFO{
		fMask:       0x00000040 | 0x00000100, // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
		lpFile:      checkFile,
		lpParameters: checkArgs,
		nShow:       0, // SW_HIDE
	}
	seiCheck.cbSize = uint32(unsafe.Sizeof(*seiCheck))
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteEx := shell32.NewProc("ShellExecuteExW")

	// Добавляем правило через elevated netsh
	addArgs, _ := windows.UTF16PtrFromString(
		"/C netsh advfirewall firewall add rule name=\"" + ruleName + "\" " +
		"dir=in action=allow protocol=UDP localport=47832 " +
		"description=\"NatBypass UDP hole-punch P2P port\" enable=yes profile=any",
	)
	addFile, _ := windows.UTF16PtrFromString("cmd.exe")
	runas, _ := windows.UTF16PtrFromString("runas")

	seiAdd := &SHELLEXECUTEINFO{
		fMask:       0x00000040 | 0x00000100,
		lpVerb:      runas,
		lpFile:      addFile,
		lpParameters: addArgs,
		nShow:       0, // SW_HIDE — без окна консоли
	}
	seiAdd.cbSize = uint32(unsafe.Sizeof(*seiAdd))

	ret, _, _ := procShellExecuteEx.Call(uintptr(unsafe.Pointer(seiAdd)))
	if ret != 0 {
		log.Info().Msg("✅ Правило Windows Firewall для UDP 47832 (P2P Direct) создано или уже существует")
	} else {
		log.Warn().Msg("⚠️ Не удалось создать правило Windows Firewall для UDP 47832. Статус Direct P2P может не работать.")
	}
	_ = seiCheck // suppress unused warning
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

