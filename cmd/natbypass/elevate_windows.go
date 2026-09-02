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
	// При запуске с правами администратора: очищаем накопленные дублирующиеся правила,
	// затем создаём ровно один набор нужных правил.
	go func() {
		cleanupFirewallDuplicates()
		ensureFirewallRule()
	}()
}

// cleanupFirewallDuplicates удаляет все накопившиеся дублирующиеся правила NatBypass
// (созданные предыдущими версиями программы) через PowerShell.
func cleanupFirewallDuplicates() {
	psScript := `
$names = @('NatBypass-ICMPv4','NatBypass ICMP Allow','NatBypass ICMP Reply Allow',
           'NatBypass ICMPv4 In','NatBypass Adapter All','NatBypass All In',
           'NatBypass ICMP In','NatBypass Mesh Outbound','NatBypass TCP Mesh',
           'NatBypass UDP Mesh','NatBypass','NatBypass ICMPv4')
foreach ($n in $names) { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue }
`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	_ = cmd.Run()
	log.Info().Msg("🧹 Старые дублирующиеся правила NatBypass Firewall очищены")
}

// ensureFirewallRule создаёт правила Windows Firewall для NatBypass (без дубликатов):
// входящий UDP 47832, входящий ICMPv4, и разрешение всего трафика через адаптер.
func ensureFirewallRule() {
	rules := []struct {
		name    string
		netshArgs []string
		psNew   string
	}{
		{
			name: "NatBypass UDP P2P (47832)",
			netshArgs: []string{"dir=in", "action=allow", "protocol=UDP", "localport=47832", "enable=yes", "profile=any"},
		},
		{
			name: "NatBypass ICMPv4 In",
			psNew: `New-NetFirewallRule -DisplayName 'NatBypass ICMPv4 In' -Name 'NatBypass ICMPv4 In' -Direction Inbound -Action Allow -Protocol ICMPv4 -ErrorAction SilentlyContinue`,
		},
		{
			name: "NatBypass Adapter All",
			psNew: `New-NetFirewallRule -DisplayName 'NatBypass Adapter All' -Name 'NatBypass Adapter All' -Direction Inbound -Action Allow -InterfaceAlias 'NatBypass' -ErrorAction SilentlyContinue`,
		},
	}

	for _, r := range rules {
		checkCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+r.name)
		checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if checkCmd.Run() == nil {
			continue // уже существует
		}
		if r.psNew != "" {
			cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", r.psNew)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
			_ = cmd.Run()
		} else {
			args := append([]string{"advfirewall", "firewall", "add", "rule", "name=" + r.name}, r.netshArgs...)
			cmd := exec.Command("netsh", args...)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
			_ = cmd.Run()
		}
		log.Info().Str("rule", r.name).Msg("✅ Правило Windows Firewall создано")
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

