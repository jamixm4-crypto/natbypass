//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// restartService перезапускает сервис на Windows с поддержкой путей со скобками (1), пробелами и спецсимволами
func restartService(execPath string) {
	// Используем PowerShell Start-Process с задержкой 1.5 сек в полностью отвязанной группе процессов.
	// Это гарантирует, что текущий процесс успеет освободить порт 8080 и мьютекс,
	// а пути вида "NatBypass (1).exe" гарантированно корректно запустятся без синтаксических ошибок cmd.exe!
	escapedPath := strings.ReplaceAll(execPath, "'", "''")
	psScript := fmt.Sprintf(`Start-Sleep -Milliseconds 1500; Start-Process -FilePath '%s' -ArgumentList 'gui'`, escapedPath)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000 | 0x00000200, // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
	}
	_ = cmd.Start()
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}
