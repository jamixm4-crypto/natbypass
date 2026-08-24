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

// restartService перезапускает сервис на Windows с правами Администратора (UAC RunAs)
func restartService(execPath string) {
	escapedPath := strings.ReplaceAll(execPath, "'", "''")
	// Задержка 1.5 сек для полного освобождения портов и мьютексов, затем чистый запуск от Администратора
	psScript := fmt.Sprintf(`Start-Sleep -Milliseconds 1500; Start-Process -FilePath '%s' -Verb RunAs`, escapedPath)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000 | 0x00000200, // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
	}
	_ = cmd.Start()
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}
