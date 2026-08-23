//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// restartService перезапускает сервис на Windows через отложенный cmd.exe
func restartService(execPath string) {
	// Отложенный запуск через 1.5 сек с помощью cmd.exe в полностью отвязанной группе процессов
	// Это гарантирует, что текущий процесс NatBypass успеет завершиться,
	// освободить Single Instance Named Mutex и закрыть порт 8080 до старта нового процесса!
	cmd := exec.Command("cmd.exe", "/c", fmt.Sprintf("ping 127.0.0.1 -n 3 >nul & start \"\" \"%s\"", execPath))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000 | 0x00000200, // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
	}
	_ = cmd.Start()
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}
