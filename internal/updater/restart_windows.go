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

// RestartService перезапускает сервис на Windows с правами Администратора (UAC RunAs) и сохранением аргументов
func RestartService(execPath string) {
	escapedPath := strings.ReplaceAll(execPath, "'", "''")

	var argList []string
	for i := 1; i < len(os.Args); i++ {
		argList = append(argList, fmt.Sprintf("'%s'", strings.ReplaceAll(os.Args[i], "'", "''")))
	}
	var psScript string
	if len(argList) > 0 {
		argStr := strings.Join(argList, ", ")
		psScript = fmt.Sprintf(`Start-Sleep -Milliseconds 1500; Start-Process -FilePath '%s' -ArgumentList @(%s) -Verb RunAs`, escapedPath, argStr)
	} else {
		psScript = fmt.Sprintf(`Start-Sleep -Milliseconds 1500; Start-Process -FilePath '%s' -Verb RunAs`, escapedPath)
	}

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000 | 0x00000200, // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
	}
	_ = cmd.Start()
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}

func restartService(execPath string) {
	RestartService(execPath)
}
