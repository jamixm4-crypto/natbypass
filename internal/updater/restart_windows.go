//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

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
	// 1. Выполняем хуки очистки (удаление значка из трея и закрытие дескрипторов)
	RunPreExitHooks()

	escapedPath := strings.ReplaceAll(execPath, "'", "''")
	isGUI := strings.Contains(strings.ToLower(execPath), "gui")

	var argList []string
	hasNoWindow := false
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--no-window" || arg == "-no-window" || arg == "--silent" || arg == "-silent" || arg == "--updated" || arg == "-updated" || strings.HasPrefix(arg, "--ui=none") || strings.HasPrefix(arg, "--ui=off") {
			hasNoWindow = true
		}
		argList = append(argList, fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "''")))
	}

	// Для фонового демона/CLI передаем --no-window, чтобы не открывать окно заново.
	// Для оконного Win32 GUI (NatBypass-GUI.exe) данный флаг НЕ добавляем!
	if !isGUI && !hasNoWindow {
		argList = append(argList, "'--no-window'")
	}

	curPID := os.Getpid()
	var psScript string
	if len(argList) > 0 {
		argStr := strings.Join(argList, ", ")
		psScript = fmt.Sprintf(`Wait-Process -Id %d -Timeout 15 -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500; Start-Process -FilePath '%s' -ArgumentList @(%s) -Verb RunAs`, curPID, escapedPath, argStr)
	} else {
		psScript = fmt.Sprintf(`Wait-Process -Id %d -Timeout 15 -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500; Start-Process -FilePath '%s' -Verb RunAs`, curPID, escapedPath)
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
