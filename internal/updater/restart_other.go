//go:build !windows

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
	"time"
)

// isSystemdService проверяет, управляется ли процесс natbypass через systemd
func isSystemdService() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	// Если процесс запущен systemd, переменная INVOCATION_ID всегда установлена
	if os.Getenv("INVOCATION_ID") != "" {
		return true
	}
	// Проверяем, существует ли файл юнита или активна ли служба
	if _, err := os.Stat("/etc/systemd/system/natbypass.service"); err == nil {
		return true
	}
	if _, err := os.Stat("/lib/systemd/system/natbypass.service"); err == nil {
		return true
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "natbypass").Run(); err == nil {
		return true
	}
	return false
}

// hasBinaryInPath возвращает true, если команда есть в PATH.
func hasBinaryInPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RestartService перезапускает сервис на Linux/router платформах безопасно.
//
// Особенности реализации для BusyBox (Keenetic MIPS, OpenWrt):
//   - sleep использует только целые числа (BusyBox не принимает дробные, напр. 1.5)
//   - nohup опционален — используется setsid или просто двойной fork как fallback
//   - двойной fork через "sh -c '... &'" гарантирует отсоединение от текущего PID
func RestartService(execPath string) {
	var restartCmd string
	if _, err := os.Stat("/opt/etc/init.d/S99natbypass"); err == nil {
		// Keenetic Entware
		restartCmd = "/opt/etc/init.d/S99natbypass restart"
	} else if _, err := os.Stat("/etc/init.d/natbypass"); err == nil {
		// OpenWrt Procd / SysVinit
		restartCmd = "/etc/init.d/natbypass restart"
	} else if isSystemdService() {
		// Linux systemd (только если служба реально управляется systemd)
		restartCmd = "systemctl restart natbypass"
	} else {
		// Прямой перезапуск бинарника с сохранением оригинальных аргументов (включая --config)
		var escapedArgs []string
		for i, a := range os.Args {
			if i == 0 {
				escapedArgs = append(escapedArgs, fmt.Sprintf("'%s'", execPath))
			} else {
				escapedArgs = append(escapedArgs, fmt.Sprintf("'%s'", strings.ReplaceAll(a, "'", "'\\''")))
			}
		}
		restartCmd = strings.Join(escapedArgs, " ")
	}

	// Строим BusyBox-совместимый detached-скрипт.
	// ВАЖНО: sleep должен использовать только целое число секунд —
	// BusyBox sleep не принимает дробные значения (sleep 1.5 завершается ошибкой,
	// прерывая весь пайп и служба не запускается).
	var detachedScript string
	switch {
	case hasBinaryInPath("nohup"):
		detachedScript = fmt.Sprintf("(sleep 2; nohup %s >/dev/null 2>&1 &) &", restartCmd)
	case hasBinaryInPath("setsid"):
		// BusyBox без nohup, но с setsid (некоторые OpenWrt/Entware сборки)
		detachedScript = fmt.Sprintf("(sleep 2; setsid %s >/dev/null 2>&1 &) &", restartCmd)
	default:
		// Минимальный вариант: двойной fork через вложенный &
		// Работает на любом POSIX sh, включая BusyBox ash
		detachedScript = fmt.Sprintf("(sleep 2; %s >/dev/null 2>&1 &) &", restartCmd)
	}

	cmd := exec.Command("sh", "-c", detachedScript)
	// Явно отсоединяем все стандартные дескрипторы, чтобы sh не унаследовал
	// открытые сокеты / pipe'ы текущего процесса natbypass
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start()

	// Даём subshell зарегистрироваться в планировщике ядра, затем завершаем текущий процесс
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}

func restartService(execPath string) {
	RestartService(execPath)
}

