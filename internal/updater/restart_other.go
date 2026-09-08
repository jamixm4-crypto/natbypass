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
	"path/filepath"
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
// Особенности реализации:
//   - systemd: использует 'systemctl --no-block restart natbypass'. Запрос ставится
//     в очередь PID 1, что исключает потерю службы при выходе текущего cgroup.
//   - BusyBox (Keenetic MIPS, OpenWrt): экранирует SIGHUP через 'trap "" HUP INT TERM',
//     предотвращая сброс дочернего процесса при завершении родительского процесса.
func RestartService(execPath string) {
	// 1. Linux systemd: асинхронный перезапуск напрямую через PID 1
	if isSystemdService() {
		_ = exec.Command("systemctl", "--no-block", "restart", "natbypass").Run()
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}

	// 2. Роутеры (Keenetic Entware / OpenWrt / SysVinit / прямое выполнение)
	var restartCmd string
	if _, err := os.Stat("/opt/etc/init.d/S99natbypass"); err == nil {
		// Keenetic Entware
		restartCmd = "/opt/etc/init.d/S99natbypass restart"
	} else if _, err := os.Stat("/etc/init.d/natbypass"); err == nil {
		// OpenWrt Procd / SysVinit
		restartCmd = "/etc/init.d/natbypass restart"
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

	// Строим BusyBox-совместимый detached-скрипт с защитой от SIGHUP
	var detachedScript string
	switch {
	case hasBinaryInPath("nohup"):
		detachedScript = fmt.Sprintf("trap '' HUP INT TERM; (sleep 2; nohup %s >/dev/null 2>&1 &) &", restartCmd)
	case hasBinaryInPath("setsid"):
		detachedScript = fmt.Sprintf("trap '' HUP INT TERM; (sleep 2; setsid %s >/dev/null 2>&1 &) &", restartCmd)
	default:
		detachedScript = fmt.Sprintf("trap '' HUP INT TERM; (sleep 2; %s >/dev/null 2>&1 &) &", restartCmd)
	}

	cmd := exec.Command("sh", "-c", detachedScript)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Dir = filepath.Dir(execPath)
	_ = cmd.Start()

	// Даём subshell зарегистрироваться в ядре, затем завершаем текущий процесс
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}

func restartService(execPath string) {
	RestartService(execPath)
}

