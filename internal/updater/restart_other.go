//go:build !windows

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

// RestartService перезапускает сервис на Linux/router платформах безопасно,
// запуская команду перезапуска в отсоединённом фоновом процессе с задержкой 1.5 секунды,
// чтобы текущий процесс natbypass успел завершиться и корректно освободить сокеты,
// интерфейсы TUN (nb0) и файлы блокировок.
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

	// Запуск через отсоединённый subshell с nohup: ждём 1.5 сек, пока текущий процесс natbypass завершит работу,
	// затем перезапускаем службу или запускаем новый процесс
	detachedScript := fmt.Sprintf("(sleep 1.5; nohup %s >/dev/null 2>&1 &) &", restartCmd)
	cmd := exec.Command("sh", "-c", detachedScript)
	_ = cmd.Start()

	// Даём команду на завершение текущего процесса
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

func restartService(execPath string) {
	RestartService(execPath)
}

