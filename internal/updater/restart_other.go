//go:build !windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// restartService перезапускает сервис на Linux/router платформах безопасно,
// запуская команду перезапуска в отсоединённом фоновом процессе с задержкой 1.2 секунды,
// чтобы текущий процесс natbypass успел завершиться и корректно освободить сокеты,
// интерфейсы TUN (nb0) и файлы блокировок.
func restartService(execPath string) {
	var restartCmd string
	if _, err := os.Stat("/opt/etc/init.d/S99natbypass"); err == nil {
		// Keenetic Entware
		restartCmd = "/opt/etc/init.d/S99natbypass restart"
	} else if _, err := os.Stat("/etc/init.d/natbypass"); err == nil {
		// OpenWrt Procd / SysVinit
		restartCmd = "/etc/init.d/natbypass restart"
	} else if _, err := exec.LookPath("systemctl"); err == nil {
		// Linux systemd
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

	// Запуск через отсоединённый subshell: ждём 1.2 сек, пока текущий процесс natbypass завершит работу,
	// затем перезапускаем службу или запускаем новый процесс
	detachedScript := fmt.Sprintf("(sleep 1.2; %s) >/dev/null 2>&1 &", restartCmd)
	cmd := exec.Command("sh", "-c", detachedScript)
	_ = cmd.Start()

	// Даём команду на завершение текущего процесса
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}
