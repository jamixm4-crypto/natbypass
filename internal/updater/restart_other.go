//go:build !windows

package updater

import (
	"os"
	"os/exec"
	"time"
)

// restartService перезапускает сервис на Linux/router платформах
func restartService(execPath string) {
	// Linux / Keenetic Entware / OpenWrt
	if _, err := os.Stat("/opt/etc/init.d/S99natbypass"); err == nil {
		_ = exec.Command("/opt/etc/init.d/S99natbypass", "restart").Run()
		return
	}
	if _, err := os.Stat("/etc/init.d/natbypass"); err == nil {
		_ = exec.Command("/etc/init.d/natbypass", "restart").Run()
		return
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "restart", "natbypass").Run()
		return
	}

	// Direct spawn fallback
	cmd := exec.Command(execPath, "start")
	_ = cmd.Start()
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}
