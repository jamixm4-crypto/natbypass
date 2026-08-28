//go:build windows

package tray

import (
	"os"
	"os/exec"
	"time"
)

// RestartSelf restarts the current executable process with the same arguments.
func RestartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
	return nil
}