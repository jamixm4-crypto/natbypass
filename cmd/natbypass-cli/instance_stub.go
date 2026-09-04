//go:build !windows

package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	singleInstanceLockFile *os.File
	singleInstanceLockPath string
)

func acquireSingleInstanceMutex(cfgPath string, port int) bool {
	absPath, err := filepath.Abs(cfgPath)
	if err != nil {
		absPath = cfgPath
	}
	hash := sha256.Sum256([]byte(strings.ToLower(absPath)))
	lockFileName := fmt.Sprintf("natbypass_%x.lock", hash[:8])

	candidates := []string{
		"/run",
		"/var/run",
		"/tmp",
		os.TempDir(),
	}

	var lockF *os.File
	var chosenPath string
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		target := filepath.Join(dir, lockFileName)
		f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, 0644)
		if err == nil {
			lockF = f
			chosenPath = target
			break
		}
	}

	if lockF == nil {
		return true
	}

	err = syscall.Flock(int(lockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		buf := make([]byte, 64)
		n, _ := lockF.Read(buf)
		pidStr := strings.TrimSpace(string(buf[:n]))
		pid, _ := strconv.Atoi(pidStr)

		if port > 0 {
			client := http.Client{Timeout: 400 * time.Millisecond}
			resp, httpErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", port))
			if httpErr == nil && resp != nil {
				_ = resp.Body.Close()
				if resp.StatusCode == 200 {
					fmt.Fprintf(os.Stderr, "NatBypass is already running for config '%s' (PID %d) on port %d.\n", cfgPath, pid, port)
					_ = lockF.Close()
					return false
				}
			}
		}

		if pid > 0 {
			if killErr := syscall.Kill(pid, 0); killErr == nil {
				fmt.Fprintf(os.Stderr, "NatBypass is already running (PID %d) for config '%s'. Refusing to start duplicate instance.\n", pid, cfgPath)
				_ = lockF.Close()
				return false
			}
		}

		fmt.Fprintf(os.Stderr, "NatBypass lock is held by another process for config '%s'. Refusing to start duplicate instance.\n", cfgPath)
		_ = lockF.Close()
		return false
	}

	_ = lockF.Truncate(0)
	_, _ = lockF.Seek(0, 0)
	_, _ = fmt.Fprintf(lockF, "%d\n", os.Getpid())
	_ = lockF.Sync()

	singleInstanceLockFile = lockF
	singleInstanceLockPath = chosenPath
	return true
}

func releaseSingleInstanceMutex() {
	if singleInstanceLockFile != nil {
		_ = syscall.Flock(int(singleInstanceLockFile.Fd()), syscall.LOCK_UN)
		_ = singleInstanceLockFile.Close()
		if singleInstanceLockPath != "" {
			_ = os.Remove(singleInstanceLockPath)
		}
		singleInstanceLockFile = nil
	}
}

func cleanupTrayIcon() {}

func openAppWindow(port int) {}


