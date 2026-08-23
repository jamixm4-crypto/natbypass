//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	singleInstanceMutex windows.Handle
)

// acquireSingleInstanceMutex пытается захватить глобальный именованный мьютекс Windows.
// Если мьютекс уже занят другим запущенным процессом NatBypass, функция возвращает false.
func acquireSingleInstanceMutex(port int) bool {
	if runtime.GOOS != "windows" {
		return true
	}

	mutexName, _ := windows.UTF16PtrFromString("Local\\NatBypass_SingleInstance_App_Mutex")
	hMutex, err := windows.CreateMutex(nil, false, mutexName)
	if err != nil || hMutex == 0 {
		return true
	}

	lastErr := windows.GetLastError()
	if lastErr == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(hMutex)
		// Экземпляр уже запущен — активируем окно приложения
		openAppWindow(port)
		return false
	}

	singleInstanceMutex = hMutex
	return true
}

func releaseSingleInstanceMutex() {
	if singleInstanceMutex != 0 {
		_ = windows.CloseHandle(singleInstanceMutex)
		singleInstanceMutex = 0
	}
}

// openAppWindow открывает интерфейс NatBypass в виде нативного окна через Edge / Chrome / Браузер
func openAppWindow(port int) {
	if port <= 0 {
		port = 8080
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = os.TempDir()
	}
	profileDir := filepath.Join(localAppData, "NatBypass", "app_profile")
	_ = os.MkdirAll(profileDir, 0755)

	appCandidates := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		filepath.Join(localAppData, `Microsoft\Edge\Application\msedge.exe`),
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}
	for _, p := range appCandidates {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p,
				fmt.Sprintf("--app=%s", url),
				fmt.Sprintf("--user-data-dir=%s", profileDir),
				"--new-window",
				"--window-size=1180,820",
			)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			if err := cmd.Start(); err == nil {
				return
			}
		}
	}

	// Fallback
	_ = exec.Command("cmd", "/c", "start", url).Start()
}
