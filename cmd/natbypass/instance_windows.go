//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

var (
	singleInstanceMutex windows.Handle
	moduser32Instance   = windows.NewLazySystemDLL("user32.dll")
	modshell32Instance  = windows.NewLazySystemDLL("shell32.dll")
)

func init() {
	if runtime.GOOS == "windows" {
		procSetAppID := modshell32Instance.NewProc("SetCurrentProcessExplicitAppUserModelID")
		if procSetAppID.Find() == nil {
			appID, _ := windows.UTF16PtrFromString("NatBypass.MeshNetwork.App")
			_, _, _ = procSetAppID.Call(uintptr(unsafe.Pointer(appID)))
		}
	}
}

// acquireSingleInstanceMutex гарантирует, что одновременно может работать только один экземпляр NatBypass
func acquireSingleInstanceMutex(port int) bool {
	if runtime.GOOS != "windows" {
		return true
	}

	mutexName, _ := windows.UTF16PtrFromString("Global\\NatBypass_SingleInstance_App_Mutex")
	hMutex, err := windows.CreateMutex(nil, true, mutexName)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || err == windows.ERROR_ALREADY_EXISTS || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			if hMutex != 0 {
				_ = windows.CloseHandle(hMutex)
			}
			// Экземпляр уже запущен — активируем окно приложения и выходим
			openAppWindow(port)
			return false
		}
	}
	if hMutex == 0 {
		return true
	}

	singleInstanceMutex = hMutex
	cleanupStaleBackups()
	return true
}

// cleanupStaleBackups удаляет старые резервные копии .old.* после успешного обновления
func cleanupStaleBackups() {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(execPath)
	base := filepath.Base(execPath)
	matches, _ := filepath.Glob(filepath.Join(dir, base+".old.*"))
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

func releaseSingleInstanceMutex() {
	if singleInstanceMutex != 0 {
		_ = windows.CloseHandle(singleInstanceMutex)
		singleInstanceMutex = 0
	}
}

// openAppWindow открывает интерфейс NatBypass в виде нативного окна с правильным размером и родной иконкой
func openAppWindow(port int) {
	if port <= 0 {
		port = 8080
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	// 1. Попытка запустить нативное окно WebView2 напрямую в процессе NatBypass.exe
	// Это дает 100% фирменную иконку на панели задач и в заголовке окна без значка Edge!
	go func() {
		defer func() {
			if r := recover(); r != nil {
				openBrowserFallback(url)
			}
		}()

		w := webview2.NewWithOptions(webview2.WebViewOptions{
			Debug:     false,
			AutoFocus: true,
			WindowOptions: webview2.WindowOptions{
				Title:  "NatBypass — P2P Mesh Network",
				Width:  1280,
				Height: 860,
				Center: true,
			},
		})
		if w != nil {
			defer w.Destroy()
			w.SetSize(1280, 860, webview2.HintNone)
			w.Navigate(url)
			w.Run()
			return
		}

		openBrowserFallback(url)
	}()
}

func openBrowserFallback(url string) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = os.TempDir()
	}
	appDir := filepath.Join(localAppData, "NatBypass")
	profileDir := filepath.Join(appDir, "app_profile")
	_ = os.MkdirAll(profileDir, 0755)

	execPath, _ := os.Executable()
	if execPath != "" {
		execPath, _ = filepath.Abs(execPath)
	}

	appCandidates := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		filepath.Join(localAppData, `Microsoft\Edge\Application\msedge.exe`),
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}

	var browserExe string
	for _, p := range appCandidates {
		if _, err := os.Stat(p); err == nil {
			browserExe = p
			break
		}
	}

	if browserExe != "" {
		cmd := exec.Command(browserExe,
			fmt.Sprintf("--app=%s", url),
			fmt.Sprintf("--user-data-dir=%s", profileDir),
			"--app-id=NatBypassMeshApp",
			"--new-window",
			"--window-size=1280,860",
		)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Start(); err == nil {
			applyWindowIcon(execPath)
			return
		}
	}

	// Fallback
	_ = exec.Command("cmd", "/c", "start", url).Start()
}

// applyWindowIcon находит окно NatBypass и устанавливает иконку через WM_SETICON
func applyWindowIcon(execPath string) {
	if execPath == "" {
		return
	}
	procExtractIconW := modshell32Instance.NewProc("ExtractIconW")
	procFindWindowW := moduser32Instance.NewProc("FindWindowW")
	procSendMessageW := moduser32Instance.NewProc("SendMessageW")

	execPathPtr, _ := windows.UTF16PtrFromString(execPath)
	hIcon, _, _ := procExtractIconW.Call(0, uintptr(unsafe.Pointer(execPathPtr)), 0)
	if hIcon == 0 {
		return
	}

	go func() {
		for i := 0; i < 20; i++ {
			time.Sleep(400 * time.Millisecond)
			titlePtr, _ := windows.UTF16PtrFromString("NatBypass")
			hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePtr)))
			if hwnd != 0 {
				procSendMessageW.Call(hwnd, 0x0080 /* WM_SETICON */, 1 /* ICON_BIG */, hIcon)
				procSendMessageW.Call(hwnd, 0x0080 /* WM_SETICON */, 0 /* ICON_SMALL */, hIcon)
				break
			}
		}
	}()
}
