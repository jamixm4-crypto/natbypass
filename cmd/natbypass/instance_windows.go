//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

var (
	singleInstanceMutex windows.Handle
	moduser32Instance   = windows.NewLazySystemDLL("user32.dll")
	modshell32Instance  = windows.NewLazySystemDLL("shell32.dll")
	moddwmapiInstance   = windows.NewLazySystemDLL("dwmapi.dll")
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
			// Экземпляр уже запущен — активируем существующее окно и мгновенно выходим (НИКАКИХ вторых окон!)
			activateExistingWindow()
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

func activateExistingWindow() {
	procFindWindowW := moduser32Instance.NewProc("FindWindowW")
	procSetForegroundWindow := moduser32Instance.NewProc("SetForegroundWindow")
	procShowWindow := moduser32Instance.NewProc("ShowWindow")

	titlePtr, _ := windows.UTF16PtrFromString("NatBypass — P2P Mesh Network")
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePtr)))
	if hwnd != 0 {
		procShowWindow.Call(hwnd, 9 /* SW_RESTORE */)
		procSetForegroundWindow.Call(hwnd)
	}
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

	// 1. Запуск нативного окна WebView2 напрямую в процессе NatBypass.exe
	// Это дает 100% фирменную иконку на панели задач и в заголовке окна без значка Edge!
	go func() {
		defer func() {
			if r := recover(); r != nil {
				openBrowserFallback(url)
			}
		}()

		// Небольшая задержка 150мс для гарантии готовности HTTP порта
		time.Sleep(150 * time.Millisecond)

		w := webview2.NewWithOptions(webview2.WebViewOptions{
			Debug:     false,
			AutoFocus: true,
			WindowOptions: webview2.WindowOptions{
				Title:  "NatBypass — P2P Mesh Network",
				Width:  1020,
				Height: 630,
				Center: true,
			},
		})
		if w != nil {
			defer func() {
				w.Destroy()
				os.Exit(0)
			}()

			hwnd := uintptr(w.Window())

			// 1. Включаем нативный Immersive Dark Mode для рамки и заголовка окна
			procDwmSetWindowAttribute := moddwmapiInstance.NewProc("DwmSetWindowAttribute")
			if procDwmSetWindowAttribute.Find() == nil {
				darkMode := int32(1)
				_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, uintptr(unsafe.Pointer(&darkMode)), 4)
				_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 19 /* DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 */, uintptr(unsafe.Pointer(&darkMode)), 4)
			}

			// 2. Устанавливаем нативную иконку из PE ресурсов бинарника
			execPath, _ := os.Executable()
			if execPath != "" {
				execPathPtr, _ := windows.UTF16PtrFromString(execPath)
				hIcon, _, _ := modshell32Instance.NewProc("ExtractIconW").Call(0, uintptr(unsafe.Pointer(execPathPtr)), 0)
				if hIcon != 0 {
					procSendMessageW := moduser32Instance.NewProc("SendMessageW")
					_, _, _ = procSendMessageW.Call(hwnd, 0x0080 /* WM_SETICON */, 1 /* ICON_BIG */, hIcon)
					_, _, _ = procSendMessageW.Call(hwnd, 0x0080 /* WM_SETICON */, 0 /* ICON_SMALL */, hIcon)
				}
			}

			// 3. Отключаем контекстное меню браузера и горячие клавиши перезагрузки страницы
			w.Init(`
				window.addEventListener('contextmenu', function(e) { e.preventDefault(); });
				window.addEventListener('keydown', function(e) {
					if (e.key === 'F5' || (e.ctrlKey && (e.key === 'r' || e.key === 'R' || e.key === 'f' || e.key === 'F' || e.key === 'u' || e.key === 'U' || e.key === 'p' || e.key === 'P'))) {
						e.preventDefault();
					}
				});
			`)

			// 4. Задаем компактный минимальный размер окна и начальный размер под любые ноутбуки
			w.SetSize(840, 520, webview2.HintMin)
			w.SetSize(1020, 630, webview2.HintNone)
			w.Navigate(url)
			w.Run()
			return
		}

		openBrowserFallback(url)
	}()
}

func openBrowserFallback(url string) {
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
