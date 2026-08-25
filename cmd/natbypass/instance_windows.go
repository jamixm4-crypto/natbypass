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

	// Используем Local\ (не Global\) — Global\ требует SeCreateGlobalPrivilege,
	// которой нет у обычных пользователей даже с отключённым UAC.
	mutexName, _ := windows.UTF16PtrFromString("Local\\NatBypass_SingleInstance_App_Mutex")
	hMutex, err := windows.CreateMutex(nil, true, mutexName)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || err == windows.ERROR_ALREADY_EXISTS {
			if hMutex != 0 {
				_ = windows.CloseHandle(hMutex)
			}
			// Экземпляр уже запущен — активируем существующее окно и выходим
			activateExistingWindow()
			return false
		}
		// ERROR_ACCESS_DENIED или любая другая ошибка — разрешаем запуск
		// (лучше запустить два экземпляра, чем не запустить ни одного)
		return true
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
	url := fmt.Sprintf("http://127.0.0.1:%d/?v=%d", port, time.Now().Unix())

	// 1. Запуск нативного окна WebView2 напрямую в процессе NatBypass.exe
	// Это дает 100% фирменную иконку на панели задач и в заголовке окна без значка Edge!
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		defer func() {
			if r := recover(); r != nil {
				openBrowserFallback(url)
			}
		}()

		// Включаем Per-Monitor DPI Awareness для четкого отображения на 1080p/2K/4K и ноутбуках с масштабированием 125%-175%
		procSetProcessDpiAwarenessContext := moduser32Instance.NewProc("SetProcessDpiAwarenessContext")
		if procSetProcessDpiAwarenessContext.Find() == nil {
			_, _, _ = procSetProcessDpiAwarenessContext.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
		} else {
			procSetProcessDPIAware := moduser32Instance.NewProc("SetProcessDPIAware")
			if procSetProcessDPIAware.Find() == nil {
				_, _, _ = procSetProcessDPIAware.Call()
			}
		}

		screenWidth, _, _ := moduser32Instance.NewProc("GetSystemMetrics").Call(0 /* SM_CXSCREEN */)
		screenHeight, _, _ := moduser32Instance.NewProc("GetSystemMetrics").Call(1 /* SM_CYSCREEN */)

		winWidth := 1180
		winHeight := 750
		if screenWidth > 0 && int(screenWidth) < winWidth+60 {
			winWidth = int(screenWidth) - 60
		}
		if screenHeight > 0 && int(screenHeight) < winHeight+60 {
			winHeight = int(screenHeight) - 60
		}

		w := webview2.NewWithOptions(webview2.WebViewOptions{
			Debug:     false,
			AutoFocus: true,
			WindowOptions: webview2.WindowOptions{
				Title:  "NatBypass — P2P Mesh Network",
				Width:  uint(winWidth),
				Height: uint(winHeight),
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

			// 4. Задаем комфортные размеры и позиционирование окна
			w.SetSize(880, 560, webview2.HintMin)
			w.SetSize(winWidth, winHeight, webview2.HintNone)

			if screenWidth > 0 && screenHeight > 0 {
				x := (int(screenWidth) - winWidth) / 2
				y := (int(screenHeight) - winHeight) / 2
				if x < 0 {
					x = 10
				}
				if y < 0 {
					y = 10
				}
				procSetWindowPos := moduser32Instance.NewProc("SetWindowPos")
				_, _, _ = procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(winWidth), uintptr(winHeight), 0x0040 /* SWP_SHOWWINDOW */)
			}

			w.Navigate(url)
			w.Run()
			return
		}

		openBrowserFallback(url)
	}()
}

func openBrowserFallback(url string) {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
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
