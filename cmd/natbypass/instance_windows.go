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

// isWindowsServer возвращает true если ОС является серверной редакцией Windows
// (ProductType != VER_NT_WORKSTATION=1). На Server 2016/2019/2022 WebView2 может
// вести себя непредсказуемо (открывать и окно и браузер одновременно).
func isWindowsServer() bool {
	type OSVERSIONINFOEXW struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
		dwPlatformId        uint32
		szCSDVersion        [128]uint16
		wServicePackMajor   uint16
		wServicePackMinor   uint16
		wSuiteMask          uint16
		wProductType        uint8
		wReserved           uint8
	}
	var info OSVERSIONINFOEXW
	info.dwOSVersionInfoSize = uint32(unsafe.Sizeof(info))
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion := ntdll.NewProc("RtlGetVersion")
	ret, _, _ := rtlGetVersion.Call(uintptr(unsafe.Pointer(&info)))
	if ret != 0 {
		return false
	}
	// wProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server
	return info.wProductType != 1
}

// openAppWindow открывает интерфейс NatBypass в виде нативного окна с правильным размером и родной иконкой.
// На серверных редакциях Windows (Server 2016/2019/2022) использует только браузер.
func openAppWindow(port int) {
	if port <= 0 {
		port = 8080
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/?v=%d", port, time.Now().Unix())

	// На Windows Server — только браузер (WebView2 на Server может открыть и окно и браузер одновременно)
	if isWindowsServer() {
		openBrowserFallback(url)
		return
	}

	// На Windows Desktop — нативное окно WebView2
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// browserOpened — флаг что браузер уже открыли, не открываем повторно
		var browserOpened bool
		defer func() {
			if r := recover(); r != nil {
				if !browserOpened {
					browserOpened = true
					openBrowserFallback(url)
				}
			}
		}()

		// Включаем Per-Monitor DPI Awareness
		procSetProcessDpiAwarenessContext := moduser32Instance.NewProc("SetProcessDpiAwarenessContext")
		if procSetProcessDpiAwarenessContext.Find() == nil {
			_, _, _ = procSetProcessDpiAwarenessContext.Call(^uintptr(3))
		} else {
			procSetProcessDPIAware := moduser32Instance.NewProc("SetProcessDPIAware")
			if procSetProcessDPIAware.Find() == nil {
				_, _, _ = procSetProcessDPIAware.Call()
			}
		}

		screenWidth, _, _ := moduser32Instance.NewProc("GetSystemMetrics").Call(0)
		screenHeight, _, _ := moduser32Instance.NewProc("GetSystemMetrics").Call(1)

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
		if w == nil {
			// WebView2 Runtime не установлен — открываем в браузере
			browserOpened = true
			openBrowserFallback(url)
			return
		}

		defer func() {
			w.Destroy()
			os.Exit(0)
		}()

		hwnd := uintptr(w.Window())

		// Dark Mode для рамки и заголовка
		procDwmSetWindowAttribute := moddwmapiInstance.NewProc("DwmSetWindowAttribute")
		if procDwmSetWindowAttribute.Find() == nil {
			darkMode := int32(1)
			_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)
			_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 19, uintptr(unsafe.Pointer(&darkMode)), 4)
		}

		// Нативная иконка из PE ресурсов
		execPath, _ := os.Executable()
		if execPath != "" {
			execPathPtr, _ := windows.UTF16PtrFromString(execPath)
			hIcon, _, _ := modshell32Instance.NewProc("ExtractIconW").Call(0, uintptr(unsafe.Pointer(execPathPtr)), 0)
			if hIcon != 0 {
				procSendMessageW := moduser32Instance.NewProc("SendMessageW")
				_, _, _ = procSendMessageW.Call(hwnd, 0x0080, 1, hIcon)
				_, _, _ = procSendMessageW.Call(hwnd, 0x0080, 0, hIcon)
			}
		}

		// Отключаем контекстное меню и горячие клавиши браузера
		w.Init(`
			window.addEventListener('contextmenu', function(e) { e.preventDefault(); });
			window.addEventListener('keydown', function(e) {
				if (e.key === 'F5' || (e.ctrlKey && (e.key === 'r' || e.key === 'R' || e.key === 'f' || e.key === 'F' || e.key === 'u' || e.key === 'U' || e.key === 'p' || e.key === 'P'))) {
					e.preventDefault();
				}
			});
		`)

		w.SetSize(880, 560, webview2.HintMin)
		w.SetSize(winWidth, winHeight, webview2.HintNone)

		if screenWidth > 0 && screenHeight > 0 {
			x := (int(screenWidth) - winWidth) / 2
			y := (int(screenHeight) - winHeight) / 2
			if x < 0 { x = 10 }
			if y < 0 { y = 10 }
			procSetWindowPos := moduser32Instance.NewProc("SetWindowPos")
			_, _, _ = procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(winWidth), uintptr(winHeight), 0x0040)
		}

		w.Navigate(url)
		w.Run()
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
