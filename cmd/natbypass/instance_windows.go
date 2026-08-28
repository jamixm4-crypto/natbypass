//go:build windows

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

var (
	singleInstanceMutex windows.Handle
	moduser32Instance   = windows.NewLazySystemDLL("user32.dll")
	modkernel32Instance = windows.NewLazySystemDLL("kernel32.dll")
	modshell32Instance  = windows.NewLazySystemDLL("shell32.dll")
	moddwmapiInstance   = windows.NewLazySystemDLL("dwmapi.dll")
	appHIcon            uintptr
	lastWebUIPort       = 8080
	mainAppHWnd         uintptr
	origWndProc         uintptr
)

func init() {
	if runtime.GOOS == "windows" {
		procSetAppID := modshell32Instance.NewProc("SetCurrentProcessExplicitAppUserModelID")
		if procSetAppID.Find() == nil {
			appID, _ := windows.UTF16PtrFromString("NatBypass.MeshNetwork.App")
			_, _, _ = procSetAppID.Call(uintptr(unsafe.Pointer(appID)))
		}

		// Загружаем фирменную иконку приложения из PE-ресурсов
		execPath, _ := os.Executable()
		if execPath != "" {
			execPathPtr, _ := windows.UTF16PtrFromString(execPath)
			hIcon, _, _ := modshell32Instance.NewProc("ExtractIconW").Call(0, uintptr(unsafe.Pointer(execPathPtr)), 0)
			if hIcon != 0 && hIcon != 1 {
				appHIcon = hIcon
			}
		}
	}
}

// acquireSingleInstanceMutex гарантирует, что одновременно может работать только один экземпляр NatBypass
func acquireSingleInstanceMutex(port int) bool {
	if runtime.GOOS != "windows" {
		return true
	}

	if port <= 0 {
		port = 8080
	}
	lastWebUIPort = port

	// Очищаем LastError перед созданием мьютекса
	procSetLastError := modkernel32Instance.NewProc("SetLastError")
	if procSetLastError.Find() == nil {
		_, _, _ = procSetLastError.Call(0)
	}

	mutexName, _ := windows.UTF16PtrFromString("Local\\NatBypass_SingleInstance_App_Mutex")
	hMutex, err := windows.CreateMutex(nil, false, mutexName)
	if hMutex == 0 {
		return true
	}

	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || err == windows.ERROR_ALREADY_EXISTS {
		// Проверяем, действительно ли предыдущий процесс жив и отвечает на HTTP
		client := http.Client{Timeout: 350 * time.Millisecond}
		resp, httpErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", port))
		if httpErr == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				// Сервер реально работает — активируем существующее окно и выходим
				_ = windows.CloseHandle(hMutex)
				activateExistingWindow()
				return false
			}
		}
		// Предыдущий процесс не отвечает (завис или был убит) — перехватываем мьютекс и продолжаем работу
	}

	singleInstanceMutex = hMutex
	cleanupStaleBackups()
	return true
}


// subclassWebViewWindow перехватывает WM_CLOSE (нажатие на крестик) и сворачивает окно в трей вместо закрытия
func subclassWebViewWindow(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	mainAppHWnd = hwnd

	procSetWindowLongPtrW := moduser32Instance.NewProc("SetWindowLongPtrW")
	if procSetWindowLongPtrW.Find() != nil {
		procSetWindowLongPtrW = moduser32Instance.NewProc("SetWindowLongW")
	}
	procCallWindowProcW := moduser32Instance.NewProc("CallWindowProcW")

	customProc := syscall.NewCallback(func(h uintptr, msg uint32, wparam uintptr, lparam uintptr) uintptr {
		if msg == 0x0010 /* WM_CLOSE */ {
			// Скрываем окно при нажатии на крестик — оно остаётся живым в трее
			procShowWindow := moduser32Instance.NewProc("ShowWindow")
			procShowWindow.Call(h, 0 /* SW_HIDE */)
			return 0
		}
		if msg == 0x0002 /* WM_DESTROY */ {
			if mainAppHWnd == h {
				mainAppHWnd = 0
			}
		}
		ret, _, _ := procCallWindowProcW.Call(origWndProc, h, uintptr(msg), wparam, lparam)
		return ret
	})

	// GWLP_WNDPROC = -4
	res, _, _ := procSetWindowLongPtrW.Call(hwnd, ^uintptr(3), customProc)
	if res != 0 {
		origWndProc = res
	}
}

func activateExistingWindow() {
	procShowWindow := moduser32Instance.NewProc("ShowWindow")
	procSetForegroundWindow := moduser32Instance.NewProc("SetForegroundWindow")

	// 1. Быстрое мгновенное восстановление сохраненного HWND
	if mainAppHWnd != 0 {
		procShowWindow.Call(mainAppHWnd, 5 /* SW_SHOW */)
		procShowWindow.Call(mainAppHWnd, 9 /* SW_RESTORE */)
		procSetForegroundWindow.Call(mainAppHWnd)
		return
	}

	// 2. Поиск окна через EnumWindows если mainAppHWnd был утерян
	type RECT struct { Left, Top, Right, Bottom int32 }
	var foundHWnd uintptr
	procGetWindowRect := moduser32Instance.NewProc("GetWindowRect")
	procGetWindowTextW := moduser32Instance.NewProc("GetWindowTextW")
	procGetWindowTextLengthW := moduser32Instance.NewProc("GetWindowTextLengthW")
	procEnumWindows := moduser32Instance.NewProc("EnumWindows")

	cb := syscall.NewCallback(func(h uintptr, lparam uintptr) uintptr {
		lenRet, _, _ := procGetWindowTextLengthW.Call(h)
		if lenRet > 0 {
			buf := make([]uint16, lenRet+1)
			procGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), lenRet+1)
			title := windows.UTF16ToString(buf)
			if strings.Contains(title, "NatBypass") && !strings.Contains(title, "Tray") {
				var rc RECT
				procGetWindowRect.Call(h, uintptr(unsafe.Pointer(&rc)))
				w := rc.Right - rc.Left
				hH := rc.Bottom - rc.Top
				if w >= 400 && hH >= 300 {
					foundHWnd = h
					return 0 // Найдено главное окно
				}
			}
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)

	if foundHWnd != 0 {
		mainAppHWnd = foundHWnd
		procShowWindow.Call(foundHWnd, 5 /* SW_SHOW */)
		procShowWindow.Call(foundHWnd, 9 /* SW_RESTORE */)
		procSetForegroundWindow.Call(foundHWnd)
		return
	}

	// 3. Если окно не существует — открываем новое окно на актуальном порту
	port := lastWebUIPort
	if port <= 0 {
		port = 8080
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	if !tryOpenAppMode(url, 1220, 780) {
		openBrowserFallback(url)
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
// (ProductType != VER_NT_WORKSTATION=1).
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

// tryOpenAppMode запускает Microsoft Edge или Google Chrome в режиме
// отдельного изолированного оконного приложения (--app=URL).
// Это создаёт настоящее отдельное окно программы без вкладок и адресной строки,
// что идеально для Windows Server и систем без установленного WebView2 Runtime.
func tryOpenAppMode(url string, winWidth, winHeight int) bool {
	userDataDir := filepath.Join(os.TempDir(), "NatBypass_Edge_UI_Profile")
	dataDirArg := fmt.Sprintf("--user-data-dir=%s", userDataDir)

	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "Google", "Chrome", "Application", "chrome.exe"),
	}

	for _, exe := range candidates {
		if exe == "" {
			continue
		}
		if _, err := os.Stat(exe); err == nil {
			appArg := fmt.Sprintf("--app=%s", url)
			sizeArg := fmt.Sprintf("--window-size=%d,%d", winWidth, winHeight)
			cmd := exec.Command(exe, appArg, sizeArg, dataDirArg, "--disable-plugins", "--disable-extensions", "--no-first-run", "--no-default-browser-check")
			if err := cmd.Start(); err == nil {
				// Запускаем установку фирменной иконки на окно Edge/Chrome
				go applyWindowIconToApp()
				return true
			}
		}
	}
	return false
}

// applyWindowIconToApp находит окно приложения и устанавливает фирменную иконку через WM_SETICON
func applyWindowIconToApp() {
	if appHIcon == 0 {
		return
	}
	procEnumWindows := moduser32Instance.NewProc("EnumWindows")
	procGetWindowTextW := moduser32Instance.NewProc("GetWindowTextW")
	procGetWindowTextLengthW := moduser32Instance.NewProc("GetWindowTextLengthW")
	procSendMessageW := moduser32Instance.NewProc("SendMessageW")

	for i := 0; i < 30; i++ {
		time.Sleep(300 * time.Millisecond)
		var found bool

		cb := syscall.NewCallback(func(h uintptr, lparam uintptr) uintptr {
			lenRet, _, _ := procGetWindowTextLengthW.Call(h)
			if lenRet > 0 {
				buf := make([]uint16, lenRet+1)
				procGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), lenRet+1)
				title := windows.UTF16ToString(buf)
				if strings.Contains(title, "NatBypass") {
					procSendMessageW.Call(h, 0x0080 /* WM_SETICON */, 1 /* ICON_BIG */, appHIcon)
					procSendMessageW.Call(h, 0x0080 /* WM_SETICON */, 0 /* ICON_SMALL */, appHIcon)
					found = true
					return 0
				}
			}
			return 1
		})
		procEnumWindows.Call(cb, 0)
		if found {
			break
		}
	}
}

// openAppWindow открывает интерфейс NatBypass в виде окна:
// - На Windows Desktop: нативное окно WebView2 (fallback → standalone --app окно)
// - На Windows Server: сразу standalone --app окно (Edge/Chrome), избегая зависаний WebView2
func openAppWindow(port int) {
	if port <= 0 {
		port = 8080
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)

	screenWidth, _, _ := moduser32Instance.NewProc("GetSystemMetrics").Call(0)
	screenHeight, _, _ := moduser32Instance.NewProc("GetSystemMetrics").Call(1)

	winWidth := 1220
	winHeight := 780
	if screenWidth > 0 && int(screenWidth) < winWidth+40 {
		winWidth = int(screenWidth) - 40
	}
	if screenHeight > 0 && int(screenHeight) < winHeight+40 {
		winHeight = int(screenHeight) - 40
	}

	// Запускаем System Tray иконку в фоновом потоке
	go startTrayIcon(port)

	// На Windows Server — сразу используем стабильный режим standalone окна Edge/Chrome,
	// так как рантайм WebView2 на Server 2016/2019 без рабочего стола Desktop Experience создаёт зависшее пустое окно.
	if isWindowsServer() {
		if !tryOpenAppMode(url, winWidth, winHeight) {
			openBrowserFallback(url)
		}
		return
	}

	// На Windows Desktop — пробуем нативный WebView2
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		var fallbackDone bool
		fallbackOpen := func() {
			if fallbackDone {
				return
			}
			fallbackDone = true
			if !tryOpenAppMode(url, winWidth, winHeight) {
				openBrowserFallback(url)
			}
		}

		defer func() {
			if r := recover(); r != nil {
				fallbackOpen()
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
			fallbackOpen()
			return
		}

		defer func() {
			defer func() { recover() }()
			w.Destroy()
		}()

		hwnd := uintptr(w.Window())
		subclassWebViewWindow(hwnd)

		// Dark Mode для рамки и заголовка
		procDwmSetWindowAttribute := moddwmapiInstance.NewProc("DwmSetWindowAttribute")
		if procDwmSetWindowAttribute.Find() == nil {
			darkMode := int32(1)
			_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)
			_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 19, uintptr(unsafe.Pointer(&darkMode)), 4)
		}

		// Устанавливаем нативную иконку
		if appHIcon != 0 {
			procSendMessageW := moduser32Instance.NewProc("SendMessageW")
			_, _, _ = procSendMessageW.Call(hwnd, 0x0080, 1, appHIcon)
			_, _, _ = procSendMessageW.Call(hwnd, 0x0080, 0, appHIcon)
		}

		// Отключаем контекстное меню и горячие клавиши браузера
		w.Init(`
			window.addEventListener('contextmenu', function(e) { e.preventDefault(); });
			window.addEventListener('keydown', function(e) {
				if (e.key === 'F5' || (e.ctrlKey && (e.key === 'r' || e.key === 'R' || e.key === 'f' || e.key === 'F' || e.key === 'u' || e.key === 'U' || e.key === 'p' || e.key === 'P'))) {
					e.preventDefault();
				}
			});
			window.open = function(url) { return null; };
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
	procShellExecuteW := modshell32Instance.NewProc("ShellExecuteW")
	if procShellExecuteW.Find() == nil {
		urlPtr, _ := windows.UTF16PtrFromString(url)
		openVerb, _ := windows.UTF16PtrFromString("open")
		ret, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(openVerb)), uintptr(unsafe.Pointer(urlPtr)), 0, 0, 1 /* SW_SHOWNORMAL */)
		if ret > 32 {
			return
		}
	}
	cmd := exec.Command("cmd.exe", "/C", "start", "", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	_ = cmd.Start()
}

// ── System Tray Icon (Область уведомлений Windows) ───────────────────────────

const (
	wmUserTray   = 0x0400 + 101
	trayIconID   = 1001
	menuItemOpen = 2001
	menuItemExit = 2002
)

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uTimeoutOrVersion uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     uintptr
}

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type msgW struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	ptX     int32
	ptY     int32
}

type pointW struct {
	x int32
	y int32
}

// startTrayIcon регистрирует иконку в системном трее Windows (рядом с часами)
func startTrayIcon(port int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	procRegisterClassExW := moduser32Instance.NewProc("RegisterClassExW")
	procCreateWindowExW := moduser32Instance.NewProc("CreateWindowExW")
	procDefWindowProcW := moduser32Instance.NewProc("DefWindowProcW")
	procGetMessageW := moduser32Instance.NewProc("GetMessageW")
	procTranslateMessage := moduser32Instance.NewProc("TranslateMessage")
	procDispatchMessageW := moduser32Instance.NewProc("DispatchMessageW")
	procDestroyWindow := moduser32Instance.NewProc("DestroyWindow")
	procCreatePopupMenu := moduser32Instance.NewProc("CreatePopupMenu")
	procAppendMenuW := moduser32Instance.NewProc("AppendMenuW")
	procTrackPopupMenu := moduser32Instance.NewProc("TrackPopupMenu")
	procDestroyMenu := moduser32Instance.NewProc("DestroyMenu")
	procGetCursorPos := moduser32Instance.NewProc("GetCursorPos")
	procSetForegroundWindow := moduser32Instance.NewProc("SetForegroundWindow")
	procShellNotifyIconW := modshell32Instance.NewProc("Shell_NotifyIconW")

	className, _ := windows.UTF16PtrFromString("NatBypass_TrayMsg_Class")

	var trayHWnd uintptr

	wndProc := syscall.NewCallback(func(hwnd uintptr, msg uint32, wparam uintptr, lparam uintptr) uintptr {
		switch msg {
		case wmUserTray:
			event := uint32(lparam & 0xFFFF)
			switch event {
			case 0x0202, 0x0203: // WM_LBUTTONUP, WM_LBUTTONDBLCLK
				activateExistingWindow()
			case 0x0205: // WM_RBUTTONUP — контекстное меню
				hMenu, _, _ := procCreatePopupMenu.Call()
				if hMenu != 0 {
					openText, _ := windows.UTF16PtrFromString("Открыть NatBypass")
					exitText, _ := windows.UTF16PtrFromString("Выход")

					// MF_STRING = 0x0000, MF_SEPARATOR = 0x0800
					procAppendMenuW.Call(hMenu, 0, uintptr(menuItemOpen), uintptr(unsafe.Pointer(openText)))
					procAppendMenuW.Call(hMenu, 0x0800, 0, 0)
					procAppendMenuW.Call(hMenu, 0, uintptr(menuItemExit), uintptr(unsafe.Pointer(exitText)))

					var pt pointW
					procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
					procSetForegroundWindow.Call(hwnd)

					// TPM_RIGHTALIGN = 0x0008, TPM_BOTTOMALIGN = 0x0020, TPM_RETURNCMD = 0x0100
					cmd, _, _ := procTrackPopupMenu.Call(hMenu, 0x0008|0x0020|0x0100, uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
					procDestroyMenu.Call(hMenu)

					switch cmd {
					case uintptr(menuItemOpen):
						activateExistingWindow()
					case uintptr(menuItemExit):
						var nid notifyIconDataW
						nid.cbSize = uint32(unsafe.Sizeof(nid))
						nid.hWnd = hwnd
						nid.uID = trayIconID
						procShellNotifyIconW.Call(2 /* NIM_DELETE */, uintptr(unsafe.Pointer(&nid)))
						procDestroyWindow.Call(hwnd)
						cleanupSingleInstanceMutex()
						closeLogging()
						os.Exit(0)
					}
				}
			}
			return 0
		case 0x0010: // WM_CLOSE
			procDestroyWindow.Call(hwnd)
			return 0
		case 0x0002: // WM_DESTROY
			return 0
		}
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wparam, lparam)
		return ret
	})

	var wc wndClassExW
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	wc.lpfnWndProc = wndProc
	wc.lpszClassName = className
	wc.hIcon = appHIcon
	wc.hIconSm = appHIcon
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		0,
		0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	)
	if hwnd == 0 {
		return
	}
	trayHWnd = hwnd

	// Создаем иконку в системном трее
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = trayHWnd
	nid.uID = trayIconID
	nid.uFlags = 0x00000001 | 0x00000002 | 0x00000004 // NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.uCallbackMessage = wmUserTray
	nid.hIcon = appHIcon

	tip, _ := windows.UTF16FromString("NatBypass — P2P Mesh Network")
	copy(nid.szTip[:], tip)

	procShellNotifyIconW.Call(0 /* NIM_ADD */, uintptr(unsafe.Pointer(&nid)))

	// Цикл обработки сообщений трея
	var msg msgW
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	// Очистка при выходе
	procShellNotifyIconW.Call(2 /* NIM_DELETE */, uintptr(unsafe.Pointer(&nid)))
}



func cleanupSingleInstanceMutex() {
	if singleInstanceMutex != 0 {
		_ = windows.CloseHandle(singleInstanceMutex)
		singleInstanceMutex = 0
	}
}
