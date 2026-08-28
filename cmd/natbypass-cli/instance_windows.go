//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"github.com/natbypass/natbypass/internal/tray"
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

	// trayRunning = 1 if tray is already running
	trayRunning int32
)

func isTrayRunning() bool { return atomic.LoadInt32(&trayRunning) == 1 }
func setTrayRunning()     { atomic.StoreInt32(&trayRunning, 1) }

func init() {
	if runtime.GOOS == "windows" {
		procSetAppID := modshell32Instance.NewProc("SetCurrentProcessExplicitAppUserModelID")
		if procSetAppID.Find() == nil {
			appID, _ := windows.UTF16PtrFromString("NatBypass.MeshNetwork.App")
			_, _, _ = procSetAppID.Call(uintptr(unsafe.Pointer(appID)))
		}

		// Load embedded application icon from PE resources
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

// acquireSingleInstanceMutex ensures only one primary NatBypass instance runs.
func acquireSingleInstanceMutex(port int) bool {
	if runtime.GOOS != "windows" {
		return true
	}

	if port <= 0 {
		port = 8080
	}
	lastWebUIPort = port

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
		// Check if running instance is active
		client := http.Client{Timeout: 400 * time.Millisecond}
		resp, httpErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", port))
		if httpErr == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Printf("NatBypass is already running on port %d. Activating window...\n", port)
				_ = windows.CloseHandle(hMutex)
				activateExistingWindow()
				return false
			}
		}
	}

	singleInstanceMutex = hMutex
	cleanupStaleBackups()
	return true
}

func cleanupStaleBackups() {
	exeDir, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exeDir)
	_ = os.Remove(filepath.Join(dir, "natbypass.exe.old"))
	_ = os.Remove(filepath.Join(dir, "NatBypass.exe.old"))
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
		return
	}

	// Fallback to default browser
	port := lastWebUIPort
	if port <= 0 {
		port = 8080
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	_ = exec.Command("cmd.exe", "/c", "start", "", url).Start()
}

// subclassWebViewWindow intercepts WM_CLOSE to minimize to tray instead of exiting
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
			procShowWindow := moduser32Instance.NewProc("ShowWindow")
			procShowWindow.Call(h, 0 /* SW_HIDE */)
			return 0
		}
		ret, _, _ := procCallWindowProcW.Call(origWndProc, h, uintptr(msg), wparam, lparam)
		return ret
	})

	res, _, _ := procSetWindowLongPtrW.Call(hwnd, ^uintptr(3) /* GWLP_WNDPROC = -4 */, customProc)
	origWndProc = res
}

func isHeadlessOrServerCore() bool {
	procGetDesktopWindow := moduser32Instance.NewProc("GetDesktopWindow")
	if procGetDesktopWindow.Find() != nil {
		return true
	}
	hDesktop, _, _ := procGetDesktopWindow.Call()
	return hDesktop == 0
}

// openAppWindow launches the WebUI window using the native in-process WebView2
// with readiness gate, automated WebView2 installation on Windows Server, and fallback to default browser.
func openAppWindow(port int) {
	if port <= 0 {
		port = 8080
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)

	// 1. Readiness Gate: Poll 127.0.0.1:port for up to 10s before launching UI
	ready := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	if !ready {
		fmt.Printf("Warning: WebUI server at 127.0.0.1:%d did not respond within readiness timeout.\n", port)
		return
	}

	// 2. Detect Desktop Experience vs Server Core
	if !tray.IsDesktopExperienceAvailable() || isHeadlessOrServerCore() {
		fmt.Printf("Windows Server Core / headless environment detected. WebUI running in background at %s\n", url)
		return
	}

	// 3. Start System Tray icon in background if not yet active
	if !isTrayRunning() {
		go startTrayIcon(port)
	}

	// 4. Check if WebView2 runtime is installed. If missing, trigger silent auto-installation with UAC elevation.
	if !tray.IsWebView2RuntimeAvailable() {
		fmt.Println("WebView2 runtime not found. Starting automatic installation...")
		installed, err := tray.InstallWebView2RuntimeIfNeeded()
		if err == nil && installed {
			fmt.Println("WebView2 runtime successfully installed. Restarting NatBypass...")
			_ = tray.RestartSelf()
			return
		}
		fmt.Printf("WebView2 installation skipped/failed (%v). Opening in default browser...\n", err)
		_ = exec.Command("cmd.exe", "/c", "start", "", url).Start()
		return
	}

	// 5. Launch in-process native WebView2 window
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

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

		var fallbackTriggered bool
		fallbackOpen := func() {
			if fallbackTriggered {
				return
			}
			fallbackTriggered = true
			_ = exec.Command("cmd.exe", "/c", "start", "", url).Start()
		}

		defer func() {
			if r := recover(); r != nil {
				fallbackOpen()
			}
		}()

		// Set DPI awareness
		procSetProcessDpiAwarenessContext := moduser32Instance.NewProc("SetProcessDpiAwarenessContext")
		if procSetProcessDpiAwarenessContext.Find() == nil {
			_, _, _ = procSetProcessDpiAwarenessContext.Call(^uintptr(3))
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

		// Enable Dark Mode on titlebar
		procDwmSetWindowAttribute := moddwmapiInstance.NewProc("DwmSetWindowAttribute")
		if procDwmSetWindowAttribute.Find() == nil {
			darkMode := int32(1)
			_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)
			_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 19, uintptr(unsafe.Pointer(&darkMode)), 4)
		}

		// Apply application icon to the window
		if appHIcon != 0 {
			procSendMessageW := moduser32Instance.NewProc("SendMessageW")
			_, _, _ = procSendMessageW.Call(hwnd, 0x0080 /* WM_SETICON */, 1 /* ICON_BIG */, appHIcon)
			_, _, _ = procSendMessageW.Call(hwnd, 0x0080 /* WM_SETICON */, 0 /* ICON_SMALL */, appHIcon)
		}

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

		w.Navigate(url)
		w.Run()
	}()
}

const (
	wmUserTray   = 0x0400 + 1
	trayIconID   = 1
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
	uTimeoutOrVer    uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
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

	wndProc := syscall.NewCallback(func(hwnd uintptr, msg uint32, wparam uintptr, lparam uintptr) uintptr {
		switch msg {
		case wmUserTray:
			event := uint32(lparam & 0xFFFF)
			switch event {
			case 0x0202, 0x0203: // WM_LBUTTONUP, WM_LBUTTONDBLCLK
				activateExistingWindow()
			case 0x0205: // WM_RBUTTONUP
				hMenu, _, _ := procCreatePopupMenu.Call()
				if hMenu != 0 {
					openText, _ := windows.UTF16PtrFromString("Открыть NatBypass")
					exitText, _ := windows.UTF16PtrFromString("Выход")

					procAppendMenuW.Call(hMenu, 0, uintptr(menuItemOpen), uintptr(unsafe.Pointer(openText)))
					procAppendMenuW.Call(hMenu, 0x0800 /* MF_SEPARATOR */, 0, 0)
					procAppendMenuW.Call(hMenu, 0, uintptr(menuItemExit), uintptr(unsafe.Pointer(exitText)))

					var pt pointW
					procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
					procSetForegroundWindow.Call(hwnd)

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

	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = trayIconID
	nid.uFlags = 0x00000001 | 0x00000002 | 0x00000004 // NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.uCallbackMessage = wmUserTray
	nid.hIcon = appHIcon

	tip, _ := windows.UTF16FromString("NatBypass — P2P Mesh Network")
	copy(nid.szTip[:], tip)

	procShellNotifyIconW.Call(0 /* NIM_ADD */, uintptr(unsafe.Pointer(&nid)))

	var msg msgW
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}