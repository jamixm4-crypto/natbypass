//go:build windows

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"github.com/natbypass/natbypass/internal/tray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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

var (
	trayHWnd uintptr
	trayMu   sync.Mutex
)

func cleanupTrayIcon() {
	if runtime.GOOS != "windows" {
		return
	}
	trayMu.Lock()
	defer trayMu.Unlock()
	if trayHWnd != 0 {
		procShellNotifyIconW := modshell32Instance.NewProc("Shell_NotifyIconW")
		if procShellNotifyIconW.Find() == nil {
			var nid notifyIconDataW
			nid.cbSize = uint32(unsafe.Sizeof(nid))
			nid.hWnd = trayHWnd
			nid.uID = trayIconID
			_, _, _ = procShellNotifyIconW.Call(2 /* NIM_DELETE */, uintptr(unsafe.Pointer(&nid)))
		}
		trayHWnd = 0
		atomic.StoreInt32(&trayRunning, 0)
	}
}

// acquireSingleInstanceMutex ensures only one primary NatBypass instance runs per configuration.
func acquireSingleInstanceMutex(cfgPath string, port int) bool {
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

	absPath, err := filepath.Abs(cfgPath)
	if err != nil {
		absPath = cfgPath
	}
	hash := sha256.Sum256([]byte(strings.ToLower(absPath)))
	mutexNameStr := fmt.Sprintf("Local\\NatBypass_Instance_%x", hash[:8])
	mutexName, _ := windows.UTF16PtrFromString(mutexNameStr)
	hMutex, err := windows.CreateMutex(nil, false, mutexName)
	if hMutex == 0 {
		return true
	}

	// Also check global GUI mutex so CLI and GUI cannot run simultaneously and collide over Wintun/ports
	guiMutexName, _ := windows.UTF16PtrFromString("Global\\NatBypass_SingleInstance_Mutex_App")
	hGuiMutex, guiErr := windows.CreateMutex(nil, false, guiMutexName)
	if errors.Is(guiErr, windows.ERROR_ALREADY_EXISTS) || guiErr == windows.ERROR_ALREADY_EXISTS {
		client := http.Client{Timeout: 400 * time.Millisecond}
		resp, httpErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", port))
		if httpErr == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Println("NatBypass GUI is already active. Closing duplicate instance to avoid Wintun adapter collision...")
				if hGuiMutex != 0 {
					_ = windows.CloseHandle(hGuiMutex)
				}
				_ = windows.CloseHandle(hMutex)
				activateExistingWindow()
				return false
			}
		}
	}

	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || err == windows.ERROR_ALREADY_EXISTS {
		// Check if running instance is active
		client := http.Client{Timeout: 400 * time.Millisecond}
		resp, httpErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", port))
		if httpErr == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Printf("NatBypass is already running for config '%s' on port %d. Activating window...\n", cfgPath, port)
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

	port := lastWebUIPort
	if port <= 0 {
		port = 8080
	}
	openAppWindow(port)
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

// launchNativeWebView attempts to create and run an in-process native WebView2 window.
// Returns true on success, false if WebView2 runtime is missing or fails to initialize.
func launchNativeWebView(url string, port int) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	modole32 := windows.NewLazySystemDLL("ole32.dll")
	procOleInitialize := modole32.NewProc("OleInitialize")
	if procOleInitialize.Find() == nil {
		_, _, _ = procOleInitialize.Call(0)
	}

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

	// Set DPI awareness
	procSetProcessDpiAwarenessContext := moduser32Instance.NewProc("SetProcessDpiAwarenessContext")
	if procSetProcessDpiAwarenessContext.Find() == nil {
		_, _, _ = procSetProcessDpiAwarenessContext.Call(^uintptr(3))
	}

	userDataDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "NatBypass", "webview2")
	_ = os.MkdirAll(userDataDir, 0755)

	var w webview2.WebView
	var initErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				initErr = fmt.Errorf("panic in webview2 init: %v", r)
			}
		}()
		w = webview2.NewWithOptions(webview2.WebViewOptions{
			Debug:     false,
			AutoFocus: true,
			DataPath:  userDataDir,
			WindowOptions: webview2.WindowOptions{
				Title:  "NatBypass — P2P Mesh Network",
				Width:  uint(winWidth),
				Height: uint(winHeight),
				Center: true,
			},
		})
	}()

	if w == nil || initErr != nil {
		return false
	}

	defer func() {
		defer func() { recover() }()
		w.Destroy()
		mainAppHWnd = 0
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
	return true
}

// openAppWindow launches the WebUI window using Native-First strategy:
// 1. If uiMode == "browser" -> opens default browser immediately.
// 2. Otherwise (auto / native) -> ALWAYS tries native WebView2 first.
// 3. If native fails (e.g. Server without runtime) -> checks auto-install or falls back to dedicated App window.
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

	// 3. If explicit browser mode requested via CLI flag:
	if strings.EqualFold(uiMode, "browser") {
		_ = exec.Command("cmd.exe", "/c", "start", "", url).Start()
		return
	}

	// 5. MULTI-TIER WINDOW LAUNCHER (Windows 7/10/11 & Windows Server 2012-2025):
	go func() {
		// Tier 1: In-process WebView2 Native Window (Windows 10/11 & Servers with WebView2 runtime)
		if launchNativeWebView(url, port) {
			return
		}

		// Tier 2: Dedicated Chromium App Window (msedge.exe / chrome.exe / brave.exe with --app)
		// This runs on Windows 10/11 and Windows Server, opening a dedicated frameless app window without browser tabs or address bar.
		if browserPath := findChromiumAppBrowser(); browserPath != "" {
			fmt.Printf("Launching NatBypass in dedicated app window (%s)...\n", filepath.Base(browserPath))
			userDataDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "NatBypass", "edge-profile")
			_ = os.MkdirAll(userDataDir, 0755)
			appArgs := []string{
				fmt.Sprintf("--app=%s", url),
				fmt.Sprintf("--user-data-dir=%s", userDataDir),
				"--new-window",
				"--disable-features=Translate",
				"--window-size=1220,780",
			}
			cmd := exec.Command(browserPath, appArgs...)
			if err := cmd.Start(); err == nil {
				return
			}
		}

		// Tier 3: Pure Win32 Native Dark Mode GDI GUI (Zero dependencies - works on Windows Server 2012-2025 out of the box)
		exeDir, err := os.Executable()
		if err == nil {
			guiPath := filepath.Join(filepath.Dir(exeDir), "NatBypass-GUI.exe")
			if _, statErr := os.Stat(guiPath); statErr == nil {
				fmt.Println("Launching Pure Win32 Native GUI window (NatBypass-GUI)...")
				cmd := exec.Command(guiPath, "-port", strconv.Itoa(port))
				if startErr := cmd.Start(); startErr == nil {
					return
				}
			}
		}

		// Tier 4: If on Windows Server with Desktop Experience, trigger on-demand WebView2 auto-install
		if tray.IsDesktopExperienceAvailable() && !tray.IsWebView2RuntimeAvailable() {
			fmt.Println("Attempting on-demand WebView2 runtime setup...")
			go func() {
				installed, instErr := tray.InstallWebView2RuntimeIfNeeded()
				if instErr == nil && installed {
					_ = launchNativeWebView(url, port)
				}
			}()
		}

		// Tier 5: Fallback to default browser with IE ESC Intranet Zone preconfigured
		configureLocalIntranetZone()
		fmt.Printf("Opening WebUI in default browser at %s\n", url)
		_ = exec.Command("cmd.exe", "/c", "start", "", url).Start()
	}()
}

const (
	wmUserTray     = 0x0400 + 1
	trayIconID     = 1
	menuItemOpen   = 2001
	menuItemBrowse = 2002
	menuItemDiag   = 2003
	menuItemExit   = 2004
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
	if !atomic.CompareAndSwapInt32(&trayRunning, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&trayRunning, 0)

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
					openText, _ := windows.UTF16PtrFromString("Открыть окно NatBypass")
					browseText, _ := windows.UTF16PtrFromString("Открыть в браузере")
					diagText, _ := windows.UTF16PtrFromString("🩺 Диагностика WebUI")
					exitText, _ := windows.UTF16PtrFromString("Выход")

					procAppendMenuW.Call(hMenu, 0, uintptr(menuItemOpen), uintptr(unsafe.Pointer(openText)))
					procAppendMenuW.Call(hMenu, 0, uintptr(menuItemBrowse), uintptr(unsafe.Pointer(browseText)))
					procAppendMenuW.Call(hMenu, 0, uintptr(menuItemDiag), uintptr(unsafe.Pointer(diagText)))
					procAppendMenuW.Call(hMenu, 0x0800 /* MF_SEPARATOR */, 0, 0)
					procAppendMenuW.Call(hMenu, 0, uintptr(menuItemExit), uintptr(unsafe.Pointer(exitText)))

					var pt pointW
					procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
					procSetForegroundWindow.Call(hwnd)

					cmd, _, _ := procTrackPopupMenu.Call(hMenu, 0x0008|0x0020|0x0100, uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
					procDestroyMenu.Call(hMenu)

					switch cmd {
					case uintptr(menuItemOpen):
						if mainAppHWnd != 0 {
							activateExistingWindow()
						} else {
							go launchNativeWebView(fmt.Sprintf("http://127.0.0.1:%d/", port), port)
						}
					case uintptr(menuItemBrowse):
						_ = exec.Command("cmd.exe", "/c", "start", "", fmt.Sprintf("http://127.0.0.1:%d/", port)).Start()
					case uintptr(menuItemDiag):
						go diagnoseWebUI(port)
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

	trayMu.Lock()
	trayHWnd = hwnd
	trayMu.Unlock()

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
func diagnoseWebUI(port int) {
	fmt.Printf("\n=== WebUI Diagnostics (Port %d) ===\n", port)

	// 1. Check if listening
	cmdNetstat := exec.Command("netstat", "-an")
	cmdNetstat.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmdNetstat.CombinedOutput()
	if err == nil && strings.Contains(string(out), fmt.Sprintf(":%d", port)) {
		fmt.Printf("✓ Port %d is actively listening\n", port)
	} else {
		fmt.Printf("✗ Port %d is NOT listening!\n", port)
	}

	// 2. Check Firewall
	cmdFw := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=NatBypass WebUI")
	cmdFw.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outFw, errFw := cmdFw.CombinedOutput()
	if errFw == nil && strings.Contains(string(outFw), "NatBypass WebUI") {
		fmt.Println("✓ Windows Firewall rule: ENABLED")
	} else {
		fmt.Println("! Windows Firewall rule: not found or disabled")
	}

	// 3. Test HTTP GET to /healthz
	client := &http.Client{Timeout: 2 * time.Second}
	resp, httpErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if httpErr == nil && resp != nil {
		fmt.Printf("✓ HTTP GET /healthz responded with status %d\n", resp.StatusCode)
		_ = resp.Body.Close()
	} else {
		fmt.Printf("✗ HTTP GET failed: %v\n", httpErr)
	}
	fmt.Println("===================================")
}
// findChromiumAppBrowser returns the path to an installed Chromium browser
// (Edge, Chrome, Brave) suitable for launching dedicated standalone App windows.
func findChromiumAppBrowser() string {
	// 1. Check Registry App Paths for msedge.exe and chrome.exe
	for _, appName := range []string{"msedge.exe", "chrome.exe", "brave.exe"} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`+appName, registry.QUERY_VALUE); err == nil {
			val, _, err2 := k.GetStringValue("")
			k.Close()
			if err2 == nil && val != "" {
				if _, statErr := os.Stat(val); statErr == nil {
					return val
				}
			}
		}
		if k2, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`+appName, registry.QUERY_VALUE); err == nil {
			val, _, err2 := k2.GetStringValue("")
			k2.Close()
			if err2 == nil && val != "" {
				if _, statErr := os.Stat(val); statErr == nil {
					return val
				}
			}
		}
	}

	candidates := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft\Edge\Application\msedge.exe`),
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\Application\chrome.exe`),
		`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), `BraveSoftware\Brave-Browser\Application\brave.exe`),
	}
	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// configureLocalIntranetZone adds 127.0.0.1 and localhost to the Trusted/Intranet zone in Registry
// to prevent IE Enhanced Security Configuration (IE ESC) on Windows Server from blocking WebUI.
func configureLocalIntranetZone() {
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost`, registry.SET_VALUE); err == nil {
		_ = k.SetDWordValue("*", 1) // Zone 1 = Local Intranet
		k.Close()
	}
	if k2, _, err2 := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Ranges\Range99`, registry.SET_VALUE); err2 == nil {
		_ = k2.SetStringValue(":Range", "127.0.0.1")
		_ = k2.SetDWordValue("http", 1)
		_ = k2.SetDWordValue("https", 1)
		k2.Close()
	}
}