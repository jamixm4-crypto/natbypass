//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modgdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modcomctl32 = windows.NewLazySystemDLL("comctl32.dll")

	procRegisterClassExW      = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW       = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW        = moduser32.NewProc("DefWindowProcW")
	procPostQuitMessage       = moduser32.NewProc("PostQuitMessage")
	procGetMessageW           = moduser32.NewProc("GetMessageW")
	procTranslateMessage      = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW      = moduser32.NewProc("DispatchMessageW")
	procSendMessageW          = moduser32.NewProc("SendMessageW")
	procGetWindowTextW        = moduser32.NewProc("GetWindowTextW")
	procSetWindowTextW        = moduser32.NewProc("SetWindowTextW")
	procEnableWindow          = moduser32.NewProc("EnableWindow")
	procLoadIconW             = moduser32.NewProc("LoadIconW")
	procGetModuleHandleW      = modkernel32.NewProc("GetModuleHandleW")
	procCreateFontW           = modgdi32.NewProc("CreateFontW")
	procCreateSolidBrush      = modgdi32.NewProc("CreateSolidBrush")
	procSetBkMode             = modgdi32.NewProc("SetBkMode")
	procSetTextColor          = modgdi32.NewProc("SetTextColor")
	procSetBkColor            = modgdi32.NewProc("SetBkColor")
	procInitCommonControlsEx  = modcomctl32.NewProc("InitCommonControlsEx")
)

const (
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_BORDER           = 0x00800000
	WS_VSCROLL          = 0x00200000
	WS_TABSTOP          = 0x00010000

	WS_EX_CLIENTEDGE    = 0x00000200
	WS_EX_STATICEDGE    = 0x00020000

	BS_AUTOCHECKBOX     = 0x00000003
	BS_PUSHBUTTON       = 0x00000000
	BS_DEFPUSHBUTTON    = 0x00000001

	ES_LEFT             = 0x0000
	ES_MULTILINE        = 0x0004
	ES_AUTOVSCROLL      = 0x0040
	ES_AUTOHSCROLL      = 0x0080
	ES_READONLY         = 0x0800
	ES_PASSWORD         = 0x0020

	WM_COMMAND          = 0x0111
	WM_DESTROY          = 0x0002
	WM_SETFONT          = 0x0030
	WM_CTLCOLOREDIT     = 0x0133
	WM_CTLCOLORSTATIC   = 0x0138
	WM_CTLCOLORBTN      = 0x0135

	EM_SETSEL           = 0x00B1
	EM_REPLACESEL       = 0x00C2
	EM_SCROLLCARET      = 0x00B7
	BM_GETCHECK         = 0x00F0
	BM_SETCHECK         = 0x00F1
	BST_CHECKED         = 1

	PBM_SETRANGE32      = 0x0406
	PBM_SETPOS          = 0x0402
	PBM_SETBARCOLOR     = 0x0409

	IDI_APPLICATION     = 32512

	BTN_BUILD_ALL       = 101
	BTN_BUILD_ROUTER    = 102
	BTN_OPEN_DIST       = 103
)

type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type MSG struct {
	HWnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

var (
	hMainWnd       windows.HWND
	hFont          windows.Handle
	hFontBold      windows.Handle
	hFontTitle     windows.Handle
	hFontCode      windows.Handle
	hBgBrush       windows.Handle
	hEditBrush     windows.Handle

	// Controls
	hTxtTgToken    windows.HWND
	hTxtTgChatID   windows.HWND
	hTxtMqttBroker windows.HWND
	hTxtMqttTopic  windows.HWND
	hTxtWebhook    windows.HWND
	hTxtPort       windows.HWND
	hTxtUser       windows.HWND
	hTxtPass       windows.HWND
	hChkWin        windows.HWND
	hChkLinux      windows.HWND
	hChkArm64      windows.HWND
	hChkMips       windows.HWND
	hChkMipsle     windows.HWND
	hBtnBuildAll   windows.HWND
	hBtnBuildRtr   windows.HWND
	hBtnOpenDist   windows.HWND
	hProgressBar   windows.HWND
	hLblProgress   windows.HWND
	hTxtLog        windows.HWND
)

func wndProc(hwnd windows.HWND, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_COMMAND:
		ctrlID := uint32(wparam & 0xFFFF)
		switch ctrlID {
		case BTN_BUILD_ALL:
			go startBuild("all")
		case BTN_BUILD_ROUTER:
			go startBuild("router")
		case BTN_OPEN_DIST:
			distDir := getDistDir()
			exec.Command("explorer.exe", distDir).Start()
		}
		return 0

	case WM_CTLCOLORSTATIC:
		hdc := wparam
		procSetBkMode.Call(hdc, 1) // TRANSPARENT
		procSetTextColor.Call(hdc, 0x00222222)
		return uintptr(hBgBrush)

	case WM_CTLCOLOREDIT:
		hdc := wparam
		procSetBkColor.Call(hdc, 0x00FFFFFF)
		procSetTextColor.Call(hdc, 0x00111111)
		return uintptr(hEditBrush)

	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
	return r
}

func main() {
	runtime.LockOSThread()

	// Init common controls for progress bar
	icc := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  0x00000020, // ICC_PROGRESS_CLASS
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))

	hInstRaw, _, _ := procGetModuleHandleW.Call(0)
	hInst := windows.Handle(hInstRaw)

	className, _ := windows.UTF16PtrFromString("NatBypassBuilderClass")
	windowTitle, _ := windows.UTF16PtrFromString("NatBypass — Кроссплатформенный Сборщик")

	hIconRaw, _, _ := procLoadIconW.Call(0, uintptr(IDI_APPLICATION))
	hIcon := windows.Handle(hIconRaw)

	// Background brushes: clean light gray window, white edit boxes
	bgRaw, _, _ := procCreateSolidBrush.Call(0x00F0F0F0)
	hBgBrush = windows.Handle(bgRaw)

	editBgRaw, _, _ := procCreateSolidBrush.Call(0x00FFFFFF)
	hEditBrush = windows.Handle(editBgRaw)

	wndClass := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     hInst,
		LpszClassName: className,
		HIcon:         hIcon,
		HbrBackground: hBgBrush,
	}

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wndClass)))

	// Fonts
	fName, _ := windows.UTF16PtrFromString("Segoe UI")
	fNameCode, _ := windows.UTF16PtrFromString("Consolas")

	hfRaw, _, _ := procCreateFontW.Call(16, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 2, 0, uintptr(unsafe.Pointer(fName)))
	hFont = windows.Handle(hfRaw)

	hfBoldRaw, _, _ := procCreateFontW.Call(16, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 2, 0, uintptr(unsafe.Pointer(fName)))
	hFontBold = windows.Handle(hfBoldRaw)

	hfTitleRaw, _, _ := procCreateFontW.Call(19, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 2, 0, uintptr(unsafe.Pointer(fName)))
	hFontTitle = windows.Handle(hfTitleRaw)

	hfCodeRaw, _, _ := procCreateFontW.Call(14, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 2, 0, uintptr(unsafe.Pointer(fNameCode)))
	hFontCode = windows.Handle(hfCodeRaw)

	hwndRaw, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		WS_OVERLAPPEDWINDOW&^0x00040000&^0x00010000, // no resize/maximize
		100, 80, 800, 750,
		0, 0,
		uintptr(hInst),
		0,
	)
	hMainWnd = windows.HWND(hwndRaw)

	createControls(hInst)

	moduser32.NewProc("ShowWindow").Call(uintptr(hMainWnd), 5) // SW_SHOW
	moduser32.NewProc("UpdateWindow").Call(uintptr(hMainWnd))

	appendLog("🚀 NatBypass Builder готов к работе.\r\nЗадайте параметры, выберите платформы и нажмите «🔨 Начать сборку».\r\n============================================================\r\n")

	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func createControls(hInst windows.Handle) {
	sStatic, _ := windows.UTF16PtrFromString("STATIC")
	sEdit, _ := windows.UTF16PtrFromString("EDIT")
	sButton, _ := windows.UTF16PtrFromString("BUTTON")
	sProgress, _ := windows.UTF16PtrFromString("msctls_progress32")

	// Header Label
	createWin(0, sStatic, "🚀 NatBypass — Кроссплатформенный Сборщик", WS_CHILD|WS_VISIBLE, 18, 12, 740, 26, hMainWnd, 0, hInst, hFontTitle)

	// Section 1: Signaling
	createWin(0, sStatic, "📡 Настройки сигнальных каналов (Fallback)", WS_CHILD|WS_VISIBLE, 18, 45, 740, 18, hMainWnd, 0, hInst, hFontBold)

	createWin(0, sStatic, "Telegram Bot Token:", WS_CHILD|WS_VISIBLE, 18, 70, 140, 20, hMainWnd, 0, hInst, hFont)
	hTxtTgToken = createWin(WS_EX_CLIENTEDGE, sEdit, "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 160, 68, 250, 24, hMainWnd, 0, hInst, hFont)

	createWin(0, sStatic, "Chat/Channel ID:", WS_CHILD|WS_VISIBLE, 425, 70, 110, 20, hMainWnd, 0, hInst, hFont)
	hTxtTgChatID = createWin(WS_EX_CLIENTEDGE, sEdit, "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 540, 68, 215, 24, hMainWnd, 0, hInst, hFont)

	createWin(0, sStatic, "MQTT Broker URL:", WS_CHILD|WS_VISIBLE, 18, 102, 140, 20, hMainWnd, 0, hInst, hFont)
	hTxtMqttBroker = createWin(WS_EX_CLIENTEDGE, sEdit, "tcp://mqtt.eclipseprojects.io:1883", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 160, 100, 250, 24, hMainWnd, 0, hInst, hFont)

	createWin(0, sStatic, "MQTT Topic:", WS_CHILD|WS_VISIBLE, 425, 102, 110, 20, hMainWnd, 0, hInst, hFont)
	hTxtMqttTopic = createWin(WS_EX_CLIENTEDGE, sEdit, "natbypass/mynet/peers", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 540, 100, 215, 24, hMainWnd, 0, hInst, hFont)

	createWin(0, sStatic, "Webhook URL (опц.):", WS_CHILD|WS_VISIBLE, 18, 134, 140, 20, hMainWnd, 0, hInst, hFont)
	hTxtWebhook = createWin(WS_EX_CLIENTEDGE, sEdit, "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 160, 132, 595, 24, hMainWnd, 0, hInst, hFont)

	// Section 2: General Settings
	createWin(0, sStatic, "⚙ Параметры приложения", WS_CHILD|WS_VISIBLE, 18, 168, 740, 18, hMainWnd, 0, hInst, hFontBold)

	createWin(0, sStatic, "Web UI Порт:", WS_CHILD|WS_VISIBLE, 18, 193, 90, 20, hMainWnd, 0, hInst, hFont)
	hTxtPort = createWin(WS_EX_CLIENTEDGE, sEdit, "8080", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 110, 191, 65, 24, hMainWnd, 0, hInst, hFont)

	createWin(0, sStatic, "Логин:", WS_CHILD|WS_VISIBLE, 195, 193, 50, 20, hMainWnd, 0, hInst, hFont)
	hTxtUser = createWin(WS_EX_CLIENTEDGE, sEdit, "admin", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 250, 191, 110, 24, hMainWnd, 0, hInst, hFont)

	createWin(0, sStatic, "Пароль (опц.):", WS_CHILD|WS_VISIBLE, 380, 193, 95, 20, hMainWnd, 0, hInst, hFont)
	hTxtPass = createWin(WS_EX_CLIENTEDGE, sEdit, "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL|ES_PASSWORD, 480, 191, 140, 24, hMainWnd, 0, hInst, hFont)

	// Section 3: Targets
	createWin(0, sStatic, "🎯 Целевые платформы для сборки", WS_CHILD|WS_VISIBLE, 18, 227, 740, 18, hMainWnd, 0, hInst, hFontBold)

	hChkWin = createWin(0, sButton, "Windows x64 (.exe)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 18, 250, 150, 22, hMainWnd, 0, hInst, hFont)
	hChkLinux = createWin(0, sButton, "Linux x64", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 175, 250, 95, 22, hMainWnd, 0, hInst, hFont)
	hChkArm64 = createWin(0, sButton, "ARM64 (Keenetic/RPi)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 275, 250, 165, 22, hMainWnd, 0, hInst, hFont)
	hChkMips = createWin(0, sButton, "MIPS (Big Endian)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 450, 250, 140, 22, hMainWnd, 0, hInst, hFont)
	hChkMipsle = createWin(0, sButton, "MIPSLE (Keenetic)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 600, 250, 150, 22, hMainWnd, 0, hInst, hFont)

	for _, chk := range []windows.HWND{hChkWin, hChkLinux, hChkArm64, hChkMips, hChkMipsle} {
		procSendMessageW.Call(uintptr(chk), uintptr(BM_SETCHECK), uintptr(BST_CHECKED), 0)
	}

	// Action Buttons
	hBtnBuildAll = createWin(0, sButton, "🔨 Начать сборку", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 18, 282, 210, 36, hMainWnd, uintptr(BTN_BUILD_ALL), hInst, hFontBold)
	hBtnBuildRtr = createWin(0, sButton, "📡 Только для роутеров", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 238, 282, 210, 36, hMainWnd, uintptr(BTN_BUILD_ROUTER), hInst, hFontBold)
	hBtnOpenDist = createWin(0, sButton, "📂 Открыть папку dist\\", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 458, 282, 297, 36, hMainWnd, uintptr(BTN_OPEN_DIST), hInst, hFont)

	// Progress Bar
	hProgressBar = createWin(WS_EX_CLIENTEDGE, sProgress, "", WS_CHILD|WS_VISIBLE, 18, 328, 620, 20, hMainWnd, 0, hInst, 0)
	procSendMessageW.Call(uintptr(hProgressBar), uintptr(PBM_SETRANGE32), 0, 100)

	hLblProgress = createWin(0, sStatic, "Готов к сборке (0%)", WS_CHILD|WS_VISIBLE, 648, 329, 130, 20, hMainWnd, 0, hInst, hFontBold)

	// Multiline Log Box
	hTxtLog = createWin(WS_EX_CLIENTEDGE, sEdit, "", WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY, 18, 355, 737, 335, hMainWnd, 0, hInst, hFontCode)
}

func createWin(exStyle uint32, className *uint16, text string, style uint32, x, y, w, h int32, parent windows.HWND, id uintptr, hInst windows.Handle, font windows.Handle) windows.HWND {
	textW, _ := windows.UTF16PtrFromString(text)
	hwndRaw, _, _ := procCreateWindowExW.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textW)),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent),
		id,
		uintptr(hInst),
		0,
	)
	hControl := windows.HWND(hwndRaw)
	if font != 0 {
		procSendMessageW.Call(uintptr(hControl), uintptr(WM_SETFONT), uintptr(font), 1)
	}
	return hControl
}

func getControlText(hwnd windows.HWND) string {
	buf := make([]uint16, 512)
	procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf)
}

func isChecked(hwnd windows.HWND) bool {
	r, _, _ := procSendMessageW.Call(uintptr(hwnd), uintptr(BM_GETCHECK), 0, 0)
	return r == uintptr(BST_CHECKED)
}

func setProgress(pct int, label string) {
	procSendMessageW.Call(uintptr(hProgressBar), uintptr(PBM_SETPOS), uintptr(pct), 0)
	tW, _ := windows.UTF16PtrFromString(fmt.Sprintf("%s (%d%%)", label, pct))
	procSetWindowTextW.Call(uintptr(hLblProgress), uintptr(unsafe.Pointer(tW)))
}

func appendLog(text string) {
	textW, _ := windows.UTF16PtrFromString(text)
	procSendMessageW.Call(uintptr(hTxtLog), uintptr(EM_SETSEL), uintptr(0xFFFFFFF), uintptr(0xFFFFFFF))
	procSendMessageW.Call(uintptr(hTxtLog), uintptr(EM_REPLACESEL), 0, uintptr(unsafe.Pointer(textW)))
	procSendMessageW.Call(uintptr(hTxtLog), uintptr(EM_SCROLLCARET), 0, 0)
}

func getProjectRoot() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		for i := 0; i < 5; i++ {
			if _, err := os.Stat(filepath.Join(dir, "cmd", "natbypass", "main.go")); err == nil {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	cwd, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(cwd, "cmd", "natbypass", "main.go")); err == nil {
			return cwd
		}
		parent := filepath.Dir(cwd)
		if parent == cwd {
			break
		}
		cwd = parent
	}
	return "e:\\qwen\\fnat"
}

func getDistDir() string {
	root := getProjectRoot()
	d := filepath.Join(root, "dist")
	os.MkdirAll(d, 0755)
	return d
}

func getGoExe() (string, string) {
	root := getProjectRoot()
	candidates := []string{
		filepath.Join(root, "soft", "go", "bin", "go.exe"),
		`C:\Program Files\Go\bin\go.exe`,
		`C:\Go\bin\go.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			goroot := filepath.Dir(filepath.Dir(c))
			return c, goroot
		}
	}
	if p, err := exec.LookPath("go.exe"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs, filepath.Dir(filepath.Dir(abs))
		}
		return p, ""
	}
	return "go", ""
}

func startBuild(mode string) {
	procEnableWindow.Call(uintptr(hBtnBuildAll), 0)
	procEnableWindow.Call(uintptr(hBtnBuildRtr), 0)
	defer func() {
		procEnableWindow.Call(uintptr(hBtnBuildAll), 1)
		procEnableWindow.Call(uintptr(hBtnBuildRtr), 1)
	}()

	setProgress(5, "Инициализация")
	appendLog("\r\n============================================================\r\n")
	appendLog(fmt.Sprintf(">> Запуск компиляции NatBypass [%s]...\r\n", mode))

	projectRoot := getProjectRoot()
	goExe, goroot := getGoExe()
	distDir := getDistDir()
	appendLog(fmt.Sprintf("   Папка проекта: %s\r\n", projectRoot))
	appendLog(fmt.Sprintf("   Компилятор Go: %s\r\n", goExe))

	tgToken := getControlText(hTxtTgToken)
	tgChat := getControlText(hTxtTgChatID)
	mqttBroker := getControlText(hTxtMqttBroker)
	mqttTopic := getControlText(hTxtMqttTopic)
	webhook := getControlText(hTxtWebhook)
	port := getControlText(hTxtPort)
	user := getControlText(hTxtUser)
	pass := getControlText(hTxtPass)

	buildDate := time.Now().UTC().Format(time.RFC3339)
	version := "1.0.0"
	commit := "release"
	module := "github.com/natbypass/natbypass"

	ldflags := fmt.Sprintf("-s -w "+
		"-X %s/cmd/natbypass.Version=%s "+
		"-X %s/cmd/natbypass.Commit=%s "+
		"-X %s/cmd/natbypass.BuildDate=%s "+
		"-X %s/cmd/natbypass.DefaultTgToken=%s "+
		"-X %s/cmd/natbypass.DefaultTgChatID=%s "+
		"-X %s/cmd/natbypass.DefaultMQTTBroker=%s "+
		"-X %s/cmd/natbypass.DefaultMQTTTopic=%s "+
		"-X %s/cmd/natbypass.DefaultWebhookURL=%s "+
		"-X %s/cmd/natbypass.DefaultWebUIPort=%s "+
		"-X %s/cmd/natbypass.DefaultWebUIUser=%s "+
		"-X %s/cmd/natbypass.DefaultWebUIPass=%s",
		module, version,
		module, commit,
		module, buildDate,
		module, tgToken,
		module, tgChat,
		module, mqttBroker,
		module, mqttTopic,
		module, webhook,
		module, port,
		module, user,
		module, pass,
	)

	type target struct {
		goos, goarch, ext, gomips, name string
		checked                          bool
	}

	targets := []target{
		{"windows", "amd64", ".exe", "", "Windows x64", isChecked(hChkWin) || mode == "all"},
		{"linux", "amd64", "", "", "Linux x64", (isChecked(hChkLinux) || mode == "all") && mode != "router"},
		{"linux", "arm64", "", "", "ARM64 (Keenetic/RPi)", isChecked(hChkArm64) || mode == "all" || mode == "router"},
		{"linux", "mips", "", "softfloat", "MIPS (Big Endian)", isChecked(hChkMips) || mode == "all" || mode == "router"},
		{"linux", "mipsle", "", "softfloat", "MIPSLE (Keenetic)", isChecked(hChkMipsle) || mode == "all" || mode == "router"},
	}

	gopath := filepath.Join(projectRoot, "soft", "gopath")
	gocache := filepath.Join(projectRoot, "soft", "gocache")
	os.MkdirAll(gopath, 0755)
	os.MkdirAll(gocache, 0755)

	envBase := os.Environ()
	envBase = append(envBase,
		"CGO_ENABLED=0",
		"GOPATH="+gopath,
		"GOCACHE="+gocache,
	)
	if goroot != "" {
		envBase = append(envBase,
			"GOROOT="+goroot,
			"PATH="+filepath.Join(goroot, "bin")+";"+os.Getenv("PATH"),
		)
	}

	allOk := true
	countChecked := 0
	for _, t := range targets {
		if t.checked {
			countChecked++
		}
	}
	if countChecked == 0 {
		countChecked = 1
	}

	currentStep := 0

	for _, t := range targets {
		if !t.checked {
			continue
		}
		currentStep++
		pct := 10 + int(float64(currentStep)/float64(countChecked)*80)
		setProgress(pct, t.name)

		outName := fmt.Sprintf("natbypass-%s-%s%s", t.goos, t.goarch, t.ext)
		outPath := filepath.Join(distDir, outName)

		appendLog(fmt.Sprintf("   🔨 Компиляция для %s (%s/%s)... ", t.name, t.goos, t.goarch))

		env := append(envBase, "GOOS="+t.goos, "GOARCH="+t.goarch)
		if t.gomips != "" {
			env = append(env, "GOMIPS="+t.gomips)
		}

		cmd := exec.Command(goExe, "build", "-trimpath", "-ldflags", ldflags, "-o", outPath, "./cmd/natbypass")
		cmd.Dir = projectRoot
		cmd.Env = env

		output, err := cmd.CombinedOutput()
		if err != nil {
			appendLog(fmt.Sprintf("ОШИБКА!\r\n%s\r\n", string(output)))
			allOk = false
		} else {
			sz := float64(0)
			if fi, err := os.Stat(outPath); err == nil {
				sz = float64(fi.Size()) / (1024 * 1024)
			}
			appendLog(fmt.Sprintf("OK (%.2f МБ)\r\n", sz))
		}
	}

	// Also build natbypass-gui.exe if Windows was checked
	if isChecked(hChkWin) || mode == "all" {
		guiOut := filepath.Join(distDir, "natbypass-gui.exe")
		appendLog("   🔨 Компиляция GUI версии natbypass-gui.exe... ")
		cmd := exec.Command(goExe, "build", "-trimpath", "-ldflags", ldflags+" -H=windowsgui", "-o", guiOut, "./cmd/natbypass-gui")
		cmd.Dir = projectRoot
		cmd.Env = append(envBase, "GOOS=windows", "GOARCH=amd64")
		if out, err := cmd.CombinedOutput(); err != nil {
			appendLog(fmt.Sprintf("ОШИБКА!\r\n%s\r\n", string(out)))
		} else {
			sz := float64(0)
			if fi, err := os.Stat(guiOut); err == nil {
				sz = float64(fi.Size()) / (1024 * 1024)
			}
			appendLog(fmt.Sprintf("OK (%.2f МБ)\r\n", sz))
			// Копируем как NatBypass.exe
			exec.Command("cmd", "/c", "copy", "/y", guiOut, filepath.Join(distDir, "NatBypass.exe")).Run()
		}
	}

	// Write config.yaml
	cfgPath := filepath.Join(distDir, "config.yaml")
	cfgContent := fmt.Sprintf(`app:
  name: "NatBypass"
  version: "%s"
  log_level: "info"
  publish_interval: 60

web_ui:
  enabled: true
  port: %s
  username: "%s"
  password: "%s"

network:
  upnp_enabled: true
  stun_servers:
    - "stun.l.google.com:19302"
    - "stun1.l.google.com:19302"
    - "stun.cloudflare.com:3478"
  ip_apis:
    - "https://api.ipify.org"
    - "https://ifconfig.me/ip"
    - "https://icanhazip.com"

signaling:
  channels:
    - type: "telegram"
      priority: 1
      enabled: true
      params:
        token: "%s"
        chat_id: "%s"
    - type: "mqtt"
      priority: 2
      enabled: true
      params:
        broker_url: "%s"
        topic: "%s"

wireguard:
  enabled: false
  interface: "wg0"
  listen_port: 51820
`, version, port, user, pass, tgToken, tgChat, mqttBroker, mqttTopic)

	os.WriteFile(cfgPath, []byte(cfgContent), 0644)

	if allOk {
		setProgress(100, "Сборка завершена")
		appendLog("============================================================\r\n")
		appendLog("✓ ВСЕ БИНАРНИКИ И CONFIG.YAML УСПЕШНО СКОМПИЛИРОВАНЫ В dist\\\r\n")
	} else {
		setProgress(100, "С ошибками")
	}
}