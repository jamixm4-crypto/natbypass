//go:build windows

package tray

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modshell32  = windows.NewLazySystemDLL("shell32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW  = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW   = moduser32.NewProc("DefWindowProcW")
	procDestroyWindow    = moduser32.NewProc("DestroyWindow")
	procPostQuitMessage  = moduser32.NewProc("PostQuitMessage")
	procGetMessageW      = moduser32.NewProc("GetMessageW")
	procTranslateMessage = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW = moduser32.NewProc("DispatchMessageW")
	procPostMessageW     = moduser32.NewProc("PostMessageW")
	procCreatePopupMenu  = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW      = moduser32.NewProc("AppendMenuW")
	procTrackPopupMenu   = moduser32.NewProc("TrackPopupMenu")
	procDestroyMenu      = moduser32.NewProc("DestroyMenu")
	procGetCursorPos     = moduser32.NewProc("GetCursorPos")
	procSetForegroundWnd = moduser32.NewProc("SetForegroundWindow")
	procLoadIconW        = moduser32.NewProc("LoadIconW")

	procShell_NotifyIconW = modshell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW  = modkernel32.NewProc("GetModuleHandleW")
)

const (
	WM_USER          = 0x0400
	WM_TRAYICON      = WM_USER + 1
	WM_COMMAND       = 0x0111
	WM_RBUTTONUP     = 0x0205
	WM_LBUTTONDBLCLK = 0x0203
	WM_CLOSE         = 0x0010
	WM_DESTROY       = 0x0002

	NIM_ADD        = 0x00000000
	NIM_MODIFY     = 0x00000001
	NIM_DELETE     = 0x00000002
	NIM_SETVERSION = 0x00000004

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004
	NIF_INFO    = 0x00000010

	NIIF_INFO = 0x00000001

	MF_STRING    = 0x00000000
	MF_SEPARATOR = 0x00000800
	MF_GRAYED    = 0x00000001
	MF_DISABLED  = 0x00000002

	TPM_BOTTOMALIGN = 0x0020
	TPM_LEFTALIGN   = 0x0000

	IDI_APPLICATION = 32512
	IDI_SHIELD      = 32518

	CMD_OPEN_WEBUI  = 1001
	CMD_REFRESH_IP  = 1002
	CMD_OPEN_CONFIG = 1003
	CMD_STATUS_INFO = 1004
	CMD_EXIT        = 1005
)

type NOTIFYICONDATAW struct {
	CbSize           uint32
	HWnd             windows.HWND
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

type POINT struct {
	X, Y int32
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
	Pt      POINT
}

type TrayOptions struct {
	WebUIPort     int
	ConfigPath    string
	GetWebUIPort  func() int
	OnRefreshIP   func()
	OnExit        func()
	GetStatusText func() string
}

type TrayApp struct {
	opts   TrayOptions
	hwnd   windows.HWND
	nid    NOTIFYICONDATAW
	hInst  windows.Handle
	ctx    context.Context
	cancel context.CancelFunc
}

var globalTray *TrayApp

func wndProc(hwnd windows.HWND, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_TRAYICON:
		switch lparam {
		case WM_RBUTTONUP:
			if globalTray != nil {
				globalTray.showMenu()
			}
		case WM_LBUTTONDBLCLK:
			if globalTray != nil {
				globalTray.openWebUI()
			}
		}
		return 0

	case WM_COMMAND:
		cmdID := uint32(wparam & 0xFFFF)
		if globalTray != nil {
			globalTray.handleCommand(cmdID)
		}
		return 0

	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
	return r
}

func NewTray(opts TrayOptions) *TrayApp {
	ctx, cancel := context.WithCancel(context.Background())
	return &TrayApp{
		opts:   opts,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (t *TrayApp) Run(ctx context.Context) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	globalTray = t

	hInstRaw, _, _ := procGetModuleHandleW.Call(0)
	t.hInst = windows.Handle(hInstRaw)

	className, _ := windows.UTF16PtrFromString("NatBypassTrayClass")
	windowName, _ := windows.UTF16PtrFromString("NatBypassTrayWindow")

	hIconRaw, _, _ := procLoadIconW.Call(0, uintptr(IDI_SHIELD))
	hIcon := windows.Handle(hIconRaw)

	wndClass := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     t.hInst,
		LpszClassName: className,
		HIcon:         hIcon,
	}

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wndClass)))

	hwndRaw, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0,
		0, 0, 0, 0,
		0, 0,
		uintptr(t.hInst),
		0,
	)
	t.hwnd = windows.HWND(hwndRaw)

	t.nid = NOTIFYICONDATAW{
		HWnd:             t.hwnd,
		UID:              1,
		UFlags:           NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_INFO,
		UCallbackMessage: WM_TRAYICON,
		HIcon:            hIcon,
	}
	t.nid.CbSize = uint32(unsafe.Sizeof(t.nid))

	tip, _ := windows.UTF16FromString(fmt.Sprintf("NatBypass - NAT Traversal (:%d)", t.opts.WebUIPort))
	copy(t.nid.SzTip[:], tip)

	title, _ := windows.UTF16FromString("NatBypass активен")
	copy(t.nid.SzInfoTitle[:], title)

	info, _ := windows.UTF16FromString("Приложение работает в системном трее. Двойной клик - открыть панель управления.")
	copy(t.nid.SzInfo[:], info)
	t.nid.DwInfoFlags = NIIF_INFO

	procShell_NotifyIconW.Call(uintptr(NIM_ADD), uintptr(unsafe.Pointer(&t.nid)))
	defer procShell_NotifyIconW.Call(uintptr(NIM_DELETE), uintptr(unsafe.Pointer(&t.nid)))

	go func() {
		select {
		case <-ctx.Done():
			procPostMessageW.Call(uintptr(t.hwnd), uintptr(WM_DESTROY), 0, 0)
		case <-t.ctx.Done():
		}
	}()

	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	return nil
}

func (t *TrayApp) showMenu() {
	hMenuRaw, _, _ := procCreatePopupMenu.Call()
	hMenu := windows.Handle(hMenuRaw)
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(uintptr(hMenu))

	sWebUI, _ := windows.UTF16PtrFromString("🚀 Открыть панель управления (Web UI)")
	sRefresh, _ := windows.UTF16PtrFromString("🔄 Обновить внешний IP")
	sConfig, _ := windows.UTF16PtrFromString("⚙ Открыть файл настроек (config.yaml)")
	sExit, _ := windows.UTF16PtrFromString("❌ Выход")

	statusText := "💡 Статус: Онлайн"
	if t.opts.GetStatusText != nil {
		statusText = t.opts.GetStatusText()
	}
	sStatus, _ := windows.UTF16PtrFromString(statusText)

	procAppendMenuW.Call(uintptr(hMenu), uintptr(MF_STRING), uintptr(CMD_OPEN_WEBUI), uintptr(unsafe.Pointer(sWebUI)))
	procAppendMenuW.Call(uintptr(hMenu), uintptr(MF_STRING), uintptr(CMD_REFRESH_IP), uintptr(unsafe.Pointer(sRefresh)))
	procAppendMenuW.Call(uintptr(hMenu), uintptr(MF_STRING), uintptr(CMD_OPEN_CONFIG), uintptr(unsafe.Pointer(sConfig)))
	procAppendMenuW.Call(uintptr(hMenu), uintptr(MF_SEPARATOR), 0, 0)
	procAppendMenuW.Call(uintptr(hMenu), uintptr(MF_STRING|MF_DISABLED|MF_GRAYED), uintptr(CMD_STATUS_INFO), uintptr(unsafe.Pointer(sStatus)))
	procAppendMenuW.Call(uintptr(hMenu), uintptr(MF_SEPARATOR), 0, 0)
	procAppendMenuW.Call(uintptr(hMenu), uintptr(MF_STRING), uintptr(CMD_EXIT), uintptr(unsafe.Pointer(sExit)))

	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	procSetForegroundWnd.Call(uintptr(t.hwnd))
	procTrackPopupMenu.Call(
		uintptr(hMenu),
		uintptr(TPM_LEFTALIGN|TPM_BOTTOMALIGN),
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		uintptr(t.hwnd),
		0,
	)
}

func (t *TrayApp) handleCommand(cmdID uint32) {
	switch cmdID {
	case CMD_OPEN_WEBUI:
		t.openWebUI()
	case CMD_REFRESH_IP:
		if t.opts.OnRefreshIP != nil {
			t.opts.OnRefreshIP()
		}
	case CMD_OPEN_CONFIG:
		cfg := t.opts.ConfigPath
		if cfg == "" {
			cfg = "config.yaml"
		}
		exec.Command("notepad.exe", cfg).Start()
	case CMD_EXIT:
		if t.opts.OnExit != nil {
			t.opts.OnExit()
		}
		t.cancel()
		procDestroyWindow.Call(uintptr(t.hwnd))
	}
}

func (t *TrayApp) openWebUI() {
	port := t.opts.WebUIPort
	if t.opts.GetWebUIPort != nil {
		if p := t.opts.GetWebUIPort(); p > 0 {
			port = p
		}
	}
	url := fmt.Sprintf("http://localhost:%d", port)

	// Launch as a sleek standalone application window (no URL bar, no tabs)
	appCandidates := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}
	for _, p := range appCandidates {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p, fmt.Sprintf("--app=%s", url), "--window-size=1120,780")
			if err := cmd.Start(); err == nil {
				return
			}
		}
	}

	exec.Command("cmd", "/c", "start", url).Start()
}

func (t *TrayApp) ShowNotification(titleStr, msgStr string) {
	title, _ := windows.UTF16FromString(titleStr)
	copy(t.nid.SzInfoTitle[:], title)

	info, _ := windows.UTF16FromString(msgStr)
	copy(t.nid.SzInfo[:], info)
	t.nid.DwInfoFlags = NIIF_INFO
	t.nid.UFlags |= NIF_INFO

	procShell_NotifyIconW.Call(uintptr(NIM_MODIFY), uintptr(unsafe.Pointer(&t.nid)))
}