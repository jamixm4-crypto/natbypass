//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/webui"
)

// Win32 API для системного трея и скрытого окна сообщений
var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modshell32  = windows.NewLazySystemDLL("shell32.dll")

	procRegisterClassExW    = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW     = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW      = moduser32.NewProc("DefWindowProcW")
	procPostQuitMessage     = moduser32.NewProc("PostQuitMessage")
	procGetMessageW         = moduser32.NewProc("GetMessageW")
	procTranslateMessage    = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW    = moduser32.NewProc("DispatchMessageW")
	procShowWindow          = moduser32.NewProc("ShowWindow")
	procSetForegroundWindow = moduser32.NewProc("SetForegroundWindow")
	procCreatePopupMenu     = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW         = moduser32.NewProc("AppendMenuW")
	procTrackPopupMenu      = moduser32.NewProc("TrackPopupMenu")
	procGetCursorPos        = moduser32.NewProc("GetCursorPos")
	procDestroyMenu         = moduser32.NewProc("DestroyMenu")
	procLoadIconW           = moduser32.NewProc("LoadIconW")
	procGetModuleHandleW    = modkernel32.NewProc("GetModuleHandleW")
	procShellNotifyIconW    = modshell32.NewProc("Shell_NotifyIconW")
)

const (
	WM_DESTROY  = 0x0002
	WM_COMMAND  = 0x0111
	WM_USER     = 0x0400
	WM_TRAYICON = WM_USER + 100

	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004
	NIF_INFO    = 0x00000010

	MF_STRING       = 0x00000000
	MF_SEPARATOR    = 0x00000800
	TPM_RIGHTBUTTON = 0x0002

	IDM_TRAY_OPEN    = 1001
	IDM_TRAY_REFRESH = 1002
	IDM_TRAY_EXIT    = 1003
)

type POINT struct {
	X, Y int32
}

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

type NOTIFYICONDATAW struct {
	CbSize            uint32
	HWnd              uintptr
	UID               uint32
	UFlags            uint32
	UCallbackMessage  uint32
	HIcon             uintptr
	SzTip             [128]uint16
	DwState           uint32
	DwStateMask       uint32
	SzInfo            [256]uint16
	UTimeoutOrVersion uint32
	SzInfoTitle       [64]uint16
	DwInfoFlags       uint32
}

var (
	hMsgWnd      uintptr
	configPath   string
	cfg          *config.Config
	registry     *peer.Registry
	sigMgr       *signaling.FallbackManager
	ipDisc       *network.Discoverer
	stunClient   *network.STUNClient
	uiServer     *webui.Server
	myDevID      string
	myPublicIP   string
	mySTUNAddr   string
	webUIPort    int
	engineCtx    context.Context
	engineCancel context.CancelFunc
	browserCmd   *exec.Cmd
	browserMu    sync.Mutex
)

func main() {
	cfgFile := flag.String("config", "config.yaml", "Path to config.yaml")
	portFlag := flag.Int("port", 0, "Web UI Port override")
	flag.Parse()
	configPath = *cfgFile

	// 1. Загрузка конфигурации
	loadedCfg, err := config.Load(configPath)
	if err != nil {
		loadedCfg = &config.Config{
			App: config.AppConfig{
				Name:            "NatBypass",
				LogLevel:        "info",
				PublishInterval: 60,
			},
			WebUI: config.WebUIConfig{
				Enabled: true,
				Port:    8080,
			},
			Network: config.NetworkConfig{
				UpnpEnabled: true,
				StunServers: []string{
					"stun.l.google.com:19302",
					"stun1.l.google.com:19302",
					"stun.cloudflare.com:3478",
				},
				IPApis: []string{
					"https://api.ipify.org",
					"https://ifconfig.me/ip",
					"https://icanhazip.com",
				},
			},
			WireGuard: config.WireGuardConfig{
				Enabled:    true,
				Interface:  "wg0",
				ListenPort: 51820,
				MTU:        1420,
				AWG: config.AWGConfig{
					Enabled: true,
					Jc:      4,
					Jmin:    40,
					Jmax:    70,
					S1:      48,
					S2:      32,
					H1:      1428571428,
					H2:      2147483647,
					H3:      857142857,
					H4:      1122334455,
				},
			},
		}
	}
	cfg = loadedCfg

	webUIPort = cfg.WebUI.Port
	if *portFlag > 0 {
		webUIPort = *portFlag
	}
	if webUIPort <= 0 {
		webUIPort = 8080
	}

	// 2. Инициализация фонового окна сообщений Win32 для трея
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	className, _ := windows.UTF16PtrFromString("NatBypassTrayMsgWindowClass")

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		LpfnWndProc:   windows.NewCallback(trayWndProc),
		HInstance:     hInstance,
		LpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hMsgWnd, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		0,
		0,
		0, 0, 0, 0,
		0, 0, hInstance, 0,
	)

	// 3. Добавление иконки в системный трей
	addTrayIcon()

	// 4. Запуск ядра NatBypass в фоне
	startEngine()

	// 5. Открытие полноценного нативного App-окна через Edge / Chrome
	time.Sleep(300 * time.Millisecond)
	openAppWindow()

	// 6. Цикл сообщений Windows
	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 || int32(ret) == -1 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	removeTrayIcon()
}

func trayWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_TRAYICON:
		if lParam == 0x0203 { // WM_LBUTTONDBLCLK
			openAppWindow()
		} else if lParam == 0x0205 { // WM_RBUTTONUP
			showTrayMenu()
		}
		return 0

	case WM_COMMAND:
		id := LOWORD(wParam)
		switch id {
		case IDM_TRAY_OPEN:
			openAppWindow()
		case IDM_TRAY_REFRESH:
			if ipDisc != nil {
				go func() {
					if ip, err := ipDisc.GetPublicIP(context.Background()); err == nil {
						myPublicIP = ip.String()
						showBalloon("Внешний IP обновлен", "Новый IP: "+myPublicIP)
					}
				}()
			}
		case IDM_TRAY_EXIT:
			stopEngine()
			removeTrayIcon()
			os.Exit(0)
		}
		return 0

	case WM_DESTROY:
		stopEngine()
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func startEngine() {
	ctx, cancel := context.WithCancel(context.Background())
	engineCtx = ctx
	engineCancel = cancel

	pubKey, _, _ := crypto.GenerateKeyPair()
	myDevID = "Win-" + crypto.KeyToHex(pubKey)[:8]
	if hn, err := os.Hostname(); err == nil && hn != "" {
		myDevID = hn
	}

	registry = peer.NewRegistry()
	registry.StartMonitor(ctx, 2*time.Minute)

	// Сигнальные каналы
	var channels []signaling.SignalingChannel
	channels = append(channels, signaling.NewMQTTChannel(
		"tcp://mqtt.eclipseprojects.io:1883",
		"natbypass/public/peers",
		myDevID, "", "",
	))
	sigMgr = signaling.NewFallbackManager(channels)

	// IP и STUN
	ipDisc = network.NewDiscoverer(cfg.Network.IPApis, 5*time.Second)
	stunClient = network.NewSTUNClient(cfg.Network.StunServers)

	go func() {
		if ip, err := ipDisc.GetPublicIPCached(ctx, 5*time.Minute); err == nil {
			myPublicIP = ip.String()
		}
		if extIP, port, err := stunClient.GetMappedAddress(ctx); err == nil {
			mySTUNAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
		}
	}()

	// Запуск Web UI
	uiServer = webui.NewServer(webUIPort, cfg.WebUI.Username, cfg.WebUI.Password, registry, sigMgr)
	uiServer.SetAppState(myDevID, "Определяется...", "Определяется...")
	uiServer.SetDeviceName(myDevID)
	go func() {
		_ = uiServer.Start(ctx)
	}()
}

func stopEngine() {
	if engineCancel != nil {
		engineCancel()
	}
}

// openAppWindow открывает интерфейс NatBypass в виде отдельного нативного окна приложения
func openAppWindow() {
	browserMu.Lock()
	defer browserMu.Unlock()

	targetURL := fmt.Sprintf("http://localhost:%d", webUIPort)

	// Папка профиля приложения (чтобы не пересекаться с обычным браузером)
	tempDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "NatBypass", "AppProfile")
	_ = os.MkdirAll(tempDir, 0755)

	// 1. Проверяем Microsoft Edge (стандартный в Windows 10/11)
	edgePaths := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft\Edge\Application\msedge.exe`),
	}

	for _, p := range edgePaths {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p,
				fmt.Sprintf("--app=%s", targetURL),
				"--window-size=1120,800",
				fmt.Sprintf("--user-data-dir=%s", tempDir),
				"--no-first-run",
				"--no-default-browser-check",
			)
			if err := cmd.Start(); err == nil {
				browserCmd = cmd
				return
			}
		}
	}

	// 2. Проверяем Google Chrome
	chromePaths := []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\Application\chrome.exe`),
	}
	for _, p := range chromePaths {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p,
				fmt.Sprintf("--app=%s", targetURL),
				"--window-size=1120,800",
				fmt.Sprintf("--user-data-dir=%s", tempDir),
			)
			if err := cmd.Start(); err == nil {
				browserCmd = cmd
				return
			}
		}
	}

	// 3. Fallback: системный браузер по умолчанию
	exec.Command("cmd", "/c", "start", targetURL).Start()
}

func addTrayIcon() {
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hMsgWnd
	nid.UID = 1
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.UCallbackMessage = WM_TRAYICON
	nid.HIcon, _, _ = procLoadIconW.Call(0, 32512) // IDI_APPLICATION
	tipPtr, _ := windows.UTF16FromString("NatBypass — P2P Mesh Сеть & AmneziaWG 2.0")
	copy(nid.SzTip[:], tipPtr)

	procShellNotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
}

func removeTrayIcon() {
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hMsgWnd
	nid.UID = 1
	procShellNotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
}

func showBalloon(title, msg string) {
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hMsgWnd
	nid.UID = 1
	nid.UFlags = NIF_INFO
	tPtr, _ := windows.UTF16FromString(title)
	mPtr, _ := windows.UTF16FromString(msg)
	copy(nid.SzInfoTitle[:], tPtr)
	copy(nid.SzInfo[:], mPtr)
	nid.DwInfoFlags = 1 // NIIF_INFO

	procShellNotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
}

func showTrayMenu() {
	hMenu, _, _ := procCreatePopupMenu.Call()
	m1, _ := windows.UTF16PtrFromString("🖥 Открыть панель управления")
	m2, _ := windows.UTF16PtrFromString("⚡ Обновить внешний IP")
	m3, _ := windows.UTF16PtrFromString("❌ Завершить работу")

	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_OPEN, uintptr(unsafe.Pointer(m1)))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_REFRESH, uintptr(unsafe.Pointer(m2)))
	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_EXIT, uintptr(unsafe.Pointer(m3)))

	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hMsgWnd)
	procTrackPopupMenu.Call(hMenu, TPM_RIGHTBUTTON, uintptr(pt.X), uintptr(pt.Y), 0, hMsgWnd, 0)
	procDestroyMenu.Call(hMenu)
}

func LOWORD(l uintptr) uint16 {
	return uint16(l & 0xFFFF)
}
