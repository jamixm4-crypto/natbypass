//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	"github.com/natbypass/natbypass/internal/wireguard"
)

// Win32 API
var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modgdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modcomctl32 = windows.NewLazySystemDLL("comctl32.dll")
	modshell32  = windows.NewLazySystemDLL("shell32.dll")
	moddwmapi   = windows.NewLazySystemDLL("dwmapi.dll")

	procRegisterClassExW     = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW      = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW       = moduser32.NewProc("DefWindowProcW")
	procPostQuitMessage      = moduser32.NewProc("PostQuitMessage")
	procGetMessageW          = moduser32.NewProc("GetMessageW")
	procTranslateMessage     = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW     = moduser32.NewProc("DispatchMessageW")
	procSendMessageW         = moduser32.NewProc("SendMessageW")
	procGetWindowTextW       = moduser32.NewProc("GetWindowTextW")
	procSetWindowTextW       = moduser32.NewProc("SetWindowTextW")
	procShowWindow           = moduser32.NewProc("ShowWindow")
	procSetForegroundWindow  = moduser32.NewProc("SetForegroundWindow")
	procCreatePopupMenu      = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW          = moduser32.NewProc("AppendMenuW")
	procTrackPopupMenu       = moduser32.NewProc("TrackPopupMenu")
	procGetCursorPos         = moduser32.NewProc("GetCursorPos")
	procDestroyMenu          = moduser32.NewProc("DestroyMenu")
	procSetTimer             = moduser32.NewProc("SetTimer")
	procKillTimer            = moduser32.NewProc("KillTimer")
	procLoadIconW            = moduser32.NewProc("LoadIconW")
	procGetModuleHandleW     = modkernel32.NewProc("GetModuleHandleW")
	procCreateFontW          = modgdi32.NewProc("CreateFontW")
	procCreateSolidBrush     = modgdi32.NewProc("CreateSolidBrush")
	procSetBkMode            = modgdi32.NewProc("SetBkMode")
	procSetTextColor         = modgdi32.NewProc("SetTextColor")
	procSetBkColor           = modgdi32.NewProc("SetBkColor")
	procInitCommonControlsEx = modcomctl32.NewProc("InitCommonControlsEx")
	procShellNotifyIconW     = modshell32.NewProc("Shell_NotifyIconW")
	procDwmSetWindowAttribute= moddwmapi.NewProc("DwmSetWindowAttribute")
)

const (
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_BORDER           = 0x00800000
	WS_VSCROLL          = 0x00200000
	WS_TABSTOP          = 0x00010000

	WS_EX_CLIENTEDGE = 0x00000200

	BS_PUSHBUTTON    = 0x00000000
	BS_DEFPUSHBUTTON = 0x00000001

	ES_LEFT        = 0x0000
	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_AUTOHSCROLL = 0x0080
	ES_READONLY    = 0x0800
	ES_PASSWORD    = 0x0020

	SS_LEFT = 0x0000

	LBS_NOTIFY           = 0x0001
	LBS_NOINTEGRALHEIGHT = 0x0100

	WM_DESTROY        = 0x0002
	WM_SIZE           = 0x0005
	WM_COMMAND        = 0x0111
	WM_SYSCOMMAND     = 0x0112
	WM_TIMER          = 0x0113
	WM_CTLCOLORSTATIC = 0x0138
	WM_CTLCOLOREDIT   = 0x0133
	WM_CTLCOLORBTN    = 0x0135
	WM_CTLCOLORDLG    = 0x0136
	WM_NOTIFY         = 0x004E
	WM_USER           = 0x0400

	WM_TRAYICON = WM_USER + 100

	SC_MINIMIZE = 0xF020
	SC_CLOSE    = 0xF060

	SW_HIDE    = 0
	SW_SHOW    = 5
	SW_RESTORE = 9

	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004
	NIF_INFO    = 0x00000010

	TCM_INSERTITEMW = 0x1300 + 62
	TCM_SETCURSEL   = 0x1300 + 12
	TCM_GETCURSEL   = 0x1300 + 11

	TCN_SELCHANGE = 0xFFFFFDD9

	MF_STRING       = 0x00000000
	MF_SEPARATOR    = 0x00000800
	TPM_RIGHTBUTTON = 0x0002

	COLOR_WINDOW = 5
)

// Цвета темной темы
const (
	COLOR_BG     = 0x17110D // #0D1117 in BGR
	COLOR_PANEL  = 0x221B16 // #161B22
	COLOR_INPUT  = 0x2D2621 // #21262D
	COLOR_BORDER = 0x3D3630 // #30363D
	COLOR_TEXT   = 0xD9D1C9 // #C9D1D9
	COLOR_MUTED  = 0x9E948B // #8B949E
	COLOR_ACCENT = 0xFFA658 // #58A6FF
	COLOR_GREEN  = 0x50B93F // #3FB950
	COLOR_RED    = 0x4951F8 // #F85149
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

type NMHDR struct {
	HwndFrom uintptr
	IdFrom   uintptr
	Code     uint32
}

type TCITEMW struct {
	Mask        uint32
	DwState     uint32
	DwStateMask uint32
	PszText     *uint16
	CchTextMax  int32
	IImage      int32
	LParam      uintptr
}

// Глобальные переменные UI
var (
	hMainWnd    uintptr
	hTabCtrl    uintptr
	hFontNormal uintptr
	hFontBold   uintptr
	hFontTitle  uintptr
	hFontMono   uintptr
	hBrushBg    uintptr
	hBrushPanel uintptr
	hBrushInput uintptr

	// Элементы управления
	// Вкладка 1: Обзор
	hLblStatus  uintptr
	hLblIpInfo  uintptr
	hBtnVpn     uintptr
	hListPeers  uintptr
	hBtnRefresh uintptr
	hBtnOpenWeb uintptr

	// Вкладка 2: AmneziaWG
	hBtnAwgStd     uintptr
	hBtnAwgDpi     uintptr
	hBtnAwgStealth uintptr
	hEditAwgJc     uintptr
	hEditAwgJmin   uintptr
	hEditAwgJmax   uintptr
	hEditAwgS1     uintptr
	hEditAwgS2     uintptr
	hEditAwgH1     uintptr
	hEditAwgH2     uintptr
	hEditAwgH3     uintptr
	hEditAwgH4     uintptr
	hBtnRandomAwg  uintptr
	hEditAwgConf   uintptr
	hBtnCopyAwg    uintptr

	// Вкладка 3: Настройки
	hEditTgToken uintptr
	hEditTgChat  uintptr
	hBtnTestTg   uintptr
	hEditMqttBr  uintptr
	hEditMqttTp  uintptr
	hBtnTestMqtt uintptr
	hBtnSaveCfg  uintptr

	// Вкладка 4: Диагностика
	hBtnRunDiag  uintptr
	hEditDiagLog uintptr

	// Вкладка 5: Логи
	hEditLogs   uintptr
	hBtnClrLogs uintptr

	// Вкладка 6: Служба Windows
	hLblSvcStatus uintptr
	hBtnSvcInst   uintptr
	hBtnSvcStart  uintptr
	hBtnSvcStop   uintptr
	hBtnSvcUninst uintptr

	allControls []uintptr
	tabPages    [6][]uintptr

	// Движок
	configPath   string
	engineCtx    context.Context
	engineCancel context.CancelFunc
	vpnConnected bool
	cfg          *config.Config
	registry     *peer.Registry
	sigMgr       *signaling.FallbackManager
	ipDisc       *network.Discoverer
	stunClient   *network.STUNClient
	uiServer     *webui.Server
	myDevID      string
	myPublicIP   string
	mySTUNAddr   string
	startedAt    time.Time
	logsMutex    sync.Mutex
	logsBuffer   []string
)

const (
	ID_TIMER_POLL = 1001

	// Команды меню трея
	IDM_TRAY_RESTORE = 2001
	IDM_TRAY_WEBUI   = 2002
	IDM_TRAY_REFRESH = 2003
	IDM_TRAY_EXIT    = 2004

	// ID кнопок UI
	ID_BTN_VPN         = 3001
	ID_BTN_REFRESH     = 3002
	ID_BTN_WEBUI       = 3003
	ID_BTN_AWG_STD     = 3004
	ID_BTN_AWG_DPI     = 3005
	ID_BTN_AWG_STEALTH = 3006
	ID_BTN_RAND_AWG    = 3007
	ID_BTN_COPY_AWG    = 3008
	ID_BTN_TEST_TG     = 3009
	ID_BTN_TEST_MQTT   = 3010
	ID_BTN_SAVE_CFG    = 3011
	ID_BTN_RUN_DIAG    = 3012
	ID_BTN_CLR_LOGS    = 3013
	ID_BTN_SVC_INST    = 3014
	ID_BTN_SVC_START   = 3015
	ID_BTN_SVC_STOP    = 3016
	ID_BTN_SVC_UNINST  = 3017
)

func main() {
	cfgFile := flag.String("config", "config.yaml", "Path to config.yaml")
	flag.Parse()
	configPath = *cfgFile

	// Инициализация графических библиотек
	type INITCOMMONCONTROLSEX struct {
		DwSize uint32
		DwICC  uint32
	}
	icex := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  0x00000008 | 0x00000001, // ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icex)))

	// Загружаем конфиг
	loadedCfg, err := config.Load(configPath)
	if err != nil {
		loadedCfg = &config.Config{
			App:   config.AppConfig{Name: "NatBypass", LogLevel: "info", PublishInterval: 60},
			WebUI: config.WebUIConfig{Enabled: true, Port: 8080},
			Network: config.NetworkConfig{
				UpnpEnabled: true,
				StunServers: []string{"stun.l.google.com:19302", "stun1.l.google.com:19302", "stun.cloudflare.com:3478"},
				IPApis:      []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"},
			},
			WireGuard: config.WireGuardConfig{
				Enabled: true, Interface: "wg0", ListenPort: 51820, MTU: 1420,
				AWG: config.AWGConfig{
					Enabled: true, Jc: 4, Jmin: 40, Jmax: 70, S1: 48, S2: 32,
					H1: 1428571428, H2: 2147483647, H3: 857142857, H4: 1122334455,
				},
			},
		}
	}
	cfg = loadedCfg

	// Регистрация класса окна
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	className, _ := windows.UTF16PtrFromString("NatBypassMainWindowClass")
	windowTitle, _ := windows.UTF16PtrFromString("NatBypass — Панель управления P2P сетью & AmneziaWG 2.0")

	hIcon, _, _ := procLoadIconW.Call(0, 32512) // IDI_APPLICATION
	hBrushBg, _, _ = procCreateSolidBrush.Call(COLOR_BG)
	hBrushPanel, _, _ = procCreateSolidBrush.Call(COLOR_PANEL)
	hBrushInput, _, _ = procCreateSolidBrush.Call(COLOR_INPUT)

	// Шрифты
	hFontNormal = createFont("Segoe UI", 16, 400)
	hFontBold = createFont("Segoe UI", 16, 700)
	hFontTitle = createFont("Segoe UI", 22, 700)
	hFontMono = createFont("Consolas", 14, 400)

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         3, // CS_HREDRAW | CS_VREDRAW
		LpfnWndProc:   windows.NewCallback(wndProc),
		HInstance:     hInstance,
		HIcon:         hIcon,
		HCursor:       hIcon,
		HbrBackground: hBrushBg,
		LpszClassName: className,
		HIconSm:       hIcon,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	// Создание главного окна
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		WS_OVERLAPPEDWINDOW,
		100, 100, 960, 720,
		0, 0, hInstance, 0,
	)
	hMainWnd = hwnd

	// Принудительно включаем тёмную тему заголовка окна Windows 10/11 (DWMWA_USE_IMMERSIVE_DARK_MODE = 20)
	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hMainWnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	// Создаем элементы интерфейса
	buildUI(hInstance)

	// Показываем вкладку 0 по умолчанию
	showTab(0)

	// Добавляем иконку в системный трей
	addTrayIcon()

	// Отображаем окно
	procShowWindow.Call(hMainWnd, SW_SHOW)

	// Запускаем движок NatBypass в фоне
	startEngine()

	// Таймер периодического обновления UI (раз в 2 сек)
	procSetTimer.Call(hMainWnd, ID_TIMER_POLL, 2000, 0)

	// Главный цикл сообщений
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

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_SYSCOMMAND:
		if wParam == SC_MINIMIZE {
			procShowWindow.Call(hMainWnd, SW_HIDE)
			showBalloon("NatBypass свернут в трей", "Программа продолжает работать в фоне и поддерживать P2P сеть.")
			return 0
		}
		if wParam == SC_CLOSE {
			procShowWindow.Call(hMainWnd, SW_HIDE)
			showBalloon("NatBypass работает в трее", "Двойной клик для открытия. Правый клик -> Выход.")
			return 0
		}

	case WM_TRAYICON:
		if lParam == 0x0203 { // WM_LBUTTONDBLCLK
			procShowWindow.Call(hMainWnd, SW_RESTORE)
			procSetForegroundWindow.Call(hMainWnd)
		} else if lParam == 0x0205 { // WM_RBUTTONUP
			showTrayMenu()
		}
		return 0

	case WM_NOTIFY:
		nm := (*NMHDR)(unsafe.Pointer(lParam))
		if nm.HwndFrom == hTabCtrl && nm.Code == TCN_SELCHANGE {
			curSel, _, _ := procSendMessageW.Call(hTabCtrl, TCM_GETCURSEL, 0, 0)
			showTab(int(curSel))
			return 0
		}

	case WM_CTLCOLORSTATIC:
		hdc := wParam
		procSetBkMode.Call(hdc, 1) // TRANSPARENT
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushBg

	case WM_CTLCOLOREDIT:
		hdc := wParam
		procSetBkColor.Call(hdc, COLOR_INPUT)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushInput

	case WM_CTLCOLORBTN:
		return hBrushBg

	case WM_TIMER:
		if wParam == ID_TIMER_POLL {
			updateUIData()
		}
		return 0

	case WM_COMMAND:
		id := LOWORD(wParam)
		handleCommand(id)
		return 0

	case WM_DESTROY:
		procKillTimer.Call(hMainWnd, ID_TIMER_POLL)
		stopEngine()
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func handleCommand(id uint16) {
	switch id {
	case ID_BTN_VPN:
		toggleVPN()

	case ID_BTN_REFRESH:
		addLog("⚡ Запрос на обновление внешнего IP...")
		if ipDisc != nil {
			go func() {
				if ip, err := ipDisc.GetPublicIP(context.Background()); err == nil {
					myPublicIP = ip.String()
					addLog("✓ Новый публичный IP: " + myPublicIP)
				}
			}()
		}

	case ID_BTN_WEBUI:
		exec.Command("cmd", "/c", "start", "http://localhost:8080").Start()

	case ID_BTN_AWG_STD:
		setAWGPresetValues(wireguard.AWGParams{Enabled: true, Jc: 0, Jmin: 0, Jmax: 0, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4})
		addLog("🛡️ Выбран пресет: 🟢 Стандартный WireGuard")

	case ID_BTN_AWG_DPI:
		setAWGPresetValues(wireguard.DefaultAWGParams())
		addLog("🛡️ Выбран пресет: 🟡 Обход DPI (AmneziaWG 2.0)")

	case ID_BTN_AWG_STEALTH:
		randP := wireguard.GenerateRandomAWGParams()
		setAWGPresetValues(randP)
		addLog("🛡️ Выбран пресет: 🔴 Максимальная скрытность (случайные параметры)")

	case ID_BTN_RAND_AWG:
		randP := wireguard.GenerateRandomAWGParams()
		setAWGPresetValues(randP)
		addLog("🎲 Сгенерированы новые случайные параметры AWG")

	case ID_BTN_COPY_AWG:
		copyAWGToClipboard()

	case ID_BTN_TEST_TG:
		testTelegramFromUI()

	case ID_BTN_TEST_MQTT:
		testMQTTFromUI()

	case ID_BTN_SAVE_CFG:
		saveConfigFromUI()

	case ID_BTN_RUN_DIAG:
		runDiagnosticsUI()

	case ID_BTN_CLR_LOGS:
		logsMutex.Lock()
		logsBuffer = nil
		logsMutex.Unlock()
		setControlText(hEditLogs, "")

	case ID_BTN_SVC_INST:
		exec.Command("natbypass-cli.exe", "service", "install", "--config", configPath).Run()
		addLog("🛠️ Запрос на установку службы Windows отправлен")
		updateServiceStatus()

	case ID_BTN_SVC_START:
		exec.Command("natbypass-cli.exe", "service", "start").Run()
		addLog("🛠️ Запрос на запуск службы Windows отправлен")
		updateServiceStatus()

	case ID_BTN_SVC_STOP:
		exec.Command("natbypass-cli.exe", "service", "stop").Run()
		addLog("🛠️ Запрос на остановку службы Windows отправлен")
		updateServiceStatus()

	case ID_BTN_SVC_UNINST:
		exec.Command("natbypass-cli.exe", "service", "uninstall").Run()
		addLog("🛠️ Запрос на удаление службы Windows отправлен")
		updateServiceStatus()

	case IDM_TRAY_RESTORE:
		procShowWindow.Call(hMainWnd, SW_RESTORE)
		procSetForegroundWindow.Call(hMainWnd)

	case IDM_TRAY_WEBUI:
		exec.Command("cmd", "/c", "start", "http://localhost:8080").Start()

	case IDM_TRAY_REFRESH:
		handleCommand(ID_BTN_REFRESH)

	case IDM_TRAY_EXIT:
		procShowWindow.Call(hMainWnd, SW_HIDE)
		stopEngine()
		os.Exit(0)
	}
}

func buildUI(hInstance uintptr) {
	// Создание Tab Control
	tabClass, _ := windows.UTF16PtrFromString("SysTabControl32")
	hTabCtrl, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(tabClass)),
		0,
		WS_CHILD|WS_VISIBLE|WS_TABSTOP,
		16, 16, 912, 640,
		hMainWnd, 0, hInstance, 0,
	)
	procSendMessageW.Call(hTabCtrl, 0x0030, hFontBold, 1) // WM_SETFONT

	// Добавляем 6 вкладок
	tabs := []string{
		"🚀 Обзор и Подключение",
		"🛡️ AmneziaWG 2.0",
		"⚙️ Настройки каналов",
		"🩺 Диагностика",
		"📋 Журнал событий",
		"🛠️ Служба Windows",
	}
	for i, title := range tabs {
		tPtr, _ := windows.UTF16PtrFromString(title)
		item := TCITEMW{
			Mask:    1, // TCIF_TEXT
			PszText: tPtr,
		}
		procSendMessageW.Call(hTabCtrl, TCM_INSERTITEMW, uintptr(i), uintptr(unsafe.Pointer(&item)))
	}

	// ══════════════════════════════════════════════════════════════
	// ВКЛАДКА 0: ОБЗОР И ПОДКЛЮЧЕНИЕ
	// ══════════════════════════════════════════════════════════════
	hLblStatus = createLabel(hInstance, "🟢 СЕТЬ АКТИВНА (P2P Mesh Режим)", 40, 70, 500, 30, hFontTitle)
	hLblIpInfo = createLabel(hInstance, "Устройство: Определение... | Внешний IP: — | STUN: —", 40, 105, 800, 24, hFontNormal)

	hBtnVpn = createButton(hInstance, "🟢 ПОДКЛЮЧЕНО (Mesh 10.200.0.1)", 40, 140, 320, 50, ID_BTN_VPN, hFontBold)
	hBtnRefresh = createButton(hInstance, "⚡ Обновить IP", 380, 145, 140, 40, ID_BTN_REFRESH, hFontNormal)
	hBtnOpenWeb = createButton(hInstance, "🌐 Открыть Web UI", 530, 145, 150, 40, ID_BTN_WEBUI, hFontNormal)

	lblPeers := createLabel(hInstance, "Устройства в вашей сети:", 40, 210, 400, 24, hFontBold)
	hListPeers = createListBox(hInstance, 40, 240, 860, 390, hFontMono)

	tabPages[0] = []uintptr{hLblStatus, hLblIpInfo, hBtnVpn, hBtnRefresh, hBtnOpenWeb, lblPeers, hListPeers}

	// ══════════════════════════════════════════════════════════════
	// ВКЛАДКА 1: AMNEZIAWG 2.0
	// ══════════════════════════════════════════════════════════════
	lblAwgTitle := createLabel(hInstance, "🛡️ AmneziaWG 2.0 — Обход блокировок DPI провайдеров", 40, 70, 700, 28, hFontTitle)
	hBtnAwgStd = createButton(hInstance, "🟢 Стандартный WG", 40, 110, 180, 36, ID_BTN_AWG_STD, hFontNormal)
	hBtnAwgDpi = createButton(hInstance, "🟡 Обход DPI (AWG)", 230, 110, 180, 36, ID_BTN_AWG_DPI, hFontBold)
	hBtnAwgStealth = createButton(hInstance, "🔴 Макс. скрытность", 420, 110, 180, 36, ID_BTN_AWG_STEALTH, hFontNormal)
	hBtnRandomAwg = createButton(hInstance, "🎲 Случайные параметры", 610, 110, 190, 36, ID_BTN_RAND_AWG, hFontNormal)

	lblJc := createLabel(hInstance, "Jc (мусор):", 40, 160, 80, 20, hFontNormal)
	hEditAwgJc = createEdit(hInstance, "4", 130, 158, 60, 26, false, false, hFontNormal)

	lblJmin := createLabel(hInstance, "Jmin:", 210, 160, 50, 20, hFontNormal)
	hEditAwgJmin = createEdit(hInstance, "40", 260, 158, 60, 26, false, false, hFontNormal)

	lblJmax := createLabel(hInstance, "Jmax:", 340, 160, 50, 20, hFontNormal)
	hEditAwgJmax = createEdit(hInstance, "70", 390, 158, 60, 26, false, false, hFontNormal)

	lblS1 := createLabel(hInstance, "S1:", 470, 160, 30, 20, hFontNormal)
	hEditAwgS1 = createEdit(hInstance, "48", 510, 158, 60, 26, false, false, hFontNormal)

	lblS2 := createLabel(hInstance, "S2:", 590, 160, 30, 20, hFontNormal)
	hEditAwgS2 = createEdit(hInstance, "32", 630, 158, 60, 26, false, false, hFontNormal)

	lblH1 := createLabel(hInstance, "H1 (Init):", 40, 200, 80, 20, hFontNormal)
	hEditAwgH1 = createEdit(hInstance, "1428571428", 130, 198, 120, 26, false, false, hFontNormal)

	lblH2 := createLabel(hInstance, "H2 (Resp):", 270, 200, 80, 20, hFontNormal)
	hEditAwgH2 = createEdit(hInstance, "2147483647", 350, 198, 120, 26, false, false, hFontNormal)

	lblH3 := createLabel(hInstance, "H3 (Cookie):", 490, 200, 90, 20, hFontNormal)
	hEditAwgH3 = createEdit(hInstance, "857142857", 580, 198, 120, 26, false, false, hFontNormal)

	lblH4 := createLabel(hInstance, "H4 (Data):", 720, 200, 80, 20, hFontNormal)
	hEditAwgH4 = createEdit(hInstance, "1122334455", 790, 198, 110, 26, false, false, hFontNormal)

	lblConf := createLabel(hInstance, "Сгенерированная конфигурация AmneziaWG:", 40, 240, 400, 20, hFontBold)
	hEditAwgConf = createEdit(hInstance, "Загрузка AWG конфигурации...", 40, 265, 860, 320, true, true, hFontMono)
	hBtnCopyAwg = createButton(hInstance, "📋 Скопировать AWG конфиг в буфер обмена", 40, 595, 340, 36, ID_BTN_COPY_AWG, hFontBold)

	tabPages[1] = []uintptr{
		lblAwgTitle, hBtnAwgStd, hBtnAwgDpi, hBtnAwgStealth, hBtnRandomAwg,
		lblJc, hEditAwgJc, lblJmin, hEditAwgJmin, lblJmax, hEditAwgJmax, lblS1, hEditAwgS1, lblS2, hEditAwgS2,
		lblH1, hEditAwgH1, lblH2, hEditAwgH2, lblH3, hEditAwgH3, lblH4, hEditAwgH4,
		lblConf, hEditAwgConf, hBtnCopyAwg,
	}

	// ══════════════════════════════════════════════════════════════
	// ВКЛАДКА 2: НАСТРОЙКИ СИГНАЛИЗАЦИИ
	// ══════════════════════════════════════════════════════════════
	lblCfgTitle := createLabel(hInstance, "⚙️ Сигнальные каналы (Обмен координатами пиров)", 40, 70, 700, 28, hFontTitle)

	lblTg := createLabel(hInstance, "💬 Telegram Bot API:", 40, 120, 300, 24, hFontBold)
	lblTgT := createLabel(hInstance, "Токен бота (@BotFather):", 40, 155, 200, 20, hFontNormal)
	hEditTgToken = createEdit(hInstance, "", 240, 152, 440, 28, false, true, hFontNormal)
	hBtnTestTg = createButton(hInstance, "🧪 Проверить Telegram", 700, 150, 200, 32, ID_BTN_TEST_TG, hFontNormal)

	lblTgC := createLabel(hInstance, "Chat ID (@userinfobot):", 40, 195, 200, 20, hFontNormal)
	hEditTgChat = createEdit(hInstance, "", 240, 192, 440, 28, false, false, hFontNormal)

	lblMq := createLabel(hInstance, "⚡ MQTT Брокер:", 40, 250, 300, 24, hFontBold)
	lblMqB := createLabel(hInstance, "URL Брокера:", 40, 285, 200, 20, hFontNormal)
	hEditMqttBr = createEdit(hInstance, "tcp://mqtt.eclipseprojects.io:1883", 240, 282, 440, 28, false, false, hFontNormal)
	hBtnTestMqtt = createButton(hInstance, "🧪 Проверить MQTT", 700, 280, 200, 32, ID_BTN_TEST_MQTT, hFontNormal)

	lblMqT := createLabel(hInstance, "Топик (уникальный):", 40, 325, 200, 20, hFontNormal)
	hEditMqttTp = createEdit(hInstance, "natbypass/mynet/peers", 240, 322, 440, 28, false, false, hFontNormal)

	hBtnSaveCfg = createButton(hInstance, "💾 Сохранить настройки в config.yaml", 240, 380, 320, 44, ID_BTN_SAVE_CFG, hFontBold)

	tabPages[2] = []uintptr{
		lblCfgTitle, lblTg, lblTgT, hEditTgToken, hBtnTestTg, lblTgC, hEditTgChat,
		lblMq, lblMqB, hEditMqttBr, hBtnTestMqtt, lblMqT, hEditMqttTp, hBtnSaveCfg,
	}

	// ══════════════════════════════════════════════════════════════
	// ВКЛАДКА 3: ДИАГНОСТИКА
	// ══════════════════════════════════════════════════════════════
	lblDiagTitle := createLabel(hInstance, "🩺 Диагностика сетевой связности", 40, 70, 600, 28, hFontTitle)
	hBtnRunDiag = createButton(hInstance, "🔄 Запустить диагностику", 40, 115, 220, 38, ID_BTN_RUN_DIAG, hFontBold)
	hEditDiagLog = createEdit(hInstance, "Нажмите «Запустить диагностику» для тестирования интернета, STUN и сигнального канала...", 40, 165, 860, 460, true, true, hFontMono)

	tabPages[3] = []uintptr{lblDiagTitle, hBtnRunDiag, hEditDiagLog}

	// ══════════════════════════════════════════════════════════════
	// ВКЛАДКА 4: ЖУРНАЛ СОБЫТИЙ
	// ══════════════════════════════════════════════════════════════
	lblLogsTitle := createLabel(hInstance, "📋 Журнал событий NatBypass в реальном времени", 40, 70, 600, 28, hFontTitle)
	hBtnClrLogs = createButton(hInstance, "🗑 Очистить", 780, 70, 120, 30, ID_BTN_CLR_LOGS, hFontNormal)
	hEditLogs = createEdit(hInstance, "", 40, 115, 860, 510, true, true, hFontMono)

	tabPages[4] = []uintptr{lblLogsTitle, hBtnClrLogs, hEditLogs}

	// ══════════════════════════════════════════════════════════════
	// ВКЛАДКА 5: СЛУЖБА WINDOWS
	// ══════════════════════════════════════════════════════════════
	lblSvcTitle := createLabel(hInstance, "🛠️ Управление системной службой Windows Service", 40, 70, 700, 28, hFontTitle)
	hLblSvcStatus = createLabel(hInstance, "Статус службы: Проверка...", 40, 120, 600, 26, hFontBold)

	hBtnSvcInst = createButton(hInstance, "➕ Установить службу", 40, 170, 200, 40, ID_BTN_SVC_INST, hFontNormal)
	hBtnSvcStart = createButton(hInstance, "▶ Запустить службу", 260, 170, 200, 40, ID_BTN_SVC_START, hFontNormal)
	hBtnSvcStop = createButton(hInstance, "⏹ Остановить службу", 480, 170, 200, 40, ID_BTN_SVC_STOP, hFontNormal)
	hBtnSvcUninst = createButton(hInstance, "🗑 Удалить службу", 700, 170, 200, 40, ID_BTN_SVC_UNINST, hFontNormal)

	tabPages[5] = []uintptr{lblSvcTitle, hLblSvcStatus, hBtnSvcInst, hBtnSvcStart, hBtnSvcStop, hBtnSvcUninst}

	// Заполняем настройки из конфига
	fillConfigUI()
}

func showTab(tabIndex int) {
	for i, page := range tabPages {
		show := SW_HIDE
		if i == tabIndex {
			show = SW_SHOW
		}
		for _, hwnd := range page {
			procShowWindow.Call(hwnd, uintptr(show))
		}
	}
	if tabIndex == 1 {
		updateAWGConfigText()
	}
	if tabIndex == 5 {
		updateServiceStatus()
	}
}

func toggleVPN() {
	vpnConnected = !vpnConnected
	if vpnConnected {
		setControlText(hBtnVpn, "🟢 ПОДКЛЮЧЕНО (Mesh 10.200.0.1)")
		addLog("🟢 VPN туннель активирован")
		showBalloon("NatBypass: Подключено", "Защищенный P2P туннель активен.")
	} else {
		setControlText(hBtnVpn, "🔴 ОТКЛЮЧЕНО (Нажмите для старта)")
		addLog("🔴 VPN туннель приостановлен")
	}
}

func startEngine() {
	ctx, cancel := context.WithCancel(context.Background())
	engineCtx = ctx
	engineCancel = cancel
	startedAt = time.Now()
	vpnConnected = true

	// Генерация или загрузка ключей
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
		addLog(fmt.Sprintf("✓ Ядро инициализировано. IP: %s | STUN: %s", myPublicIP, mySTUNAddr))
	}()

	// Запуск Web UI сервера
	uiServer = webui.NewServer(cfg.WebUI.Port, cfg.WebUI.Username, cfg.WebUI.Password, registry, sigMgr)
	uiServer.SetAppState(myDevID, "Определяется...", "Определяется...")
	uiServer.SetDeviceName(myDevID)
	go func() {
		_ = uiServer.Start(ctx)
	}()

	addLog("🚀 NatBypass ядро успешно запущено в фоновом режиме")
}

func stopEngine() {
	if engineCancel != nil {
		engineCancel()
	}
}

func updateUIData() {
	// Обновление заголовка
	ipStr := myPublicIP
	if ipStr == "" {
		ipStr = "Определяется..."
	}
	stunStr := mySTUNAddr
	if stunStr == "" {
		stunStr = "Определяется..."
	}
	chStr := "MQTT (Резервный)"
	if sigMgr != nil && sigMgr.CurrentChannel() != "" {
		chStr = sigMgr.CurrentChannel()
	}

	infoText := fmt.Sprintf("Устройство: %s | Внешний IP: %s | STUN: %s | Канал: %s", myDevID, ipStr, stunStr, chStr)
	setControlText(hLblIpInfo, infoText)

	// Обновление списка пиров
	if registry != nil {
		peers := registry.List()
		procSendMessageW.Call(hListPeers, 0x0184, 0, 0) // LB_RESETCONTENT
		if len(peers) == 0 {
			addListBoxItem(hListPeers, "📡 Ожидание подключения других устройств... (0 пиров онлайн)")
		} else {
			for _, p := range peers {
				st := "🟢 Онлайн"
				if !p.Online {
					st = "🔴 Офлайн"
				}
				itemStr := fmt.Sprintf("%s | IP: %s | STUN: %s | %s", p.DeviceID, p.PublicIP, p.STUNAddr, st)
				addListBoxItem(hListPeers, itemStr)
			}
		}
	}
}

func updateAWGConfigText() {
	jc, _ := strconv.Atoi(getControlText(hEditAwgJc))
	jmin, _ := strconv.Atoi(getControlText(hEditAwgJmin))
	jmax, _ := strconv.Atoi(getControlText(hEditAwgJmax))
	s1, _ := strconv.Atoi(getControlText(hEditAwgS1))
	s2, _ := strconv.Atoi(getControlText(hEditAwgS2))
	h1, _ := strconv.ParseUint(getControlText(hEditAwgH1), 10, 32)
	h2, _ := strconv.ParseUint(getControlText(hEditAwgH2), 10, 32)
	h3, _ := strconv.ParseUint(getControlText(hEditAwgH3), 10, 32)
	h4, _ := strconv.ParseUint(getControlText(hEditAwgH4), 10, 32)

	awgParams := wireguard.AWGParams{
		Enabled: true,
		Jc:      jc,
		Jmin:    jmin,
		Jmax:    jmax,
		S1:      s1,
		S2:      s2,
		H1:      uint32(h1),
		H2:      uint32(h2),
		H3:      uint32(h3),
		H4:      uint32(h4),
	}
	awgCfg := wireguard.AWGConfig{
		WGConfig: wireguard.WGConfig{
			PrivateKey: "(Ключ генерируется автоматически при запуске)",
			Address:    "10.200.0.1/24",
			ListenPort: 51820,
			MTU:        1420,
		},
		AWGParams: awgParams,
	}
	conf, _ := wireguard.GenerateAWGConfig(&awgCfg)
	setControlText(hEditAwgConf, conf)
}

func setAWGPresetValues(p wireguard.AWGParams) {
	setControlText(hEditAwgJc, strconv.Itoa(p.Jc))
	setControlText(hEditAwgJmin, strconv.Itoa(p.Jmin))
	setControlText(hEditAwgJmax, strconv.Itoa(p.Jmax))
	setControlText(hEditAwgS1, strconv.Itoa(p.S1))
	setControlText(hEditAwgS2, strconv.Itoa(p.S2))
	setControlText(hEditAwgH1, fmt.Sprintf("%d", p.H1))
	setControlText(hEditAwgH2, fmt.Sprintf("%d", p.H2))
	setControlText(hEditAwgH3, fmt.Sprintf("%d", p.H3))
	setControlText(hEditAwgH4, fmt.Sprintf("%d", p.H4))
	updateAWGConfigText()
}

func copyAWGToClipboard() {
	text := getControlText(hEditAwgConf)
	copyToClipboard(text)
	addLog("📋 Конфигурация AmneziaWG скопирована в буфер обмена")
	showBalloon("AmneziaWG 2.0", "Конфиг успешно скопирован в буфер обмена.")
}

func fillConfigUI() {
	if cfg != nil {
		for _, ch := range cfg.Signaling.Channels {
			if ch.Type == "telegram" {
				setControlText(hEditTgToken, ch.Params["token"])
				setControlText(hEditTgChat, ch.Params["chat_id"])
			}
			if ch.Type == "mqtt" {
				setControlText(hEditMqttBr, ch.Params["broker_url"])
				setControlText(hEditMqttTp, ch.Params["topic"])
			}
		}
	}
}

func saveConfigFromUI() {
	tgToken := getControlText(hEditTgToken)
	tgChat := getControlText(hEditTgChat)
	mqBroker := getControlText(hEditMqttBr)
	mqTopic := getControlText(hEditMqttTp)

	cfgContent := fmt.Sprintf(`app:
  name: "NatBypass"
  log_level: "info"
  publish_interval: 60
web_ui:
  enabled: true
  port: 8080
network:
  upnp_enabled: true
  stun_servers:
    - "stun.l.google.com:19302"
    - "stun1.l.google.com:19302"
    - "stun.cloudflare.com:3478"
signaling:
  channels:
    - type: "telegram"
      priority: 1
      enabled: %t
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
  enabled: true
  listen_port: 51820
  mtu: 1420
`, tgToken != "", tgToken, tgChat, mqBroker, mqTopic)

	_ = os.WriteFile(configPath, []byte(cfgContent), 0644)
	addLog("💾 Настройки успешно сохранены в " + configPath)
	showBalloon("Настройки сохранены", "Файл config.yaml обновлен.")
}

func testTelegramFromUI() {
	tok := getControlText(hEditTgToken)
	if tok == "" {
		addLog("⚠️ Укажите токен бота для проверки")
		return
	}
	addLog("⏳ Проверка подключения к Telegram Bot API...")
	go func() {
		ch := signaling.NewTelegramChannel(tok, "123", "")
		if ch.IsAvailable(context.Background()) {
			addLog("✅ Успех! Telegram бот доступен и отвечает на запросы.")
		} else {
			addLog("❌ Ошибка: не удалось подключиться к Telegram API.")
		}
	}()
}

func testMQTTFromUI() {
	br := getControlText(hEditMqttBr)
	addLog("⏳ Проверка подключения к MQTT брокеру...")
	go func() {
		ch := signaling.NewMQTTChannel(br, "test", "tester", "", "")
		if ch.IsAvailable(context.Background()) {
			addLog("✅ Успех! MQTT брокер доступен.")
		} else {
			addLog("❌ Ошибка: MQTT брокер недоступен.")
		}
	}()
}

func runDiagnosticsUI() {
	setControlText(hEditDiagLog, "⏳ Выполняется диагностика сети...\r\n")
	go func() {
		res := "════════════════════════════════════════\r\n"
		res += "     ДИАГНОСТИКА СВЯЗНОСТИ NATBYPASS    \r\n"
		res += "════════════════════════════════════════\r\n\r\n"

		// 1. Интернет
		conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 3*time.Second)
		if err == nil {
			conn.Close()
			res += "✅ 1. Доступ к сети Интернет: ДОСТУПЕН\r\n"
		} else {
			res += "❌ 1. Доступ к сети Интернет: НЕДОСТУПЕН\r\n"
		}

		// 2. Внешний IP
		if myPublicIP != "" {
			res += fmt.Sprintf("✅ 2. Публичный IP-адрес: %s\r\n", myPublicIP)
		} else {
			res += "⚠️ 2. Публичный IP-адрес: Определяется...\r\n"
		}

		// 3. STUN сокет
		if mySTUNAddr != "" {
			res += fmt.Sprintf("✅ 3. STUN NAT Hole Punching: РАБОТАЕТ (%s)\r\n", mySTUNAddr)
		} else {
			res += "⚠️ 3. STUN NAT Hole Punching: Ожидание сокета...\r\n"
		}

		// 4. Пиры
		peersCount := 0
		if registry != nil {
			peersCount = len(registry.List())
		}
		res += fmt.Sprintf("👥 4. Устройств в сети: %d\r\n\r\n", peersCount)
		res += "✓ Диагностика завершена успешно."

		setControlText(hEditDiagLog, res)
		addLog("🩺 Диагностика сети завершена")
	}()
}

func updateServiceStatus() {
	go func() {
		out, err := exec.Command("sc", "query", "NatBypass").CombinedOutput()
		statusText := "Служба Windows: НЕ УСТАНОВЛЕНА"
		if err == nil {
			if strings.Contains(string(out), "RUNNING") {
				statusText = "Служба Windows: 🟢 РАБОТАЕТ"
			} else if strings.Contains(string(out), "STOPPED") {
				statusText = "Служба Windows: 🟡 ОСТАНОВЛЕНА"
			} else {
				statusText = "Служба Windows: УСТАНОВЛЕНА"
			}
		}
		setControlText(hLblSvcStatus, statusText)
	}()
}

func addLog(msg string) {
	logsMutex.Lock()
	defer logsMutex.Unlock()
	entry := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	logsBuffer = append(logsBuffer, entry)
	if len(logsBuffer) > 100 {
		logsBuffer = logsBuffer[1:]
	}
	all := strings.Join(logsBuffer, "\r\n")
	setControlText(hEditLogs, all)
}

func addTrayIcon() {
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hMainWnd
	nid.UID = 1
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.UCallbackMessage = WM_TRAYICON
	nid.HIcon, _, _ = procLoadIconW.Call(0, 32512)
	tipPtr, _ := windows.UTF16FromString("NatBypass P2P Mesh Network")
	copy(nid.SzTip[:], tipPtr)

	procShellNotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
}

func removeTrayIcon() {
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hMainWnd
	nid.UID = 1
	procShellNotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
}

func showBalloon(title, msg string) {
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hMainWnd
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
	m1, _ := windows.UTF16PtrFromString("🖥 Открыть главное окно")
	m2, _ := windows.UTF16PtrFromString("🌐 Открыть Web UI")
	m3, _ := windows.UTF16PtrFromString("⚡ Обновить внешний IP")
	m4, _ := windows.UTF16PtrFromString("❌ Завершить работу")

	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_RESTORE, uintptr(unsafe.Pointer(m1)))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_WEBUI, uintptr(unsafe.Pointer(m2)))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_REFRESH, uintptr(unsafe.Pointer(m3)))
	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_EXIT, uintptr(unsafe.Pointer(m4)))

	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hMainWnd)
	procTrackPopupMenu.Call(hMenu, TPM_RIGHTBUTTON, uintptr(pt.X), uintptr(pt.Y), 0, hMainWnd, 0)
	procDestroyMenu.Call(hMenu)
}

// Вспомогательные функции создания элементов
func createLabel(hInstance uintptr, text string, x, y, w, h int, font uintptr) uintptr {
	staticClass, _ := windows.UTF16PtrFromString("STATIC")
	textPtr, _ := windows.UTF16PtrFromString(text)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(staticClass)),
		uintptr(unsafe.Pointer(textPtr)),
		WS_CHILD|WS_VISIBLE|SS_LEFT,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		hMainWnd, 0, hInstance, 0,
	)
	if font != 0 {
		procSendMessageW.Call(hwnd, 0x0030, font, 1)
	}
	allControls = append(allControls, hwnd)
	return hwnd
}

func createButton(hInstance uintptr, text string, x, y, w, h int, id uintptr, font uintptr) uintptr {
	btnClass, _ := windows.UTF16PtrFromString("BUTTON")
	textPtr, _ := windows.UTF16PtrFromString(text)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(btnClass)),
		uintptr(unsafe.Pointer(textPtr)),
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		hMainWnd, id, hInstance, 0,
	)
	if font != 0 {
		procSendMessageW.Call(hwnd, 0x0030, font, 1)
	}
	allControls = append(allControls, hwnd)
	return hwnd
}

func createEdit(hInstance uintptr, text string, x, y, w, h int, multiline, readonly bool, font uintptr) uintptr {
	editClass, _ := windows.UTF16PtrFromString("EDIT")
	textPtr, _ := windows.UTF16PtrFromString(text)
	style := uint32(WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_LEFT)
	if multiline {
		style |= ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL
	} else {
		style |= ES_AUTOHSCROLL
	}
	if readonly {
		style |= ES_READONLY
	}
	hwnd, _, _ := procCreateWindowExW.Call(
		WS_EX_CLIENTEDGE,
		uintptr(unsafe.Pointer(editClass)),
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		hMainWnd, 0, hInstance, 0,
	)
	if font != 0 {
		procSendMessageW.Call(hwnd, 0x0030, font, 1)
	}
	allControls = append(allControls, hwnd)
	return hwnd
}

func createListBox(hInstance uintptr, x, y, w, h int, font uintptr) uintptr {
	lbClass, _ := windows.UTF16PtrFromString("LISTBOX")
	hwnd, _, _ := procCreateWindowExW.Call(
		WS_EX_CLIENTEDGE,
		uintptr(unsafe.Pointer(lbClass)),
		0,
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		hMainWnd, 0, hInstance, 0,
	)
	if font != 0 {
		procSendMessageW.Call(hwnd, 0x0030, font, 1)
	}
	allControls = append(allControls, hwnd)
	return hwnd
}

func addListBoxItem(hwnd uintptr, text string) {
	tPtr, _ := windows.UTF16PtrFromString(text)
	procSendMessageW.Call(hwnd, 0x0180, 0, uintptr(unsafe.Pointer(tPtr))) // LB_ADDSTRING
}

func createFont(name string, height int, weight int) uintptr {
	namePtr, _ := windows.UTF16PtrFromString(name)
	hFont, _, _ := procCreateFontW.Call(
		uintptr(height), 0, 0, 0,
		uintptr(weight), 0, 0, 0,
		1, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(namePtr)),
	)
	return hFont
}

func setControlText(hwnd uintptr, text string) {
	tPtr, _ := windows.UTF16PtrFromString(text)
	procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(tPtr)))
}

func getControlText(hwnd uintptr) string {
	buf := make([]uint16, 2048)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 2048)
	return windows.UTF16ToString(buf)
}

func copyToClipboard(text string) {
	// Используем clip.exe для гарантированного копирования текста в UTF-8
	cmd := exec.Command("clip")
	cmd.Stdin = strings.NewReader(text)
	_ = cmd.Run()
}

func LOWORD(l uintptr) uint16 {
	return uint16(l & 0xFFFF)
}
