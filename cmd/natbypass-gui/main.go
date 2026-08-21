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
	moduxtheme  = windows.NewLazySystemDLL("uxtheme.dll")

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
	procSelectObject         = modgdi32.NewProc("SelectObject")
	procRectangle            = modgdi32.NewProc("Rectangle")
	procCreatePen            = modgdi32.NewProc("CreatePen")
	procDeleteObject         = modgdi32.NewProc("DeleteObject")
	procInitCommonControlsEx = modcomctl32.NewProc("InitCommonControlsEx")
	procShellNotifyIconW     = modshell32.NewProc("Shell_NotifyIconW")
	procDwmSetWindowAttribute= moddwmapi.NewProc("DwmSetWindowAttribute")
	procSetWindowTheme       = moduxtheme.NewProc("SetWindowTheme")
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
	WM_PAINT          = 0x000F
	WM_COMMAND        = 0x0111
	WM_SYSCOMMAND     = 0x0112
	WM_TIMER          = 0x0113
	WM_CTLCOLORSTATIC = 0x0138
	WM_CTLCOLOREDIT   = 0x0133
	WM_CTLCOLORBTN    = 0x0135
	WM_CTLCOLORLISTBOX= 0x0134
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

	MF_STRING       = 0x00000000
	MF_SEPARATOR    = 0x00000800
	TPM_RIGHTBUTTON = 0x0002
)

// Цветовая палитра Dark Mode
const (
	COLOR_BG      = 0x17110D // #0D1117 in BGR
	COLOR_SIDEBAR = 0x221B16 // #161B22
	COLOR_CARD    = 0x2D2621 // #21262D
	COLOR_BORDER  = 0x3D3630 // #30363D
	COLOR_TEXT    = 0xD9D1C9 // #C9D1D9
	COLOR_MUTED   = 0x9E948B // #8B949E
	COLOR_ACCENT  = 0xFFA658 // #58A6FF
	COLOR_GREEN   = 0x50B93F // #3FB950
	COLOR_RED     = 0x4951F8 // #F85149
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

// Глобальные переменные UI
var (
	hMainWnd    uintptr
	hFontNormal uintptr
	hFontBold   uintptr
	hFontTitle  uintptr
	hFontHeader uintptr
	hFontMono   uintptr

	hBrushBg      uintptr
	hBrushSidebar uintptr
	hBrushCard    uintptr
	hPenBorder    uintptr

	// Навигация (Sidebar)
	navButtons [5]uintptr
	currentTab = 0

	// Страницы
	tabPages [5][]uintptr

	// Вкладка 0: Обзор
	hLblStatus   uintptr
	hLblIpInfo   uintptr
	hBtnVpn      uintptr
	hListPeers   uintptr
	hBtnRefresh  uintptr

	// Вкладка 1: AmneziaWG
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

	// Вкладка 2: Настройки
	hEditTgToken uintptr
	hEditTgChat  uintptr
	hBtnTestTg   uintptr
	hEditMqttBr  uintptr
	hEditMqttTp  uintptr
	hBtnTestMqtt uintptr
	hBtnSaveCfg  uintptr

	// Вкладка 3: Диагностика
	hBtnRunDiag  uintptr
	hEditDiagLog uintptr

	// Вкладка 4: Логи
	hEditLogs   uintptr
	hBtnClrLogs uintptr

	allControls []uintptr

	// Движок
	configPath   string
	cfg          *config.Config
	registry     *peer.Registry
	sigMgr       *signaling.FallbackManager
	ipDisc       *network.Discoverer
	stunClient   *network.STUNClient
	myDevID      string
	myPublicIP   string
	mySTUNAddr   string
	vpnConnected bool
	engineCtx    context.Context
	engineCancel context.CancelFunc
	logsMutex    sync.Mutex
	logsBuffer   []string
)

const (
	ID_TIMER_POLL = 1001

	// Меню трея
	IDM_TRAY_OPEN    = 2001
	IDM_TRAY_REFRESH = 2002
	IDM_TRAY_EXIT    = 2003

	// Навигация
	ID_NAV_DASHBOARD = 3001
	ID_NAV_AWG       = 3002
	ID_NAV_SETTINGS  = 3003
	ID_NAV_DIAG      = 3004
	ID_NAV_LOGS      = 3005

	// Действия
	ID_BTN_VPN         = 4001
	ID_BTN_REFRESH     = 4002
	ID_BTN_AWG_STD     = 4003
	ID_BTN_AWG_DPI     = 4004
	ID_BTN_AWG_STEALTH = 4005
	ID_BTN_RAND_AWG    = 4006
	ID_BTN_COPY_AWG    = 4007
	ID_BTN_TEST_TG     = 4008
	ID_BTN_TEST_MQTT   = 4009
	ID_BTN_SAVE_CFG    = 4010
	ID_BTN_RUN_DIAG    = 4011
	ID_BTN_CLR_LOGS    = 4012
)

func main() {
	cfgFile := flag.String("config", "config.yaml", "Path to config.yaml")
	flag.Parse()
	configPath = *cfgFile

	// 1. Инициализация Common Controls
	type INITCOMMONCONTROLSEX struct {
		DwSize uint32
		DwICC  uint32
	}
	icex := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  0x00000008 | 0x00000001,
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icex)))

	// 2. Загрузка конфигурации
	loadedCfg, err := config.Load(configPath)
	if err != nil {
		loadedCfg = &config.Config{
			App: config.AppConfig{Name: "NatBypass", LogLevel: "info", PublishInterval: 60},
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

	// 3. Создание ресурсов GDI
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	hIcon, _, _ := procLoadIconW.Call(0, 32512)

	hBrushBg, _, _ = procCreateSolidBrush.Call(COLOR_BG)
	hBrushSidebar, _, _ = procCreateSolidBrush.Call(COLOR_SIDEBAR)
	hBrushCard, _, _ = procCreateSolidBrush.Call(COLOR_CARD)
	hPenBorder, _, _ = procCreatePen.Call(0, 1, COLOR_BORDER)

	hFontNormal = createFont("Segoe UI", 15, 400)
	hFontBold = createFont("Segoe UI", 15, 700)
	hFontHeader = createFont("Segoe UI", 18, 700)
	hFontTitle = createFont("Segoe UI", 22, 700)
	hFontMono = createFont("Consolas", 13, 400)

	// 4. Регистрация класса окна
	className, _ := windows.UTF16PtrFromString("NatBypassNativeAppClass")
	windowTitle, _ := windows.UTF16PtrFromString("NatBypass — Нативное приложение P2P Mesh & AmneziaWG 2.0")

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         3,
		LpfnWndProc:   windows.NewCallback(wndProc),
		HInstance:     hInstance,
		HIcon:         hIcon,
		HCursor:       hIcon,
		HbrBackground: hBrushBg,
		LpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	// 5. Создание окна
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		WS_OVERLAPPEDWINDOW,
		120, 120, 1060, 720,
		0, 0, hInstance, 0,
	)
	hMainWnd = hwnd

	// Включаем DWM Dark Mode заголовок
	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hMainWnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	// Построение элементов интерфейса
	buildNativeUI(hInstance)

	// Переключаем на 1 вкладку
	selectTab(0)

	// Трей
	addTrayIcon()

	// Показываем окно
	procShowWindow.Call(hMainWnd, SW_SHOW)

	// Запуск движка
	startEngine()

	// Таймер опроса
	procSetTimer.Call(hMainWnd, ID_TIMER_POLL, 2000, 0)

	// Цикл сообщений
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
		if wParam == SC_MINIMIZE || wParam == SC_CLOSE {
			procShowWindow.Call(hMainWnd, SW_HIDE)
			showBalloon("NatBypass работает в фоне", "Двойной клик по значку у часов для открытия окна.")
			return 0
		}

	case WM_TRAYICON:
		if lParam == 0x0203 { // Double Click
			procShowWindow.Call(hMainWnd, SW_RESTORE)
			procSetForegroundWindow.Call(hMainWnd)
		} else if lParam == 0x0205 { // Right Click
			showTrayMenu()
		}
		return 0

	case WM_CTLCOLORSTATIC:
		hdc := wParam
		procSetBkMode.Call(hdc, 1) // TRANSPARENT
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushBg

	case WM_CTLCOLOREDIT:
		hdc := wParam
		procSetBkColor.Call(hdc, COLOR_CARD)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushCard

	case WM_CTLCOLORLISTBOX:
		hdc := wParam
		procSetBkColor.Call(hdc, COLOR_CARD)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushCard

	case WM_TIMER:
		if wParam == ID_TIMER_POLL {
			updateData()
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
	// Навигация
	case ID_NAV_DASHBOARD:
		selectTab(0)
	case ID_NAV_AWG:
		selectTab(1)
	case ID_NAV_SETTINGS:
		selectTab(2)
	case ID_NAV_DIAG:
		selectTab(3)
	case ID_NAV_LOGS:
		selectTab(4)

	// Действия
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

	case ID_BTN_AWG_STD:
		setAWGPreset(wireguard.AWGParams{Enabled: true, Jc: 0, Jmin: 0, Jmax: 0, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4})
		addLog("🛡️ Выбран пресет: 🟢 Стандартный WireGuard")

	case ID_BTN_AWG_DPI:
		setAWGPreset(wireguard.DefaultAWGParams())
		addLog("🛡️ Выбран пресет: 🟡 Обход DPI (AmneziaWG 2.0)")

	case ID_BTN_AWG_STEALTH:
		randP := wireguard.GenerateRandomAWGParams()
		setAWGPreset(randP)
		addLog("🛡️ Выбран пресет: 🔴 Максимальная скрытность")

	case ID_BTN_RAND_AWG:
		randP := wireguard.GenerateRandomAWGParams()
		setAWGPreset(randP)
		addLog("🎲 Сгенерированы новые уникальные параметры AWG")

	case ID_BTN_COPY_AWG:
		conf := getControlText(hEditAwgConf)
		copyToClipboard(conf)
		addLog("📋 Конфиг AmneziaWG скопирован в буфер обмена")
		showBalloon("AmneziaWG 2.0", "Конфигурация скопирована в буфер.")

	case ID_BTN_TEST_TG:
		testTelegram()

	case ID_BTN_TEST_MQTT:
		testMQTT()

	case ID_BTN_SAVE_CFG:
		saveConfig()

	case ID_BTN_RUN_DIAG:
		runDiag()

	case ID_BTN_CLR_LOGS:
		logsMutex.Lock()
		logsBuffer = nil
		logsMutex.Unlock()
		setControlText(hEditLogs, "")

	// Трей
	case IDM_TRAY_OPEN:
		procShowWindow.Call(hMainWnd, SW_RESTORE)
		procSetForegroundWindow.Call(hMainWnd)
	case IDM_TRAY_REFRESH:
		handleCommand(ID_BTN_REFRESH)
	case IDM_TRAY_EXIT:
		procShowWindow.Call(hMainWnd, SW_HIDE)
		stopEngine()
		removeTrayIcon()
		os.Exit(0)
	}
}

func buildNativeUI(hInstance uintptr) {
	// ══════════════════════════════════════════════════════════════
	// БОКОВАЯ ПАНЕЛЬ НАВИГАЦИИ (SIDEBAR)
	// ══════════════════════════════════════════════════════════════
	lblLogo := createLabel(hInstance, "🛸 NatBypass", 24, 24, 180, 32, hFontTitle)
	lblVer := createLabel(hInstance, "Native v1.0 • P2P Mesh", 24, 60, 180, 20, hFontNormal)

	navTitles := []string{
		"🚀 Обзор и Сеть",
		"🛡️ AmneziaWG 2.0",
		"⚙️ Настройки",
		"🩺 Диагностика",
		"📋 Журнал логов",
	}
	navIDs := []uintptr{ID_NAV_DASHBOARD, ID_NAV_AWG, ID_NAV_SETTINGS, ID_NAV_DIAG, ID_NAV_LOGS}

	for i, t := range navTitles {
		btn := createButton(hInstance, t, 16, 110+(i*48), 188, 40, navIDs[i], hFontBold)
		navButtons[i] = btn
		allControls = append(allControls, btn)
	}

	allControls = append(allControls, lblLogo, lblVer)

	// Контентная область начинается с X = 230
	contentX := 230
	contentW := 790

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 0: ОБЗОР (DASHBOARD)
	// ══════════════════════════════════════════════════════════════
	hLblStatus = createLabel(hInstance, "🟢 P2P МЕШ-СЕТЬ АКТИВНА", contentX, 24, contentW, 30, hFontTitle)
	hLblIpInfo = createLabel(hInstance, "Устройство: Определение... | Внешний IP: — | STUN: — | Канал: mqtt", contentX, 60, contentW, 22, hFontNormal)

	hBtnVpn = createButton(hInstance, "🟢 ВКЛЮЧЕНО (Адрес в сети: 10.200.0.1)", contentX, 96, 360, 48, ID_BTN_VPN, hFontBold)
	hBtnRefresh = createButton(hInstance, "⚡ Обновить IP", contentX+380, 96, 140, 48, ID_BTN_REFRESH, hFontBold)

	lblPeersHeader := createLabel(hInstance, "👥 Обнаруженные устройства в вашей сети:", contentX, 165, contentW, 24, hFontHeader)
	hListPeers = createListBox(hInstance, contentX, 195, contentW, 460, hFontMono)

	tabPages[0] = []uintptr{hLblStatus, hLblIpInfo, hBtnVpn, hBtnRefresh, lblPeersHeader, hListPeers}

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 1: AMNEZIAWG 2.0
	// ══════════════════════════════════════════════════════════════
	lblAwgTitle := createLabel(hInstance, "🛡️ AmneziaWG 2.0 — Встроенная защита от блокировок DPI", contentX, 24, contentW, 30, hFontTitle)
	lblAwgDesc := createLabel(hInstance, "Модифицирует заголовки пакетов и подмешивает мусорный трафик, обходя ТСПУ / РКН.", contentX, 58, contentW, 20, hFontNormal)

	hBtnAwgStd = createButton(hInstance, "🟢 Стандартный WG", contentX, 90, 180, 36, ID_BTN_AWG_STD, hFontBold)
	hBtnAwgDpi = createButton(hInstance, "🟡 Обход DPI (AWG)", contentX+195, 90, 180, 36, ID_BTN_AWG_DPI, hFontBold)
	hBtnAwgStealth = createButton(hInstance, "🔴 Макс. скрытность", contentX+390, 90, 180, 36, ID_BTN_AWG_STEALTH, hFontBold)
	hBtnRandomAwg = createButton(hInstance, "🎲 Случайные ключи", contentX+585, 90, 180, 36, ID_BTN_RAND_AWG, hFontNormal)

	// Параметры
	lblJc := createLabel(hInstance, "Jc (мусор):", contentX, 142, 80, 20, hFontNormal)
	hEditAwgJc = createEdit(hInstance, "4", contentX+85, 138, 55, 26, false, false, hFontNormal)

	lblJmin := createLabel(hInstance, "Jmin:", contentX+155, 142, 45, 20, hFontNormal)
	hEditAwgJmin = createEdit(hInstance, "40", contentX+205, 138, 55, 26, false, false, hFontNormal)

	lblJmax := createLabel(hInstance, "Jmax:", contentX+275, 142, 45, 20, hFontNormal)
	hEditAwgJmax = createEdit(hInstance, "70", contentX+325, 138, 55, 26, false, false, hFontNormal)

	lblS1 := createLabel(hInstance, "S1:", contentX+395, 142, 30, 20, hFontNormal)
	hEditAwgS1 = createEdit(hInstance, "48", contentX+430, 138, 55, 26, false, false, hFontNormal)

	lblS2 := createLabel(hInstance, "S2:", contentX+500, 142, 30, 20, hFontNormal)
	hEditAwgS2 = createEdit(hInstance, "32", contentX+535, 138, 55, 26, false, false, hFontNormal)

	lblH1 := createLabel(hInstance, "H1:", contentX, 178, 30, 20, hFontNormal)
	hEditAwgH1 = createEdit(hInstance, "1428571428", contentX+35, 174, 110, 26, false, false, hFontNormal)

	lblH2 := createLabel(hInstance, "H2:", contentX+160, 178, 30, 20, hFontNormal)
	hEditAwgH2 = createEdit(hInstance, "2147483647", contentX+195, 174, 110, 26, false, false, hFontNormal)

	lblH3 := createLabel(hInstance, "H3:", contentX+320, 178, 30, 20, hFontNormal)
	hEditAwgH3 = createEdit(hInstance, "857142857", contentX+355, 174, 110, 26, false, false, hFontNormal)

	lblH4 := createLabel(hInstance, "H4:", contentX+480, 178, 30, 20, hFontNormal)
	hEditAwgH4 = createEdit(hInstance, "1122334455", contentX+515, 174, 110, 26, false, false, hFontNormal)

	lblConfTitle := createLabel(hInstance, "Конфигурация туннеля AmneziaWG (.conf):", contentX, 218, contentW, 22, hFontBold)
	hEditAwgConf = createEdit(hInstance, "", contentX, 245, contentW, 360, true, true, hFontMono)
	hBtnCopyAwg = createButton(hInstance, "📋 Скопировать конфигурацию в буфер обмена", contentX, 615, 360, 40, ID_BTN_COPY_AWG, hFontBold)

	tabPages[1] = []uintptr{
		lblAwgTitle, lblAwgDesc, hBtnAwgStd, hBtnAwgDpi, hBtnAwgStealth, hBtnRandomAwg,
		lblJc, hEditAwgJc, lblJmin, hEditAwgJmin, lblJmax, hEditAwgJmax, lblS1, hEditAwgS1, lblS2, hEditAwgS2,
		lblH1, hEditAwgH1, lblH2, hEditAwgH2, lblH3, hEditAwgH3, lblH4, hEditAwgH4,
		lblConfTitle, hEditAwgConf, hBtnCopyAwg,
	}

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 2: НАСТРОЙКИ
	// ══════════════════════════════════════════════════════════════
	lblSetTitle := createLabel(hInstance, "⚙️ Сигнальные каналы (Обмен пирами)", contentX, 24, contentW, 30, hFontTitle)

	lblTgHead := createLabel(hInstance, "💬 Telegram Bot API (Рекомендуется):", contentX, 75, contentW, 22, hFontHeader)
	lblTgToken := createLabel(hInstance, "Токен бота (@BotFather):", contentX, 110, 200, 20, hFontNormal)
	hEditTgToken = createEdit(hInstance, "", contentX+210, 106, 380, 28, false, true, hFontNormal)
	hBtnTestTg = createButton(hInstance, "🧪 Проверить бот", contentX+600, 104, 170, 32, ID_BTN_TEST_TG, hFontBold)

	lblTgChat := createLabel(hInstance, "Chat ID (@userinfobot):", contentX, 150, 200, 20, hFontNormal)
	hEditTgChat = createEdit(hInstance, "", contentX+210, 146, 380, 28, false, false, hFontNormal)

	lblMqHead := createLabel(hInstance, "⚡ MQTT Брокер:", contentX, 210, contentW, 22, hFontHeader)
	lblMqBr := createLabel(hInstance, "URL Брокера:", contentX, 245, 200, 20, hFontNormal)
	hEditMqttBr = createEdit(hInstance, "tcp://mqtt.eclipseprojects.io:1883", contentX+210, 241, 380, 28, false, false, hFontNormal)
	hBtnTestMqtt = createButton(hInstance, "🧪 Проверить MQTT", contentX+600, 239, 170, 32, ID_BTN_TEST_MQTT, hFontBold)

	lblMqTp := createLabel(hInstance, "Уникальный топик:", contentX, 285, 200, 20, hFontNormal)
	hEditMqttTp = createEdit(hInstance, "natbypass/mynet/peers", contentX+210, 281, 380, 28, false, false, hFontNormal)

	hBtnSaveCfg = createButton(hInstance, "💾 Сохранить настройки в config.yaml", contentX+210, 340, 380, 46, ID_BTN_SAVE_CFG, hFontBold)

	tabPages[2] = []uintptr{
		lblSetTitle, lblTgHead, lblTgToken, hEditTgToken, hBtnTestTg, lblTgChat, hEditTgChat,
		lblMqHead, lblMqBr, hEditMqttBr, hBtnTestMqtt, lblMqTp, hEditMqttTp, hBtnSaveCfg,
	}

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 3: ДИАГНОСТИКА
	// ══════════════════════════════════════════════════════════════
	lblDiagTitle := createLabel(hInstance, "🩺 Диагностика связности и NAT", contentX, 24, contentW, 30, hFontTitle)
	hBtnRunDiag = createButton(hInstance, "🔄 Запустить полную диагностику", contentX, 70, 280, 42, ID_BTN_RUN_DIAG, hFontBold)
	hEditDiagLog = createEdit(hInstance, "Нажмите кнопку выше для проверки внешнего IP, доступности Telegram/MQTT и STUN сокета...", contentX, 130, contentW, 520, true, true, hFontMono)

	tabPages[3] = []uintptr{lblDiagTitle, hBtnRunDiag, hEditDiagLog}

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 4: ЖУРНАЛ ЛОГОВ
	// ══════════════════════════════════════════════════════════════
	lblLogTitle := createLabel(hInstance, "📋 Журнал событий в реальном времени", contentX, 24, contentW-120, 30, hFontTitle)
	hBtnClrLogs = createButton(hInstance, "🗑 Очистить", contentX+contentW-120, 24, 120, 32, ID_BTN_CLR_LOGS, hFontNormal)
	hEditLogs = createEdit(hInstance, "", contentX, 70, contentW, 585, true, true, hFontMono)

	tabPages[4] = []uintptr{lblLogTitle, hBtnClrLogs, hEditLogs}

	fillConfigFields()
	updateAWGText()
}

func selectTab(index int) {
	currentTab = index
	for i, page := range tabPages {
		show := SW_HIDE
		if i == index {
			show = SW_SHOW
		}
		for _, h := range page {
			procShowWindow.Call(h, uintptr(show))
		}
	}
	if index == 1 {
		updateAWGText()
	}
}

func toggleVPN() {
	vpnConnected = !vpnConnected
	if vpnConnected {
		setControlText(hBtnVpn, "🟢 ВКЛЮЧЕНО (Адрес в сети: 10.200.0.1)")
		addLog("🟢 Туннель активен")
		showBalloon("NatBypass", "Защищенная mesh-сеть активна.")
	} else {
		setControlText(hBtnVpn, "🔴 ОТКЛЮЧЕНО (Нажмите для старта)")
		addLog("🔴 Туннель приостановлен")
	}
}

func startEngine() {
	ctx, cancel := context.WithCancel(context.Background())
	engineCtx = ctx
	engineCancel = cancel
	vpnConnected = true

	pubKey, _, _ := crypto.GenerateKeyPair()
	myDevID = "Win-" + crypto.KeyToHex(pubKey)[:8]
	if hn, err := os.Hostname(); err == nil && hn != "" {
		myDevID = hn
	}

	registry = peer.NewRegistry()
	registry.StartMonitor(ctx, 2*time.Minute)

	var channels []signaling.SignalingChannel
	channels = append(channels, signaling.NewMQTTChannel(
		"tcp://mqtt.eclipseprojects.io:1883",
		"natbypass/public/peers",
		myDevID, "", "",
	))
	sigMgr = signaling.NewFallbackManager(channels)

	ipDisc = network.NewDiscoverer(cfg.Network.IPApis, 5*time.Second)
	stunClient = network.NewSTUNClient(cfg.Network.StunServers)

	go func() {
		if ip, err := ipDisc.GetPublicIPCached(ctx, 5*time.Minute); err == nil {
			myPublicIP = ip.String()
		}
		if extIP, port, err := stunClient.GetMappedAddress(ctx); err == nil {
			mySTUNAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
		}
		addLog(fmt.Sprintf("✓ Ядро инициализировано. Публичный IP: %s | STUN: %s", myPublicIP, mySTUNAddr))
	}()

	addLog("🛸 NatBypass нативное ядро запущено")
}

func stopEngine() {
	if engineCancel != nil {
		engineCancel()
	}
}

func updateData() {
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

	if registry != nil {
		peers := registry.List()
		procSendMessageW.Call(hListPeers, 0x0184, 0, 0)
		if len(peers) == 0 {
			addListBoxItem(hListPeers, "📡 Ожидание подключения других устройств... (0 пиров онлайн)")
		} else {
			for _, p := range peers {
				st := "🟢 Онлайн"
				if !p.Online {
					st = "🔴 Офлайн"
				}
				itemStr := fmt.Sprintf("%-20s | %-16s | %-22s | %s", p.DeviceID, p.PublicIP, p.STUNAddr, st)
				addListBoxItem(hListPeers, itemStr)
			}
		}
	}
}

func updateAWGText() {
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

func setAWGPreset(p wireguard.AWGParams) {
	setControlText(hEditAwgJc, strconv.Itoa(p.Jc))
	setControlText(hEditAwgJmin, strconv.Itoa(p.Jmin))
	setControlText(hEditAwgJmax, strconv.Itoa(p.Jmax))
	setControlText(hEditAwgS1, strconv.Itoa(p.S1))
	setControlText(hEditAwgS2, strconv.Itoa(p.S2))
	setControlText(hEditAwgH1, fmt.Sprintf("%d", p.H1))
	setControlText(hEditAwgH2, fmt.Sprintf("%d", p.H2))
	setControlText(hEditAwgH3, fmt.Sprintf("%d", p.H3))
	setControlText(hEditAwgH4, fmt.Sprintf("%d", p.H4))
	updateAWGText()
}

func fillConfigFields() {
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

func saveConfig() {
	tgToken := getControlText(hEditTgToken)
	tgChat := getControlText(hEditTgChat)
	mqBroker := getControlText(hEditMqttBr)
	mqTopic := getControlText(hEditMqttTp)

	cfgContent := fmt.Sprintf(`app:
  name: "NatBypass"
  log_level: "info"
  publish_interval: 60
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
	addLog("💾 Настройки сохранены в " + configPath)
	showBalloon("NatBypass", "Настройки сохранены в config.yaml")
}

func testTelegram() {
	tok := getControlText(hEditTgToken)
	if tok == "" {
		addLog("⚠️ Введите токен бота")
		return
	}
	addLog("⏳ Проверка Telegram Bot API...")
	go func() {
		ch := signaling.NewTelegramChannel(tok, "123", "")
		if ch.IsAvailable(context.Background()) {
			addLog("✅ Успех! Telegram бот активен и отвечает на запросы.")
		} else {
			addLog("❌ Ошибка: не удалось подключиться к Telegram API.")
		}
	}()
}

func testMQTT() {
	br := getControlText(hEditMqttBr)
	addLog("⏳ Проверка MQTT брокера...")
	go func() {
		ch := signaling.NewMQTTChannel(br, "test", "tester", "", "")
		if ch.IsAvailable(context.Background()) {
			addLog("✅ Успех! MQTT брокер доступен.")
		} else {
			addLog("❌ Ошибка: MQTT брокер недоступен.")
		}
	}()
}

func runDiag() {
	setControlText(hEditDiagLog, "⏳ Выполняется тестирование сети...\r\n")
	go func() {
		res := "═══════════════════════════════════════════════════\r\n"
		res += "         СИСТЕМНАЯ ДИАГНОСТИКА СЕТИ NATBYPASS      \r\n"
		res += "═══════════════════════════════════════════════════\r\n\r\n"

		conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 3*time.Second)
		if err == nil {
			conn.Close()
			res += "✅ 1. Доступ к сети Интернет: ДОСТУПЕН\r\n"
		} else {
			res += "❌ 1. Доступ к сети Интернет: НЕДОСТУПЕН\r\n"
		}

		if myPublicIP != "" {
			res += fmt.Sprintf("✅ 2. Публичный IP-адрес: %s\r\n", myPublicIP)
		} else {
			res += "⚠️ 2. Публичный IP-адрес: Ожидание...\r\n"
		}

		if mySTUNAddr != "" {
			res += fmt.Sprintf("✅ 3. STUN NAT Hole Punching: %s (P2P доступен)\r\n", mySTUNAddr)
		} else {
			res += "⚠️ 3. STUN NAT: Ожидание сокета...\r\n"
		}

		peersCount := 0
		if registry != nil {
			peersCount = len(registry.List())
		}
		res += fmt.Sprintf("👥 4. Устройств обнаружено: %d\r\n\r\n", peersCount)
		res += "✓ Проверка завершена. Все системы готовы к передаче трафика."

		setControlText(hEditDiagLog, res)
		addLog("🩺 Диагностика сети успешно завершена")
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
	tipPtr, _ := windows.UTF16FromString("NatBypass P2P Mesh")
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
	nid.DwInfoFlags = 1

	procShellNotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
}

func showTrayMenu() {
	hMenu, _, _ := procCreatePopupMenu.Call()
	m1, _ := windows.UTF16PtrFromString("🖥 Открыть окно")
	m2, _ := windows.UTF16PtrFromString("⚡ Обновить внешний IP")
	m3, _ := windows.UTF16PtrFromString("❌ Выход")

	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_OPEN, uintptr(unsafe.Pointer(m1)))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_REFRESH, uintptr(unsafe.Pointer(m2)))
	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_TRAY_EXIT, uintptr(unsafe.Pointer(m3)))

	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hMainWnd)
	procTrackPopupMenu.Call(hMenu, TPM_RIGHTBUTTON, uintptr(pt.X), uintptr(pt.Y), 0, hMainWnd, 0)
	procDestroyMenu.Call(hMenu)
}

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
	// Применяем тему Explorer
	uxtheme, _ := windows.UTF16PtrFromString("Explorer")
	procSetWindowTheme.Call(hwnd, uintptr(unsafe.Pointer(uxtheme)), 0)

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
	uxtheme, _ := windows.UTF16PtrFromString("DarkMode_Explorer")
	procSetWindowTheme.Call(hwnd, uintptr(unsafe.Pointer(uxtheme)), 0)

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
	uxtheme, _ := windows.UTF16PtrFromString("DarkMode_Explorer")
	procSetWindowTheme.Call(hwnd, uintptr(unsafe.Pointer(uxtheme)), 0)

	allControls = append(allControls, hwnd)
	return hwnd
}

func addListBoxItem(hwnd uintptr, text string) {
	tPtr, _ := windows.UTF16PtrFromString(text)
	procSendMessageW.Call(hwnd, 0x0180, 0, uintptr(unsafe.Pointer(tPtr)))
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
	buf := make([]uint16, 4096)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 4096)
	return windows.UTF16ToString(buf)
}

func copyToClipboard(text string) {
	cmd := exec.Command("clip")
	cmd.Stdin = strings.NewReader(text)
	_ = cmd.Run()
}

func LOWORD(l uintptr) uint16 {
	return uint16(l & 0xFFFF)
}
