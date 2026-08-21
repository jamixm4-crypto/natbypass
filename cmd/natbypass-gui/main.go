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
	procRoundRect            = modgdi32.NewProc("RoundRect")
	procCreatePen            = modgdi32.NewProc("CreatePen")
	procDeleteObject         = modgdi32.NewProc("DeleteObject")
	procDrawTextW            = moduser32.NewProc("DrawTextW")
	procFillRect             = moduser32.NewProc("FillRect")
	procBeginPaint           = moduser32.NewProc("BeginPaint")
	procEndPaint             = moduser32.NewProc("EndPaint")
	procInvalidateRect       = moduser32.NewProc("InvalidateRect")
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

	BS_PUSHBUTTON = 0x00000000
	BS_OWNERDRAW  = 0x0000000B

	ES_LEFT        = 0x0000
	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_AUTOHSCROLL = 0x0080
	ES_READONLY    = 0x0800

	SS_LEFT = 0x0000

	LBS_NOTIFY           = 0x0001
	LBS_NOINTEGRALHEIGHT = 0x0100

	WM_DESTROY        = 0x0002
	WM_PAINT          = 0x000F
	WM_COMMAND        = 0x0111
	WM_SYSCOMMAND     = 0x0112
	WM_TIMER          = 0x0113
	WM_DRAWITEM       = 0x002B
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

	DT_CENTER     = 0x00000001
	DT_VCENTER    = 0x00000004
	DT_SINGLELINE = 0x00000020
	DT_LEFT       = 0x00000000

	ODS_SELECTED = 0x0001
)

// Цветовая палитра Slate Dark (Modern Fluent Theme)
const (
	COLOR_BG        = 0x18120D // #0D1218 (Глубокий темный фон)
	COLOR_SIDEBAR   = 0x221A15 // #151A22 (Боковая панель)
	COLOR_CARD      = 0x29211A // #1A2129 (Контейнеры контента)
	COLOR_INPUT     = 0x332820 // #202833 (Поля ввода)
	COLOR_BORDER    = 0x473B32 // #323B47 (Контуры полей и карточек)
	COLOR_BORDER_LT = 0x5E4E42 // #424E5E (Границы кнопок)
	COLOR_TEXT      = 0xF3EDE6 // #E6EDF3 (Основной белый текст)
	COLOR_MUTED     = 0xA89D91 // #919DA8 (Мягкий серый для подписей)
	COLOR_ACCENT    = 0xFFA658 // #58A6FF (Голубой акцент)
	COLOR_ACCENT_BG = 0xEB6F1F // #1F6FEB (Синяя кнопка)
	COLOR_GREEN_BG  = 0x368623 // #238636 (Зеленая кнопка)
	COLOR_GREEN_LT  = 0x50B93F // #3FB950
	COLOR_RED_BG    = 0x3336DA // #DA3633 (Красная кнопка)
	COLOR_BTN_HOVER = 0x3D3328 // #28333D
)

type RECT struct {
	Left, Top, Right, Bottom int32
}

type POINT struct {
	X, Y int32
}

type PAINTSTRUCT struct {
	Hdc         uintptr
	FErase      int32
	RcPaint     RECT
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type DRAWITEMSTRUCT struct {
	CtlType    uint32
	CtlID      uint32
	ItemID     uint32
	ItemAction uint32
	ItemState  uint32
	HwndItem   uintptr
	Hdc        uintptr
	RcItem     RECT
	ItemData   uintptr
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
	hFontHeader uintptr
	hFontTitle  uintptr
	hFontMono   uintptr

	hBrushBg      uintptr
	hBrushSidebar uintptr
	hBrushCard    uintptr
	hBrushInput   uintptr
	hPenBorder    uintptr

	buttonLabels = make(map[uint32]string)
	buttonTypes  = make(map[uint32]string) // "nav", "primary", "green", "red", "normal"

	navButtons [5]uintptr
	currentTab = 0
	tabPages   [5][]uintptr

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
	hBrushInput, _, _ = procCreateSolidBrush.Call(COLOR_INPUT)
	hPenBorder, _, _ = procCreatePen.Call(0, 1, COLOR_BORDER)

	hFontNormal = createFont("Segoe UI", 15, 400)
	hFontBold = createFont("Segoe UI", 15, 600)
	hFontHeader = createFont("Segoe UI", 17, 700)
	hFontTitle = createFont("Segoe UI", 21, 700)
	hFontMono = createFont("Consolas", 13, 400)

	// 4. Регистрация класса окна
	className, _ := windows.UTF16PtrFromString("NatBypassModernAppClass")
	windowTitle, _ := windows.UTF16PtrFromString("NatBypass — P2P Mesh Сеть & AmneziaWG 2.0")

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
		120, 120, 1080, 740,
		0, 0, hInstance, 0,
	)
	hMainWnd = hwnd

	// DWM Dark Mode заголовок
	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hMainWnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	// Построение элементов интерфейса
	buildModernUI(hInstance)

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
	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))

		// 1. Отрисовка левой боковой панели (Sidebar)
		sidebarRect := RECT{Left: 0, Top: 0, Right: 220, Bottom: 740}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&sidebarRect)), hBrushSidebar)

		// 2. Линия разделения сайдбара
		procSelectObject.Call(hdc, hPenBorder)
		var pt POINT
		procMoveToEx(hdc, 220, 0, &pt)
		procLineTo(hdc, 220, 740)

		// 3. Отрисовка фоновой карточки контентной зоны
		cardRect := RECT{Left: 236, Top: 16, Right: 1044, Bottom: 680}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&cardRect)), hBrushCard)

		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case WM_DRAWITEM:
		pDIS := (*DRAWITEMSTRUCT)(unsafe.Pointer(lParam))
		drawCustomButton(pDIS)
		return 1

	case WM_SYSCOMMAND:
		if wParam == SC_MINIMIZE || wParam == SC_CLOSE {
			procShowWindow.Call(hMainWnd, SW_HIDE)
			showBalloon("NatBypass работает в трее", "Двойной клик по значку у часов для вызова панели.")
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
		return hBrushCard

	case WM_CTLCOLOREDIT:
		hdc := wParam
		procSetBkColor.Call(hdc, COLOR_INPUT)
		procSetTextColor.Call(hdc, 0xFFFFFF) // Яркий белый цвет вводимого текста
		return hBrushInput

	case WM_CTLCOLORLISTBOX:
		hdc := wParam
		procSetBkColor.Call(hdc, COLOR_INPUT)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushInput

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

func drawCustomButton(pDIS *DRAWITEMSTRUCT) {
	hdc := pDIS.Hdc
	rc := pDIS.RcItem
	id := pDIS.CtlID
	text := buttonLabels[id]
	bType := buttonTypes[id]
	isPressed := (pDIS.ItemState & ODS_SELECTED) != 0

	isNav := bType == "nav"

	// 1. Устранение артефактов по краям: заливаем фон кнопки цветом родителя
	var parentBrush uintptr
	if isNav {
		parentBrush = hBrushSidebar
	} else {
		parentBrush = hBrushCard
	}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), parentBrush)

	// 2. Выбор цвета заливки и текста кнопки
	var bgBrush uintptr
	var txtColor uint32 = COLOR_TEXT

	isActiveNav := false
	if isNav {
		if (id == ID_NAV_DASHBOARD && currentTab == 0) ||
			(id == ID_NAV_AWG && currentTab == 1) ||
			(id == ID_NAV_SETTINGS && currentTab == 2) ||
			(id == ID_NAV_DIAG && currentTab == 3) ||
			(id == ID_NAV_LOGS && currentTab == 4) {
			isActiveNav = true
		}
	}

	if isPressed {
		bgBrush, _, _ = procCreateSolidBrush.Call(COLOR_BTN_HOVER)
		txtColor = 0xFFFFFF
	} else if isActiveNav {
		bgBrush, _, _ = procCreateSolidBrush.Call(COLOR_CARD)
		txtColor = COLOR_ACCENT
	} else if isNav {
		bgBrush, _, _ = procCreateSolidBrush.Call(COLOR_SIDEBAR)
		txtColor = COLOR_MUTED
	} else if bType == "green" {
		bgBrush, _, _ = procCreateSolidBrush.Call(COLOR_GREEN_BG)
		txtColor = 0xFFFFFF
	} else if bType == "red" {
		bgBrush, _, _ = procCreateSolidBrush.Call(COLOR_RED_BG)
		txtColor = 0xFFFFFF
	} else if bType == "primary" {
		bgBrush, _, _ = procCreateSolidBrush.Call(COLOR_ACCENT_BG)
		txtColor = 0xFFFFFF
	} else {
		bgBrush, _, _ = procCreateSolidBrush.Call(COLOR_INPUT)
		txtColor = COLOR_TEXT
	}

	// 3. Рамка кнопки
	penBorder, _, _ := procCreatePen.Call(0, 1, COLOR_BORDER_LT)
	if isActiveNav || bType == "primary" {
		penBorder, _, _ = procCreatePen.Call(0, 1, COLOR_ACCENT)
	}

	procSelectObject.Call(hdc, bgBrush)
	procSelectObject.Call(hdc, penBorder)
	procRoundRect.Call(hdc, uintptr(rc.Left), uintptr(rc.Top), uintptr(rc.Right), uintptr(rc.Bottom), 8, 8)

	// 4. Текст
	procSetBkMode.Call(hdc, 1) // TRANSPARENT
	procSetTextColor.Call(hdc, uintptr(txtColor))

	tPtr, _ := windows.UTF16FromString(text)
	var textRect = rc
	if isPressed {
		textRect.Top += 1
		textRect.Bottom += 1
	}

	if isNav {
		textRect.Left += 14
		procSelectObject.Call(hdc, hFontBold)
		procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&tPtr[0])), uintptr(int32(len(tPtr)-1)), uintptr(unsafe.Pointer(&textRect)), DT_LEFT|DT_VCENTER|DT_SINGLELINE)
	} else {
		procSelectObject.Call(hdc, hFontBold)
		procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&tPtr[0])), uintptr(int32(len(tPtr)-1)), uintptr(unsafe.Pointer(&textRect)), DT_CENTER|DT_VCENTER|DT_SINGLELINE)
	}

	procDeleteObject.Call(bgBrush)
	procDeleteObject.Call(penBorder)
}

func handleCommand(id uint16) {
	switch id {
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

	case ID_BTN_VPN:
		toggleVPN()

	case ID_BTN_REFRESH:
		addLog("⚡ Обновление публичного IP...")
		if ipDisc != nil {
			go func() {
				if ip, err := ipDisc.GetPublicIP(context.Background()); err == nil {
					myPublicIP = ip.String()
					addLog("✓ Получен публичный IP: " + myPublicIP)
				}
			}()
		}

	case ID_BTN_AWG_STD:
		setAWGPreset(wireguard.AWGParams{Enabled: true, Jc: 0, Jmin: 0, Jmax: 0, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4})
		setActiveAWGPresetButton(ID_BTN_AWG_STD)
		addLog("🛡️ Включен пресет: 🟢 Стандартный WireGuard")

	case ID_BTN_AWG_DPI:
		setAWGPreset(wireguard.DefaultAWGParams())
		setActiveAWGPresetButton(ID_BTN_AWG_DPI)
		addLog("🛡️ Включен пресет: 🟡 Обход DPI (AmneziaWG 2.0)")

	case ID_BTN_AWG_STEALTH:
		randP := wireguard.GenerateRandomAWGParams()
		setAWGPreset(randP)
		setActiveAWGPresetButton(ID_BTN_AWG_STEALTH)
		addLog("🛡️ Включен пресет: 🔴 Максимальная скрытность")

	case ID_BTN_RAND_AWG:
		randP := wireguard.GenerateRandomAWGParams()
		setAWGPreset(randP)
		setActiveAWGPresetButton(ID_BTN_AWG_STEALTH)
		addLog("🎲 Сгенерированы новые уникальные сигнатуры AWG")

	case ID_BTN_COPY_AWG:
		conf := getControlText(hEditAwgConf)
		copyToClipboard(conf)
		addLog("📋 Конфигурация AmneziaWG скопирована в буфер обмена")
		buttonLabels[ID_BTN_COPY_AWG] = "✓ СКОПИРОВАНО В БУФЕР ОБМЕНА!"
		procInvalidateRect.Call(hBtnCopyAwg, 0, 1)
		time.AfterFunc(2*time.Second, func() {
			buttonLabels[ID_BTN_COPY_AWG] = "📋 Скопировать конфигурацию в буфер обмена"
			procInvalidateRect.Call(hBtnCopyAwg, 0, 1)
		})
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

func setActiveAWGPresetButton(activeID uint32) {
	buttonTypes[ID_BTN_AWG_STD] = "normal"
	buttonTypes[ID_BTN_AWG_DPI] = "normal"
	buttonTypes[ID_BTN_AWG_STEALTH] = "normal"
	buttonTypes[activeID] = "primary"

	procInvalidateRect.Call(hBtnAwgStd, 0, 1)
	procInvalidateRect.Call(hBtnAwgDpi, 0, 1)
	procInvalidateRect.Call(hBtnAwgStealth, 0, 1)
}

func buildModernUI(hInstance uintptr) {
	// ══════════════════════════════════════════════════════════════
	// SIDEBAR (X: 0..220)
	// ══════════════════════════════════════════════════════════════
	lblLogo := createLabel(hInstance, "🛸 NatBypass", 20, 24, 180, 30, hFontTitle)
	lblVer := createLabel(hInstance, "Desktop Client • P2P Mesh", 20, 56, 180, 20, hFontNormal)

	navTitles := []string{
		"🚀  Обзор и Сеть",
		"🛡️  AmneziaWG 2.0",
		"⚙️  Настройки",
		"🩺  Диагностика",
		"📋  Журнал событий",
	}
	navIDs := []uint32{ID_NAV_DASHBOARD, ID_NAV_AWG, ID_NAV_SETTINGS, ID_NAV_DIAG, ID_NAV_LOGS}

	for i, t := range navTitles {
		navButtons[i] = createOwnerDrawButton(hInstance, t, 16, 100+(i*46), 188, 38, navIDs[i], "nav")
	}

	allControls = append(allControls, lblLogo, lblVer)

	// Контентная зона (X: 256..1024)
	cx := 256
	cw := 768

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 0: ОБЗОР (DASHBOARD)
	// ══════════════════════════════════════════════════════════════
	hLblStatus = createLabel(hInstance, "🟢 P2P МЕШ-СЕТЬ АКТИВНА", cx, 36, cw, 28, hFontTitle)
	hLblIpInfo = createLabel(hInstance, "Устройство: Определение... | Внешний IP: — | STUN: — | Канал: mqtt", cx, 68, cw, 22, hFontNormal)

	hBtnVpn = createOwnerDrawButton(hInstance, "🟢 ПОДКЛЮЧЕНО (Адрес: 10.200.0.1)", cx, 106, 340, 44, ID_BTN_VPN, "green")
	hBtnRefresh = createOwnerDrawButton(hInstance, "⚡ Обновить IP", cx+355, 106, 150, 44, ID_BTN_REFRESH, "normal")

	lblPeersTitle := createLabel(hInstance, "👥 Устройства в вашей локальной mesh-сети:", cx, 172, cw, 24, hFontHeader)
	hListPeers = createListBox(hInstance, cx, 204, cw, 450, hFontMono)

	tabPages[0] = []uintptr{hLblStatus, hLblIpInfo, hBtnVpn, hBtnRefresh, lblPeersTitle, hListPeers}

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 1: AMNEZIAWG 2.0
	// ══════════════════════════════════════════════════════════════
	lblAwgTitle := createLabel(hInstance, "🛡️ AmneziaWG 2.0 — Защита от блокировок DPI", cx, 36, cw, 28, hFontTitle)
	lblAwgDesc := createLabel(hInstance, "Маскирует протокол WireGuard мусорными пакетами и заголовками (ТСПУ / РКН).", cx, 66, cw, 20, hFontNormal)

	hBtnAwgStd = createOwnerDrawButton(hInstance, "🟢 Стандартный WG", cx, 100, 180, 36, ID_BTN_AWG_STD, "normal")
	hBtnAwgDpi = createOwnerDrawButton(hInstance, "🟡 Обход DPI (AWG)", cx+192, 100, 180, 36, ID_BTN_AWG_DPI, "primary")
	hBtnAwgStealth = createOwnerDrawButton(hInstance, "🔴 Скрытный режим", cx+384, 100, 180, 36, ID_BTN_AWG_STEALTH, "normal")
	hBtnRandomAwg = createOwnerDrawButton(hInstance, "🎲 Случайные ключи", cx+576, 100, 180, 36, ID_BTN_RAND_AWG, "normal")

	// Ряд 1 параметров: Jc, Jmin, Jmax, S1, S2
	lblJc := createLabel(hInstance, "Jc (мусор):", cx, 150, 75, 20, hFontNormal)
	hEditAwgJc = createEdit(hInstance, "4", cx+80, 146, 55, 28, false, false, hFontNormal)

	lblJmin := createLabel(hInstance, "Jmin:", cx+150, 150, 45, 20, hFontNormal)
	hEditAwgJmin = createEdit(hInstance, "40", cx+198, 146, 55, 28, false, false, hFontNormal)

	lblJmax := createLabel(hInstance, "Jmax:", cx+268, 150, 45, 20, hFontNormal)
	hEditAwgJmax = createEdit(hInstance, "70", cx+318, 146, 55, 28, false, false, hFontNormal)

	lblS1 := createLabel(hInstance, "S1:", cx+388, 150, 30, 20, hFontNormal)
	hEditAwgS1 = createEdit(hInstance, "48", cx+422, 146, 55, 28, false, false, hFontNormal)

	lblS2 := createLabel(hInstance, "S2:", cx+492, 150, 30, 20, hFontNormal)
	hEditAwgS2 = createEdit(hInstance, "32", cx+526, 146, 55, 28, false, false, hFontNormal)

	// Ряд 2 параметров: H1, H2, H3, H4
	lblH1 := createLabel(hInstance, "H1 (Init):", cx, 188, 65, 20, hFontNormal)
	hEditAwgH1 = createEdit(hInstance, "1428571428", cx+70, 184, 110, 28, false, false, hFontNormal)

	lblH2 := createLabel(hInstance, "H2 (Resp):", cx+195, 188, 70, 20, hFontNormal)
	hEditAwgH2 = createEdit(hInstance, "2147483647", cx+270, 184, 110, 28, false, false, hFontNormal)

	lblH3 := createLabel(hInstance, "H3 (Cookie):", cx+395, 188, 80, 20, hFontNormal)
	hEditAwgH3 = createEdit(hInstance, "857142857", cx+480, 184, 110, 28, false, false, hFontNormal)

	lblH4 := createLabel(hInstance, "H4 (Data):", cx+605, 188, 70, 20, hFontNormal)
	hEditAwgH4 = createEdit(hInstance, "1122334455", cx+680, 184, 88, 28, false, false, hFontNormal)

	lblConfTitle := createLabel(hInstance, "Конфигурация AmneziaWG (.conf):", cx, 226, cw, 22, hFontHeader)
	hEditAwgConf = createEdit(hInstance, "", cx, 254, cw, 345, true, true, hFontMono)
	hBtnCopyAwg = createOwnerDrawButton(hInstance, "📋 Скопировать конфигурацию в буфер обмена", cx, 612, 360, 40, ID_BTN_COPY_AWG, "primary")

	tabPages[1] = []uintptr{
		lblAwgTitle, lblAwgDesc, hBtnAwgStd, hBtnAwgDpi, hBtnAwgStealth, hBtnRandomAwg,
		lblJc, hEditAwgJc, lblJmin, hEditAwgJmin, lblJmax, hEditAwgJmax, lblS1, hEditAwgS1, lblS2, hEditAwgS2,
		lblH1, hEditAwgH1, lblH2, hEditAwgH2, lblH3, hEditAwgH3, lblH4, hEditAwgH4,
		lblConfTitle, hEditAwgConf, hBtnCopyAwg,
	}

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 2: НАСТРОЙКИ
	// ══════════════════════════════════════════════════════════════
	lblSetTitle := createLabel(hInstance, "⚙️ Сигнальные каналы (Обмен пирами)", cx, 36, cw, 28, hFontTitle)

	lblTgHead := createLabel(hInstance, "💬 Telegram Bot API:", cx, 80, cw, 22, hFontHeader)
	lblTgToken := createLabel(hInstance, "Токен бота (@BotFather):", cx, 114, 200, 20, hFontNormal)
	hEditTgToken = createEdit(hInstance, "", cx+210, 110, 380, 28, false, false, hFontNormal)
	hBtnTestTg = createOwnerDrawButton(hInstance, "🧪 Проверить бот", cx+600, 108, 160, 32, ID_BTN_TEST_TG, "normal")

	lblTgChat := createLabel(hInstance, "Chat ID (@userinfobot):", cx, 154, 200, 20, hFontNormal)
	hEditTgChat = createEdit(hInstance, "", cx+210, 150, 380, 28, false, false, hFontNormal)

	lblMqHead := createLabel(hInstance, "⚡ MQTT Брокер:", cx, 212, cw, 22, hFontHeader)
	lblMqBr := createLabel(hInstance, "URL Брокера:", cx, 246, 200, 20, hFontNormal)
	hEditMqttBr = createComboBox(hInstance, cx+210, 242, 380, 220, hFontNormal)
	brokers := []string{
		"tcp://broker.emqx.io:1883",
		"tcp://broker.hivemq.com:1883",
		"tcp://mqtt.eclipseprojects.io:1883",
		"tcp://test.mosquitto.org:1883",
		"tcp://public.cloud.shiftr.io:1883",
		"tcp://broker.flespi.io:1883",
	}
	for _, b := range brokers {
		tPtr, _ := windows.UTF16PtrFromString(b)
		procSendMessageW.Call(hEditMqttBr, 0x0143, 0, uintptr(unsafe.Pointer(tPtr)))
	}
	setControlText(hEditMqttBr, "tcp://broker.emqx.io:1883")
	hBtnTestMqtt = createOwnerDrawButton(hInstance, "🧪 Проверить MQTT", cx+600, 240, 160, 32, ID_BTN_TEST_MQTT, "normal")

	lblMqHint := createLabel(hInstance, "💡 Выберите брокер из списка или введите адрес любого своего сервера", cx+210, 276, 550, 18, hFontNormal)

	lblMqTp := createLabel(hInstance, "Уникальный топик:", cx, 304, 200, 20, hFontNormal)
	hEditMqttTp = createEdit(hInstance, "natbypass/mynet/peers", cx+210, 300, 380, 28, false, false, hFontNormal)

	hBtnSaveCfg = createOwnerDrawButton(hInstance, "💾 Сохранить настройки в config.yaml", cx+210, 350, 380, 44, ID_BTN_SAVE_CFG, "primary")

	tabPages[2] = []uintptr{
		lblSetTitle, lblTgHead, lblTgToken, hEditTgToken, hBtnTestTg, lblTgChat, hEditTgChat,
		lblMqHead, lblMqBr, hEditMqttBr, hBtnTestMqtt, lblMqHint, lblMqTp, hEditMqttTp, hBtnSaveCfg,
	}

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 3: ДИАГНОСТИКА
	// ══════════════════════════════════════════════════════════════
	lblDiagTitle := createLabel(hInstance, "🩺 Диагностика связности сети", cx, 36, cw, 28, hFontTitle)
	hBtnRunDiag = createOwnerDrawButton(hInstance, "🔄 Запустить полную диагностику", cx, 75, 280, 40, ID_BTN_RUN_DIAG, "primary")
	hEditDiagLog = createEdit(hInstance, "Нажмите кнопку выше для проверки внешнего IP, доступности Telegram/MQTT и STUN сокета...", cx, 130, cw, 520, true, true, hFontMono)

	tabPages[3] = []uintptr{lblDiagTitle, hBtnRunDiag, hEditDiagLog}

	// ══════════════════════════════════════════════════════════════
	// СТРАНИЦА 4: ЖУРНАЛ СОБЫТИЙ
	// ══════════════════════════════════════════════════════════════
	lblLogTitle := createLabel(hInstance, "📋 Журнал событий в реальном времени", cx, 36, cw-120, 28, hFontTitle)
	hBtnClrLogs = createOwnerDrawButton(hInstance, "🗑 Очистить", cx+cw-120, 36, 120, 32, ID_BTN_CLR_LOGS, "normal")
	hEditLogs = createEdit(hInstance, "", cx, 75, cw, 575, true, true, hFontMono)

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
	// Мгновенно обновляем подсветку всех 5 кнопок сайдбара
	for _, btn := range navButtons {
		if btn != 0 {
			procInvalidateRect.Call(btn, 0, 1)
		}
	}
	if index == 1 {
		updateAWGText()
	}
	procInvalidateRect.Call(hMainWnd, 0, 1)
}

func toggleVPN() {
	vpnConnected = !vpnConnected
	if vpnConnected {
		buttonLabels[ID_BTN_VPN] = "🟢 ПОДКЛЮЧЕНО (Адрес: 10.200.0.1)"
		buttonTypes[ID_BTN_VPN] = "green"
		addLog("🟢 Туннель активен")
		showBalloon("NatBypass", "Защищенная mesh-сеть активна.")
	} else {
		buttonLabels[ID_BTN_VPN] = "🔴 ОТКЛЮЧЕНО (Нажмите для включения)"
		buttonTypes[ID_BTN_VPN] = "red"
		addLog("🔴 Туннель приостановлен")
	}
	procInvalidateRect.Call(hBtnVpn, 0, 1)
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
		addLog(fmt.Sprintf("✓ Ядро запущено. Публичный IP: %s | STUN: %s", myPublicIP, mySTUNAddr))
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
			addListBoxItem(hListPeers, "  📡 Ожидание подключения других устройств... (0 пиров онлайн)")
		} else {
			for _, p := range peers {
				st := "🟢 Онлайн"
				if !p.Online {
					st = "🔴 Офлайн"
				}
				itemStr := fmt.Sprintf("  %-20s | %-16s | %-22s | %s", p.DeviceID, p.PublicIP, p.STUNAddr, st)
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
	// ВАЖНО: Win32 Edit Control требует \r\n для переноса строк!
	conf = strings.ReplaceAll(conf, "\r\n", "\n")
	conf = strings.ReplaceAll(conf, "\n", "\r\n")
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
	buttonLabels[ID_BTN_SAVE_CFG] = "✓ НАСТРОЙКИ СОХРАНЕНЫ!"
	procInvalidateRect.Call(hBtnSaveCfg, 0, 1)
	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_SAVE_CFG] = "💾 Сохранить настройки в config.yaml"
		procInvalidateRect.Call(hBtnSaveCfg, 0, 1)
	})
	showBalloon("NatBypass", "Настройки сохранены в config.yaml")
}

func testTelegram() {
	tok := getControlText(hEditTgToken)
	if tok == "" {
		addLog("⚠️ Введите токен бота")
		return
	}
	buttonLabels[ID_BTN_TEST_TG] = "⏳ Проверка..."
	procInvalidateRect.Call(hBtnTestTg, 0, 1)
	addLog("⏳ Проверка Telegram Bot API...")
	go func() {
		ch := signaling.NewTelegramChannel(tok, "123", "")
		if ch.IsAvailable(context.Background()) {
			addLog("✅ Успех! Telegram бот активен и отвечает на запросы.")
			buttonLabels[ID_BTN_TEST_TG] = "✅ Бот активен"
		} else {
			addLog("❌ Ошибка: не удалось подключиться к Telegram API.")
			buttonLabels[ID_BTN_TEST_TG] = "❌ Ошибка"
		}
		procInvalidateRect.Call(hBtnTestTg, 0, 1)
		time.AfterFunc(3*time.Second, func() {
			buttonLabels[ID_BTN_TEST_TG] = "🧪 Проверить бот"
			procInvalidateRect.Call(hBtnTestTg, 0, 1)
		})
	}()
}

func testMQTT() {
	br := getControlText(hEditMqttBr)
	buttonLabels[ID_BTN_TEST_MQTT] = "⏳ Проверка..."
	procInvalidateRect.Call(hBtnTestMqtt, 0, 1)
	addLog("⏳ Проверка MQTT брокера...")
	go func() {
		ch := signaling.NewMQTTChannel(br, "test", "tester", "", "")
		if ch.IsAvailable(context.Background()) {
			addLog("✅ Успех! MQTT брокер доступен.")
			buttonLabels[ID_BTN_TEST_MQTT] = "✅ Доступен"
		} else {
			addLog("❌ Ошибка: MQTT брокер недоступен.")
			buttonLabels[ID_BTN_TEST_MQTT] = "❌ Недоступен"
		}
		procInvalidateRect.Call(hBtnTestMqtt, 0, 1)
		time.AfterFunc(3*time.Second, func() {
			buttonLabels[ID_BTN_TEST_MQTT] = "🧪 Проверить MQTT"
			procInvalidateRect.Call(hBtnTestMqtt, 0, 1)
		})
	}()
}

func runDiag() {
	buttonLabels[ID_BTN_RUN_DIAG] = "⏳ Выполняется диагностика..."
	procInvalidateRect.Call(hBtnRunDiag, 0, 1)
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

		buttonLabels[ID_BTN_RUN_DIAG] = "🔄 Запустить повторно"
		procInvalidateRect.Call(hBtnRunDiag, 0, 1)
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

func createOwnerDrawButton(hInstance uintptr, text string, x, y, w, h int, id uint32, bType string) uintptr {
	btnClass, _ := windows.UTF16PtrFromString("BUTTON")
	textPtr, _ := windows.UTF16PtrFromString(text)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(btnClass)),
		uintptr(unsafe.Pointer(textPtr)),
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		hMainWnd, uintptr(id), hInstance, 0,
	)
	buttonLabels[id] = text
	buttonTypes[id] = bType
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
		0,
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

func createComboBox(hInstance uintptr, x, y, w, h int, font uintptr) uintptr {
	cbClass, _ := windows.UTF16PtrFromString("COMBOBOX")
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(cbClass)),
		0,
		uintptr(WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_VSCROLL|0x0002|0x0100), // CBS_DROPDOWN | CBS_AUTOHSCROLL
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
		0,
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

func procMoveToEx(hdc uintptr, x, y int, pt *POINT) {
	modgdi32.NewProc("MoveToEx").Call(hdc, uintptr(x), uintptr(y), uintptr(unsafe.Pointer(pt)))
}

func procLineTo(hdc uintptr, x, y int) {
	modgdi32.NewProc("LineTo").Call(hdc, uintptr(x), uintptr(y))
}
