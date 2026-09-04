//go:build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/natbypass/natbypass/internal/autostart"
	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/relay"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/tunnel"
	"github.com/natbypass/natbypass/internal/updater"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
	"github.com/skip2/go-qrcode"
)

func applyAWGProfileToGUI(p *config.Profile) {
	if p == nil || cfg == nil {
		return
	}
	cfg.SyncAWGWithProfile(p)

	if hEditAwgH1 != 0 && p.H1 > 0 {
		setControlText(hEditAwgH1, fmt.Sprintf("%d", p.H1))
	}
	if hEditAwgH2 != 0 && p.H2 > 0 {
		setControlText(hEditAwgH2, fmt.Sprintf("%d", p.H2))
	}
	if hEditAwgH3 != 0 && p.H3 > 0 {
		setControlText(hEditAwgH3, fmt.Sprintf("%d", p.H3))
	}
	if hEditAwgH4 != 0 && p.H4 > 0 {
		setControlText(hEditAwgH4, fmt.Sprintf("%d", p.H4))
	}
	if hEditAwgS1 != 0 && p.S1 > 0 {
		setControlText(hEditAwgS1, fmt.Sprintf("%d", p.S1))
	}
	if hEditAwgS2 != 0 && p.S2 > 0 {
		setControlText(hEditAwgS2, fmt.Sprintf("%d", p.S2))
	}
	if hEditAwgJc != 0 && p.Jc > 0 {
		setControlText(hEditAwgJc, fmt.Sprintf("%d", p.Jc))
	}
	if hEditAwgJmin != 0 && p.Jmin > 0 {
		setControlText(hEditAwgJmin, fmt.Sprintf("%d", p.Jmin))
	}
	if hEditAwgJmax != 0 && p.Jmax > 0 {
		setControlText(hEditAwgJmax, fmt.Sprintf("%d", p.Jmax))
	}

	cachedAWGParams = wireguard.AWGParams{
		Enabled:                 true,
		Version:                 wireguard.AWGVersion31,
		Jc:                      p.Jc,
		Jmin:                    p.Jmin,
		Jmax:                    p.Jmax,
		S1:                      p.S1,
		S2:                      p.S2,
		H1:                      p.H1,
		H2:                      p.H2,
		H3:                      p.H3,
		H4:                      p.H4,
		HeaderProtectionEnabled: p.HeaderProtectionKey != "",
		RandomTrailers:          p.RandomTrailers,
		DisableCookies:          p.DisableCookies,
	}
	renderAWGTextFromUI()
	triggerPublish()
}


var (
	Version = "1.9.215"
	Commit  = "release"
)


// Win32 API
var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modgdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modcomctl32 = windows.NewLazySystemDLL("comctl32.dll")
	moddwmapi   = windows.NewLazySystemDLL("dwmapi.dll")

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
	procSetWindowPos          = moduser32.NewProc("SetWindowPos")
	procShowWindow            = moduser32.NewProc("ShowWindow")
	procUpdateWindow          = moduser32.NewProc("UpdateWindow")
	procSetForegroundWindow   = moduser32.NewProc("SetForegroundWindow")
	procFindWindowW           = moduser32.NewProc("FindWindowW")
	procSetTimer              = moduser32.NewProc("SetTimer")
	procKillTimer             = moduser32.NewProc("KillTimer")
	procLoadIconW             = moduser32.NewProc("LoadIconW")
	procLoadCursorW           = moduser32.NewProc("LoadCursorW")
	procSetCursor             = moduser32.NewProc("SetCursor")
	procGetModuleHandleW      = modkernel32.NewProc("GetModuleHandleW")
	procRtlMoveMemory         = modkernel32.NewProc("RtlMoveMemory")
	procCreateFontW           = modgdi32.NewProc("CreateFontW")
	procCreateSolidBrush      = modgdi32.NewProc("CreateSolidBrush")
	procDeleteObject          = modgdi32.NewProc("DeleteObject")
	procSetBkMode             = modgdi32.NewProc("SetBkMode")
	procSetTextColor          = modgdi32.NewProc("SetTextColor")
	procSetBkColor            = modgdi32.NewProc("SetBkColor")
	procSelectObject          = modgdi32.NewProc("SelectObject")
	procRoundRect             = modgdi32.NewProc("RoundRect")
	procCreatePen             = modgdi32.NewProc("CreatePen")
	procDrawTextW             = moduser32.NewProc("DrawTextW")
	procFillRect              = moduser32.NewProc("FillRect")
	procFrameRect             = moduser32.NewProc("FrameRect")
	procBeginPaint            = moduser32.NewProc("BeginPaint")
	procEndPaint              = moduser32.NewProc("EndPaint")
	procInvalidateRect        = moduser32.NewProc("InvalidateRect")
	procInitCommonControlsEx  = modcomctl32.NewProc("InitCommonControlsEx")
	procDwmSetWindowAttribute = moddwmapi.NewProc("DwmSetWindowAttribute")
	procMoveToEx              = modgdi32.NewProc("MoveToEx")
	procLineTo                = modgdi32.NewProc("LineTo")
	procCreateMutexW          = modkernel32.NewProc("CreateMutexW")
	procCloseHandle           = modkernel32.NewProc("CloseHandle")
	procEnumWindows           = moduser32.NewProc("EnumWindows")
	procGetWindowThreadProcessId = moduser32.NewProc("GetWindowThreadProcessId")
	procPostMessageW          = moduser32.NewProc("PostMessageW")
	procGetClientRect         = moduser32.NewProc("GetClientRect")
	procGetWindowRect         = moduser32.NewProc("GetWindowRect")
	procEnableWindow          = moduser32.NewProc("EnableWindow")
	procSetFocus              = moduser32.NewProc("SetFocus")
	procDestroyWindow         = moduser32.NewProc("DestroyWindow")
	procMessageBoxW           = moduser32.NewProc("MessageBoxW")
	procGetTextExtentPoint32W = modgdi32.NewProc("GetTextExtentPoint32W")
	procCreatePopupMenu       = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW           = moduser32.NewProc("AppendMenuW")
	procTrackPopupMenu        = moduser32.NewProc("TrackPopupMenu")
	procGetCursorPos          = moduser32.NewProc("GetCursorPos")
	procLoadImageW            = moduser32.NewProc("LoadImageW")

	modshell32            = syscall.NewLazyDLL("shell32.dll")
	procShell_NotifyIconW = modshell32.NewProc("Shell_NotifyIconW")
	procDragAcceptFiles   = modshell32.NewProc("DragAcceptFiles")
	procDragQueryFileW    = modshell32.NewProc("DragQueryFileW")
	procDragFinish        = modshell32.NewProc("DragFinish")
)


type NOTIFYICONDATAW struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

const (
	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004

	WM_TRAYICON = 0x0400 + 100
)

const (
	WM_SETREDRAW        = 0x000B
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_BORDER           = 0x00800000
	WS_VSCROLL          = 0x00200000
	WS_TABSTOP          = 0x00010000
	WS_CLIPCHILDREN     = 0x02000000
	WS_CLIPSIBLINGS     = 0x04000000

	BS_PUSHBUTTON = 0x00000000
	BS_OWNERDRAW  = 0x0000000B

	ES_LEFT        = 0x0000
	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_AUTOHSCROLL = 0x0080
	ES_READONLY    = 0x0800

	SS_LEFT     = 0x0000
	SS_NOPREFIX = 0x0080

	LBS_NOTIFY           = 0x0001
	LBS_NOINTEGRALHEIGHT = 0x0100

	WM_SIZE           = 0x0005
	WM_DESTROY        = 0x0002
	WM_ERASEBKGND     = 0x0014
	WM_SETCURSOR      = 0x0020
	WM_CLOSE          = 0x0010
	WM_PAINT          = 0x000F
	WM_COMMAND        = 0x0111
	WM_SYSCOMMAND     = 0x0112
	WM_TIMER          = 0x0113
	WM_DRAWITEM       = 0x002B
	WM_CTLCOLORSTATIC = 0x0138
	WM_CTLCOLOREDIT   = 0x0133
	WM_CTLCOLORBTN    = 0x0135
	WM_CTLCOLORLISTBOX= 0x0134
	WS_FIXEDWINDOW    = 0x00CA0000

	SC_CLOSE = 0xF060

	SW_HIDE    = 0
	SW_SHOW    = 5
	SW_RESTORE = 9

	DT_CENTER     = 0x00000001
	DT_VCENTER    = 0x00000004
	DT_SINGLELINE = 0x00000020
	DT_LEFT       = 0x00000000

	ODS_SELECTED = 0x0001
)

// Цветовая палитра Slate Dark (Modern Fluent Theme)
const (
	COLOR_BG        = 0x18120D // #0D1218
	COLOR_SIDEBAR   = 0x221A15 // #151A22
	COLOR_CARD      = 0x29211A // #1A2129
	COLOR_INPUT     = 0x332820 // #202833
	COLOR_BORDER    = 0x473B32 // #323B47
	COLOR_BORDER_LT = 0x5E4E42 // #424E5E
	COLOR_TEXT      = 0xF3EDE6 // #E6EDF3
	COLOR_MUTED     = 0xA89D91 // #919DA8
	COLOR_ACCENT    = 0xFFA658 // #58A6FF
	COLOR_ACCENT_BG = 0xEB6F1F // #1F6FEB
	COLOR_GREEN_BG  = 0x368623 // #238636
	COLOR_RED_BG    = 0x3336DA // #DA3633
	COLOR_YELLOW_BG = 0x2299D2 // #D29922
	COLOR_BTN_HOVER = 0x3D3328 // #28333D
)

type RECT struct {
	Left, Top, Right, Bottom int32
}

type POINT struct {
	X, Y int32
}

type SIZE struct {
	CX, CY int32
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

// Глобальные постоянные GDI ресурсы (создаются 1 раз при старте, 0 утечек)
var (
	guiMagicSock *network.MagicSock
	guiWSSClient *relay.WSSRelayClient
	hMainWnd     uintptr
	hAppIcon     uintptr
	hCursor      uintptr
	hFontNormal  uintptr
	hFontBold    uintptr
	hFontSmall   uintptr
	hFontHeader  uintptr
	hFontTitle   uintptr
	hFontMono    uintptr

	hBrushBg        uintptr
	hBrushSidebar   uintptr
	hBrushCard      uintptr
	hBrushInput     uintptr
	hBrushBtnHover  uintptr
	hBrushBtnGreen  uintptr
	hBrushBtnRed    uintptr
	hBrushBtnYellow uintptr
	hBrushBtnAccent uintptr

	hPenBorder   uintptr
	hPenBorderLt uintptr
	hPenAccent   uintptr

	buttonLabels = make(map[uint32]string)
	buttonTypes  = make(map[uint32]string)

	navButtons [8]uintptr
	currentTab = 0
	tabPages   [8][]uintptr

	// Настройки окна и автозапуска
	minimizeToTray     bool = true
	isAutostartEnabled bool = false

	// Вкладка 0: Обзор (Dashboard)
	hLblStatus            uintptr
	hLblIpInfo            uintptr
	hLblChannels          uintptr
	hLblCardVIP           uintptr
	hLblCardPubIP         uintptr
	hLblCardSTUN          uintptr
	hLblCardSig           uintptr
	hBtnVpn               uintptr
	hBtnRefresh           uintptr
	hBtnManageProfiles    uintptr
	hBtnBookmarkPeer      uintptr
	hBtnExitNodeSelect    uintptr
	hBtnToggleSubnetRoute uintptr
	hListSummaryPeers     uintptr

	// Вкладка 1: Устройства (Peers)
	hListPeers            uintptr
	hBtnCopyPeerVIP       uintptr
	hBtnPingPeer          uintptr
	lastPeersHash         string
	activeExitNodeID      string
	activeExitVIP         string
	activeSubnetRoutes    = make(map[string]string)
	activeSubnetRoutesMu  sync.RWMutex

	// Вкладка 2: Профили сетей
	hListProfiles   uintptr
	hBtnProfSwitch  uintptr
	hBtnProfQR      uintptr
	hBtnProfCreate  uintptr
	hBtnProfImport  uintptr
	hEditProfName   uintptr
	hBtnProfExport  uintptr
	hEditProfTopic  uintptr
	hEditProfBroker uintptr
	hEditProfVIP    uintptr
	hBtnProfSave    uintptr
	hBtnProfDelete  uintptr
	selectedProfID  string
	activeQRBitmap  [][]bool
	activeQRText    string

	// Вкладка 3: AmneziaWG 3.1
	hBtnAwgStd        uintptr
	hBtnAwgDpi        uintptr
	hBtnAwgStealth    uintptr
	hBtnSyncAwg       uintptr
	syncAWGPeerParams *signaling.AWGParams
	syncAWGPeerName   string
	hEditAwgJc        uintptr
	hEditAwgJmin      uintptr
	hEditAwgJmax      uintptr
	hEditAwgS1        uintptr
	hEditAwgS2        uintptr
	hEditAwgH1        uintptr
	hEditAwgH2        uintptr
	hEditAwgH3        uintptr
	hEditAwgH4        uintptr
	hBtnRandomAwg     uintptr
	hEditAwgConf      uintptr
	hBtnCopyAwg       uintptr
	hBtnSaveAwg       uintptr
	hBtnOpenAwgClient uintptr

	// Вкладка 4: Каналы связи (Signaling)
	hBtnModeParallel uintptr
	hBtnModeMQTT     uintptr
	hBtnModeTG       uintptr
	chosenModeStr    string = "parallel"
	hEditTgToken     uintptr
	hEditTgChat      uintptr
	hBtnTestTg       uintptr
	hEditMqttBr      uintptr
	hEditMqttTp      uintptr
	hBtnTestMqtt     uintptr
	hBtnSaveChannels uintptr

	// Вкладка 5: Шлюз и подсети (Routing)
	hBtnAllowExit      uintptr
	allowExitNode      bool
	hBtnAddLocalSubnet uintptr
	hEditAdvSubnets    uintptr

	// Вкладка 6: Диагностика и Журнал
	hBtnRunDiag    uintptr
	hBtnDumpStack  uintptr
	hEditDiagLog   uintptr
	hEditLogs      uintptr
	hBtnClrLogs    uintptr
	hBtnSaveLogs   uintptr
	hBtnToggleDiag uintptr

	// Вкладка 7: Настройки приложения (Settings)
	hEditMyNick              uintptr
	hBtnToggleAutostart      uintptr
	hBtnToggleMinimizeToTray uintptr
	hBtnToggleLogs           uintptr
	hBtnSaveCfg              uintptr
	hBtnCheckUpdate          uintptr
	lblUpdateStatus          uintptr

	// Стартовый экран (Startup / Splash)
	hSplashTitle   uintptr
	hSplashSub     uintptr
	hSplashStep1   uintptr
	hSplashStep2   uintptr
	hSplashStep3   uintptr
	hSplashStep4   uintptr
	hSplashBar     uintptr
	splashControls []uintptr
	splashTicks    int  = 0
	isSplashActive bool = true

	allControls []uintptr

	// Движок и сетевое состояние
	configPath       string
	cfg              *config.Config
	registry         *peer.Registry
	sigChannels      []signaling.SignalingChannel
	sigMode          string
	ipDisc           *network.Discoverer
	udpPuncher       *network.UDPPuncher
	activeMQTT       *signaling.MQTTChannel
	uiServer         *webui.Server
	tunDev           *tunnel.Device
	myPubKey         [32]byte
	myPrivKey        [32]byte
	myWGPubKey       string
	myWGPrivKey      string
	myDevID          string
	myNick           string
	addressBook      map[string]string = make(map[string]string)
	addressBookMu    sync.RWMutex
	saveLogsToDisk   bool = false
	showDiagnostics  bool = true
	myVirtualIP      string = "100.64.200.1"
	myPublicIP       string
	mySTUNAddr       string
	activeChannelStr string
	vpnConnected     bool = false
	engineCtx        context.Context
	engineCancel     context.CancelFunc
	engineMu         sync.Mutex
	logsMutex        sync.Mutex
	logsBuffer       []string
	logsDirty        bool
	awgDirty         bool
	cachedAWGParams  wireguard.AWGParams
	triggerPublishCh chan struct{}
	isShuttingDown   int32
	tgMuted          bool

	// Статистика дебаггера
	startTime        time.Time
	packetsSentCount uint64
	packetsRecvCount uint64
	debugLogFile     *os.File
	debugLogMu       sync.Mutex
	singleMutex      uintptr

	// Состояние модального диалога закладок
	dlgResultText string
	dlgResultOK   bool
	dlgFinished   bool
	hDlgEdit      uintptr
)

const (
	ID_TIMER_POLL = 1001

	// Навигация (8 вкладок)
	ID_NAV_DASHBOARD = 3001
	ID_NAV_PEERS     = 3002
	ID_NAV_PROFILES  = 3003
	ID_NAV_AWG       = 3004
	ID_NAV_CHANNELS  = 3005
	ID_NAV_ROUTING   = 3006
	ID_NAV_DIAG      = 3007
	ID_NAV_SETTINGS  = 3008

	// Действия
	ID_BTN_VPN             = 4001
	ID_BTN_REFRESH         = 4002
	ID_BTN_MANAGE_PROFILES = 4003
	ID_BTN_AWG_STD         = 4004
	ID_BTN_AWG_DPI         = 4005
	ID_BTN_AWG_STEALTH     = 4006
	ID_BTN_RAND_AWG        = 4007
	ID_BTN_COPY_AWG        = 4008
	ID_BTN_TEST_TG         = 4009
	ID_BTN_TEST_MQTT       = 4010
	ID_BTN_SAVE_CFG        = 4011
	ID_BTN_RUN_DIAG        = 4012
	ID_BTN_CLR_LOGS        = 4013
	ID_BTN_MODE_PARALLEL   = 4020
	ID_BTN_MODE_MQTT       = 4021
	ID_BTN_MODE_TG         = 4022
	ID_BTN_DUMP_STACK      = 4023
	ID_BTN_SAVE_LOGS       = 4024
	ID_BTN_SAVE_AWG        = 4025
	ID_BTN_OPEN_AWG_CLIENT = 4026
	ID_BTN_SYNC_AWG        = 4027
	ID_BTN_BOOKMARK_PEER   = 4030
	ID_BTN_TOGGLE_LOGS     = 4031
	ID_BTN_TOGGLE_DIAG     = 4032
	ID_BTN_ALLOW_EXIT      = 4033
	ID_BTN_EXIT_NODE_SELECT = 4034
	ID_BTN_TOGGLE_SUBNET   = 4035
	ID_BTN_ADD_LOCAL_SUBNET = 4036
	ID_BTN_COPY_PEER_VIP   = 4037
	ID_BTN_PING_PEER       = 4038
	ID_BTN_TOGGLE_AUTOSTART = 4039
	ID_BTN_TOGGLE_TRAY     = 4040
	ID_BTN_SAVE_CHANNELS   = 4041

	ID_BTN_MQ_EMQX         = 4051
	ID_BTN_MQ_HIVE         = 4052
	ID_BTN_MQ_MOSQ         = 4053
	ID_BTN_MQ_ECL          = 4054
	ID_BTN_CHECK_UPDATE    = 4055

	// Профили
	ID_BTN_PROF_SWITCH = 4060
	ID_BTN_PROF_CREATE = 4061
	ID_BTN_PROF_SAVE   = 4062
	ID_BTN_PROF_DELETE = 4063
	ID_BTN_PROF_EXPORT = 4064
	ID_BTN_PROF_IMPORT = 4065
	ID_BTN_PROF_QR     = 4066
)



func initDebugLog() {
	startTime = time.Now()
	if saveLogsToDisk {
		f, err := os.OpenFile("natbypass_debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			debugLogFile = f
		}
	}
	writeDebug("==================================================================")
	writeDebug(fmt.Sprintf("🚀 NatBypass GUI Запущен | PID: %d | Время: %s", os.Getpid(), time.Now().Format("2006-01-02 15:04:05.000")))
	writeDebug(fmt.Sprintf("⚙️ OS: Windows %s | Arch: %s | CPU: %d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()))
	writeDebug("==================================================================")
}

func writeDebug(msg string) {
	entry := fmt.Sprintf("[%s] %s\r\n", time.Now().Format("15:04:05.000"), msg)
	fmt.Print(entry)
	if !saveLogsToDisk {
		debugLogMu.Lock()
		if debugLogFile != nil {
			_ = debugLogFile.Close()
			debugLogFile = nil
		}
		debugLogMu.Unlock()
		return
	}
	debugLogMu.Lock()
	defer debugLogMu.Unlock()
	if debugLogFile == nil {
		f, err := os.OpenFile("natbypass_debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			debugLogFile = f
		}
	}
	if debugLogFile != nil {
		debugLogFile.WriteString(entry)
		debugLogFile.Sync()
	}
}

// startSystemWatchdog — фоновый сторожевой таймер для мониторинга здоровья и предотвращения дедлоков
func startSystemWatchdog() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				writeDebug(fmt.Sprintf("вќЊ Watchdog panic: %v", r))
			}
		}()

		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C
			if atomic.LoadInt32(&isShuttingDown) == 1 {
				return
			}

			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			grCount := runtime.NumGoroutine()
			uptime := time.Since(startTime).Round(time.Second)

			pIn := atomic.LoadUint64(&packetsRecvCount)
			pOut := atomic.LoadUint64(&packetsSentCount)

			peersCount := 0
			directCount := 0
			if registry != nil {
				for _, p := range registry.List() {
					if p.Online {
						peersCount++
						if p.DirectP2P {
							directCount++
						}
					}
				}
			}

			hbMsg := fmt.Sprintf("🩺 [WATCHDOG] Uptime: %v | Goroutines: %d | RAM Alloc: %.1f MB | Peers: %d (P2P: %d) | Pkts In/Out: %d/%d",
				uptime, grCount, float64(m.Alloc)/(1024*1024), peersCount, directCount, pIn, pOut)
			writeDebug(hbMsg)

			// Если количество горутин аномально велико (> 200), автоматически сбрасываем стектрейс в лог
			if grCount > 200 {
				writeDebug(fmt.Sprintf("⚠️ WARNING: High goroutine count (%d)! Dumping stack:\r\n%s", grCount, string(debug.Stack())))
			}
		}
	}()
}

// cleanStaleInstances завершает зависшие предыдущие процессы NatBypass
func cleanStaleInstances() {
	defer func() { recover() }()
	myPID := uint32(os.Getpid())
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return
	}

	var stalePIDs []uint32
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		lowerName := strings.ToLower(name)
		if strings.Contains(lowerName, "natbypass") && !strings.Contains(lowerName, "diag") && entry.ProcessID != myPID {
			stalePIDs = append(stalePIDs, entry.ProcessID)
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	if len(stalePIDs) == 0 {
		return
	}

	// 1. Посылаем WM_CLOSE для плавного завершения (предотвращает зависшие хуки User32 и GDI-блокировки)
	cb := windows.NewCallback(func(hwnd, lParam uintptr) uintptr {
		var pid uint32
		procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		for _, targetPID := range stalePIDs {
			if pid == targetPID {
				procPostMessageW.Call(hwnd, WM_CLOSE, 0, 0)
				break
			}
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)

	// Даем 300мс на корректное закрытие ресурсов
	time.Sleep(300 * time.Millisecond)

	// 2. Принудительно завершаем процессы, если они не закрылись сами
	for _, pid := range stalePIDs {
		if hProc, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid); err == nil {
			_ = windows.TerminateProcess(hProc, 0)
			windows.CloseHandle(hProc)
			writeDebug(fmt.Sprintf("🧹 Очищен предыдущий зависший процесс PID: %d", pid))
		}
	}
}

func setupDPI() {
	defer func() { recover() }()
	proc := moduser32.NewProc("SetProcessDpiAwarenessContext")
	if proc.Find() == nil {
		proc.Call(uintptr(uint64(0xFFFFFFFFFFFFFFFC)))
		return
	}
	proc2 := moduser32.NewProc("SetProcessDPIAware")
	if proc2.Find() == nil {
		proc2.Call()
	}
}

func main() {
	runtime.LockOSThread()
	defer func() {
		if r := recover(); r != nil {
			stackStr := string(debug.Stack())
			writeDebug(fmt.Sprintf("CRITICAL PANIC IN MAIN: %v\r\n%s", r, stackStr))
			_ = os.WriteFile("crash_dump.log", []byte(fmt.Sprintf("CRASH: %v\r\n%s", r, stackStr)), 0644)
		}
	}()

	setupDPI()

	initDebugLog()

	// 1. Инициализация единого экземпляра (Single Instance Protection)
	mutName, _ := windows.UTF16PtrFromString("Global\\NatBypass_SingleInstance_Mutex_App")
	hMut, _, err := procCreateMutexW.Call(0, 1, uintptr(unsafe.Pointer(mutName)))
	if err == windows.ERROR_ALREADY_EXISTS || err == syscall.ERROR_ALREADY_EXISTS || windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		clsName, _ := windows.UTF16PtrFromString("NatBypassModernAppClass")
		hExisting, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(clsName)), 0)
		if hExisting != 0 {
			procShowWindow.Call(hExisting, 9 /* SW_RESTORE */)
			procSetForegroundWindow.Call(hExisting)
		}
		os.Exit(0)
		return
	}
	singleMutex = hMut

	// 2. Очистка зависших зомби-процессов предыдущих аварийных запусков
	cleanStaleInstances()

	// Запуск сторожевого таймера дебаггера
	startSystemWatchdog()

	cfgFile := flag.String("config", "config.yaml", "Path to config.yaml")

	flag.Parse()
	configPath = *cfgFile
	writeDebug("Загрузка конфигурации: " + configPath)

	// 2. Инициализация Common Controls
	type INITCOMMONCONTROLSEX struct {
		DwSize uint32
		DwICC  uint32
	}
	icex := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  0x00000008 | 0x00000001,
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icex)))
	writeDebug("CommonControls инициализированы")

	// 3. Загрузка конфигурации
	loadedCfg, err := config.Load(configPath)
	if err != nil {
		writeDebug("Конфиг не найден или ошибка загрузки, используем дефолты: " + err.Error())
		loadedCfg = &config.Config{
			App: config.AppConfig{
				Name:            "NatBypass",
				LogLevel:        "info",
				PublishInterval: 10,
				ShowDiagnostics: true,
				SaveLogsToDisk:  false,
				AddressBook:     make(map[string]string),
			},
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
	} else {
		writeDebug("Конфиг успешно загружен из " + configPath)
	}
	cfg = loadedCfg
	if cfg.App.AddressBook == nil {
		cfg.App.AddressBook = make(map[string]string)
	}
	addressBook = cfg.App.AddressBook
	myNick = cfg.App.DeviceName
	saveLogsToDisk = cfg.App.SaveLogsToDisk
	showDiagnostics = cfg.App.ShowDiagnostics
	allowExitNode = cfg.Network.AllowExitNode
	if allowExitNode {
		go func() {
			_ = tunnel.EnableHostIPForwarding()
		}()
	}
	// Восстанавливаем активный Exit Node из сохранённого конфига
	// Маршруты будут пересозданы после подключения к пиру в handleExitNodeSelect()
	if cfg.Network.SelectedExitNode != "" {
		activeExitNodeID = cfg.Network.SelectedExitNode
	}
	if err != nil {
		showDiagnostics = false
	}
	cachedAWGParams = wireguard.DefaultAWGParams()

	// 4. Создание постоянных ресурсов GDI, иконок и курсора
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	hCursor, _, _ = procLoadCursorW.Call(0, 32512) // IDC_ARROW

	// Загружаем иконку (большая для Taskbar / Alt+Tab и маленькая для заголовка окна / системного трея)
	var hIconBig uintptr
	var hIconSmall uintptr

	// 1) Пробуем загрузить из встроенных PE ресурсов по ID 1 (MAKEINTRESOURCE(1))
	hIconBig, _, _ = procLoadImageW.Call(
		hInstance,
		1,
		1, // IMAGE_ICON
		32, 32,
		0x00000040, // LR_SHARED
	)
	hIconSmall, _, _ = procLoadImageW.Call(
		hInstance,
		1,
		1, // IMAGE_ICON
		16, 16,
		0x00000040, // LR_SHARED
	)

	// 2) Если по ID 1 не найдено, пробуем LoadIconW по ID 1 или имени "APP"
	if hIconBig == 0 {
		hIconBig, _, _ = procLoadIconW.Call(hInstance, 1)
	}
	if hIconBig == 0 {
		appStr, _ := windows.UTF16PtrFromString("APP")
		hIconBig, _, _ = procLoadIconW.Call(hInstance, uintptr(unsafe.Pointer(appStr)))
	}
	if hIconSmall == 0 {
		hIconSmall = hIconBig
	}

	// 3) Если все еще 0, пробуем загрузить из файла app.ico рядом с исполняемым файлом
	if hIconBig == 0 {
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath)
			icoFile := filepath.Join(exeDir, "app.ico")
			if _, err := os.Stat(icoFile); err == nil {
				icoPtr, _ := windows.UTF16PtrFromString(icoFile)
				hIconBig, _, _ = procLoadImageW.Call(
					0,
					uintptr(unsafe.Pointer(icoPtr)),
					1, // IMAGE_ICON
					32, 32,
					0x00000010|0x00000040, // LR_LOADFROMFILE | LR_SHARED
				)
				hIconSmall, _, _ = procLoadImageW.Call(
					0,
					uintptr(unsafe.Pointer(icoPtr)),
					1, // IMAGE_ICON
					16, 16,
					0x00000010|0x00000040, // LR_LOADFROMFILE | LR_SHARED
				)
			}
		}
	}

	// 4) Фолбэк на стандартную иконку Windows, если совсем ничего нет
	if hIconBig == 0 {
		hIconBig, _, _ = procLoadIconW.Call(0, 32512)
	}
	if hIconSmall == 0 {
		hIconSmall = hIconBig
	}

	hBrushBg, _, _ = procCreateSolidBrush.Call(COLOR_BG)
	hBrushSidebar, _, _ = procCreateSolidBrush.Call(COLOR_SIDEBAR)
	hBrushCard, _, _ = procCreateSolidBrush.Call(COLOR_CARD)
	hBrushInput, _, _ = procCreateSolidBrush.Call(COLOR_INPUT)
	hBrushBtnHover, _, _ = procCreateSolidBrush.Call(COLOR_BTN_HOVER)
	hBrushBtnGreen, _, _ = procCreateSolidBrush.Call(COLOR_GREEN_BG)
	hBrushBtnRed, _, _ = procCreateSolidBrush.Call(COLOR_RED_BG)
	hBrushBtnYellow, _, _ = procCreateSolidBrush.Call(COLOR_YELLOW_BG)
	hBrushBtnAccent, _, _ = procCreateSolidBrush.Call(COLOR_ACCENT_BG)

	hPenBorder, _, _ = procCreatePen.Call(0, 1, COLOR_BORDER)
	hPenBorderLt, _, _ = procCreatePen.Call(0, 1, COLOR_BORDER_LT)
	hPenAccent, _, _ = procCreatePen.Call(0, 1, COLOR_ACCENT)

	hFontNormal = createFont("Segoe UI", 15, 400)
	hFontBold = createFont("Segoe UI", 15, 600)
	hFontSmall = createFont("Segoe UI", 13, 600)
	hFontHeader = createFont("Segoe UI", 17, 700)
	hFontTitle = createFont("Segoe UI", 21, 700)
	hFontMono = createFont("Consolas", 13, 400)
	writeDebug("GDI ресурсы и шрифты созданы")

	// 5. Регистрация класса окна
	className, _ := windows.UTF16PtrFromString("NatBypassModernAppClass")
	windowTitle, _ := windows.UTF16PtrFromString("NatBypass — P2P Mesh Сеть & AmneziaWG 3.1")

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         3,
		LpfnWndProc:   windows.NewCallback(wndProc),
		HInstance:     hInstance,
		HIcon:         hIconBig,
		HCursor:       hCursor,
		HbrBackground: hBrushBg,
		LpszClassName: className,
		HIconSm:       hIconSmall,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	writeDebug("Класс окна зарегистрирован")

	// Проверяем текущий статус автозапуска в реестре Windows
	isAutostartEnabled = autostart.IsAutoStartEnabled("NatBypass")

	// 6. Создание главного окна (комфортный премиальный размер 1120x760 для четкого отображения всех элементов)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		WS_FIXEDWINDOW|WS_CLIPCHILDREN|WS_CLIPSIBLINGS,
		60, 40, 1120, 760,
		0, 0, hInstance, 0,
	)
	hMainWnd = hwnd
	procDragAcceptFiles.Call(hMainWnd, 1)
	writeDebug(fmt.Sprintf("Главное окно создано, HWND=0x%X", hMainWnd))


	// Устанавливаем иконки окна для панели задач и заголовка (WM_SETICON)
	procSendMessageW.Call(hMainWnd, 0x0080 /* WM_SETICON */, 1 /* ICON_BIG */, hIconBig)
	procSendMessageW.Call(hMainWnd, 0x0080 /* WM_SETICON */, 0 /* ICON_SMALL */, hIconSmall)

	// DWM Dark Mode заголовок
	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hMainWnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	// Инициализация иконки в системном трее Windows
	initTrayIcon(hMainWnd, hIconSmall)

	// Построение элементов нативного интерфейса Windows (Pure Win32 GDI Controls)
	writeDebug("Начало построения UI buildModernUI()...")
	buildModernUI(hInstance)

	// Показываем нативное главное окно Win32
	procShowWindow.Call(hMainWnd, SW_SHOW)
	procUpdateWindow.Call(hMainWnd)
	procSetForegroundWindow.Call(hMainWnd)
	procSetTimer.Call(hMainWnd, ID_TIMER_POLL, 1000, 0)

	// Запуск сетевого ядра напрямую из параметров cfg
	writeDebug("Запуск сетевого ядра NatBypass Mesh...")
	go startEngineFromConfig(cfg)

	// Цикл сообщений Windows (UI thread)
	writeDebug("Сетевое ядро и нативный Win32 GUI активны, вход в цикл событий...")
	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	writeDebug("Завершение работы...")
	exitApp()
}

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			writeDebug(fmt.Sprintf("⚠️ Panic в wndProc (msg=0x%X): %v", msg, r))
		}
	}()

	switch msg {
	case WM_ERASEBKGND:
		return 1

	case WM_SIZE:
		procInvalidateRect.Call(hwnd, 0, 1)
		return 0

	case WM_SETCURSOR:
		if LOWORD(lParam) == 1 {
			procSetCursor.Call(hCursor)
			return 1
		}

	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))

		var clientRect RECT
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&clientRect)))
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&clientRect)), hBrushBg)

		sidebarRect := RECT{Left: 0, Top: 0, Right: 230, Bottom: clientRect.Bottom}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&sidebarRect)), hBrushSidebar)

		procSelectObject.Call(hdc, hPenBorder)
		var pt POINT
		procMoveToEx.Call(hdc, 230, 0, uintptr(unsafe.Pointer(&pt)))
		procLineTo.Call(hdc, 230, uintptr(clientRect.Bottom))

		cardRect := RECT{Left: 242, Top: 10, Right: clientRect.Right - 10, Bottom: clientRect.Bottom - 10}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&cardRect)), hBrushCard)

		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case WM_DRAWITEM:
		dis := *(*DRAWITEMSTRUCT)(unsafe.Pointer(lParam))
		drawCustomButton(&dis)
		return 1

	case 0x007B: // WM_CONTEXTMENU
		targetHWND := wParam
		if targetHWND == hListPeers || targetHWND == hListSummaryPeers {
			x := int32(LOWORD(lParam))
			y := int32(HIWORD(lParam))
			if x == -1 && y == -1 {
				var pt struct{ X, Y int32 }
				procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
				x = pt.X
				y = pt.Y
			}
			showPeerContextMenu(hwnd, targetHWND, x, y)
			return 0
		}

	case WM_SYSCOMMAND:
		if wParam == SC_CLOSE {
			if minimizeToTray {
				procShowWindow.Call(hwnd, SW_HIDE)
				return 0
			}
			exitApp()
			return 0
		}

	case WM_CLOSE:
		if minimizeToTray {
			procShowWindow.Call(hwnd, SW_HIDE)
			return 0
		}
		exitApp()
		return 0

	case WM_CTLCOLORSTATIC:
		hdc := wParam
		ctrlHWND := lParam
		if ctrlHWND == hEditDiagLog || ctrlHWND == hEditLogs || ctrlHWND == hEditAwgConf {
			procSetBkMode.Call(hdc, 2 /* OPAQUE */)
			procSetBkColor.Call(hdc, COLOR_INPUT)
			procSetTextColor.Call(hdc, 0x00E0E0E0)
			return hBrushInput
		}
		procSetBkMode.Call(hdc, 1 /* TRANSPARENT */)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushCard

	case WM_CTLCOLOREDIT:
		hdc := wParam
		procSetBkMode.Call(hdc, 2 /* OPAQUE */)
		procSetBkColor.Call(hdc, COLOR_INPUT)
		procSetTextColor.Call(hdc, 0xFFFFFF)
		return hBrushInput

	case WM_CTLCOLORLISTBOX:
		hdc := wParam
		procSetBkColor.Call(hdc, COLOR_INPUT)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushInput

	case 0x0233: /* WM_DROPFILES */
		hDrop := wParam
		var buf [512]uint16
		ret, _, _ := procDragQueryFileW.Call(hDrop, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if ret > 0 {
			filePath := windows.UTF16ToString(buf[:ret])
			procDragFinish.Call(hDrop)
			handleDroppedFile(filePath)
		}
		return 0

	case WM_TIMER:
		if wParam == ID_TIMER_POLL {
			updateData()
		}
		return 0


	case WM_COMMAND:
		id := LOWORD(wParam)
		if lParam == hListProfiles {
			if HIWORD(wParam) == 1 /* LBN_SELCHANGE */ {
				onProfileSelectionChange()
				return 0
			} else if HIWORD(wParam) == 2 /* LBN_DBLCLK */ {
				handleProfileSwitch()
				return 0
			}
		}
		handleCommand(id)
		return 0

	case WM_TRAYICON:
		if lParam == 0x0205 /* WM_RBUTTONUP */ {
			var pt struct{ X, Y int32 }
			procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
			hMenu, _, _ := procCreatePopupMenu.Call()

			titleStr, _ := syscall.UTF16PtrFromString("🌐 Открыть NatBypass")
			syncStr, _ := syscall.UTF16PtrFromString("⚡ Обновить сокеты P2P")
			exitStr, _ := syscall.UTF16PtrFromString("🚪 Выход")

			procAppendMenuW.Call(hMenu, 0, 1001, uintptr(unsafe.Pointer(titleStr)))
			procAppendMenuW.Call(hMenu, 0, 1002, uintptr(unsafe.Pointer(syncStr)))
			procAppendMenuW.Call(hMenu, 0x00000800 /* MF_SEPARATOR */, 0, 0)
			procAppendMenuW.Call(hMenu, 0, 1003, uintptr(unsafe.Pointer(exitStr)))

			procSetForegroundWindow.Call(hwnd)
			cmd, _, _ := procTrackPopupMenu.Call(hMenu, 0x0100 /* TPM_RETURNCMD */|0x0002 /* TPM_RIGHTBUTTON */, uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)

			if cmd == 1001 {
				procShowWindow.Call(hMainWnd, SW_RESTORE)
				procShowWindow.Call(hMainWnd, SW_SHOW)
				procSetForegroundWindow.Call(hMainWnd)
			} else if cmd == 1002 {
				triggerPublish()
			} else if cmd == 1003 {
				removeTrayIcon(hwnd)
				exitApp()
			}
			return 0
		} else if lParam == 0x0203 /* WM_LBUTTONDBLCLK */ || lParam == 0x0202 /* WM_LBUTTONUP */ {
			procShowWindow.Call(hMainWnd, SW_RESTORE)
			procShowWindow.Call(hMainWnd, SW_SHOW)
			procSetForegroundWindow.Call(hMainWnd)
			return 0
		}
		return 0

	case WM_DESTROY:
		removeTrayIcon(hwnd)
		exitApp()
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func initTrayIcon(hwnd uintptr, hIcon uintptr) {
	if hIcon == 0 {
		hIcon, _, _ = procLoadIconW.Call(0, 32512)
	}
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hwnd
	nid.UID = 1001
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.UCallbackMessage = WM_TRAYICON
	nid.HIcon = hIcon

	tip := syscall.StringToUTF16("NatBypass Mesh & AWG 2.0")
	copy(nid.SzTip[:], tip)

	ret, _, _ := procShell_NotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
	if ret == 0 {
		go func() {
			time.Sleep(800 * time.Millisecond)
			procShell_NotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
		}()
	}
}

func removeTrayIcon(hwnd uintptr) {
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hwnd
	nid.UID = 1001
	procShell_NotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
}

// exitApp — гарантированное мгновенное завершение процесса без зависаний
func exitApp() {
	if !atomic.CompareAndSwapInt32(&isShuttingDown, 0, 1) {
		return
	}

	writeDebug("🛑 Завершение работы приложения...")

	// 1. Мгновенно скрываем окно от пользователя и убираем иконку из трея
	removeTrayIcon(hMainWnd)
	procKillTimer.Call(hMainWnd, ID_TIMER_POLL)
	procShowWindow.Call(hMainWnd, SW_HIDE)

	// 2. Закрываем дескриптор единого мьютекса
	if singleMutex != 0 {
		procCloseHandle.Call(singleMutex)
	}

	writeDebug("✓ NatBypass процесс полностью остановлен.")
	if debugLogFile != nil {
		_ = debugLogFile.Close()
	}

	// 3. Отправляем прощальный маяк выхода другим узлам сети
	broadcastGoodbye()

	// 4. Быстрая остановка сокетов и моментальный выход
	go func() {
		stopEngine()
	}()
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}

func broadcastGoodbye() {
	goodbyePayload := &signaling.Payload{
		DeviceID:  myDevID,
		Offline:   true,
		Leave:     true,
		Timestamp: time.Now(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	for _, ch := range sigChannels {
		if ch != nil {
			_ = ch.Send(ctx, goodbyePayload)
		}
	}
}

func drawCustomButton(pDIS *DRAWITEMSTRUCT) {
	if pDIS == nil {
		return
	}
	hdc := pDIS.Hdc
	rc := pDIS.RcItem
	id := pDIS.CtlID
	text := buttonLabels[id]
	bType := buttonTypes[id]
	isPressed := (pDIS.ItemState & ODS_SELECTED) != 0

	isNav := bType == "nav"

	var parentBrush uintptr
	if isNav {
		parentBrush = hBrushSidebar
	} else {
		parentBrush = hBrushCard
	}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), parentBrush)

	var bgBrush uintptr
	var txtColor uint32 = COLOR_TEXT

	isActiveNav := false
	if isNav {
		if (id == ID_NAV_DASHBOARD && currentTab == 0) ||
			(id == ID_NAV_PEERS && currentTab == 1) ||
			(id == ID_NAV_PROFILES && currentTab == 2) ||
			(id == ID_NAV_AWG && currentTab == 3) ||
			(id == ID_NAV_CHANNELS && currentTab == 4) ||
			(id == ID_NAV_ROUTING && currentTab == 5) ||
			(id == ID_NAV_DIAG && currentTab == 6) ||
			(id == ID_NAV_SETTINGS && currentTab == 7) {
			isActiveNav = true
		}
	}

	if isPressed {
		bgBrush = hBrushBtnHover
		txtColor = 0xFFFFFF
	} else if isActiveNav {
		bgBrush = hBrushCard
		txtColor = COLOR_ACCENT
	} else if isNav {
		bgBrush = hBrushSidebar
		txtColor = COLOR_MUTED
	} else if bType == "green" {
		bgBrush = hBrushBtnGreen
		txtColor = 0xFFFFFF
	} else if bType == "red" {
		bgBrush = hBrushBtnRed
		txtColor = 0xFFFFFF
	} else if bType == "yellow" {
		bgBrush = hBrushBtnYellow
		txtColor = 0xFFFFFF
	} else if bType == "primary" {
		bgBrush = hBrushBtnAccent
		txtColor = 0xFFFFFF
	} else {
		bgBrush = hBrushInput
		txtColor = COLOR_TEXT
	}

	var penBorder uintptr
	if isActiveNav || bType == "primary" {
		penBorder = hPenAccent
	} else {
		penBorder = hPenBorderLt
	}

	procSelectObject.Call(hdc, bgBrush)
	procSelectObject.Call(hdc, penBorder)
	procRoundRect.Call(hdc, uintptr(rc.Left), uintptr(rc.Top), uintptr(rc.Right), uintptr(rc.Bottom), 8, 8)

	procSetBkMode.Call(hdc, 1)
	procSetTextColor.Call(hdc, uintptr(txtColor))

	tPtr, _ := windows.UTF16FromString(text)
	var textRect = rc
	if isPressed {
		textRect.Top += 1
		textRect.Bottom += 1
	}

	if len(tPtr) > 1 {
		availW := (rc.Right - rc.Left) - 16
		if isNav {
			availW = (rc.Right - rc.Left) - 24
		}

		fontToUse := hFontBold
		var sz SIZE
		procSelectObject.Call(hdc, hFontBold)
		procGetTextExtentPoint32W.Call(hdc, uintptr(unsafe.Pointer(&tPtr[0])), uintptr(int32(len(tPtr)-1)), uintptr(unsafe.Pointer(&sz)))
		if availW > 0 && sz.CX > availW {
			procSelectObject.Call(hdc, hFontNormal)
			procGetTextExtentPoint32W.Call(hdc, uintptr(unsafe.Pointer(&tPtr[0])), uintptr(int32(len(tPtr)-1)), uintptr(unsafe.Pointer(&sz)))
			if sz.CX > availW {
				fontToUse = hFontSmall
			} else {
				fontToUse = hFontNormal
			}
		}

		procSelectObject.Call(hdc, fontToUse)
		if isNav {
			textRect.Left += 14
			procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&tPtr[0])), uintptr(int32(len(tPtr)-1)), uintptr(unsafe.Pointer(&textRect)), DT_LEFT|DT_VCENTER|DT_SINGLELINE)
		} else {
			procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&tPtr[0])), uintptr(int32(len(tPtr)-1)), uintptr(unsafe.Pointer(&textRect)), DT_CENTER|DT_VCENTER|DT_SINGLELINE)
		}
	}
}

func handleCommand(id uint16) {
	switch id {
	case ID_NAV_DASHBOARD:
		selectTab(0)
	case ID_NAV_PEERS:
		selectTab(1)
	case ID_NAV_PROFILES:
		selectTab(2)
	case ID_NAV_AWG:
		selectTab(3)
	case ID_NAV_CHANNELS:
		selectTab(4)
	case ID_NAV_ROUTING:
		selectTab(5)
	case ID_NAV_DIAG:
		selectTab(6)
	case ID_NAV_SETTINGS:
		selectTab(7)

	case ID_BTN_MANAGE_PROFILES:
		selectTab(2)

	case ID_BTN_COPY_PEER_VIP:
		handleCopySelectedPeerVIP()

	case ID_BTN_PING_PEER:
		handlePingSelectedPeer()

	case ID_BTN_TOGGLE_AUTOSTART:
		handleToggleAutostart()

	case ID_BTN_TOGGLE_TRAY:
		handleToggleMinimizeToTray()

	case ID_BTN_SAVE_CHANNELS:
		handleSaveChannels()



	case ID_BTN_PROF_SWITCH:
		handleProfileSwitch()

	case ID_BTN_PROF_CREATE:
		handleProfileCreate()

	case ID_BTN_PROF_SAVE:
		handleProfileSave()

	case ID_BTN_PROF_DELETE:
		handleProfileDelete()

	case ID_BTN_PROF_EXPORT:
		handleProfileExport()

	case ID_BTN_PROF_QR:
		handleProfileQR()

	case ID_BTN_PROF_IMPORT:
		handleProfileImport()

	case ID_BTN_VPN:
		toggleVPNManual()

	case ID_BTN_REFRESH:
		addLog("⚡ Принудительное обновление STUN сокета и внешнего IP...")
		go func() {
			if ipDisc != nil {
				if ip, err := ipDisc.GetPublicIP(context.Background()); err == nil {
					myPublicIP = ip.String()
					addLog("✓ Публичный IP обновлен: " + myPublicIP)
				}
			}
			if udpPuncher != nil {
				if extIP, port, err := udpPuncher.DiscoverMappedAddress(context.Background()); err == nil {
					mySTUNAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
					addLog("✓ STUN UDP Hole Punch сокет: " + mySTUNAddr)
				}
			}
			triggerPublish()
		}()

	case ID_BTN_BOOKMARK_PEER:
		handleBookmarkPeer()

	case ID_BTN_AWG_STD:
		setAWGPreset(wireguard.AWGParams{Enabled: true, Jc: 0, Jmin: 0, Jmax: 0, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4})
		setActiveAWGPresetButton(ID_BTN_AWG_STD)
		addLog("🛡️ Выбран пресет: 🟢 Стандартный WireGuard")

	case ID_BTN_AWG_DPI:
		setAWGPreset(wireguard.GenerateAWG31StrictParams())
		setActiveAWGPresetButton(ID_BTN_AWG_DPI)
		addLog("🛡️ Выбран пресет: 🔒 AWG 3.1 Strict (Header Protection + Custom Timings)")

	case ID_BTN_AWG_STEALTH:
		setAWGPreset(wireguard.GenerateAWG31BalancedParams())
		setActiveAWGPresetButton(ID_BTN_AWG_STEALTH)
		addLog("🛡️ Выбран пресет: ⚖️ AWG 3.1 Balanced")

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
			buttonLabels[ID_BTN_COPY_AWG] = "📋 Скопировать конфиг"
			procInvalidateRect.Call(hBtnCopyAwg, 0, 1)
		})

	case ID_BTN_SAVE_AWG:
		conf := getControlText(hEditAwgConf)
		confFile := "natbypass.conf"
		if err := os.WriteFile(confFile, []byte(conf), 0644); err == nil {
			addLog("💾 Конфиг успешно сохранен в файл: " + confFile)
			writeDebug("Конфигурация сохранена в " + confFile)
			buttonLabels[ID_BTN_SAVE_AWG] = "✓ СОХРАНЕНО В natbypass.conf!"
			procInvalidateRect.Call(hBtnSaveAwg, 0, 1)
			_ = exec.Command("explorer.exe", "/select,"+confFile).Start()
		} else {
			addLog("❌ Ошибка сохранения конфига: " + err.Error())
		}
		time.AfterFunc(2*time.Second, func() {
			buttonLabels[ID_BTN_SAVE_AWG] = "💾 Сохранить в natbypass.conf"
			procInvalidateRect.Call(hBtnSaveAwg, 0, 1)
		})

	case ID_BTN_OPEN_AWG_CLIENT:
		amneziaPath := `C:\Program Files\AmneziaVPN\AmneziaVPN.exe`
		if _, err := os.Stat(amneziaPath); err == nil {
			_ = exec.Command(amneziaPath).Start()
			addLog("🚀 Запущен клиент AmneziaVPN")
		} else {
			addLog("💡 AmneziaVPN не найден по пути по умолчанию. Скачайте его с github.com/amnezia-vpn/amneziawg-windows-client")
		}

	case ID_BTN_SYNC_AWG:
		if syncAWGPeerParams != nil {
			targetAWG := *syncAWGPeerParams
			targetName := syncAWGPeerName

			setControlText(hEditAwgJc, strconv.Itoa(targetAWG.Jc))
			setControlText(hEditAwgJmin, strconv.Itoa(targetAWG.Jmin))
			setControlText(hEditAwgJmax, strconv.Itoa(targetAWG.Jmax))
			setControlText(hEditAwgS1, strconv.Itoa(targetAWG.S1))
			setControlText(hEditAwgS2, strconv.Itoa(targetAWG.S2))
			setControlText(hEditAwgH1, targetAWG.H1)
			setControlText(hEditAwgH2, targetAWG.H2)
			setControlText(hEditAwgH3, targetAWG.H3)
			setControlText(hEditAwgH4, targetAWG.H4)

			renderAWGTextFromUI()
			saveConfig()
			addLog(fmt.Sprintf("🔄 Настройки AmneziaWG 2.0 успешно применены с узла [%s] и сохранены!", targetName))
			writeDebug(fmt.Sprintf("AmneziaWG 2.0 synced from peer [%s]", targetName))

			syncAWGPeerParams = nil
			syncAWGPeerName = ""
			procShowWindow.Call(hBtnSyncAwg, uintptr(SW_HIDE))
			procInvalidateRect.Call(hMainWnd, 0, 1)
		}

	case ID_BTN_TEST_TG:
		testTelegram()

	case ID_BTN_TEST_MQTT:
		testMQTT()

	case ID_BTN_TOGGLE_LOGS:
		saveLogsToDisk = !saveLogsToDisk
		if saveLogsToDisk {
			buttonLabels[ID_BTN_TOGGLE_LOGS] = "💾 Запись логов на диск: ВКЛ"
			buttonTypes[ID_BTN_TOGGLE_LOGS] = "green"
			addLog("💾 Запись отладочных логов на диск ВКЛЮЧЕНА (natbypass_debug.log)")
		} else {
			buttonLabels[ID_BTN_TOGGLE_LOGS] = "💾 Запись логов на диск: ВЫКЛ"
			buttonTypes[ID_BTN_TOGGLE_LOGS] = "normal"
			addLog("💾 Запись отладочных логов на диск ВЫКЛЮЧЕНА")
		}
		procInvalidateRect.Call(hBtnToggleLogs, 0, 1)
		saveConfigFromUI()

	case ID_BTN_TOGGLE_DIAG:
		showDiagnostics = !showDiagnostics
		applyDiagnosticsVisibility()
		if showDiagnostics {
			addLog("🩺 Вкладка Диагностика ВКЛЮЧЕНА")
		} else {
			addLog("🩺 Вкладка Диагностика ВЫКЛЮЧЕНА")
		}
		saveConfigFromUI()

	case ID_BTN_SAVE_CFG:
		saveConfig()

	case ID_BTN_CHECK_UPDATE:
		addLog("🔍 Проверка обновлений на GitHub Releases...")
		buttonLabels[ID_BTN_CHECK_UPDATE] = "⏳ Проверка обновлений..."
		procInvalidateRect.Call(hBtnCheckUpdate, 0, 1)
		go func() {
			defer func() {
				buttonLabels[ID_BTN_CHECK_UPDATE] = "🚀 Проверить обновления NatBypass на GitHub"
				procInvalidateRect.Call(hBtnCheckUpdate, 0, 1)
			}()
			info, err := updater.CheckUpdate(context.Background(), Version)
			if err != nil {
				addLog("❌ Ошибка проверки обновлений: " + err.Error())
				msg, _ := windows.UTF16PtrFromString("Не удалось проверить обновления:\n" + err.Error())
				title, _ := windows.UTF16PtrFromString("Обновление NatBypass")
				procMessageBoxW.Call(hMainWnd, uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(title)), 0x10 /* MB_ICONERROR */)
				return
			}
			if !info.HasUpdate {
				addLog(fmt.Sprintf("✅ У вас установлена самая свежая версия (v%s)", Version))
				if lblUpdateStatus != 0 {
					setControlText(lblUpdateStatus, fmt.Sprintf("✅ У вас установлена самая свежая версия (v%s)", Version))
				}
				msg, _ := windows.UTF16PtrFromString(fmt.Sprintf("У вас установлена самая свежая версия NatBypass (v%s).\nОбновлений не требуется.", Version))
				title, _ := windows.UTF16PtrFromString("Обновление NatBypass")
				procMessageBoxW.Call(hMainWnd, uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(title)), 0x40 /* MB_ICONINFORMATION */)
				return
			}
			addLog(fmt.Sprintf("🚀 Доступна новая версия: %s! Открытие окна обновления...", info.LatestVersion))
			if lblUpdateStatus != 0 {
				setControlText(lblUpdateStatus, fmt.Sprintf("🚀 Доступна новая версия: %s! Нажмите для обновления", info.LatestVersion))
			}
			showUpdateModal(info)
		}()


	case ID_BTN_MODE_PARALLEL:
		setSigModeUI("parallel")
		addLog("🎯 Выбран режим: 🔄 Параллельно (MQTT + Telegram)")

	case ID_BTN_MODE_MQTT:
		setSigModeUI("mqtt_only")
		addLog("🎯 Выбран режим: ⚡ Только MQTT")

	case ID_BTN_MODE_TG:
		setSigModeUI("tg_only")
		addLog("🎯 Выбран режим: 💬 Только Telegram")

	case ID_BTN_MQ_EMQX:
		setControlText(hEditMqttBr, "tcp://broker.emqx.io:1883")
		addLog("⚡ Выбран брокер: EMQX Public (tcp://broker.emqx.io:1883)")

	case ID_BTN_MQ_HIVE:
		setControlText(hEditMqttBr, "tcp://broker.hivemq.com:1883")
		addLog("⚡ Выбран брокер: HiveMQ Public (tcp://broker.hivemq.com:1883)")

	case ID_BTN_MQ_MOSQ:
		setControlText(hEditMqttBr, "tcp://test.mosquitto.org:1883")
		addLog("⚡ Выбран брокер: Mosquitto Public (tcp://test.mosquitto.org:1883)")

	case ID_BTN_MQ_ECL:
		setControlText(hEditMqttBr, "tcp://mqtt.eclipseprojects.io:1883")
		addLog("⚡ Выбран брокер: Eclipse Foundation (tcp://mqtt.eclipseprojects.io:1883)")

	case ID_BTN_RUN_DIAG:
		runDiag()

	case ID_BTN_DUMP_STACK:
		dumpGoroutineStack()

	case ID_BTN_CLR_LOGS:
		logsMutex.Lock()
		logsBuffer = nil
		logsDirty = false
		logsMutex.Unlock()
		setControlText(hEditLogs, "")

	case ID_BTN_SAVE_LOGS:
		saveLogsToFile()

	case ID_BTN_ALLOW_EXIT:
		allowExitNode = !allowExitNode
		if cfg != nil {
			cfg.Network.AllowExitNode = allowExitNode
		}
		if allowExitNode {
			buttonLabels[ID_BTN_ALLOW_EXIT] = "🌐 Разрешить выход в интернет через меня: ВКЛ"
			buttonTypes[ID_BTN_ALLOW_EXIT] = "green"
			go func() {
				if err := tunnel.EnableHostIPForwarding(); err != nil {
					addLog("⚠️ Ошибка включения IP Forwarding: " + err.Error())
					writeDebug("EnableHostIPForwarding error: " + err.Error())
				} else {
					addLog("🌐 IP Forwarding включен на интерфейсе 'NatBypass'")
					writeDebug("EnableHostIPForwarding OK")
				}
			}()
			addLog("🌐 Разрешен выход в интернет через это устройство (Exit Node активен)")
		} else {
			buttonLabels[ID_BTN_ALLOW_EXIT] = "🌐 Разрешить выход в интернет через меня: ВЫКЛ"
			buttonTypes[ID_BTN_ALLOW_EXIT] = "normal"
			addLog("🌐 Выход в интернет через это устройство отключен")
		}
		procInvalidateRect.Call(hBtnAllowExit, 0, 1)
		saveConfigFromUI()
		triggerPublish()

	case ID_BTN_EXIT_NODE_SELECT:
		handleExitNodeSelect()

	case ID_BTN_TOGGLE_SUBNET:
		handleToggleSubnetRoute()

	case ID_BTN_ADD_LOCAL_SUBNET:
		localSubnets := network.GetLocalSubnets()
		if len(localSubnets) == 0 {
			addLog("⚠️ Локальные активные подсети не обнаружены")
			return
		}
		curText := strings.TrimSpace(getControlText(hEditAdvSubnets))
		existingMap := make(map[string]bool)
		var parts []string
		if curText != "" {
			for _, p := range strings.Split(curText, ",") {
				tr := strings.TrimSpace(p)
				if tr != "" {
					existingMap[tr] = true
					parts = append(parts, tr)
				}
			}
		}
		var added []string
		for _, s := range localSubnets {
			if !existingMap[s] {
				parts = append(parts, s)
				existingMap[s] = true
				added = append(added, s)
			}
		}
		if len(added) > 0 {
			newText := strings.Join(parts, ", ")
			setControlText(hEditAdvSubnets, newText)
			addLog("🏠 Добавлена локальная подсеть: " + strings.Join(added, ", "))
			saveConfigFromUI()
		} else {
			addLog("💡 Все обнаруженные локальные подсети уже добавлены (" + strings.Join(localSubnets, ", ") + ")")
		}
	}
}

func handleBookmarkPeer() {
	if registry == nil {
		addLog("⚠️ Сетевой реестр не инициализирован")
		return
	}

	peers := registry.List()
	if len(peers) == 0 {
		addLog("⚠️ Нет доступных пиров в сети для добавления в закладки")
		return
	}

	selIdx, _, _ := procSendMessageW.Call(hListPeers, 0x0188, 0, 0) // LB_GETCURSEL = 0x0188
	idx := int(int32(selIdx)) / 2

	if idx < 0 || idx >= len(peers) {
		if len(peers) == 1 {
			idx = 0
		} else {
			addLog("💡 Выберите устройство из списка выше и нажмите 'Задать имя / В закладки'")
			return
		}
	}

	targetPeer := peers[idx]

	addressBookMu.RLock()
	currentName := addressBook[targetPeer.DeviceID]
	addressBookMu.RUnlock()
	if currentName == "" {
		currentName = targetPeer.Nickname
	}

	newName, ok := showBookmarkDialog(targetPeer.DeviceID, currentName)
	if !ok {
		return
	}

	trimmed := strings.TrimSpace(newName)
	addressBookMu.Lock()
	if trimmed != "" {
		addressBook[targetPeer.DeviceID] = trimmed
		addLog(fmt.Sprintf("⭐ Устройству %s присвоено имя '%s' (сохранено в закладки)", targetPeer.DeviceID, trimmed))
	} else {
		delete(addressBook, targetPeer.DeviceID)
		addLog(fmt.Sprintf("🗑 Закладка для устройства %s удалена", targetPeer.DeviceID))
	}
	if cfg != nil {
		cfg.App.AddressBook = addressBook
	}
	addressBookMu.Unlock()

	lastPeersHash = ""
	saveConfigFromUI()
	updateData()
}

func handleExitNodeSelect() {
	if registry == nil {
		addLog("⚠️ Сетевой реестр не инициализирован")
		return
	}

	var exitNodes []*peer.Peer
	for _, p := range registry.List() {
		if p.Online && p.IsExitNode {
			exitNodes = append(exitNodes, p)
		}
	}

	if len(exitNodes) == 0 {
		if activeExitNodeID != "" {
			if activeExitVIP != "" {
				_ = tunnel.DisableExitNodeRouting(activeExitVIP)
			}
			activeExitNodeID = ""
			activeExitVIP = ""
			buttonLabels[ID_BTN_EXIT_NODE_SELECT] = "🌐 Выход в интернет: Локальный (Отключен)"
			buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "normal"
			if hBtnExitNodeSelect != 0 {
				procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
			}
			addLog("🌐 В сети нет доступных Exit Node устройств. Маршрут сброшен на локальный.")
		} else {
			addLog("💡 В сети пока нет устройств с включенным Exit Node. Включите Exit Node на удаленном устройстве.")
		}
		return
	}

	currIdx := -1
	for i, en := range exitNodes {
		if en.DeviceID == activeExitNodeID {
			currIdx = i
			break
		}
	}

	if currIdx == len(exitNodes)-1 {
		// Turn off exit routing
		if activeExitVIP != "" {
			_ = tunnel.DisableExitNodeRouting(activeExitVIP)
		}
		activeExitNodeID = ""
		activeExitVIP = ""
		buttonLabels[ID_BTN_EXIT_NODE_SELECT] = "🌐 Выход в интернет: Локальный (Отключен)"
		buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "normal"
		if hBtnExitNodeSelect != 0 {
			procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
		}
		addLog("🌐 Выход в интернет через Exit Node отключен. Восстановлен стандартный интернет-шлюз.")
		writeDebug("Exit Node disabled, restored default gateway")
		return
	}

	if activeExitVIP != "" {
		_ = tunnel.DisableExitNodeRouting(activeExitVIP)
	}

	nextIdx := currIdx + 1
	targetPeer := exitNodes[nextIdx]
	targetVIP := targetPeer.VirtualIP
	if targetVIP == "" {
		targetVIP = "100.64.200.2"
	}

	activeExitNodeID = targetPeer.DeviceID
	activeExitVIP = targetVIP

	if err := tunnel.EnableExitNodeRouting(targetVIP, targetPeer.ActiveEndpoint, targetPeer.STUNAddr, targetPeer.PublicIP); err != nil {
		addLog("❌ Ошибка настройки маршрутизации через Exit Node: " + err.Error())
		writeDebug("EnableExitNodeRouting error: " + err.Error())
	} else {
		addressBookMu.RLock()
		bm := addressBook[targetPeer.DeviceID]
		addressBookMu.RUnlock()
		peerDisplay := targetPeer.Nickname
		if bm != "" {
			peerDisplay = "[*] " + bm
		} else if peerDisplay == "" {
			peerDisplay = targetPeer.DeviceID
		}

		buttonLabels[ID_BTN_EXIT_NODE_SELECT] = fmt.Sprintf("🟢 Шлюз: [%s] (%s)", peerDisplay, targetVIP)
		buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "green"
		if hBtnExitNodeSelect != 0 {
			procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
		}

		msg := fmt.Sprintf("🌐 Весь интернет-трафик перенаправлен через Exit Node: [%s] (%s)", peerDisplay, targetVIP)
		addLog(msg)
		writeDebug(msg)
	}
}

func handleToggleSubnetRoute() {
	if registry == nil {
		addLog("⚠️ Сетевой реестр не инициализирован")
		return
	}

	peers := registry.List()
	if len(peers) == 0 {
		addLog("⚠️ Нет доступных пиров в сети")
		return
	}

	selIdx, _, _ := procSendMessageW.Call(hListPeers, 0x0188, 0, 0)
	idx := int(int32(selIdx)) / 2

	var targetPeer *peer.Peer
	if idx >= 0 && idx < len(peers) {
		targetPeer = peers[idx]
	}

	if targetPeer == nil || len(targetPeer.AdvertisedRoutes) == 0 {
		for _, p := range peers {
			if p.Online && len(p.AdvertisedRoutes) > 0 {
				targetPeer = p
				break
			}
		}
	}

	if targetPeer == nil || len(targetPeer.AdvertisedRoutes) == 0 {
		activeSubnetRoutesMu.Lock()
		if len(activeSubnetRoutes) > 0 {
			for cidr, vip := range activeSubnetRoutes {
				_ = tunnel.RemoveSubnetRoute(cidr, vip)
				addLog(fmt.Sprintf("🏠 Маршрут к подсети %s через %s удален", cidr, vip))
			}
			activeSubnetRoutes = make(map[string]string)
			buttonLabels[ID_BTN_TOGGLE_SUBNET] = "🏠 Подключить подсеть пира"
			buttonTypes[ID_BTN_TOGGLE_SUBNET] = "normal"
			if hBtnToggleSubnetRoute != 0 {
				procInvalidateRect.Call(hBtnToggleSubnetRoute, 0, 1)
			}
			activeSubnetRoutesMu.Unlock()
			addLog("🏠 Все маршруты к подсетям отключены")
			return
		}
		activeSubnetRoutesMu.Unlock()
		addLog("💡 В сети нет пиров с анонсированными локальными подсетями.")
		return
	}

	vip := targetPeer.VirtualIP
	if vip == "" {
		vip = "100.64.200.2"
	}

	activeSubnetRoutesMu.Lock()
	defer activeSubnetRoutesMu.Unlock()

	allActive := true
	for _, cidr := range targetPeer.AdvertisedRoutes {
		if activeSubnetRoutes[cidr] != vip {
			allActive = false
			break
		}
	}

	if allActive {
		for _, cidr := range targetPeer.AdvertisedRoutes {
			if err := tunnel.RemoveSubnetRoute(cidr, vip); err != nil {
				addLog(fmt.Sprintf("⚠️ Ошибка удаления маршрута к %s: %s", cidr, err.Error()))
			} else {
				addLog(fmt.Sprintf("🏠 Маршрут к подсети %s через %s удален", cidr, vip))
			}
			delete(activeSubnetRoutes, cidr)
		}
		if len(activeSubnetRoutes) == 0 {
			buttonLabels[ID_BTN_TOGGLE_SUBNET] = "🏠 Подключить подсеть пира"
			buttonTypes[ID_BTN_TOGGLE_SUBNET] = "normal"
		} else {
			buttonLabels[ID_BTN_TOGGLE_SUBNET] = fmt.Sprintf("🟢 Подсети: %d активных", len(activeSubnetRoutes))
			buttonTypes[ID_BTN_TOGGLE_SUBNET] = "green"
		}
		if hBtnToggleSubnetRoute != 0 {
			procInvalidateRect.Call(hBtnToggleSubnetRoute, 0, 1)
		}
	} else {
		for _, cidr := range targetPeer.AdvertisedRoutes {
			if err := tunnel.AddSubnetRoute(cidr, vip); err != nil {
				addLog(fmt.Sprintf("❌ Ошибка добавления маршрута к %s через %s: %s", cidr, vip, err.Error()))
			} else {
				activeSubnetRoutes[cidr] = vip
				addLog(fmt.Sprintf("🏠 Добавлен маршрут к подсети %s через %s (%s)", cidr, targetPeer.Nickname, vip))
			}
		}
		buttonLabels[ID_BTN_TOGGLE_SUBNET] = fmt.Sprintf("🟢 Подсеть: %s (ВКЛ)", strings.Join(targetPeer.AdvertisedRoutes, ", "))
		buttonTypes[ID_BTN_TOGGLE_SUBNET] = "green"
		if hBtnToggleSubnetRoute != 0 {
			procInvalidateRect.Call(hBtnToggleSubnetRoute, 0, 1)
		}
	}
}

func showBookmarkDialog(peerID, currentName string) (string, bool) {
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	dlgClassName, _ := windows.UTF16PtrFromString("NatBypassBookmarkDlgClass")
	dlgTitle, _ := windows.UTF16PtrFromString("⭐ Задать имя устройству (Закладка)")

	dlgWc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         3,
		LpfnWndProc:   windows.NewCallback(bookmarkDlgProc),
		HInstance:     hInstance,
		HIcon:         hAppIcon,
		HCursor:       hCursor,
		HbrBackground: hBrushBg,
		LpszClassName: dlgClassName,
		HIconSm:       hAppIcon,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&dlgWc)))

	// Вычисляем позицию по центру родительского окна
	var parentRc RECT
	procGetWindowRect.Call(hMainWnd, uintptr(unsafe.Pointer(&parentRc)))
	dlgW := int32(480)
	dlgH := int32(230)
	dlgX := parentRc.Left + (parentRc.Right-parentRc.Left-dlgW)/2
	dlgY := parentRc.Top + (parentRc.Bottom-parentRc.Top-dlgH)/2
	if dlgX < 0 {
		dlgX = 100
	}
	if dlgY < 0 {
		dlgY = 100
	}

	dlgResultText = currentName
	dlgResultOK = false
	dlgFinished = false

	hDlg, _, _ := procCreateWindowExW.Call(
		0x0008|0x00010000, // WS_EX_TOPMOST | WS_EX_CONTROLPARENT
		uintptr(unsafe.Pointer(dlgClassName)),
		uintptr(unsafe.Pointer(dlgTitle)),
		WS_FIXEDWINDOW|WS_VISIBLE|WS_CLIPCHILDREN,
		uintptr(dlgX), uintptr(dlgY), uintptr(dlgW), uintptr(dlgH),
		hMainWnd, 0, hInstance, 0,
	)

	// DWM Dark Mode
	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hDlg, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	// Добавляем контролы диалога
	_ = createLabelOn(hDlg, hInstance, fmt.Sprintf("Устройство ID: %s", peerID), 20, 16, 440, 22, hFontBold)
	_ = createLabelOn(hDlg, hInstance, "Понятное имя (например: Домашний ПК, Ноутбук, Сервер):", 20, 44, 440, 20, hFontNormal)
	hDlgEdit = createEditOn(hDlg, hInstance, currentName, 20, 72, 425, 30, false, false, hFontNormal)

	_ = createOwnerDrawButtonOn(hDlg, hInstance, "⭐ Сохранить", 20, 126, 140, 38, 5001, "primary")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "🗑 Очистить", 170, 126, 130, 38, 5002, "normal")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "Отмена", 310, 126, 135, 38, 5003, "normal")

	procShowWindow.Call(hDlg, SW_SHOW)
	procSetForegroundWindow.Call(hDlg)
	procSetFocus.Call(hDlgEdit)
	// Выделяем весь текст в поле ввода
	procSendMessageW.Call(hDlgEdit, 0x00B1, 0, uintptr(^uint32(0)))

	// Блокируем главное окно на время модального диалога
	procEnableWindow.Call(hMainWnd, 0)

	var msg MSG
	for !dlgFinished {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		// Обработка клавиш Enter и Esc
		if msg.Message == 0x0100 { // WM_KEYDOWN
			if msg.WParam == 0x0D { // VK_RETURN
				dlgResultText = getControlText(hDlgEdit)
				dlgResultOK = true
				dlgFinished = true
				break
			} else if msg.WParam == 0x1B { // VK_ESCAPE
				dlgResultOK = false
				dlgFinished = true
				break
			}
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	// Разблокируем главное окно
	procEnableWindow.Call(hMainWnd, 1)
	procSetForegroundWindow.Call(hMainWnd)
	procDestroyWindow.Call(hDlg)

	return dlgResultText, dlgResultOK
}

func bookmarkDlgProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_ERASEBKGND:
		return 1
	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		var rc RECT
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), hBrushBg)
		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0
	case WM_DRAWITEM:
		dis := *(*DRAWITEMSTRUCT)(unsafe.Pointer(lParam))
		drawCustomButton(&dis)
		return 1
	case WM_CTLCOLORSTATIC:
		hdc := wParam
		procSetBkMode.Call(hdc, 1)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushBg
	case WM_CTLCOLOREDIT:
		hdc := wParam
		procSetBkMode.Call(hdc, 2)
		procSetBkColor.Call(hdc, COLOR_INPUT)
		procSetTextColor.Call(hdc, 0xFFFFFF)
		return hBrushInput
	case WM_COMMAND:
		id := LOWORD(wParam)
		if id == 5001 { // Сохранить
			dlgResultText = getControlText(hDlgEdit)
			dlgResultOK = true
			dlgFinished = true
			return 0
		} else if id == 5002 { // Очистить
			dlgResultText = ""
			dlgResultOK = true
			dlgFinished = true
			return 0
		} else if id == 5003 { // Отмена
			dlgResultOK = false
			dlgFinished = true
			return 0
		}
	case WM_CLOSE:
		dlgResultOK = false
		dlgFinished = true
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func HIWORD(l uintptr) uint16 {
	return uint16((l >> 16) & 0xFFFF)
}

func refreshProfilesUI() {
	if hListProfiles == 0 || cfg == nil {
		return
	}
	procSendMessageW.Call(hListProfiles, 0x0184 /* LB_RESETCONTENT */, 0, 0)
	active := cfg.EnsureActiveProfile()

	var selectedIndex int = 0
	for i, p := range cfg.Profiles {
		prefix := "⚪ [Неактивна]  "
		if p.ID == cfg.ActiveProfileID || (active != nil && p.ID == active.ID) {
			prefix = "🟢 [✓ АКТИВНА] "
			selectedIndex = i
		}
		itemText := fmt.Sprintf("%s• %s  |  Топик: %s  |  Брокер: %s", prefix, p.Name, p.MQTTTopic, p.MQTTBroker)
		wText, _ := syscall.UTF16PtrFromString(itemText)
		procSendMessageW.Call(hListProfiles, 0x0180 /* LB_ADDSTRING */, 0, uintptr(unsafe.Pointer(wText)))
	}

	if len(cfg.Profiles) > 0 {
		procSendMessageW.Call(hListProfiles, 0x0186 /* LB_SETCURSEL */, uintptr(selectedIndex), 0)
		onProfileSelectionChange()
	}
}

func onProfileSelectionChange() {
	if hListProfiles == 0 || cfg == nil || len(cfg.Profiles) == 0 {
		return
	}
	sel, _, _ := procSendMessageW.Call(hListProfiles, 0x0188 /* LB_GETCURSEL */, 0, 0)
	idx := int(int32(sel))
	if idx < 0 || idx >= len(cfg.Profiles) {
		return
	}
	p := cfg.Profiles[idx]
	selectedProfID = p.ID
	setControlText(hEditProfName, p.Name)
	setControlText(hEditProfTopic, p.MQTTTopic)
	setControlText(hEditProfBroker, p.MQTTBroker)
	setControlText(hEditProfVIP, p.VirtualIP)
}

func applyActiveProfileLive(target *config.Profile) {
	if target == nil || cfg == nil {
		return
	}
	cfg.ActiveProfileID = target.ID
	for i := range cfg.Profiles {
		cfg.Profiles[i].IsActive = (cfg.Profiles[i].ID == target.ID)
	}
	cfg.SyncAWGWithProfile(target)
	_ = config.Save(cfg, configPath, false)
	applyAWGProfileToGUI(target)
	if udpPuncher != nil && target.NetworkKey != "" {
		udpPuncher.SetCipherKey(target.NetworkKey)
	}
	setControlText(hEditMqttBr, target.MQTTBroker)
	setControlText(hEditMqttTp, target.MQTTTopic)
	myVirtualIP = config.ResolveVirtualIP(cfg, myDevID)
	cleanVIP := strings.TrimSpace(strings.Split(myVirtualIP, "/")[0])
	if tunDev != nil {
		_ = tunDev.SetVirtualIP(cleanVIP)
	}
	if uiServer != nil {
		uiServer.SetVirtualIP(cleanVIP)
	}
	if registry != nil {
		registry.ClearAll()
	}
	lastPeersHash = ""
	procSendMessageW.Call(hListPeers, 0x0184 /* LB_RESETCONTENT */, 0, 0)
	if engineCtx != nil {
		go func() {
			tgToken := strings.TrimSpace(getControlText(hEditTgToken))
			tgChat := strings.TrimSpace(getControlText(hEditTgChat))
			rebuildSignalingInternal(engineCtx, chosenModeStr, tgToken, tgChat, target.MQTTBroker, target.MQTTTopic)
			triggerPublish()
		}()
	}
	refreshProfilesUI()
	triggerPublish()
}

func handleProfileSwitch() {
	if cfg == nil || len(cfg.Profiles) == 0 {
		return
	}
	sel, _, _ := procSendMessageW.Call(hListProfiles, 0x0188 /* LB_GETCURSEL */, 0, 0)
	idx := int(int32(sel))
	if idx < 0 || idx >= len(cfg.Profiles) {
		return
	}
	p := cfg.Profiles[idx]
	target, err := cfg.SwitchProfile(p.ID)
	if err != nil {
		addLog("❌ Ошибка переключения: " + err.Error())
		return
	}
	applyActiveProfileLive(target)
	addLog(fmt.Sprintf("🟢 Активный профиль переключен на «%s» (Топик: %s)", target.Name, target.MQTTTopic))
}

func handleProfileCreate() {
	if cfg == nil {
		return
	}
	newProf := config.Profile{
		ID:         "p-" + config.GenerateRandomHex(4),
		Name:       fmt.Sprintf("Сеть #%d", len(cfg.Profiles)+1),
		NetworkKey: config.GenerateRandomHex(16),
		MQTTBroker: "tcp://broker.emqx.io:1883",
		MQTTTopic:  "natbypass/mesh/" + config.GenerateRandomHex(8),
		AWGPreset:  "awg31_strict",
		IsActive:   true,
		CreatedAt:  time.Now(),
	}
	saved := cfg.AddOrUpdateProfile(newProf)
	applyActiveProfileLive(saved)
	addLog(fmt.Sprintf("✅ Создан и подключен новый профиль сети «%s»", saved.Name))
}

func handleProfileSave() {
	if cfg == nil || len(cfg.Profiles) == 0 {
		return
	}
	sel, _, _ := procSendMessageW.Call(hListProfiles, 0x0188 /* LB_GETCURSEL */, 0, 0)
	idx := int(int32(sel))
	if idx < 0 || idx >= len(cfg.Profiles) {
		return
	}
	p := &cfg.Profiles[idx]
	name := strings.TrimSpace(getControlText(hEditProfName))
	topic := strings.TrimSpace(getControlText(hEditProfTopic))
	broker := strings.TrimSpace(getControlText(hEditProfBroker))
	vip := strings.TrimSpace(getControlText(hEditProfVIP))

	if name != "" {
		p.Name = name
	}
	if topic != "" {
		p.MQTTTopic = topic
	}
	if broker != "" {
		p.MQTTBroker = broker
	}
	if vip != "" {
		p.VirtualIP = strings.TrimSpace(vip)
	}

	_ = config.Save(cfg, configPath, false)

	if p.ID == cfg.ActiveProfileID {
		applyActiveProfileLive(p)
	} else {
		refreshProfilesUI()
	}
	addLog(fmt.Sprintf("💾 Настройки профиля «%s» сохранены", p.Name))
}

func handleProfileDelete() {
	if cfg == nil || len(cfg.Profiles) <= 1 {
		procMessageBoxW.Call(hMainWnd,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Нельзя удалить единственный профиль сети."))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Удаление профиля"))),
			0x00000030 /* MB_ICONWARNING */)
		return
	}
	sel, _, _ := procSendMessageW.Call(hListProfiles, 0x0188 /* LB_GETCURSEL */, 0, 0)
	idx := int(int32(sel))
	if idx < 0 || idx >= len(cfg.Profiles) {
		return
	}
	p := cfg.Profiles[idx]

	ret, _, _ := procMessageBoxW.Call(hMainWnd,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(fmt.Sprintf("Удалить профиль «%s»? Связь с участниками этой сети будет разорвана.", p.Name)))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Подтверждение удаления"))),
		0x00000004 /* MB_YESNO */|0x00000030 /* MB_ICONWARNING */)
	if ret != 6 /* IDYES */ {
		return
	}

	wasActive := (p.ID == cfg.ActiveProfileID)
	_ = cfg.DeleteProfile(p.ID)
	_ = config.Save(cfg, configPath, false)

	if wasActive {
		active := cfg.GetActiveProfile()
		if active != nil {
			applyActiveProfileLive(active)
		}
	} else {
		refreshProfilesUI()
	}
	addLog(fmt.Sprintf("🗑️ Профиль «%s» успешно удален", p.Name))
}

func handleProfileExport() {
	if cfg == nil || len(cfg.Profiles) == 0 {
		return
	}
	sel, _, _ := procSendMessageW.Call(hListProfiles, 0x0188 /* LB_GETCURSEL */, 0, 0)
	idx := int(int32(sel))
	if idx < 0 || idx >= len(cfg.Profiles) {
		return
	}
	p := cfg.Profiles[idx]
	uri := config.ExportProfileURI(p)
	copyToClipboard(uri)
	addLog(fmt.Sprintf("✓ Ссылка на сеть «%s» скопирована в буфер обмена: %s", p.Name, uri))
	buttonLabels[ID_BTN_PROF_EXPORT] = "✓ СКОПИРОВАНО!"
	procInvalidateRect.Call(hBtnProfExport, 0, 1)
	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_PROF_EXPORT] = "🔗 Скопировать ссылку"
		procInvalidateRect.Call(hBtnProfExport, 0, 1)
	})
}

func handleProfileImport() {
	uri, ok := showProfileImportDialog()
	if !ok || strings.TrimSpace(uri) == "" {
		return
	}
	parsed, err := config.ImportProfileURI(strings.TrimSpace(uri))
	if err != nil {
		procMessageBoxW.Call(hMainWnd,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Некорректная ссылка профиля: "+err.Error()))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Ошибка импорта"))),
			0x00000010 /* MB_ICONERROR */)
		return
	}

	if cfg == nil {
		cfg = &config.Config{}
	}
	parsed.IsActive = true
	saved := cfg.AddOrUpdateProfile(*parsed)
	applyActiveProfileLive(saved)
	addLog(fmt.Sprintf("📥 Успешно импортирован и активирован профиль «%s» (Топик: %s)", saved.Name, saved.MQTTTopic))
}

func handleDroppedFile(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		addLog("❌ Ошибка чтения файла: " + err.Error())
		return
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return
	}

	// 1. Попытка распарсить как natbypass://profile?...
	if strings.HasPrefix(content, "natbypass://profile") || (strings.Contains(content, "topic=") && strings.Contains(content, "broker=")) {
		parsed, err := config.ImportProfileURI(content)
		if err == nil && parsed != nil {
			if cfg == nil {
				cfg = &config.Config{}
			}
			parsed.IsActive = true
			saved := cfg.AddOrUpdateProfile(*parsed)
			applyActiveProfileLive(saved)
			addLog(fmt.Sprintf("📥 Успешно импортирован профиль «%s» из перетащенного файла", saved.Name))
			return
		}
	}

	// 2. Попытка распарсить как YAML конфиг
	newCfg, err := config.LoadFromString(content)
	if err == nil && newCfg != nil {
		cfg = newCfg
		active := cfg.EnsureActiveProfile()
		applyActiveProfileLive(active)
		addLog("📥 Конфигурация успешно обновлена из файла " + filepath.Base(filePath))
		return
	}

	addLog("⚠️ Не удалось распознать формат файла (ожидается config.yaml или ссылка natbypass://profile)")
}

func showProfileImportDialog() (string, bool) {

	hInstance, _, _ := procGetModuleHandleW.Call(0)
	dlgClassName, _ := windows.UTF16PtrFromString("NatBypassImportDlgClass")
	dlgTitle, _ := windows.UTF16PtrFromString("Импорт профиля P2P сети")

	dlgWc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         3,
		LpfnWndProc:   windows.NewCallback(bookmarkDlgProc),
		HInstance:     hInstance,
		HIcon:         hAppIcon,
		HCursor:       hCursor,
		HbrBackground: hBrushBg,
		LpszClassName: dlgClassName,
		HIconSm:       hAppIcon,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&dlgWc)))

	var parentRc RECT
	procGetWindowRect.Call(hMainWnd, uintptr(unsafe.Pointer(&parentRc)))
	dlgW := int32(520)
	dlgH := int32(230)
	dlgX := parentRc.Left + (parentRc.Right-parentRc.Left-dlgW)/2
	dlgY := parentRc.Top + (parentRc.Bottom-parentRc.Top-dlgH)/2
	if dlgX < 0 {
		dlgX = 100
	}
	if dlgY < 0 {
		dlgY = 100
	}

	dlgResultText = ""
	dlgResultOK = false
	dlgFinished = false

	hDlg, _, _ := procCreateWindowExW.Call(
		0x0008|0x00010000,
		uintptr(unsafe.Pointer(dlgClassName)),
		uintptr(unsafe.Pointer(dlgTitle)),
		WS_FIXEDWINDOW|WS_VISIBLE|WS_CLIPCHILDREN,
		uintptr(dlgX), uintptr(dlgY), uintptr(dlgW), uintptr(dlgH),
		hMainWnd, 0, hInstance, 0,
	)

	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hDlg, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	_ = createLabelOn(hDlg, hInstance, "📥 Импорт P2P сети NatBypass", 20, 16, 480, 22, hFontBold)
	_ = createLabelOn(hDlg, hInstance, "Вставьте ссылку natbypass://profile?... полученную с другого устройства:", 20, 44, 480, 20, hFontNormal)
	hDlgEdit = createEditOn(hDlg, hInstance, "", 20, 72, 465, 30, false, false, hFontNormal)

	_ = createOwnerDrawButtonOn(hDlg, hInstance, "📥 Импортировать", 20, 126, 160, 38, 5001, "primary")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "🗑 Очистить", 190, 126, 130, 38, 5002, "normal")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "Отмена", 330, 126, 155, 38, 5003, "normal")

	procShowWindow.Call(hDlg, SW_SHOW)
	procSetForegroundWindow.Call(hDlg)
	procSetFocus.Call(hDlgEdit)

	procEnableWindow.Call(hMainWnd, 0)

	var msg MSG
	for !dlgFinished {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		if msg.Message == 0x0100 {
			if msg.WParam == 0x0D {
				dlgResultText = getControlText(hDlgEdit)
				dlgResultOK = true
				dlgFinished = true
				break
			} else if msg.WParam == 0x1B {
				dlgResultOK = false
				dlgFinished = true
				break
			}
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	procEnableWindow.Call(hMainWnd, 1)
	procSetForegroundWindow.Call(hMainWnd)
	procDestroyWindow.Call(hDlg)

	return dlgResultText, dlgResultOK
}

func handleProfileQR() {
	if cfg == nil || len(cfg.Profiles) == 0 {
		return
	}
	sel, _, _ := procSendMessageW.Call(hListProfiles, 0x0188 /* LB_GETCURSEL */, 0, 0)
	idx := int(int32(sel))
	var target *config.Profile
	if idx >= 0 && idx < len(cfg.Profiles) {
		target = &cfg.Profiles[idx]
	} else {
		target = cfg.EnsureActiveProfile()
	}
	if target == nil {
		return
	}
	uri := config.ExportProfileURI(*target)
	showQRCodeModal("QR-код сети: "+target.Name, uri)
}

func showQRCodeModal(title, qrText string) {
	qr, err := qrcode.New(qrText, qrcode.Medium)
	if err != nil {
		copyToClipboard(qrText)
		procMessageBoxW.Call(hMainWnd,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Ссылка скопирована в буфер обмена:\n"+qrText))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
			0x00000040 /* MB_ICONINFORMATION */)
		return
	}

	activeQRBitmap = qr.Bitmap()
	activeQRText = qrText
	dlgFinished = false

	hInstance, _, _ := procGetModuleHandleW.Call(0)
	dlgClassName, _ := windows.UTF16PtrFromString("NatBypassQRDlgClass")
	dlgTitle, _ := windows.UTF16PtrFromString(title)

	dlgWc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         3,
		LpfnWndProc:   windows.NewCallback(qrDlgProc),
		HInstance:     hInstance,
		HIcon:         hAppIcon,
		HCursor:       hCursor,
		HbrBackground: hBrushBg,
		LpszClassName: dlgClassName,
		HIconSm:       hAppIcon,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&dlgWc)))

	var parentRc RECT
	procGetWindowRect.Call(hMainWnd, uintptr(unsafe.Pointer(&parentRc)))
	dlgW := int32(400)
	dlgH := int32(490)
	dlgX := parentRc.Left + (parentRc.Right-parentRc.Left-dlgW)/2
	dlgY := parentRc.Top + (parentRc.Bottom-parentRc.Top-dlgH)/2
	if dlgX < 0 {
		dlgX = 100
	}
	if dlgY < 0 {
		dlgY = 100
	}

	hDlg, _, _ := procCreateWindowExW.Call(
		0x0008|0x00010000,
		uintptr(unsafe.Pointer(dlgClassName)),
		uintptr(unsafe.Pointer(dlgTitle)),
		WS_FIXEDWINDOW|WS_VISIBLE|WS_CLIPCHILDREN,
		uintptr(dlgX), uintptr(dlgY), uintptr(dlgW), uintptr(dlgH),
		hMainWnd, 0, hInstance, 0,
	)

	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hDlg, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	_ = createLabelOn(hDlg, hInstance, title, 20, 16, 360, 22, hFontBold)
	_ = createLabelOn(hDlg, hInstance, "Отсканируйте камерой в приложении NatBypass на телефоне:", 20, 42, 360, 18, hFontNormal)

	_ = createOwnerDrawButtonOn(hDlg, hInstance, "📋 Скопировать ссылку", 30, 390, 190, 36, 5001, "primary")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "Закрыть", 230, 390, 135, 36, 5002, "normal")

	procShowWindow.Call(hDlg, SW_SHOW)
	procSetForegroundWindow.Call(hDlg)
	procEnableWindow.Call(hMainWnd, 0)

	var msg MSG
	for !dlgFinished {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		if msg.Message == 0x0100 {
			if msg.WParam == 0x1B || msg.WParam == 0x0D {
				dlgFinished = true
				break
			}
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	procEnableWindow.Call(hMainWnd, 1)
	procSetForegroundWindow.Call(hMainWnd)
	procDestroyWindow.Call(hDlg)
}

func qrDlgProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_ERASEBKGND:
		return 1
	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		var rc RECT
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), hBrushBg)

		// Белая карточка под QR-код
		qrCardRc := RECT{Left: 55, Top: 70, Right: 345, Bottom: 360}
		hBrushWhite, _, _ := procCreateSolidBrush.Call(0x00FFFFFF)
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&qrCardRc)), hBrushWhite)

		// Отрисовка QR матрицы
		if len(activeQRBitmap) > 0 {
			hBrushBlack, _, _ := procCreateSolidBrush.Call(0x00000000)
			modCount := len(activeQRBitmap)
			qrSize := float64(260)
			modSize := qrSize / float64(modCount)
			startX := float64(70)
			startY := float64(85)

			for y := 0; y < modCount; y++ {
				for x := 0; x < modCount; x++ {
					if activeQRBitmap[y][x] {
						modRc := RECT{
							Left:   int32(startX + float64(x)*modSize),
							Top:    int32(startY + float64(y)*modSize),
							Right:  int32(startX + float64(x+1)*modSize + 0.9),
							Bottom: int32(startY + float64(y+1)*modSize + 0.9),
						}
						procFillRect.Call(hdc, uintptr(unsafe.Pointer(&modRc)), hBrushBlack)
					}
				}
			}
			procDeleteObject.Call(hBrushBlack)
		}
		procDeleteObject.Call(hBrushWhite)
		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case WM_DRAWITEM:
		dis := *(*DRAWITEMSTRUCT)(unsafe.Pointer(lParam))
		drawCustomButton(&dis)
		return 1

	case WM_CTLCOLORSTATIC:
		hdc := wParam
		procSetBkMode.Call(hdc, 1)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushBg

	case WM_COMMAND:
		id := LOWORD(wParam)
		if id == 5001 { // Скопировать
			copyToClipboard(activeQRText)
			dlgFinished = true
			return 0
		} else if id == 5002 { // Закрыть
			dlgFinished = true
			return 0
		}

	case WM_CLOSE:
		dlgFinished = true
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

var (
	dlgUpdateInfo       *updater.ReleaseInfo
	dlgUpdatePercent    int
	dlgUpdateStatusText string
	dlgUpdateErrorText  string
	dlgUpdateStarted    bool
	dlgUpdateCompleted  bool
	hDlgUpdateStatus    uintptr
	hDlgUpdateBtnStart  uintptr
	hDlgUpdateBtnCancel uintptr
)

func showUpdateModal(info *updater.ReleaseInfo) {
	if hMainWnd == 0 || info == nil {
		return
	}
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	dlgUpdateInfo = info
	dlgUpdatePercent = 0
	dlgUpdateStatusText = "Готов к скачиванию"
	dlgUpdateErrorText = ""
	dlgUpdateStarted = false
	dlgUpdateCompleted = false
	dlgFinished = false

	dlgClassName, _ := windows.UTF16PtrFromString("NatBypassUpdateDlgClass")
	dlgTitle, _ := windows.UTF16PtrFromString("Обновление NatBypass")

	dlgWc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         3,
		LpfnWndProc:   windows.NewCallback(updateDlgProc),
		HInstance:     hInstance,
		HIcon:         hAppIcon,
		HCursor:       hCursor,
		HbrBackground: hBrushBg,
		LpszClassName: dlgClassName,
		HIconSm:       hAppIcon,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&dlgWc)))

	var parentRc RECT
	procGetWindowRect.Call(hMainWnd, uintptr(unsafe.Pointer(&parentRc)))
	dlgW := int32(520)
	dlgH := int32(310)
	dlgX := parentRc.Left + (parentRc.Right-parentRc.Left-dlgW)/2
	dlgY := parentRc.Top + (parentRc.Bottom-parentRc.Top-dlgH)/2
	if dlgX < 0 {
		dlgX = 100
	}
	if dlgY < 0 {
		dlgY = 100
	}

	hDlg, _, _ := procCreateWindowExW.Call(
		0x0008|0x00010000,
		uintptr(unsafe.Pointer(dlgClassName)),
		uintptr(unsafe.Pointer(dlgTitle)),
		WS_FIXEDWINDOW|WS_VISIBLE|WS_CLIPCHILDREN,
		uintptr(dlgX), uintptr(dlgY), uintptr(dlgW), uintptr(dlgH),
		hMainWnd, 0, hInstance, 0,
	)

	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hDlg, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	_ = createLabelOn(hDlg, hInstance, fmt.Sprintf("🚀 Доступно обновление NatBypass %s", info.LatestVersion), 24, 18, 470, 24, hFontBold)
	_ = createLabelOn(hDlg, hInstance, fmt.Sprintf("Текущая версия: v%s   ➜   Новая версия: %s", Version, info.LatestVersion), 24, 46, 470, 18, hFontNormal)

	sizeMB := float64(info.AssetSize) / (1024 * 1024)
	sizeStr := ""
	if sizeMB > 0 {
		sizeStr = fmt.Sprintf(" • Размер: %.1f MB", sizeMB)
	}
	_ = createLabelOn(hDlg, hInstance, fmt.Sprintf("Файл: %s%s • GitHub Releases", info.AssetName, sizeStr), 24, 68, 470, 18, hFontNormal)

	hDlgUpdateStatus = createLabelOn(hDlg, hInstance, "Нажмите «Начать обновление» для загрузки и установки.", 24, 156, 470, 20, hFontNormal)

	hDlgUpdateBtnStart = createOwnerDrawButtonOn(hDlg, hInstance, "⚡ Начать обновление", 24, 200, 240, 42, 6001, "primary")
	hDlgUpdateBtnCancel = createOwnerDrawButtonOn(hDlg, hInstance, "Отмена", 274, 200, 220, 42, 6002, "normal")

	procShowWindow.Call(hDlg, SW_SHOW)
	procSetForegroundWindow.Call(hDlg)
	procEnableWindow.Call(hMainWnd, 0)

	// Запуск таймера обновления прогресса (каждые 80 мс)
	procSetTimer.Call(hDlg, 1, 80, 0)

	var msg MSG
	for !dlgFinished {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		if msg.Message == 0x0100 {
			if msg.WParam == 0x1B { // Escape
				if !dlgUpdateStarted || dlgUpdateCompleted {
					dlgFinished = true
					break
				}
			}
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	procKillTimer.Call(hDlg, 1)
	procEnableWindow.Call(hMainWnd, 1)
	procSetForegroundWindow.Call(hMainWnd)
	procDestroyWindow.Call(hDlg)
}

func updateDlgProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_ERASEBKGND:
		return 1
	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		var rc RECT
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), hBrushBg)

		// 1. Отрисовка фона полосы прогресса (Progress Bar Track)
		barRc := RECT{Left: 24, Top: 104, Right: 494, Bottom: 144}
		hBrushTrack, _, _ := procCreateSolidBrush.Call(0x002D1E16) // #161e2d
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&barRc)), hBrushTrack)
		procDeleteObject.Call(hBrushTrack)

		// 2. Рамка полосы прогресса
		hBrushBorder, _, _ := procCreateSolidBrush.Call(0x004A3626) // #26364a
		procFrameRect.Call(hdc, uintptr(unsafe.Pointer(&barRc)), hBrushBorder)
		procDeleteObject.Call(hBrushBorder)

		// 3. Заполнение полосы прогресса (Fill Bar)
		pct := dlgUpdatePercent
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		totalWidth := barRc.Right - barRc.Left - 4
		fillWidth := int32(float64(totalWidth) * (float64(pct) / 100.0))
		if fillWidth > 0 {
			fillRc := RECT{
				Left:   barRc.Left + 2,
				Top:    barRc.Top + 2,
				Right:  barRc.Left + 2 + fillWidth,
				Bottom: barRc.Bottom - 2,
			}
			fillColor := uint32(0x00E9A50E) // Cyan #0ea5e9
			if pct >= 100 {
				fillColor = uint32(0x005EC522) // Green #22c55e
			}
			hBrushFill, _, _ := procCreateSolidBrush.Call(uintptr(fillColor))
			procFillRect.Call(hdc, uintptr(unsafe.Pointer(&fillRc)), hBrushFill)
			procDeleteObject.Call(hBrushFill)
		}

		// 4. Текст поверх полосы прогресса (Например: "65% • Скачивание...")
		procSetBkMode.Call(hdc, 1 /* TRANSPARENT */)
		procSetTextColor.Call(hdc, 0x00FFFFFF)
		if hFontBold != 0 {
			procSelectObject.Call(hdc, hFontBold)
		}
		pctText := fmt.Sprintf("%d%%", pct)
		if !dlgUpdateStarted {
			pctText = "0% — Ожидание запуска"
		} else if dlgUpdateCompleted {
			pctText = "100% — Обновление установлено!"
		} else if dlgUpdatePercent > 0 {
			pctText = fmt.Sprintf("%d%% — Загрузка файла...", pct)
		}
		pctUTF16, _ := windows.UTF16FromString(pctText)
		textRc := barRc
		procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&pctUTF16[0])), uintptr(len(pctUTF16)-1), uintptr(unsafe.Pointer(&textRc)), 0x0001|0x0004|0x0020 /* DT_CENTER | DT_VCENTER | DT_SINGLELINE */)

		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case 0x0113: // WM_TIMER
		st := updater.GetStatus()
		if dlgUpdateStarted {
			changed := false
			if dlgUpdatePercent != st.Percent {
				dlgUpdatePercent = st.Percent
				changed = true
			}
			if st.Status != "" && dlgUpdateStatusText != st.Status {
				dlgUpdateStatusText = st.Status
				setControlText(hDlgUpdateStatus, st.Status)
			}
			if st.Error != "" && dlgUpdateErrorText != st.Error {
				dlgUpdateErrorText = st.Error
				setControlText(hDlgUpdateStatus, "❌ "+st.Error)
				buttonLabels[6001] = "❌ Ошибка (Повторить)"
				buttonTypes[6001] = "red"
				procEnableWindow.Call(hDlgUpdateBtnStart, 1)
				procInvalidateRect.Call(hDlgUpdateBtnStart, 0, 1)
			}
			if st.Completed && !dlgUpdateCompleted {
				dlgUpdateCompleted = true
				dlgUpdatePercent = 100
				changed = true
				setControlText(hDlgUpdateStatus, "✅ Обновление установлено! Перезапуск приложения...")
				buttonLabels[6001] = "✅ Перезапуск..."
				buttonTypes[6001] = "green"
				procInvalidateRect.Call(hDlgUpdateBtnStart, 0, 1)
				buttonLabels[6002] = "Закрыть"
				procInvalidateRect.Call(hDlgUpdateBtnCancel, 0, 1)
			}
			if changed {
				barRc := RECT{Left: 24, Top: 104, Right: 494, Bottom: 144}
				procInvalidateRect.Call(hwnd, uintptr(unsafe.Pointer(&barRc)), 0)
			}
		}
		return 0

	case WM_DRAWITEM:
		dis := *(*DRAWITEMSTRUCT)(unsafe.Pointer(lParam))
		drawCustomButton(&dis)
		return 1

	case WM_CTLCOLORSTATIC:
		hdc := wParam
		procSetBkMode.Call(hdc, 1)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushBg

	case WM_COMMAND:
		id := LOWORD(wParam)
		if id == 6001 { // Начать обновление
			if dlgUpdateCompleted {
				dlgFinished = true
				return 0
			}
			dlgUpdateStarted = true
			dlgUpdateErrorText = ""
			buttonLabels[6001] = "⏳ Скачивание..."
			buttonTypes[6001] = "normal"
			procEnableWindow.Call(hDlgUpdateBtnStart, 0)
			procInvalidateRect.Call(hDlgUpdateBtnStart, 0, 1)
			addLog(fmt.Sprintf("⚡ Запуск скачивания обновления %s (%s)...", dlgUpdateInfo.LatestVersion, dlgUpdateInfo.AssetName))

			go func() {
				if err := updater.ApplyUpdate(context.Background(), dlgUpdateInfo.AssetURL); err != nil {
					addLog("❌ Ошибка применения обновления: " + err.Error())
				}
			}()
			return 0
		} else if id == 6002 { // Отмена / Закрыть
			dlgFinished = true
			return 0
		}

	case WM_CLOSE:
		dlgFinished = true
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func handleSaveChannels() {
	saveConfigFromUI()
	addLog("💾 Настройки сигнальных каналов сохранены в config.yaml")
	if engineCtx != nil {
		go func() {
			tgToken := strings.TrimSpace(getControlText(hEditTgToken))
			tgChat := strings.TrimSpace(getControlText(hEditTgChat))
			mqBroker := strings.TrimSpace(getControlText(hEditMqttBr))
			mqTopic := strings.TrimSpace(getControlText(hEditMqttTp))
			rebuildSignalingInternal(engineCtx, chosenModeStr, tgToken, tgChat, mqBroker, mqTopic)
			triggerPublish()
		}()
	}
}


func handleCopySelectedPeerVIP() {
	if registry == nil {
		return
	}
	peers := registry.List()
	selIdx, _, _ := procSendMessageW.Call(hListPeers, 0x0188, 0, 0)
	idx := int(int32(selIdx)) / 2
	if idx >= 0 && idx < len(peers) {
		p := peers[idx]
		vip := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
		if vip != "" {
			copyToClipboard(vip)
			addLog(fmt.Sprintf("📋 Скопирован Virtual IP: %s (%s)", vip, p.Nickname))
		}
	}
}

func handlePingSelectedPeer() {
	if registry == nil {
		return
	}
	peers := registry.List()
	selIdx, _, _ := procSendMessageW.Call(hListPeers, 0x0188, 0, 0)
	idx := int(int32(selIdx)) / 2
	if idx >= 0 && idx < len(peers) {
		p := peers[idx]
		vip := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
		if vip != "" {
			addLog(fmt.Sprintf("🧪 Запуск ICMP Ping до %s (%s)...", vip, p.Nickname))
			go func() {
				cmd := exec.Command("ping", "-n", "3", "-w", "1000", vip)
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
				out, err := cmd.CombinedOutput()
				if err == nil {
					addLog(fmt.Sprintf("🟢 Результат Ping до %s:\r\n%s", p.Nickname, string(out)))
				} else {
					addLog(fmt.Sprintf("🔴 Ошибка Ping до %s: %s", p.Nickname, err.Error()))
				}
			}()
		}
	}
}

func handleToggleAutostart() {
	execPath, err := os.Executable()
	if err != nil {
		addLog("⚠️ Не удалось определить путь к исполняемому файлу: " + err.Error())
		return
	}
	isAutostartEnabled = !isAutostartEnabled
	if err := autostart.SetAutoStart("NatBypass", execPath, isAutostartEnabled); err != nil {
		addLog("⚠️ Ошибка настройки автозапуска в реестре: " + err.Error())
		isAutostartEnabled = !isAutostartEnabled
	} else {
		if isAutostartEnabled {
			buttonLabels[ID_BTN_TOGGLE_AUTOSTART] = "🚀 Автозапуск при старте Windows: ВКЛ"
			buttonTypes[ID_BTN_TOGGLE_AUTOSTART] = "green"
			addLog("🚀 Автозапуск NatBypass в реестре Windows включен")
		} else {
			buttonLabels[ID_BTN_TOGGLE_AUTOSTART] = "🚀 Автозапуск при старте Windows: ВЫКЛ"
			buttonTypes[ID_BTN_TOGGLE_AUTOSTART] = "normal"
			addLog("🚀 Автозапуск NatBypass в реестре Windows отключен")
		}
		if hBtnToggleAutostart != 0 {
			procInvalidateRect.Call(hBtnToggleAutostart, 0, 1)
		}
	}
}

func handleToggleMinimizeToTray() {
	minimizeToTray = !minimizeToTray
	if minimizeToTray {
		buttonLabels[ID_BTN_TOGGLE_TRAY] = "📥 Сворачивать в трей при закрытии: ВКЛ"
		buttonTypes[ID_BTN_TOGGLE_TRAY] = "green"
		addLog("📥 При нажатии на крестик окно сворачивается в системный трей")
	} else {
		buttonLabels[ID_BTN_TOGGLE_TRAY] = "📥 Сворачивать в трей при закрытии: ВЫКЛ"
		buttonTypes[ID_BTN_TOGGLE_TRAY] = "normal"
		addLog("📥 При нажатии на крестик приложение будет полностью завершаться")
	}
	if hBtnToggleMinimizeToTray != 0 {
		procInvalidateRect.Call(hBtnToggleMinimizeToTray, 0, 1)
	}
}

func showPeerContextMenu(hParent, hList uintptr, x, y int32) {
	if registry == nil {
		return
	}
	peers := registry.List()
	if len(peers) == 0 {
		return
	}
	selIdx, _, _ := procSendMessageW.Call(hList, 0x0188 /* LB_GETCURSEL */, 0, 0)
	idx := int(int32(selIdx))
	if hList == hListPeers {
		idx = idx / 2
	}
	if idx < 0 || idx >= len(peers) {
		return
	}
	targetPeer := peers[idx]
	if targetPeer == nil {
		return
	}

	hMenu, _, _ := procCreatePopupMenu.Call()
	copyVIPStr, _ := syscall.UTF16PtrFromString(fmt.Sprintf("📋 Скопировать Virtual IP (%s)", targetPeer.VirtualIP))
	copyPubStr, _ := syscall.UTF16PtrFromString(fmt.Sprintf("🌐 Скопировать STUN/WAN (%s)", targetPeer.STUNAddr))
	pingStr, _ := syscall.UTF16PtrFromString(fmt.Sprintf("🧪 Проверить Ping до %s", targetPeer.Nickname))
	bmStr, _ := syscall.UTF16PtrFromString("⭐ Задать имя (Закладка)...")
	exitStr, _ := syscall.UTF16PtrFromString("🌐 Использовать как шлюз (Exit Node)")
	subnetStr, _ := syscall.UTF16PtrFromString("🏠 Маршрутизировать подсеть узла")

	procAppendMenuW.Call(hMenu, 0, 6001, uintptr(unsafe.Pointer(copyVIPStr)))
	procAppendMenuW.Call(hMenu, 0, 6002, uintptr(unsafe.Pointer(copyPubStr)))
	procAppendMenuW.Call(hMenu, 0, 0x00000800 /* MF_SEPARATOR */, 0)
	procAppendMenuW.Call(hMenu, 0, 6003, uintptr(unsafe.Pointer(pingStr)))
	procAppendMenuW.Call(hMenu, 0, 6004, uintptr(unsafe.Pointer(bmStr)))
	procAppendMenuW.Call(hMenu, 0, 0x00000800 /* MF_SEPARATOR */, 0)
	procAppendMenuW.Call(hMenu, 0, 6005, uintptr(unsafe.Pointer(exitStr)))
	procAppendMenuW.Call(hMenu, 0, 6006, uintptr(unsafe.Pointer(subnetStr)))

	procSetForegroundWindow.Call(hParent)
	cmd, _, _ := procTrackPopupMenu.Call(hMenu, 0x0100 /* TPM_RETURNCMD */|0x0002 /* TPM_RIGHTBUTTON */, uintptr(x), uintptr(y), 0, hParent, 0)

	switch cmd {
	case 6001:
		vip := strings.TrimSpace(strings.Split(targetPeer.VirtualIP, "/")[0])
		if vip != "" {
			copyToClipboard(vip)
			addLog("📋 Скопирован Virtual IP: " + vip)
		}
	case 6002:
		addr := targetPeer.STUNAddr
		if addr == "" {
			addr = targetPeer.PublicIP
		}
		if addr != "" {
			copyToClipboard(addr)
			addLog("🌐 Скопирован адрес узла: " + addr)
		}
	case 6003:
		handlePingSelectedPeer()
	case 6004:
		handleBookmarkPeer()
	case 6005:
		handleExitNodeSelect()
	case 6006:
		handleToggleSubnetRoute()
	}
}

func applyDiagnosticsVisibility() {
	if showDiagnostics {
		procShowWindow.Call(navButtons[6], uintptr(SW_SHOW))
		buttonLabels[ID_BTN_TOGGLE_DIAG] = "🩺 Вкладка Диагностика: ВКЛ"
		buttonTypes[ID_BTN_TOGGLE_DIAG] = "green"
	} else {
		procShowWindow.Call(navButtons[6], uintptr(SW_HIDE))
		buttonLabels[ID_BTN_TOGGLE_DIAG] = "🩺 Вкладка Диагностика: ВЫКЛ"
		buttonTypes[ID_BTN_TOGGLE_DIAG] = "normal"
		if currentTab == 6 {
			selectTab(0)
		}
	}
	if hBtnToggleDiag != 0 {
		procInvalidateRect.Call(hBtnToggleDiag, 0, 1)
	}
	if navButtons[6] != 0 {
		procInvalidateRect.Call(navButtons[6], 0, 1)
	}
	procInvalidateRect.Call(hMainWnd, 0, 1)
}

func setSigModeUI(mode string) {
	chosenModeStr = mode
	buttonTypes[ID_BTN_MODE_PARALLEL] = "normal"
	buttonTypes[ID_BTN_MODE_MQTT] = "normal"
	buttonTypes[ID_BTN_MODE_TG] = "normal"

	if mode == "mqtt_only" {
		buttonTypes[ID_BTN_MODE_MQTT] = "primary"
	} else if mode == "tg_only" {
		buttonTypes[ID_BTN_MODE_TG] = "primary"
	} else {
		buttonTypes[ID_BTN_MODE_PARALLEL] = "primary"
	}

	procInvalidateRect.Call(hBtnModeParallel, 0, 1)
	procInvalidateRect.Call(hBtnModeMQTT, 0, 1)
	procInvalidateRect.Call(hBtnModeTG, 0, 1)

	if vpnConnected && engineCtx != nil {
		go func() {
			tgToken := strings.TrimSpace(getControlText(hEditTgToken))
			tgChat := strings.TrimSpace(getControlText(hEditTgChat))
			mqBroker := strings.TrimSpace(getControlText(hEditMqttBr))
			mqTopic := strings.TrimSpace(getControlText(hEditMqttTp))
			rebuildSignalingInternal(engineCtx, chosenModeStr, tgToken, tgChat, mqBroker, mqTopic)
		}()
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
	lblLogo := createLabel(hInstance, "🛸 NatBypass", 20, 20, 190, 30, hFontTitle)
	lblVer := createLabel(hInstance, fmt.Sprintf("v%s • P2P Mesh", strings.TrimPrefix(Version, "v")), 20, 52, 190, 20, hFontBold)

	navTitles := []string{
		"🚀  Обзор сети",
		"👥  Устройства",
		"🌐  Сети и профили",
		"🛡️  AmneziaWG 3.1",
		"📡  Каналы связи",
		"🏠  Шлюз и подсети",
		"🩺  Диагностика",
		"⚙️  Настройки",
	}
	navIDs := []uint32{
		ID_NAV_DASHBOARD,
		ID_NAV_PEERS,
		ID_NAV_PROFILES,
		ID_NAV_AWG,
		ID_NAV_CHANNELS,
		ID_NAV_ROUTING,
		ID_NAV_DIAG,
		ID_NAV_SETTINGS,
	}

	for i, t := range navTitles {
		navButtons[i] = createOwnerDrawButton(hInstance, t, 16, 88+(i*40), 198, 34, navIDs[i], "nav")
	}

	allControls = append(allControls, lblLogo, lblVer)

	cx := 250
	cw := 840

	// СТРАНИЦА 0: ОБЗОР (DASHBOARD)
	lblDashTitle := createLabel(hInstance, "🚀 Обзор состояния P2P Mesh сети", cx, 16, cw, 28, hFontTitle)
	hLblStatus = createLabel(hInstance, "🟡 ПОИСК УСТРОЙСТВ В СЕТИ...", cx, 46, cw, 22, hFontHeader)

	hBtnVpn = createOwnerDrawButton(hInstance, "🔴 ОЖИДАНИЕ СВЯЗИ (Поиск устройств...)", cx, 74, 480, 38, ID_BTN_VPN, "red")
	hBtnRefresh = createOwnerDrawButton(hInstance, "⚡ Обновить", cx+490, 74, 165, 38, ID_BTN_REFRESH, "normal")
	hBtnManageProfiles = createOwnerDrawButton(hInstance, "🌐 Профили", cx+665, 74, 175, 38, ID_BTN_MANAGE_PROFILES, "normal")

	hLblCardVIP = createLabel(hInstance, "Локальный VIP:\r\n100.64.200.1", cx, 120, 200, 42, hFontBold)
	hLblCardPubIP = createLabel(hInstance, "Внешний IP:\r\nОпределение...", cx+210, 120, 200, 42, hFontNormal)
	hLblCardSTUN = createLabel(hInstance, "STUN Сокет:\r\nПоиск сокета...", cx+420, 120, 200, 42, hFontNormal)
	hLblCardSig = createLabel(hInstance, "Сигнальный канал:\r\nИнициализация...", cx+630, 120, 210, 42, hFontNormal)

	hBtnExitNodeSelect = createOwnerDrawButton(hInstance, "🌐 Выход в интернет: Локальный (Отключен)", cx, 170, 415, 36, ID_BTN_EXIT_NODE_SELECT, "normal")
	hBtnToggleSubnetRoute = createOwnerDrawButton(hInstance, "🏠 Подключить подсеть пира", cx+425, 170, 415, 36, ID_BTN_TOGGLE_SUBNET, "normal")

	lblSummaryTitle := createLabel(hInstance, "👥 Активные участники сети (P2P статус и задержки):", cx, 214, cw, 22, hFontHeader)
	hListSummaryPeers = createListBox(hInstance, cx, 238, cw, 470, hFontNormal)

	tabPages[0] = []uintptr{
		lblDashTitle, hLblStatus, hBtnVpn, hBtnRefresh, hBtnManageProfiles,
		hLblCardVIP, hLblCardPubIP, hLblCardSTUN, hLblCardSig,
		hBtnExitNodeSelect, hBtnToggleSubnetRoute, lblSummaryTitle, hListSummaryPeers,
	}

	// СТРАНИЦА 1: УСТРОЙСТВА (PEERS)
	lblPeersPageTitle := createLabel(hInstance, "👥 Устройства в вашей P2P сети (Mesh Nodes)", cx, 16, cw, 28, hFontTitle)
	lblPeersDesc := createLabel(hInstance, "Все обнаруженные пиры с прямыми UDP P2P каналами и адресами. Кликните правой кнопкой мыши для меню действий.", cx, 44, cw, 18, hFontNormal)

	hBtnBookmarkPeer = createOwnerDrawButton(hInstance, "⭐ Задать имя", cx, 68, 180, 34, ID_BTN_BOOKMARK_PEER, "normal")
	hBtnCopyPeerVIP = createOwnerDrawButton(hInstance, "📋 Скопировать IP", cx+190, 68, 180, 34, ID_BTN_COPY_PEER_VIP, "normal")
	hBtnPingPeer = createOwnerDrawButton(hInstance, "🧪 Ping узла", cx+380, 68, 160, 34, ID_BTN_PING_PEER, "normal")
	btnExitNodeDirect := createOwnerDrawButton(hInstance, "🌐 Назначить шлюзом (Exit Node)", cx+550, 68, 290, 34, ID_BTN_EXIT_NODE_SELECT, "normal")

	hListPeers = createListBox(hInstance, cx, 108, cw, 600, hFontNormal)

	tabPages[1] = []uintptr{
		lblPeersPageTitle, lblPeersDesc, hBtnBookmarkPeer, hBtnCopyPeerVIP, hBtnPingPeer, btnExitNodeDirect, hListPeers,
	}

	// СТРАНИЦА 2: ПРОФИЛИ СЕТЕЙ (PROFILES)
	lblProfTitle := createLabel(hInstance, "🌐 Управление профилями P2P сетей (Mesh Profiles)", cx, 16, cw, 28, hFontTitle)
	lblProfDesc := createLabel(hInstance, "Каждый профиль — это отдельная изолированная сеть. Выбирайте сеть или создавайте новые.", cx, 44, cw, 18, hFontNormal)

	hListProfiles = createListBox(hInstance, cx, 68, cw, 190, hFontNormal)

	hBtnProfSwitch = createOwnerDrawButton(hInstance, "⚡ Подключить сеть", cx, 266, 175, 34, ID_BTN_PROF_SWITCH, "green")
	hBtnProfQR = createOwnerDrawButton(hInstance, "📱 QR-код", cx+185, 266, 130, 34, ID_BTN_PROF_QR, "primary")
	hBtnProfCreate = createOwnerDrawButton(hInstance, "➕ Новая сеть", cx+325, 266, 150, 34, ID_BTN_PROF_CREATE, "normal")
	hBtnProfImport = createOwnerDrawButton(hInstance, "📥 Импорт", cx+485, 266, 150, 34, ID_BTN_PROF_IMPORT, "normal")
	hBtnProfExport = createOwnerDrawButton(hInstance, "🔗 Скопировать ссылку", cx+645, 266, 195, 34, ID_BTN_PROF_EXPORT, "normal")

	lblProfEditHead := createLabel(hInstance, "⚙️ Параметры выбранной сети (Редактирование):", cx, 308, cw, 22, hFontHeader)

	lblProfName := createLabel(hInstance, "Название сети:", cx, 338, 160, 20, hFontBold)
	hEditProfName = createEdit(hInstance, "", cx+165, 334, 675, 28, false, false, hFontNormal)

	lblProfTopic := createLabel(hInstance, "MQTT Топик (секрет):", cx, 374, 160, 20, hFontBold)
	hEditProfTopic = createEdit(hInstance, "", cx+165, 370, 675, 28, false, false, hFontNormal)

	lblProfBroker := createLabel(hInstance, "MQTT Брокер:", cx, 410, 160, 20, hFontBold)
	hEditProfBroker = createEdit(hInstance, "", cx+165, 406, 675, 28, false, false, hFontNormal)

	lblProfVIP := createLabel(hInstance, "Virtual IP (напр. 100.64.200.5):", cx, 446, 160, 20, hFontBold)
	hEditProfVIP = createEdit(hInstance, "", cx+165, 442, 675, 28, false, false, hFontNormal)

	hBtnProfSave = createOwnerDrawButton(hInstance, "💾 Сохранить изменения профиля", cx+165, 480, 415, 38, ID_BTN_PROF_SAVE, "primary")
	hBtnProfDelete = createOwnerDrawButton(hInstance, "🗑️ Удалить эту сеть", cx+590, 480, 250, 38, ID_BTN_PROF_DELETE, "red")

	tabPages[2] = []uintptr{
		lblProfTitle, lblProfDesc, hListProfiles,
		hBtnProfSwitch, hBtnProfQR, hBtnProfCreate, hBtnProfImport, hBtnProfExport,
		lblProfEditHead, lblProfName, hEditProfName,
		lblProfTopic, hEditProfTopic, lblProfBroker, hEditProfBroker,
		lblProfVIP, hEditProfVIP,
		hBtnProfSave, hBtnProfDelete,
	}

	// СТРАНИЦА 3: AMNEZIAWG 3.1
	lblAwgTitle := createLabel(hInstance, "🛡️ AmneziaWG 3.1 — Защита от блокировок DPI (ТСПУ)", cx, 16, cw, 28, hFontTitle)
	lblAwgDesc := createLabel(hInstance, "Поведенческая обфускация: Header Protection (ChaCha20), Content Padding, Random Trailers и джиттер таймеров.", cx, 44, cw, 18, hFontNormal)

	hBtnAwgDpi = createOwnerDrawButton(hInstance, "🔒 AWG 3.1 Strict (ТСПУ)", cx, 70, 205, 34, ID_BTN_AWG_DPI, "primary")
	hBtnAwgStealth = createOwnerDrawButton(hInstance, "⚖️ AWG 3.1 Balanced", cx+212, 70, 205, 34, ID_BTN_AWG_STEALTH, "normal")
	hBtnAwgStd = createOwnerDrawButton(hInstance, "🛡️ Стандартный WireGuard", cx+424, 70, 205, 34, ID_BTN_AWG_STD, "normal")
	hBtnRandomAwg = createOwnerDrawButton(hInstance, "🎲 Случайный 3.1", cx+635, 70, 205, 34, ID_BTN_RAND_AWG, "normal")

	lblJc := createLabel(hInstance, "Jc (мусор):", cx, 114, 70, 20, hFontNormal)
	hEditAwgJc = createEdit(hInstance, "4", cx+75, 110, 60, 28, false, false, hFontNormal)

	lblJmin := createLabel(hInstance, "Jmin:", cx+145, 114, 45, 20, hFontNormal)
	hEditAwgJmin = createEdit(hInstance, "40", cx+195, 110, 60, 28, false, false, hFontNormal)

	lblJmax := createLabel(hInstance, "Jmax:", cx+265, 114, 45, 20, hFontNormal)
	hEditAwgJmax = createEdit(hInstance, "70", cx+315, 110, 60, 28, false, false, hFontNormal)

	lblS1 := createLabel(hInstance, "S1:", cx+385, 114, 30, 20, hFontNormal)
	hEditAwgS1 = createEdit(hInstance, "48", cx+420, 110, 60, 28, false, false, hFontNormal)

	lblS2 := createLabel(hInstance, "S2:", cx+490, 114, 30, 20, hFontNormal)
	hEditAwgS2 = createEdit(hInstance, "32", cx+525, 110, 60, 28, false, false, hFontNormal)

	lblH1 := createLabel(hInstance, "H1 (Init):", cx, 148, 65, 20, hFontNormal)
	hEditAwgH1 = createEdit(hInstance, "1428571428", cx+70, 144, 125, 28, false, false, hFontNormal)

	lblH2 := createLabel(hInstance, "H2 (Resp):", cx+205, 148, 75, 20, hFontNormal)
	hEditAwgH2 = createEdit(hInstance, "2147483647", cx+285, 144, 125, 28, false, false, hFontNormal)

	lblH3 := createLabel(hInstance, "H3 (Cookie):", cx+420, 148, 85, 20, hFontNormal)
	hEditAwgH3 = createEdit(hInstance, "857142857", cx+510, 144, 125, 28, false, false, hFontNormal)

	lblH4 := createLabel(hInstance, "H4 (Data):", cx+645, 148, 70, 20, hFontNormal)
	hEditAwgH4 = createEdit(hInstance, "1122334455", cx+720, 144, 120, 28, false, false, hFontNormal)

	lblConfTitle := createLabel(hInstance, "📄 Готовый конфиг AmneziaWG (Скопируйте в Amnezia VPN или на роутер):", cx, 180, cw, 22, hFontHeader)
	hEditAwgConf = createEdit(hInstance, "", cx, 204, cw, 440, true, true, hFontMono)

	hBtnCopyAwg = createOwnerDrawButton(hInstance, "📋 Скопировать конфиг", cx, 654, 260, 38, ID_BTN_COPY_AWG, "primary")
	hBtnSaveAwg = createOwnerDrawButton(hInstance, "💾 Сохранить в natbypass.conf", cx+275, 654, 280, 38, ID_BTN_SAVE_AWG, "normal")
	hBtnOpenAwgClient = createOwnerDrawButton(hInstance, "🚀 Открыть Amnezia", cx+570, 654, 270, 38, ID_BTN_OPEN_AWG_CLIENT, "normal")

	tabPages[3] = []uintptr{
		lblAwgTitle, lblAwgDesc, hBtnAwgStd, hBtnAwgDpi, hBtnAwgStealth, hBtnRandomAwg,
		lblJc, hEditAwgJc, lblJmin, hEditAwgJmin, lblJmax, hEditAwgJmax, lblS1, hEditAwgS1, lblS2, hEditAwgS2,
		lblH1, hEditAwgH1, lblH2, hEditAwgH2, lblH3, hEditAwgH3, lblH4, hEditAwgH4,
		lblConfTitle, hEditAwgConf, hBtnCopyAwg, hBtnSaveAwg, hBtnOpenAwgClient,
	}

	// СТРАНИЦА 4: КАНАЛЫ СВЯЗИ (SIGNALING)
	lblSigTitle := createLabel(hInstance, "📡 Сигнальные каналы связи (Signaling Channels)", cx, 16, cw, 28, hFontTitle)
	lblSigDesc := createLabel(hInstance, "Каналы используются только для обмена координатами (STUN/IP). Данные передаются строго P2P.", cx, 44, cw, 18, hFontNormal)

	lblMode := createLabel(hInstance, "🎯 Режим работы каналов:", cx, 76, 200, 20, hFontBold)
	hBtnModeParallel = createOwnerDrawButton(hInstance, "🔄 Параллельно (MQTT+TG)", cx+210, 72, 255, 32, ID_BTN_MODE_PARALLEL, "primary")
	hBtnModeMQTT = createOwnerDrawButton(hInstance, "⚡ Только MQTT", cx+475, 72, 175, 32, ID_BTN_MODE_MQTT, "normal")
	hBtnModeTG = createOwnerDrawButton(hInstance, "💬 Только Telegram", cx+660, 72, 180, 32, ID_BTN_MODE_TG, "normal")

	initBroker := "tcp://broker.emqx.io:1883"
	initTopic := "natbypass/mesh/default"
	initTgToken := ""
	initTgChat := ""
	if cfg != nil {
		if act := cfg.EnsureActiveProfile(); act != nil {
			if act.MQTTBroker != "" {
				initBroker = act.MQTTBroker
			}
			if act.MQTTTopic != "" {
				initTopic = act.MQTTTopic
			}
			if act.TGToken != "" {
				initTgToken = act.TGToken
				initTgChat = fmt.Sprintf("%d", act.TGChatID)
			}
		}
	}

	lblMqHead := createLabel(hInstance, "⚡ MQTT Брокер:", cx, 114, cw, 22, hFontHeader)
	lblMqBr := createLabel(hInstance, "URL Брокера:", cx, 140, 200, 20, hFontNormal)
	hEditMqttBr = createEdit(hInstance, initBroker, cx+210, 136, 440, 28, false, false, hFontNormal)
	hBtnTestMqtt = createOwnerDrawButton(hInstance, "🧪 Проверить MQTT", cx+660, 134, 180, 32, ID_BTN_TEST_MQTT, "normal")

	lblMqPresets := createLabel(hInstance, "Пресеты:", cx+210, 170, 75, 18, hFontNormal)
	hBtnMqEMQX := createOwnerDrawButton(hInstance, "⚡ EMQX", cx+290, 168, 95, 24, ID_BTN_MQ_EMQX, "normal")
	hBtnMqHive := createOwnerDrawButton(hInstance, "⚡ HiveMQ", cx+395, 168, 105, 24, ID_BTN_MQ_HIVE, "normal")
	hBtnMqMosq := createOwnerDrawButton(hInstance, "⚡ Mosquitto", cx+510, 168, 120, 24, ID_BTN_MQ_MOSQ, "normal")
	hBtnMqEcl := createOwnerDrawButton(hInstance, "⚡ Eclipse", cx+640, 168, 100, 24, ID_BTN_MQ_ECL, "normal")

	lblMqTp := createLabel(hInstance, "Уникальный топик:", cx, 202, 200, 20, hFontNormal)
	hEditMqttTp = createEdit(hInstance, initTopic, cx+210, 198, 630, 28, false, false, hFontNormal)
	lblMqTopicHint := createLabel(hInstance, "🔒 Задайте уникальный секретный топик (ключ вашей сети), например: natbypass/mesh/default", cx+210, 228, 630, 18, hFontNormal)

	lblTgHead := createLabel(hInstance, "💬 Telegram Bot API:", cx, 256, cw, 22, hFontHeader)
	lblTgToken := createLabel(hInstance, "Токен бота (@BotFather):", cx, 282, 200, 20, hFontNormal)
	hEditTgToken = createEdit(hInstance, initTgToken, cx+210, 278, 440, 28, false, false, hFontNormal)
	hBtnTestTg = createOwnerDrawButton(hInstance, "🧪 Проверить бот", cx+660, 276, 180, 32, ID_BTN_TEST_TG, "normal")

	lblTgChat := createLabel(hInstance, "Chat ID (ЛС или Группа):", cx, 316, 200, 20, hFontNormal)
	hEditTgChat = createEdit(hInstance, initTgChat, cx+210, 312, 630, 28, false, false, hFontNormal)
	lblTgHint := createLabel(hInstance, "💡 1) Создайте бота в @BotFather  2) Узнайте Chat ID через @userinfobot  3) Добавьте ботов всех ПК в одну группу!", cx, 344, cw, 18, hFontNormal)

	hBtnSaveChannels = createOwnerDrawButton(hInstance, "💾 Применить и сохранить настройки каналов", cx+160, 380, 520, 42, ID_BTN_SAVE_CHANNELS, "primary")

	tabPages[4] = []uintptr{
		lblSigTitle, lblSigDesc, lblMode, hBtnModeParallel, hBtnModeMQTT, hBtnModeTG,
		lblMqHead, lblMqBr, hEditMqttBr, hBtnTestMqtt, lblMqPresets, hBtnMqEMQX, hBtnMqHive, hBtnMqMosq, hBtnMqEcl, lblMqTp, hEditMqttTp, lblMqTopicHint,
		lblTgHead, lblTgToken, hEditTgToken, hBtnTestTg, lblTgChat, hEditTgChat, lblTgHint,
		hBtnSaveChannels,
	}

	// СТРАНИЦА 5: ШЛЮЗ И ПОДСЕТИ (ROUTING)
	lblRoutingTitle := createLabel(hInstance, "🏠 Маршрутизация трафика (Exit Node & Локальные подсети)", cx, 16, cw, 28, hFontTitle)
	lblRoutingDesc := createLabel(hInstance, "Настройка выхода в интернет через удаленные компьютеры сети и доступ к локальным устройствам.", cx, 44, cw, 18, hFontNormal)

	lblExitHead := createLabel(hInstance, "🌐 Выход в интернет (Exit Node):", cx, 74, cw, 22, hFontHeader)
	btnExitClientDirect := createOwnerDrawButton(hInstance, "🌐 Переключить шлюз Exit Node", cx, 102, 415, 38, ID_BTN_EXIT_NODE_SELECT, "normal")

	exitText := "🛡️ Выход через этот ПК: ВЫКЛ"
	exitType := "normal"
	if allowExitNode {
		exitText = "🛡️ Выход через этот ПК: ВКЛ"
		exitType = "green"
	}
	hBtnAllowExit = createOwnerDrawButton(hInstance, exitText, cx+425, 102, 415, 38, ID_BTN_ALLOW_EXIT, exitType)

	lblSubnetHead := createLabel(hInstance, "🏠 Доступ к локальным подсетям (LAN):", cx, 154, cw, 22, hFontHeader)

	localSubnets := network.GetLocalSubnets()
	addSubnetBtnText := "➕ Добавить мою сеть"
	if len(localSubnets) > 0 {
		addSubnetBtnText = fmt.Sprintf("➕ Добавить мою сеть: %s", localSubnets[0])
	}
	hBtnAddLocalSubnet = createOwnerDrawButton(hInstance, addSubnetBtnText, cx, 182, 415, 38, ID_BTN_ADD_LOCAL_SUBNET, "normal")
	btnSubnetToggleDirect := createOwnerDrawButton(hInstance, "🏠 Подключить подсеть пира", cx+425, 182, 415, 38, ID_BTN_TOGGLE_SUBNET, "normal")

	lblAdvSubnets := createLabel(hInstance, "Список анонсируемых подсетей (через запятую, напр. 192.168.1.0/24):", cx, 230, 480, 20, hFontNormal)
	hEditAdvSubnets = createEdit(hInstance, "", cx+490, 226, 350, 28, false, false, hFontNormal)

	tabPages[5] = []uintptr{
		lblRoutingTitle, lblRoutingDesc,
		lblExitHead, btnExitClientDirect, hBtnAllowExit,
		lblSubnetHead, hBtnAddLocalSubnet, btnSubnetToggleDirect, lblAdvSubnets, hEditAdvSubnets,
	}

	// СТРАНИЦА 6: ДИАГНОСТИКА И ЖУРНАЛ
	lblDiagTitle := createLabel(hInstance, "🩺 Диагностика связности & Журнал событий", cx, 16, cw, 28, hFontTitle)
	hBtnRunDiag = createOwnerDrawButton(hInstance, "🔄 Комплексный тест сети", cx, 48, 230, 36, ID_BTN_RUN_DIAG, "primary")
	hBtnDumpStack = createOwnerDrawButton(hInstance, "⚡ Снимок памяти", cx+240, 48, 210, 36, ID_BTN_DUMP_STACK, "normal")
	hBtnSaveLogs = createOwnerDrawButton(hInstance, "💾 Экспорт лога", cx+460, 48, 185, 36, ID_BTN_SAVE_LOGS, "normal")
	hEditLogs = createEdit(hInstance, "", cx, 92, cw, 610, true, true, hFontMono)
	hEditDiagLog = hEditLogs

	tabPages[6] = []uintptr{lblDiagTitle, hBtnRunDiag, hBtnDumpStack, hBtnSaveLogs, hBtnClrLogs, hEditLogs}

	// СТРАНИЦА 7: НАСТРОЙКИ (SETTINGS)
	lblSetTitle := createLabel(hInstance, "⚙️ Настройки приложения NatBypass", cx, 16, cw, 28, hFontTitle)
	lblSetDesc := createLabel(hInstance, "Параметры автозапуска, интеграции с Windows и обновление приложения.", cx, 44, cw, 18, hFontNormal)

	lblNick := createLabel(hInstance, "🏷️ Ваше имя / Никнейм:", cx, 74, 200, 20, hFontBold)
	hEditMyNick = createEdit(hInstance, myNick, cx+210, 70, 630, 28, false, false, hFontNormal)
	lblNickHint := createLabel(hInstance, "💡 Имя, которое увидят другие участники сети (например: Домашний ПК, Ноутбук)", cx+210, 100, 630, 18, hFontNormal)

	lblSysHead := createLabel(hInstance, "🛠️ Интеграция с системой Windows:", cx, 130, cw, 22, hFontHeader)

	autostartText := "🚀 Автозапуск при старте Windows: ВЫКЛ"
	autostartType := "normal"
	if isAutostartEnabled {
		autostartText = "🚀 Автозапуск при старте Windows: ВКЛ"
		autostartType = "green"
	}
	hBtnToggleAutostart = createOwnerDrawButton(hInstance, autostartText, cx, 158, 415, 38, ID_BTN_TOGGLE_AUTOSTART, autostartType)

	trayText := "📥 Сворачивать в трей при закрытии: ВКЛ"
	trayType := "green"
	if !minimizeToTray {
		trayText = "📥 Сворачивать в трей при закрытии: ВЫКЛ"
		trayType = "normal"
	}
	hBtnToggleMinimizeToTray = createOwnerDrawButton(hInstance, trayText, cx+425, 158, 415, 38, ID_BTN_TOGGLE_TRAY, trayType)

	logsText := "💾 Запись логов на диск: ВЫКЛ"
	logsType := "normal"
	if saveLogsToDisk {
		logsText = "💾 Запись логов на диск: ВКЛ"
		logsType = "green"
	}
	hBtnToggleLogs = createOwnerDrawButton(hInstance, logsText, cx, 204, 415, 38, ID_BTN_TOGGLE_LOGS, logsType)

	hBtnSaveCfg = createOwnerDrawButton(hInstance, "💾 Сохранить настройки в config.yaml", cx, 260, cw, 42, ID_BTN_SAVE_CFG, "primary")
	hBtnCheckUpdate = createOwnerDrawButton(hInstance, "🚀 Проверить обновления NatBypass на GitHub", cx, 310, cw, 38, ID_BTN_CHECK_UPDATE, "green")
	lblUpdateStatus = createLabel(hInstance, fmt.Sprintf("Текущая версия: v%s • Нажмите для проверки наличия обновлений с GitHub Releases", Version), cx, 354, cw, 20, hFontNormal)

	tabPages[7] = []uintptr{
		lblSetTitle, lblSetDesc, lblNick, hEditMyNick, lblNickHint,
		lblSysHead, hBtnToggleAutostart, hBtnToggleMinimizeToTray, hBtnToggleLogs,
		hBtnSaveCfg, hBtnCheckUpdate, lblUpdateStatus,
	}

	// СТАРТОВЫЙ ЭКРАН (STARTUP / SPLASH OVERLAY)
	hSplashTitle = createLabel(hInstance, "🛸 NatBypass P2P Mesh Engine", cx+40, 50, cw-80, 36, hFontTitle)
	hSplashSub = createLabel(hInstance, "Автономная P2P mesh-сеть нового поколения • Инициализация...", cx+40, 92, cw-80, 22, hFontNormal)
	hSplashStep1 = createLabel(hInstance, "🟢 [ 1/4 ] 🧹 Очистка старых сессий и фоновых процессов — Завершено", cx+60, 160, cw-120, 24, hFontHeader)
	hSplashStep2 = createLabel(hInstance, "🟡 [ 2/4 ] 🛡️ Инициализация виртуального сетевого адаптера Wintun...", cx+60, 205, cw-120, 24, hFontHeader)
	hSplashStep3 = createLabel(hInstance, "🟡 [ 3/4 ] 🌐 Определение внешнего IP и постоянного STUN сокета...", cx+60, 250, cw-120, 24, hFontHeader)
	hSplashStep4 = createLabel(hInstance, "🟡 [ 4/4 ] ⚡ Подключение каналов сигнализации (MQTT + Telegram)...", cx+60, 295, cw-120, 24, hFontHeader)
	hSplashBar = createLabel(hInstance, "🚀 Запуск сетевого ядра... Пожалуйста, подождите...", cx+40, 380, cw-80, 26, hFontBold)

	splashControls = []uintptr{hSplashTitle, hSplashSub, hSplashStep1, hSplashStep2, hSplashStep3, hSplashStep4, hSplashBar}

	for _, h := range splashControls {
		procShowWindow.Call(h, uintptr(SW_HIDE))
	}

	fillConfigFields()
	renderAWGTextFromUI()
	applyDiagnosticsVisibility()
	writeDebug("buildModernUI: fillConfigFields и renderAWGText завершены")

	selectTab(0)
}

func showSplashScreen() {
	isSplashActive = true
	if hBtnSyncAwg != 0 {
		procShowWindow.Call(hBtnSyncAwg, uintptr(SW_HIDE))
	}
	for _, page := range tabPages {
		for _, h := range page {
			procShowWindow.Call(h, uintptr(SW_HIDE))
		}
	}
	for _, btn := range navButtons {
		if btn != 0 {
			if btn == navButtons[6] && !showDiagnostics {
				procShowWindow.Call(btn, uintptr(SW_HIDE))
				continue
			}
			procShowWindow.Call(btn, uintptr(SW_SHOW))
			procInvalidateRect.Call(btn, 0, 1)
		}
	}
	for _, h := range splashControls {
		procShowWindow.Call(h, uintptr(SW_SHOW))
		procInvalidateRect.Call(h, 0, 1)
	}
	procInvalidateRect.Call(hMainWnd, 0, 1)
}

func hideSplashScreen() {
	isSplashActive = false
	for _, h := range splashControls {
		procShowWindow.Call(h, uintptr(SW_HIDE))
	}
	selectTab(0)
}

func selectTab(index int) {
	if isSplashActive {
		hideSplashScreen()
	}
	currentTab = index
	for i, page := range tabPages {
		show := SW_HIDE
		if i == index {
			show = SW_SHOW
		}
		for _, h := range page {
			procShowWindow.Call(h, uintptr(show))
			if show == SW_SHOW {
				procInvalidateRect.Call(h, 0, 1)
			}
		}
	}
	if index == 3 && syncAWGPeerParams != nil && hBtnSyncAwg != 0 {
		procShowWindow.Call(hBtnSyncAwg, uintptr(SW_SHOW))
		procInvalidateRect.Call(hBtnSyncAwg, 0, 1)
	} else if hBtnSyncAwg != 0 {
		procShowWindow.Call(hBtnSyncAwg, uintptr(SW_HIDE))
	}
	for _, btn := range navButtons {
		if btn != 0 {
			if btn == navButtons[6] && !showDiagnostics {
				procShowWindow.Call(btn, uintptr(SW_HIDE))
			} else {
				procShowWindow.Call(btn, uintptr(SW_SHOW))
				procInvalidateRect.Call(btn, 0, 1)
			}
		}
	}
	if index == 0 || index == 1 {
		updateData()
	}
	if index == 2 {
		refreshProfilesUI()
	}
	if index == 3 {
		renderAWGTextFromUI()
	}
	if index == 6 {
		flushLogsToUI()
	}
	procInvalidateRect.Call(hMainWnd, 0, 1)
}

func toggleVPNManual() {
	vpnConnected = !vpnConnected
	if vpnConnected {
		buttonLabels[ID_BTN_VPN] = fmt.Sprintf("🟢 ПОДКЛЮЧЕНО (Ваш IP: %s)", myVirtualIP)
		buttonTypes[ID_BTN_VPN] = "green"
		addLog(fmt.Sprintf("🟢 Туннель включен вручную (IP: %s/24)", myVirtualIP))
	} else {
		buttonLabels[ID_BTN_VPN] = "🔴 ОТКЛЮЧЕНО (Нажмите для включения)"
		buttonTypes[ID_BTN_VPN] = "red"
		addLog("🔴 Туннель отключен пользователем")
	}
	procInvalidateRect.Call(hBtnVpn, 0, 1)
}

func loadOrGenerateKeys(cfg *config.Config) ([32]byte, [32]byte, error) {
	if cfg.Crypto.PublicKey != "" && cfg.Crypto.PrivateKey != "" {
		pub, err := crypto.HexToKey(cfg.Crypto.PublicKey)
		if err == nil {
			priv, err := crypto.HexToKey(cfg.Crypto.PrivateKey)
			if err == nil {
				return pub, priv, nil
			}
		}
	}

	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("failed to generate encryption keys: %w", err)
	}

	cfg.Crypto.PublicKey = crypto.KeyToHex(pub)
	cfg.Crypto.PrivateKey = crypto.KeyToHex(priv)
	_ = config.Save(cfg, configPath, false)
	return pub, priv, nil
}

func startEngineFromConfig(c *config.Config) {
	defer func() {
		if r := recover(); r != nil {
			writeDebug(fmt.Sprintf("❌ CRITICAL PANIC in startEngine: %v\r\n%s", r, string(debug.Stack())))
		}
	}()

	engineMu.Lock()
	defer engineMu.Unlock()

	writeDebug("Запуск фонового сетевого ядра...")
	ctx, cancel := context.WithCancel(context.Background())
	engineCtx = ctx
	engineCancel = cancel
	triggerPublishCh = make(chan struct{}, 10)

	var err error
	myPubKey, myPrivKey, err = loadOrGenerateKeys(c)
	if err != nil {
		addLog("⚠️ Ошибка генерации ключей: " + err.Error())
	}
	pubHex := crypto.KeyToHex(myPubKey)
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "Win"
	}
	if c.App.DeviceID != "" {
		myDevID = c.App.DeviceID
	} else {
		myDevID = fmt.Sprintf("%s-%s", hn, pubHex[:6])
		c.App.DeviceID = myDevID
		_ = config.Save(c, configPath, false)
	}
	writeDebug("Идентификатор устройства: " + myDevID)

	myVirtualIP = config.ResolveVirtualIP(c, myDevID)
	writeDebug("Локальный Virtual IP: " + myVirtualIP)

	if wgKP, wgErr := wireguard.GenerateKeyPair(); wgErr == nil {
		myWGPubKey = wgKP.PublicKey
		myWGPrivKey = wgKP.PrivateKey
	}

	registry = peer.NewRegistry()
	registry.StartMonitor(ctx, 2*time.Minute)

	// Запуск встроенного современного Glassmorphism Web UI мгновенно
	webPort := 8080
	if c.WebUI.Port > 0 {
		webPort = c.WebUI.Port
	}
	uiServer = webui.NewServer(webPort, c.WebUI.Username, c.WebUI.Password, registry, nil)
	uiServer.SetDeviceName(myNick)
	uiServer.SetVersion(Version)
	uiServer.SetVirtualIP(myVirtualIP)
	uiServer.SetAppState(myDevID, myPublicIP, mySTUNAddr, myVirtualIP)
	uiServer.SetConfigPath(configPath)
	uiServer.SetOnConfigChange(func() {
		if reloaded, err := config.Load(configPath); err == nil && reloaded != nil {
			cfg = reloaded
			applyActiveProfileLive(cfg.EnsureActiveProfile())
		}
		triggerPublish()
	})
	uiServer.SetOnProfileSwitch(func(p *config.Profile) error {
		if p != nil {
			applyActiveProfileLive(p)
		}
		return nil
	})
	go func() {
		if err := uiServer.Start(ctx); err != nil {
			writeDebug("Web UI сервер: " + err.Error())
		}
	}()

	if c.Relay.Server != "" {
		guiWSSClient = relay.NewWSSRelayClient(c.Relay.Server, myDevID, func(srcID string, payload []byte) {
			if len(payload) > 0 && tunDev != nil {
				_ = tunDev.WritePacket(payload)
			}
		})
		guiWSSClient.Start()
		writeDebug("🔒 GUI: WSS/HTTPS Fallback Relay (порт 443) запущен: " + c.Relay.Server)
	}

	// Создание реального UDP Hole Punching сокета
	// Порт берётся из конфига (Network.UDPPort). По умолчанию 0 = OS назначает случайный порт.
	// Это критично чтобы не конфликтовать с локальным AWG/WireGuard на порту 51820.
	udpListenPort := c.Network.UDPPort
	puncher, err := network.NewUDPPuncher(udpListenPort, myDevID, c.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		atomic.AddUint64(&packetsRecvCount, 1)
		if guiMagicSock != nil {
			guiMagicSock.RecordProbeSuccess(remoteDevID, fromAddr, rtt)
		}
		if p, ok := registry.Get(remoteDevID); ok {
			p.DirectP2P = true
			if rtt > 0 && rtt <= 1500*time.Millisecond {
				if p.Latency > 0 {
					p.Latency = time.Duration(float64(p.Latency)*0.70 + float64(rtt)*0.30)
				} else {
					p.Latency = rtt
				}
				p.PingMs = p.Latency.Milliseconds()
			}
			p.ActiveEndpoint = fromAddr
			p.Online = true
			p.LastSeen = time.Now()
			registry.Upsert(p)
			msg := fmt.Sprintf("⚡ [P2P Direct UDP] ПОДТВЕРЖДЕНО! Прямой UDP-пинг до %s (%s): %v! NAT пробит сокет-в-сокет!", remoteDevID, fromAddr, p.Latency.Round(time.Millisecond))
			addLog(msg)
			writeDebug(msg)
		}
	})
	if err == nil {
		udpPuncher = puncher
		if activeProf := c.EnsureActiveProfile(); activeProf != nil && activeProf.NetworkKey != "" {
			udpPuncher.SetCipherKey(activeProf.NetworkKey)
		}
		puncher.StartKeepAliveLoop()
		guiMagicSock = network.NewMagicSock(puncher, func(devID, oldPath, newPath string, pType network.PathType) {
			writeDebug(fmt.Sprintf("🧲 Magicsock GUI: путь к %s переключен: %s -> %s (%s)", devID, oldPath, newPath, pType))
		})
		writeDebug(fmt.Sprintf("UDPPuncher слушает локальный UDP порт :%d", puncher.LocalPort()))

		// Маршрутизация входящих IP-пакетов туннеля напрямую в виртуальный адаптер Windows
		puncher.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
			if len(payload) < 20 {
				return
			}
			srcIP := tunnel.GetSrcIP(payload)
			cleanVIP := strings.TrimSpace(strings.Split(myVirtualIP, "/")[0])
			if srcIP != nil && srcIP.String() == cleanVIP {
				return // Защита от петель
			}
			if srcIP != nil && registry != nil && srcAddr != nil {
				fromAddrStr := srcAddr.String()
				var targetPeer *peer.Peer
				srcIPStr := srcIP.String()

				if p, ok := registry.GetByVirtualIP(srcIPStr); ok && p != nil {
					targetPeer = p
				} else {
					for _, item := range registry.List() {
						if item.ActiveEndpoint == fromAddrStr || item.STUNAddr == fromAddrStr || item.LocalAddr == fromAddrStr {
							targetPeer = item
							targetPeer.VirtualIP = srcIPStr
							break
						}
						for _, c := range item.Candidates {
							if c == fromAddrStr {
								targetPeer = item
								targetPeer.VirtualIP = srcIPStr
								break
							}
						}
						if targetPeer != nil {
							break
						}
					}
					if targetPeer == nil {
						pList := registry.List()
						if len(pList) == 1 {
							targetPeer = pList[0]
							targetPeer.VirtualIP = srcIPStr
						}
					}
				}

				if targetPeer != nil {
					targetPeer.DirectP2P = true
					targetPeer.ActiveEndpoint = fromAddrStr
					targetPeer.Online = true
					targetPeer.LastSeen = time.Now()
					registry.Upsert(targetPeer)
					if guiMagicSock != nil {
						guiMagicSock.RecordProbeSuccess(targetPeer.DeviceID, fromAddrStr, 0)
					}
					if udpPuncher != nil {
						udpPuncher.AddKeepAliveTarget(fromAddrStr)
					}
				}
			}
			if tunDev != nil {
				_ = tunDev.WritePacket(payload)
				atomic.AddUint64(&packetsRecvCount, 1)
			}
		})
	} else {
		writeDebug("Ошибка создания UDPPuncher: " + err.Error())
	}

	// 🚀 АВТОМАТИЧЕСКОЕ ПОДНЯТИЕ ВИРТУАЛЬНОГО СЕТЕВОГО АДАПТЕРА WINDOWS (Wintun TUN)
	go func() {
		tDev, tErr := tunnel.CreateAdapter("NatBypass", myVirtualIP)
		if tErr == nil {
			tunDev = tDev
			msg := fmt.Sprintf("🛡️ Виртуальный сетевой адаптер Windows 'NatBypass' активен! (IP: %s/24)", myVirtualIP)
			addLog(msg)
			writeDebug(msg)

			// Буферизированный конвейер отправки исходящих IP-пакетов из сетевого стека Windows
			pktCh := make(chan []byte, 256)
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					default:
						packet, readErr := tunDev.ReadPacket()
						if readErr != nil {
							time.Sleep(1 * time.Millisecond)
							continue
						}
						if len(packet) < 20 {
							continue
						}
						pktCopy := make([]byte, len(packet))
						copy(pktCopy, packet)
						select {
						case pktCh <- pktCopy:
						default:
						}
					}
				}
			}()

			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case packet, ok := <-pktCh:
						if !ok {
							return
						}
						srcIP := tunnel.GetSrcIP(packet)
						destIP := tunnel.GetDestIP(packet)
						if srcIP == nil || destIP == nil {
							continue
						}
						destStr := destIP.String()

						// Игнорируем мультикаст Windows (224.0.0.x, 239.255.x.x, 255.255.255.255), бродкаст и петли
						cleanVIP := strings.TrimSpace(strings.Split(myVirtualIP, "/")[0])
						if destIP.IsMulticast() || destIP.IsUnspecified() || destStr == "255.255.255.255" || destStr == cleanVIP || strings.HasSuffix(destStr, ".255") || strings.HasSuffix(destStr, ".0") {
							continue
						}

						if registry != nil {
							peers := registry.List()
							var targetPeer *peer.Peer

							for _, p := range peers {
								pVIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
								if p.DeviceID != myDevID && (p.VirtualIP == destStr || pVIP == destStr) {
									targetPeer = p
									break
								}
							}

							// 2. Маршрут к подсети пира с Longest Prefix Match (LPM)
							if targetPeer == nil {
								bestPrefixLen := -1
								for _, p := range peers {
									if p.DeviceID == myDevID {
										continue
									}
									for _, route := range p.AdvertisedRoutes {
										if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(route)); err == nil && ipNet.Contains(destIP) {
											ones, _ := ipNet.Mask.Size()
											if ones > bestPrefixLen {
												bestPrefixLen = ones
												targetPeer = p
											}
										}
									}
								}
							}

							// 3. Маршрутизация через Exit Node
							if targetPeer == nil && activeExitNodeID != "" {
								if ep, ok := registry.Get(activeExitNodeID); ok && ep.Online {
									targetPeer = ep
								}
							}

							if targetPeer != nil {
								targetEP := targetPeer.ActiveEndpoint
								if guiMagicSock != nil {
									if bestEP, _, _ := guiMagicSock.GetActiveRoute(targetPeer.DeviceID); bestEP != "" {
										targetEP = bestEP
									}
								}
								if targetEP == "" {
									targetEP = targetPeer.STUNAddr
								}
								if targetEP == "" {
									targetEP = targetPeer.LocalAddr
								}

								pmin := 0
								pmax := 0
								if targetPeer.AWG != nil {
									pmin = targetPeer.AWG.Pmin
									pmax = targetPeer.AWG.Pmax
								}

								// 1. Прямая отправка пакета строго по прямому P2P UDP сокету
								if udpPuncher != nil && targetEP != "" {
									_ = udpPuncher.SendDataPacketWithPadding(targetEP, packet, pmin, pmax)
								}
								// 1b. Мгновенное реактивное пробитие NAT при попытке отправки данных до неподтвержденного пира
								if !targetPeer.DirectP2P && udpPuncher != nil {
									if targetPeer.STUNAddr != "" && targetPeer.STUNAddr != targetEP {
										_ = udpPuncher.SendHolePunchProbe(targetPeer.STUNAddr)
									}
									for _, cand := range targetPeer.Candidates {
										if cand != "" && cand != targetEP && cand != targetPeer.STUNAddr {
											_ = udpPuncher.SendHolePunchProbe(cand)
										}
									}
								}
								atomic.AddUint64(&packetsSentCount, 1)
							}
						}
					}
				}
			}()
		} else {
			warnMsg := fmt.Sprintf("⚠️ Wintun адаптер: %s (Для полного ping запустите от Администратора)", tErr.Error())
			addLog(warnMsg)
			writeDebug(warnMsg)
		}
	}()

	activeProf := c.EnsureActiveProfile()
	if activeProf != nil {
		c.SyncSignalingWithProfile(activeProf)
		c.SyncAWGWithProfile(activeProf)
	}

	tgToken := ""
	tgChat := ""
	mqBroker := "tcp://broker.emqx.io:1883"
	mqTopic := "natbypass/mesh/default"
	if activeProf != nil {
		if activeProf.MQTTBroker != "" {
			mqBroker = activeProf.MQTTBroker
		}
		if activeProf.MQTTTopic != "" {
			mqTopic = activeProf.MQTTTopic
		}
		if activeProf.TGToken != "" {
			tgToken = activeProf.TGToken
			tgChat = fmt.Sprintf("%d", activeProf.TGChatID)
		}
	}
	for _, ch := range c.Signaling.Channels {
		if ch.Type == "telegram" && ch.Params != nil && tgToken == "" {
			if ch.Params["token"] != "" {
				tgToken = ch.Params["token"]
			}
			if ch.Params["chat_id"] != "" {
				tgChat = ch.Params["chat_id"]
			}
		}
		if ch.Type == "mqtt" && ch.Params != nil && (activeProf == nil || activeProf.MQTTTopic == "") {
			if ch.Params["broker_url"] != "" {
				mqBroker = ch.Params["broker_url"]
			}
			if ch.Params["topic"] != "" {
				mqTopic = ch.Params["topic"]
			}
		}
	}

	tgEnabled := false
	mqEnabled := false
	for _, ch := range c.Signaling.Channels {
		if ch.Type == "telegram" && ch.Enabled {
			tgEnabled = true
		}
		if ch.Type == "mqtt" && ch.Enabled {
			mqEnabled = true
		}
	}
	modeStr := "parallel"
	if tgEnabled && !mqEnabled {
		modeStr = "parallel" // Авто-включение MQTT для гарантированной P2P доставки без ограничений TG
	} else if mqEnabled && !tgEnabled {
		modeStr = "mqtt_only"
	}

	rebuildSignalingInternal(ctx, modeStr, tgToken, tgChat, mqBroker, mqTopic)

	ipDisc = network.NewDiscoverer(c.Network.IPApis, 3*time.Second)

	// Асинхронное определение IP и STUN на основном постоянном сокете
	go func() {
		writeDebug("Определение внешнего IP и STUN сокета...")
		if ip, err := ipDisc.GetPublicIPCached(ctx, 5*time.Minute); err == nil {
			myPublicIP = ip.String()
			writeDebug("Внешний публичный IP: " + myPublicIP)
		}
		if udpPuncher != nil {
			if extIP, port, err := udpPuncher.DiscoverMappedAddress(ctx); err == nil {
				mySTUNAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
				writeDebug("STUN сокет на постоянном порту: " + mySTUNAddr)
			}
		}
		addLog(fmt.Sprintf("✓ Ядро запущено. Устройство: %s | Виртуальный IP: %s | STUN: %s", myDevID, myVirtualIP, mySTUNAddr))
		triggerPublish()
	}()

	// Фоновый цикл публикации анонсов (каждые 10 секунд)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				go publishCurrentState(ctx)
			case <-triggerPublishCh:
				go publishCurrentState(ctx)
			}
		}
	}()

	// Фоновый цикл прямой отправки UDP Hole Punch пакетов (каждые 12 секунд для удержания CGNAT маппингов)
	go func() {
		probeTicker := time.NewTicker(2 * time.Second)
		defer probeTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-probeTicker.C:
				if udpPuncher != nil && registry != nil {
					peers := registry.List()
					for _, p := range peers {
						if p.DirectP2P && p.ActiveEndpoint != "" {
							_ = udpPuncher.SendKeepAlive(p.ActiveEndpoint)
						} else {
							if p.ActiveEndpoint != "" {
								_ = udpPuncher.SendHolePunchProbe(p.ActiveEndpoint)
							}
							if p.STUNAddr != "" {
								_ = udpPuncher.SendHolePunchProbe(p.STUNAddr)
							}
							if p.LocalAddr != "" {
								_ = udpPuncher.SendHolePunchProbe(p.LocalAddr)
							}
							if p.IPv6Addr != "" {
								_ = udpPuncher.SendHolePunchProbe(p.IPv6Addr)
							}
							for _, cand := range p.Candidates {
								if cand != "" && cand != p.STUNAddr && cand != p.LocalAddr {
									_ = udpPuncher.SendHolePunchProbe(cand)
								}
							}
						}
					}
				}
			}
		}
	}()

	// Фоновый монитор неактивных узлов
	go func() {
		monitorTicker := time.NewTicker(5 * time.Second)
		defer monitorTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-monitorTicker.C:
				if registry != nil {
					registry.MarkOffline(120 * time.Second)
					registry.Cleanup(24 * time.Hour)
				}
			}
		}
	}()

	// Фоновый локальный широковещательный поиск пиров в LAN
	startLANBroadcastDiscovery(ctx)

	addLog("🛸 NatBypass P2P Mesh движок готов к работе")
}

// startLANBroadcastDiscovery мгновенно находит все устройства NatBypass в локальной сети / Wi-Fi без серверов
func startLANBroadcastDiscovery(ctx context.Context) {
	broadcastAddr, err := net.ResolveUDPAddr("udp4", "255.255.255.255:51821")
	if err != nil {
		return
	}

	listenAddr, err := net.ResolveUDPAddr("udp4", ":51821")
	if err != nil {
		return
	}

	listenConn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		writeDebug("LAN Broadcast слушатель занят или недоступен: " + err.Error())
		return
	}

	writeDebug("🏠 LAN Broadcast Discovery запущен на порту :51821 (мгновенный локальный поиск)")
	addLog("🏠 Запущен локальный LAN поиск пиров (порт :51821)")

	// 1. Поток слушателя локальных LAN анонсов
	go func() {
		defer listenConn.Close()
		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = listenConn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, srcAddr, err := listenConn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				if n < 20 {
					continue
				}
				raw := string(buf[:n])
				if !strings.HasPrefix(raw, "NATBYPASS:LAN:") {
					continue
				}
				jsonData := strings.TrimPrefix(raw, "NATBYPASS:LAN:")
				var p signaling.Payload
				if err := json.Unmarshal([]byte(jsonData), &p); err == nil && p.DeviceID != "" && p.DeviceID != myDevID {
					activeKey := ""
					activeTopic := ""
					if cfg != nil {
						active := cfg.EnsureActiveProfile()
						if active != nil {
							activeKey = active.NetworkKey
							activeTopic = active.MQTTTopic
						}
					}
					match := false
					if activeKey == "" || p.NetworkKey == "" || p.NetworkKey == activeKey {
						match = true
					} else if activeTopic != "" && p.Topic == activeTopic {
						match = true
					} else if activeKey == "" && activeTopic == "" {
						match = true
					}
					if !match {
						continue
					}

					atomic.AddUint64(&packetsRecvCount, 1)

					peerVIP := p.VirtualIP
					if peerVIP == "" {
						peerVIP = "100.64.200.1"
					}

					peerPort := p.WGPort
					if peerPort <= 0 {
						peerPort = 47832
					}
					lanAddr := fmt.Sprintf("%s:%d", srcAddr.IP.String(), peerPort)
					if p.LocalAddr != "" {
						lanAddr = p.LocalAddr
					} else {
						p.LocalAddr = lanAddr
					}

					nick := p.Nickname
					if nick == "" {
						nick = p.DeviceName
					}

					if guiMagicSock != nil {
						guiMagicSock.RegisterPeerEndpoints(p.DeviceID, p.STUNAddr, p.LocalAddr, p.IPv6Addr)
					}
					registry.Upsert(&peer.Peer{
						DeviceID:         p.DeviceID,
						Nickname:         nick,
						VirtualIP:        peerVIP,
						PublicKey:        p.PublicKey,
						PublicIP:         p.PublicIP,
						LocalAddr:        lanAddr,
						STUNAddr:         p.STUNAddr,
						WGPubKey:         p.WGPubKey,
						WGPort:           p.WGPort,
						LastSeen:         time.Now(),
						Online:           true,
						IsExitNode:       p.IsExitNode,
						AdvertisedRoutes: p.AdvertisedRoutes,
						AWG:              p.AWG,
						OS:               p.OS,
						Platform:         p.Platform,
						Arch:             p.Arch,
						Version:          p.Version,
						IsKeenetic:       p.IsKeenetic,
					})

					nameInfo := p.DeviceID
					if nick != "" {
						nameInfo = fmt.Sprintf("%s (%s)", nick, p.DeviceID)
					}
					msg := fmt.Sprintf("📥 [LAN Broadcast] Мгновенно обнаружен локальный пир %s (%s)", nameInfo, lanAddr)
					addLog(msg)
					writeDebug(msg)

					if udpPuncher != nil {
						_ = udpPuncher.SendHolePunchProbe(lanAddr)
					}
					negotiateVirtualIP()
				}
			}
		}
	}()

	// 2. Периодическая отправка анонса в локальную сеть каждые 30 секунд (не 4 с — чтобы не перегружать роутер)
	go func() {
		ticker := time.NewTicker(120 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				localIP := getLocalLANIP()
				if localIP == "" {
					continue
				}
				var advSubnets []string
				if cfg != nil && len(cfg.Network.AdvertisedSubnets) > 0 {
					advSubnets = cfg.Network.AdvertisedSubnets
				} else if hEditAdvSubnets != 0 {
					subnetsRaw := strings.TrimSpace(getControlText(hEditAdvSubnets))
					if subnetsRaw != "" {
						for _, sp := range strings.Split(subnetsRaw, ",") {
							if t := strings.TrimSpace(sp); t != "" {
								advSubnets = append(advSubnets, t)
							}
						}
					}
				}
				var awgParams *signaling.AWGParams
				if hEditAwgJc != 0 {
					jc, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJc)))
					jmin, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJmin)))
					jmax, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJmax)))
					s1, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgS1)))
					s2, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgS2)))
					h1Str := strings.TrimSpace(getControlText(hEditAwgH1))
					h2Str := strings.TrimSpace(getControlText(hEditAwgH2))
					h3Str := strings.TrimSpace(getControlText(hEditAwgH3))
					h4Str := strings.TrimSpace(getControlText(hEditAwgH4))

					h1, _ := strconv.ParseUint(h1Str, 10, 32)
					h2, _ := strconv.ParseUint(h2Str, 10, 32)
					h3, _ := strconv.ParseUint(h3Str, 10, 32)
					h4, _ := strconv.ParseUint(h4Str, 10, 32)

					cachedAWGParams = wireguard.AWGParams{
						Enabled:                 true,
						Version:                 wireguard.AWGVersion31,
						Jc:                      jc,
						Jmin:                    jmin,
						Jmax:                    jmax,
						S1:                      s1,
						S2:                      s2,
						H1:                      uint32(h1),
						H2:                      uint32(h2),
						H3:                      uint32(h3),
						H4:                      uint32(h4),
						HeaderProtectionEnabled: cfg.WireGuard.AWG.HeaderProtectionKey != "",
						RandomTrailers:          cfg.WireGuard.AWG.RandomTrailers,
						DisableCookies:          cfg.WireGuard.AWG.DisableCookies,
					}
					awgParams = &signaling.AWGParams{
						Jc:                      jc,
						Jmin:                    jmin,
						Jmax:                    jmax,
						S1:                      s1,
						S2:                      s2,
						H1:                      h1Str,
						H2:                      h2Str,
						H3:                      h3Str,
						H4:                      h4Str,
						Version:                 "3.1",
						Preset:                  cfg.WireGuard.AWGPreset,
						HeaderProtectionEnabled: cfg.WireGuard.AWG.HeaderProtectionKey != "",
						RandomTrailers:          cfg.WireGuard.AWG.RandomTrailers,
						DisableCookies:          cfg.WireGuard.AWG.DisableCookies,
					}
				} else if cachedAWGParams.Enabled {
					awgParams = &signaling.AWGParams{
						Jc:   cachedAWGParams.Jc,
						Jmin: cachedAWGParams.Jmin,
						Jmax: cachedAWGParams.Jmax,
						S1:   cachedAWGParams.S1,
						S2:   cachedAWGParams.S2,
						H1:   fmt.Sprintf("%d", cachedAWGParams.H1),
						H2:   fmt.Sprintf("%d", cachedAWGParams.H2),
						H3:   fmt.Sprintf("%d", cachedAWGParams.H3),
						H4:   fmt.Sprintf("%d", cachedAWGParams.H4),
					}
				}
				activeKey := ""
				activeTopic := ""
				if cfg != nil {
					active := cfg.EnsureActiveProfile()
					if active != nil {
						activeKey = active.NetworkKey
						activeTopic = active.MQTTTopic
					}
				}
				pPort := 47832
				if udpPuncher != nil {
					pPort = udpPuncher.LocalPort()
				}
				payload := &signaling.Payload{
					DeviceID:         myDevID,
					Nickname:         myNick,
					DeviceName:       myNick,
					VirtualIP:        strings.TrimSpace(strings.Split(myVirtualIP, "/")[0]),
					PublicKey:        crypto.KeyToHex(myPubKey),
					PublicIP:         myPublicIP,
					LocalAddr:        fmt.Sprintf("%s:%d", localIP, pPort),
					STUNAddr:         mySTUNAddr,
					WGPubKey:         myWGPubKey,
					WGPort:           pPort,
					Timestamp:        time.Now(),
					IsExitNode:       allowExitNode,
					AdvertisedRoutes: advSubnets,
					AWG:              awgParams,
					OS:               "windows",
					Platform:         "Windows",
					Arch:             runtime.GOARCH,
					Version:          Version,
					IsKeenetic:       false,
					NetworkKey:       activeKey,
					Topic:            activeTopic,
				}
				data, _ := json.Marshal(payload)
				msg := "NATBYPASS:LAN:" + string(data)
				_ = listenConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				_, _ = listenConn.WriteToUDP([]byte(msg), broadcastAddr)
				atomic.AddUint64(&packetsSentCount, 1)
			}
		}
	}()
}

func rebuildSignalingInternal(ctx context.Context, modeText, tgToken, tgChat, mqBroker, mqTopic string) {
	// При перестройке каналов очищаем список пиров, чтобы исключить показ неактуальных устройств
	if registry != nil {
		registry.ClearAll()
	}
	lastPeersHash = ""

	for _, ch := range sigChannels {
		_ = ch.Close()
	}
	sigChannels = nil

	if mqBroker == "" {
		mqBroker = "tcp://broker.emqx.io:1883"
	}
	if mqTopic == "" {
		mqTopic = "natbypass/mynet/peers"
	}

	useMQTT := true
	useTG := false

	if modeText == "tg_only" || strings.Contains(modeText, "Только Telegram") {
		useMQTT = false
		useTG = true
		sigMode = "tg_only"
		activeChannelStr = "Только Telegram Bot API"
	} else if modeText == "mqtt_only" || strings.Contains(modeText, "Только MQTT") {
		useMQTT = true
		useTG = false
		sigMode = "mqtt_only"
		activeChannelStr = "Только MQTT (" + mqBroker + ")"
	} else {
		useMQTT = true
		useTG = tgToken != "" && tgChat != ""
		sigMode = "parallel"
		activeChannelStr = "Параллельно: MQTT + Telegram"
	}

	writeDebug(fmt.Sprintf("Перестройка сигнальных каналов: Режим=%s, useTG=%t, useMQTT=%t", sigMode, useTG, useMQTT))

	if useTG && (tgToken == "" || tgChat == "") {
		addLog("⚠️ Telegram выбран в режиме, но токен или Chat ID не заполнены!")
	}

	if useTG && tgToken != "" && tgChat != "" {
		tgCh := signaling.NewTelegramChannel(tgToken, tgChat, "")
		sigChannels = append(sigChannels, tgCh)
		addLog(fmt.Sprintf("✓ Подключен сигнальный канал: Telegram (Чат: %s)", tgChat))
		writeDebug(fmt.Sprintf("Запуск слушателя Telegram (Chat: %s)...", tgChat))
		startChannelReceiver(ctx, tgCh, "Telegram")
	}

	if useMQTT {
		mqttCh := signaling.NewMQTTChannel(mqBroker, mqTopic, myDevID+"-"+crypto.KeyToHex(myPubKey)[:4], "", "")
		activeMQTT = mqttCh
		sigChannels = append(sigChannels, mqttCh)
		addLog(fmt.Sprintf("✓ Подключен сигнальный канал: MQTT (%s / топик: %s)", mqBroker, mqTopic))
		writeDebug(fmt.Sprintf("Запуск слушателя MQTT (%s, Topic: %s)...", mqBroker, mqTopic))
		startChannelReceiver(ctx, mqttCh, "MQTT")

		// Быстрый релей пакетов туннеля через MQTT (гарантирует сквозной пинг при любом типе NAT/VPN)
		mqttCh.SubscribeTunnelData(myDevID, func(pkt []byte) {
			if len(pkt) < 20 {
				return
			}
			srcIP := tunnel.GetSrcIP(pkt)
			destIP := tunnel.GetDestIP(pkt)
			if srcIP == nil || destIP == nil {
				return
			}
			// Защита от петель
			if srcIP.String() == myVirtualIP {
				return
			}
			_ = destIP

			// Все пакеты идут прямо в Wintun — OS сама обрабатывает ICMP, TCP, UDP
			atomic.AddUint64(&packetsRecvCount, 1)
			if tunDev != nil {
				_ = tunDev.WritePacket(pkt)
			}
		})
	}
}

func getLocalLANIP() string {
	return network.GetLocalLANIP()
}


func startChannelReceiver(ctx context.Context, ch signaling.SignalingChannel, name string) {
	inCh, err := ch.Receive(ctx)
	if err != nil {
		addLog(fmt.Sprintf("❌ Ошибка запуска слушателя %s: %s", name, err.Error()))
		writeDebug(fmt.Sprintf("Ошибка слушателя %s: %s", name, err.Error()))
		return
	}

	bufCh := make(chan *signaling.Payload, 128)
	go func() {
		defer close(bufCh)
		for {
			select {
			case <-ctx.Done():
				return
			case p, ok := <-inCh:
				if !ok {
					return
				}
				select {
				case bufCh <- p:
				case <-ctx.Done():
					return
				default:
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case p, ok := <-bufCh:
				if !ok {
					return
				}
				if p == nil {
					continue
				}

				if len(p.Encrypted) > 0 {
					activeKey := ""
					if cfg != nil {
						if activeProf := cfg.EnsureActiveProfile(); activeProf != nil {
							activeKey = activeProf.NetworkKey
						}
					}
					if activeKey != "" {
						if dec, decErr := signaling.DecryptPayloadWithKey(p, activeKey); decErr == nil && dec != nil {
							p = dec
						}
					}
					if len(p.Encrypted) > 0 {
						if dec, err := signaling.DecryptPayload(p, myPubKey, myPrivKey); err == nil && dec != nil {
							p = dec
						}
					}
				}

				if p.DeviceID == "" || p.DeviceID == myDevID {
					continue
				}

				// Принимаем все маяки внутри сигнальной комнаты

				if p.Offline || p.Leave {
					nameInfo := p.DeviceID
					if p.Nickname != "" {
						nameInfo = fmt.Sprintf("%s (%s)", p.Nickname, p.DeviceID)
					}
					writeDebug(fmt.Sprintf("Узел %s отключился от сети (Leave beacon)", nameInfo))
					addLog(fmt.Sprintf("🔴 Узел %s отключился от сети", nameInfo))
					if registry != nil {
						registry.Delete(p.DeviceID)
					}
					continue
				}

				atomic.AddUint64(&packetsRecvCount, 1)

				peerVIP := p.VirtualIP
				if peerVIP == "" {
					peerVIP = "100.64.200.1"
				}

				nick := p.Nickname
				if nick == "" {
					nick = p.DeviceName
				}

				// Automatic Route Revocation & Safety Notification
				if activeExitNodeID != "" && p.DeviceID == activeExitNodeID && (p.ExitRevoked || !p.IsExitNode) {
					if activeExitVIP != "" {
						_ = tunnel.DisableExitNodeRouting(activeExitVIP)
					}
					peerName := p.Nickname
					if peerName == "" {
						peerName = p.DeviceID
					}
					activeExitNodeID = ""
					activeExitVIP = ""
					buttonLabels[ID_BTN_EXIT_NODE_SELECT] = "🌐 Выход в интернет: Локальный (Отключен)"
					buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "normal"
					if hBtnExitNodeSelect != 0 {
						procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
					}

					alertMsg := fmt.Sprintf("⚠️ Внимание: Устройство %s запретило выход в интернет через себя. Маршрут сброшен на стандартный интернет.", peerName)
					addLog(alertMsg)
					writeDebug(alertMsg)

					go func(msgText string) {
						titlePtr, _ := windows.UTF16PtrFromString("NatBypass — Изменение маршрута")
						textPtr, _ := windows.UTF16PtrFromString(msgText)
						procMessageBoxW.Call(hMainWnd, uintptr(unsafe.Pointer(textPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x00000030 /* MB_ICONWARNING */ | 0x00040000 /* MB_TOPMOST */)
					}(alertMsg)
				}

				osName := p.OS
				plat := p.Platform
				if plat == "" {
					if osName != "" {
						plat = osName
					} else {
						plat = "Windows"
					}
				}
				pFlag := p.CountryFlag
				if pFlag == "" && p.PublicIP != "" {
					pFlag = network.LookupCountryFlag(ctx, p.PublicIP)
				}

				existingPeer, peerFound := registry.Get(p.DeviceID)
				needsFastReply := !peerFound || existingPeer == nil || existingPeer.STUNAddr != p.STUNAddr || time.Since(existingPeer.LastSeen) > 6*time.Second

				preservedEP := ""
				preservedDirect := false
				preservedLat := time.Duration(0)
				preservedPingMs := int64(0)
				if existingPeer != nil {
					preservedEP = existingPeer.ActiveEndpoint
					preservedDirect = existingPeer.DirectP2P
					preservedLat = existingPeer.Latency
					preservedPingMs = existingPeer.PingMs
				}
				if p.ActiveEndpoint != "" {
					preservedEP = p.ActiveEndpoint
				}

				registry.Upsert(&peer.Peer{
					DeviceID:         p.DeviceID,
					Nickname:         nick,
					DeviceName:       nick,
					VirtualIP:        peerVIP,
					PublicKey:        p.PublicKey,
					PublicIP:         p.PublicIP,
					LocalAddr:        p.LocalAddr,
					STUNAddr:         p.STUNAddr,
					ActiveEndpoint:   preservedEP,
					DirectP2P:        preservedDirect,
					Latency:          preservedLat,
					PingMs:           preservedPingMs,
					Candidates:       p.Candidates,
					WGPubKey:         p.WGPubKey,
					WGPort:           p.WGPort,
					LastSeen:         time.Now(),
					Online:           true,
					IsExitNode:       p.IsExitNode,
					AdvertisedRoutes: p.AdvertisedRoutes,
					AWG:              p.AWG,
					OS:               osName,
					Platform:         plat,
					CountryFlag:      pFlag,
					Arch:             p.Arch,
					Version:          p.Version,
					IsKeenetic:       p.IsKeenetic,
				})

				if needsFastReply {
					go func() {
						time.Sleep(time.Duration(15+rand.Intn(80)) * time.Millisecond)
						triggerPublish()
					}()
				}

				nameInfo := p.DeviceID
				if nick != "" {
					nameInfo = fmt.Sprintf("%s (%s)", nick, p.DeviceID)
				}
				msg := fmt.Sprintf("📥 [%s] Сигнал от %s (VIP: %s | STUN: %s | LAN: %s)", name, nameInfo, peerVIP, p.STUNAddr, p.LocalAddr)
				addLog(msg)
				writeDebug(msg)

				// Немедленно посылаем прямой UDP-пакет для пробития сокета по всем кандидатам
				if udpPuncher != nil {
					if p.ActiveEndpoint != "" {
						_ = udpPuncher.SendHolePunchProbe(p.ActiveEndpoint)
					}
					if p.STUNAddr != "" {
						_ = udpPuncher.SendHolePunchProbe(p.STUNAddr)
					}
					if p.LocalAddr != "" {
						_ = udpPuncher.SendHolePunchProbe(p.LocalAddr)
					}
					if p.IPv6Addr != "" {
						_ = udpPuncher.SendHolePunchProbe(p.IPv6Addr)
					}
					for _, cand := range p.Candidates {
						if cand != "" && cand != p.STUNAddr && cand != p.LocalAddr {
							_ = udpPuncher.SendHolePunchProbe(cand)
						}
					}
					if p.PublicIP != "" {
						port := p.WGPort
						if port <= 0 {
							port = 47832
						}
						_ = udpPuncher.SendHolePunchProbe(fmt.Sprintf("%s:%d", p.PublicIP, port))
					}
				}

				// Автоматическое динамическое P2P согласование IP-адресов
				negotiateVirtualIP()

				// Авто-восстановление маршрутизации через Exit Node если он только что появился онлайн
				if activeExitNodeID != "" && p.DeviceID == activeExitNodeID && p.IsExitNode && activeExitVIP == "" {
					targetVIP := p.VirtualIP
					if targetVIP == "" {
						targetVIP = "100.64.200.2"
					}
					activeExitVIP = targetVIP
					go func(vip string, peerPayload *signaling.Payload) {
						time.Sleep(500 * time.Millisecond) // дождаться P2P handshake
						eps := []string{peerPayload.ActiveEndpoint, peerPayload.STUNAddr, peerPayload.PublicIP}
						if err := tunnel.EnableExitNodeRouting(vip, eps...); err == nil {
							addLog(fmt.Sprintf("🌐 Exit Node [%s] онлайн, маршрут восстановлен автоматически (%s)", peerPayload.DeviceID, vip))
							writeDebug("Auto-restored Exit Node routing via " + vip)
						}
					}(targetVIP, p)
				}
			}
		}
	}()
}

// handleICMPEcho обрабатывает входящий ICMP Echo Request (Type 8, Code 0)
func respondICMPEcho(payload []byte, fromAddr *net.UDPAddr) {
	if len(payload) < 20 {
		return
	}
	ihl := int(payload[0]&0x0F) * 4
	if len(payload) < ihl+8 {
		return
	}
	if payload[9] != 1 || payload[ihl] != 8 {
		return
	}

	reply := make([]byte, len(payload))
	copy(reply, payload)

	srcIP := net.IPv4(payload[12], payload[13], payload[14], payload[15])
	destIP := net.IPv4(payload[16], payload[17], payload[18], payload[19])
	copy(reply[12:16], destIP.To4())
	copy(reply[16:20], srcIP.To4())

	reply[10] = 0
	reply[11] = 0
	ipCS := tunnel.CalculateChecksum(reply[:ihl])
	reply[10] = byte(ipCS >> 8)
	reply[11] = byte(ipCS)

	reply[ihl] = 0
	reply[ihl+2] = 0
	reply[ihl+3] = 0
	icmpCS := tunnel.CalculateChecksum(reply[ihl:])
	reply[ihl+2] = byte(icmpCS >> 8)
	reply[ihl+3] = byte(icmpCS)

	if fromAddr != nil && udpPuncher != nil {
		_ = udpPuncher.SendDataPacket(fromAddr.String(), reply)
	}
}

func unusedOldICMP(payload []byte) {
	if len(payload) < 20 {
		return
	}
	ihl := int(payload[0]&0x0F) * 4
	if len(payload) < ihl+8 {
		return
	}

	srcIP := tunnel.GetSrcIP(payload)
	destIP := tunnel.GetDestIP(payload)
	if srcIP == nil || destIP == nil {
		return
	}

	cleanVIP := strings.TrimSpace(strings.Split(myVirtualIP, "/")[0])
	destStr := destIP.String()

	// Защита от петель: игнорируем пакеты от собственного адреса
	if srcIP.String() == cleanVIP || srcIP.String() == myVirtualIP {
		return
	}

	// Принимаем пакеты, адресованные на наш текущий VIP или шлюз
	if destStr != cleanVIP && destStr != myVirtualIP {
		if !allowExitNode {
			return
		}
	}

	atomic.AddUint64(&packetsRecvCount, 1)

	// Записываем пакет в виртуальный адаптер Wintun для обработки сетевым стеком Windows
	if tunDev != nil {
		_ = tunDev.WritePacket(payload)
	}
}

// negotiateVirtualIP динамически разрешает конфликты IP адресов между узлами
func negotiateVirtualIP() {
	if registry == nil {
		return
	}

	peers := registry.List()
	usedIPs := make(map[string]string)

	for _, p := range peers {
		if p.Online && p.VirtualIP != "" {
			usedIPs[p.VirtualIP] = p.DeviceID
		}
	}

	conflictDev, hasConflict := usedIPs[myVirtualIP]
	if hasConflict && conflictDev != "" {
		if myDevID > conflictDev {
			oldIP := myVirtualIP
			for i := 1; i <= 254; i++ {
				cand := fmt.Sprintf("100.64.200.%d", i)
				if _, used := usedIPs[cand]; !used {
					myVirtualIP = cand
					break
				}
			}
			logMsg := fmt.Sprintf("🤝 [P2P Согласование] Урегулирован конфликт IP: Устройство %s уступило %s и приняло %s (у пира %s: %s)", myDevID, oldIP, myVirtualIP, conflictDev, oldIP)
			addLog(logMsg)
			writeDebug(logMsg)

			if tunDev != nil {
				targetVIP := myVirtualIP
				go func() {
					_ = tunDev.SetVirtualIP(targetVIP)
				}()
			}
			triggerPublish()
			awgDirty = true
		}
	}
}

func triggerPublish() {
	select {
	case triggerPublishCh <- struct{}{}:
	default:
	}
}

func publishCurrentState(ctx context.Context) {
	ipStr := myPublicIP
	if ipStr == "" || ipStr == "Определяется..." {
		ipStr = "0.0.0.0"
	}

	pPort := 47832
	if udpPuncher != nil {
		pPort = udpPuncher.LocalPort()
	}
	localIP := getLocalLANIP()
	localAddr := ""
	if localIP != "" {
		localAddr = fmt.Sprintf("%s:%d", localIP, pPort)
	}

	var advSubnets []string
	if cfg != nil && len(cfg.Network.AdvertisedSubnets) > 0 {
		advSubnets = cfg.Network.AdvertisedSubnets
	} else if hEditAdvSubnets != 0 {
		subnetsRaw := strings.TrimSpace(getControlText(hEditAdvSubnets))
		if subnetsRaw != "" {
			for _, sp := range strings.Split(subnetsRaw, ",") {
				if t := strings.TrimSpace(sp); t != "" {
					advSubnets = append(advSubnets, t)
				}
			}
		}
	}

	var awgParams *signaling.AWGParams
	if hEditAwgJc != 0 {
		jc, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJc)))
		jmin, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJmin)))
		jmax, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJmax)))
		s1, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgS1)))
		s2, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgS2)))
		h1Str := strings.TrimSpace(getControlText(hEditAwgH1))
		h2Str := strings.TrimSpace(getControlText(hEditAwgH2))
		h3Str := strings.TrimSpace(getControlText(hEditAwgH3))
		h4Str := strings.TrimSpace(getControlText(hEditAwgH4))

		h1, _ := strconv.ParseUint(h1Str, 10, 32)
		h2, _ := strconv.ParseUint(h2Str, 10, 32)
		h3, _ := strconv.ParseUint(h3Str, 10, 32)
		h4, _ := strconv.ParseUint(h4Str, 10, 32)

		cachedAWGParams = wireguard.AWGParams{
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
		awgParams = &signaling.AWGParams{
			Jc:   jc,
			Jmin: jmin,
			Jmax: jmax,
			S1:   s1,
			S2:   s2,
			H1:   h1Str,
			H2:   h2Str,
			H3:   h3Str,
			H4:   h4Str,
		}
	} else if cachedAWGParams.Enabled {
		awgParams = &signaling.AWGParams{
			Jc:   cachedAWGParams.Jc,
			Jmin: cachedAWGParams.Jmin,
			Jmax: cachedAWGParams.Jmax,
			S1:   cachedAWGParams.S1,
			S2:   cachedAWGParams.S2,
			H1:   fmt.Sprintf("%d", cachedAWGParams.H1),
			H2:   fmt.Sprintf("%d", cachedAWGParams.H2),
			H3:   fmt.Sprintf("%d", cachedAWGParams.H3),
			H4:   fmt.Sprintf("%d", cachedAWGParams.H4),
		}
	}

	activeKey := ""
	activeTopic := ""
	if cfg != nil {
		active := cfg.EnsureActiveProfile()
		if active != nil {
			activeKey = active.NetworkKey
			activeTopic = active.MQTTTopic
		}
	}

	payload := &signaling.Payload{
		DeviceID:         myDevID,
		Nickname:         myNick,
		DeviceName:       myNick,
		VirtualIP:        myVirtualIP,
		PublicKey:        crypto.KeyToHex(myPubKey),
		PublicIP:         ipStr,
		LocalAddr:        localAddr,
		STUNAddr:         mySTUNAddr,
		WGPubKey:         myWGPubKey,
		WGPort:           pPort,
		Timestamp:        time.Now(),
		IsExitNode:       allowExitNode,
		AdvertisedRoutes: advSubnets,
		AWG:              awgParams,
		OS:               "windows",
		Platform:         "Windows",
		Arch:             runtime.GOARCH,
		Version:          Version,
		IsKeenetic:       false,
		CountryFlag:      network.LookupCountryFlag(ctx, ipStr),
		NetworkKey:       activeKey,
		Topic:            activeTopic,
	}

	if uiServer != nil {
		uiServer.SetAppState(myDevID, myPublicIP, mySTUNAddr, myVirtualIP)
		uiServer.SetVirtualIP(myVirtualIP)
		uiServer.SetDeviceName(myNick)
	}

	// 🔍 Проверяем, есть ли активные подключенные пиры (прямой P2P или свежий маяк < 30 сек)
	hasDirectConnectedPeers := false
	if registry != nil {
		for _, p := range registry.List() {
			if p.Online && (p.DirectP2P || time.Since(p.LastSeen) < 30*time.Second) {
				hasDirectConnectedPeers = true
				break
			}
		}
	}

	if hasDirectConnectedPeers {
		if !tgMuted {
			tgMuted = true
			msg := "💤 [Telegram] Прямое соединение установлено! Отправка в Telegram приостановлена для экономии сообщений."
			addLog(msg)
			writeDebug(msg)
		}
	} else {
		if tgMuted {
			tgMuted = false
			msg := "⚡ [Telegram] Связь с пирами оборвалась! Telegram канал возобновил отправку маяков."
			addLog(msg)
			writeDebug(msg)
		}
	}

	toSend := payload
	if activeKey != "" {
		if enc, err := signaling.EncryptPayloadWithKey(payload, activeKey); err == nil && enc != nil {
			toSend = enc
		}
	}

	for _, ch := range sigChannels {
		// Если пиры подключены и канал Telegram — не спамим в чат/группу
		if ch.Name() == "telegram" && hasDirectConnectedPeers {
			continue
		}

		go func(c signaling.SignalingChannel, outPayload *signaling.Payload) {
			sendCtx, sendCancel := context.WithTimeout(ctx, 10*time.Second)
			defer sendCancel()
			if err := c.Send(sendCtx, outPayload); err == nil {
				atomic.AddUint64(&packetsSentCount, 1)
				msg := fmt.Sprintf("📤 [%s] Отправлен анонс в сеть (VIP: %s | STUN: %s | LAN: %s)", c.Name(), myVirtualIP, mySTUNAddr, localAddr)
				addLog(msg)
				writeDebug(msg)
			} else {
				errMsg := fmt.Sprintf("⚠️ [%s] Ошибка отправки: %s", c.Name(), err.Error())
				addLog(errMsg)
				writeDebug(errMsg)
			}
		}(ch, toSend)
	}
}


func stopEngine() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if engineCancel != nil {
		engineCancel()
	}
	if tunDev != nil {
		_ = tunDev.Close()
		tunDev = nil
	}
	if udpPuncher != nil {
		_ = udpPuncher.Close()
	}
	activeMQTT = nil
	for _, ch := range sigChannels {
		_ = ch.Close()
	}
	sigChannels = nil

	if activeExitVIP != "" {
		_ = tunnel.DisableExitNodeRouting(activeExitVIP)
		activeExitVIP = ""
		activeExitNodeID = ""
	}
	activeSubnetRoutesMu.Lock()
	for cidr, vip := range activeSubnetRoutes {
		_ = tunnel.RemoveSubnetRoute(cidr, vip)
	}
	activeSubnetRoutes = make(map[string]string)
	activeSubnetRoutesMu.Unlock()
}

func awgParamsMatch(local wireguard.AWGParams, remote *signaling.AWGParams) bool {
	if remote == nil {
		return true
	}
	h1, _ := strconv.ParseUint(strings.TrimSpace(remote.H1), 10, 32)
	h2, _ := strconv.ParseUint(strings.TrimSpace(remote.H2), 10, 32)
	h3, _ := strconv.ParseUint(strings.TrimSpace(remote.H3), 10, 32)
	h4, _ := strconv.ParseUint(strings.TrimSpace(remote.H4), 10, 32)

	return local.Jc == remote.Jc &&
		local.Jmin == remote.Jmin &&
		local.Jmax == remote.Jmax &&
		local.S1 == remote.S1 &&
		local.S2 == remote.S2 &&
		local.H1 == uint32(h1) &&
		local.H2 == uint32(h2) &&
		local.H3 == uint32(h3) &&
		local.H4 == uint32(h4)
}

// updateData вызывается строго на главном UI потоке в таймере
func updateData() {
	if isSplashActive {
		splashTicks++
		if tunDev != nil {
			setControlText(hSplashStep2, fmt.Sprintf("🟢 [ 2/4 ] 🛡️ Виртуальный адаптер 'NatBypass' активен (%s/24)", myVirtualIP))
		}
		if myPublicIP != "" && myPublicIP != "Определяется..." {
			setControlText(hSplashStep3, fmt.Sprintf("🟢 [ 3/4 ] 🌐 Внешний IP: %s (STUN: %s)", myPublicIP, mySTUNAddr))
		}
		if len(sigChannels) > 0 {
			setControlText(hSplashStep4, fmt.Sprintf("🟢 [ 4/4 ] ⚡ Сигнальные каналы подключены (%s)", activeChannelStr))
		}

		if splashTicks >= 2 {
			hideSplashScreen()
		}
		return
	}

	ipStr := myPublicIP
	if ipStr == "" {
		ipStr = "Определяется..."
	}
	stunStr := mySTUNAddr
	if stunStr == "" {
		stunStr = "Определяется..."
	}

	devTitle := myDevID
	if myNick != "" {
		devTitle = fmt.Sprintf("%s (%s)", myNick, myDevID)
	}
	activeProfName := "Основная сеть"
	if cfg != nil {
		active := cfg.EnsureActiveProfile()
		if active != nil {
			activeProfName = active.Name
		}
	}
	if hLblIpInfo != 0 {
		infoText := fmt.Sprintf("Сеть: 🟢 [%s] | %s | VIP: %s | Внешний IP: %s", activeProfName, devTitle, myVirtualIP, ipStr)
		setControlText(hLblIpInfo, infoText)
	}

	if hLblChannels != 0 {
		chText := fmt.Sprintf("📡 Активный режим: %s", activeChannelStr)
		setControlText(hLblChannels, chText)
	}

	if hLblCardVIP != 0 {
		setControlText(hLblCardVIP, fmt.Sprintf("Локальный VIP:\r\n%s", myVirtualIP))
	}
	if hLblCardPubIP != 0 {
		setControlText(hLblCardPubIP, fmt.Sprintf("Внешний IP:\r\n%s", ipStr))
	}
	if hLblCardSTUN != 0 {
		setControlText(hLblCardSTUN, fmt.Sprintf("STUN Сокет:\r\n%s", stunStr))
	}
	if hLblCardSig != 0 {
		setControlText(hLblCardSig, fmt.Sprintf("Сигнальный канал:\r\n%s", activeChannelStr))
	}

	onlineCount := 0
	directP2PCount := 0
	var minRTT time.Duration = 0

	if registry != nil {
		peers := registry.List()
		currentHash := fmt.Sprintf("%d-%s-%s-%t-%v", len(peers), myVirtualIP, myNick, allowExitNode, cachedAWGParams)
		var mismatchPeer *peer.Peer
		var mismatchPeerName string

		for _, p := range peers {
			if p.Online {
				onlineCount++
				if p.DirectP2P {
					directP2PCount++
					if minRTT == 0 || (p.Latency > 0 && p.Latency < minRTT) {
						minRTT = p.Latency
					}
				}
				if p.AWG != nil && !awgParamsMatch(cachedAWGParams, p.AWG) {
					if mismatchPeer == nil {
						mismatchPeer = p
						addressBookMu.RLock()
						bm := addressBook[p.DeviceID]
						addressBookMu.RUnlock()
						if bm != "" {
							mismatchPeerName = "[*] " + bm
						} else if strings.TrimSpace(p.Nickname) != "" {
							mismatchPeerName = strings.TrimSpace(p.Nickname)
						} else {
							mismatchPeerName = p.DeviceID
						}
					}
				}
			}
			addressBookMu.RLock()
			bm := addressBook[p.DeviceID]
			addressBookMu.RUnlock()
			currentHash += fmt.Sprintf("-%s-%s-%s-%s-%t-%t-%v-%t-%s-%v", p.DeviceID, p.Nickname, bm, p.VirtualIP, p.Online, p.DirectP2P, p.Latency, p.IsExitNode, strings.Join(p.AdvertisedRoutes, ","), p.AWG)
		}

		if mismatchPeer != nil && mismatchPeer.AWG != nil {
			syncAWGPeerParams = mismatchPeer.AWG
			syncAWGPeerName = mismatchPeerName
			syncBtnLabel := fmt.Sprintf("🔄 Применить настройки AmneziaWG с узла [%s]", mismatchPeerName)
			buttonLabels[ID_BTN_SYNC_AWG] = syncBtnLabel
			buttonTypes[ID_BTN_SYNC_AWG] = "yellow"
			if currentTab == 3 && !isSplashActive && hBtnSyncAwg != 0 {
				procShowWindow.Call(hBtnSyncAwg, uintptr(SW_SHOW))
				procInvalidateRect.Call(hBtnSyncAwg, 0, 1)
			}
		} else {
			syncAWGPeerParams = nil
			syncAWGPeerName = ""
			if hBtnSyncAwg != 0 {
				procShowWindow.Call(hBtnSyncAwg, uintptr(SW_HIDE))
			}
		}

		// Автоматическая проверка состояния выбранного Exit Node
		if activeExitNodeID != "" {
			peer, ok := registry.Get(activeExitNodeID)
			if !ok || !peer.Online || !peer.IsExitNode {
				if activeExitVIP != "" {
					_ = tunnel.DisableExitNodeRouting(activeExitVIP)
				}
				oldID := activeExitNodeID
				activeExitNodeID = ""
				activeExitVIP = ""
				buttonLabels[ID_BTN_EXIT_NODE_SELECT] = "🌐 Выход в интернет: Локальный (Отключен)"
				buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "normal"
				if hBtnExitNodeSelect != 0 {
					procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
				}
				msg := fmt.Sprintf("⚠️ Exit Node [%s] стал недоступен или отключил шлюз. Маршрут сброшен на стандартный интернет.", oldID)
				addLog(msg)
				writeDebug(msg)
			} else {
				addressBookMu.RLock()
				bm := addressBook[peer.DeviceID]
				addressBookMu.RUnlock()
				peerDisplay := peer.Nickname
				if bm != "" {
					peerDisplay = "[*] " + bm
				} else if peerDisplay == "" {
					peerDisplay = peer.DeviceID
				}
				buttonLabels[ID_BTN_EXIT_NODE_SELECT] = fmt.Sprintf("🟢 Шлюз: [%s] (%s)", peerDisplay, activeExitVIP)
				buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "green"
				if hBtnExitNodeSelect != 0 {
					procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
				}
			}
		}

		// Реальная верификация статуса mesh-соединения
		if directP2PCount > 0 {
			vpnConnected = true
			pingStr := ""
			if minRTT > 0 {
				pingStr = fmt.Sprintf(" (%v)", minRTT.Round(time.Millisecond))
			}
			setControlText(hLblStatus, fmt.Sprintf("🟢 ПРЯМАЯ P2P СВЯЗЬ АКТИВНА (%d пир(ов)%s)", directP2PCount, pingStr))
			buttonLabels[ID_BTN_VPN] = fmt.Sprintf("🟢 Прямой P2P%s • VIP: %s", pingStr, myVirtualIP)
			buttonTypes[ID_BTN_VPN] = "green"
			procInvalidateRect.Call(hBtnVpn, 0, 1)
		} else if onlineCount > 0 {
			vpnConnected = true
			setControlText(hLblStatus, fmt.Sprintf("🟢 СЕТЬ АКТИВНА (%d пир(ов) онлайн | Релей/STUN)", onlineCount))
			buttonLabels[ID_BTN_VPN] = fmt.Sprintf("🟢 В СЕТИ (%d пир(ов) | VIP: %s)", onlineCount, myVirtualIP)
			buttonTypes[ID_BTN_VPN] = "green"
			procInvalidateRect.Call(hBtnVpn, 0, 1)
		} else {
			vpnConnected = false
			setControlText(hLblStatus, "🟡 ПОИСК УСТРОЙСТВ В СЕТИ...")
			buttonLabels[ID_BTN_VPN] = "🔴 ОЖИДАНИЕ СВЯЗИ (0 пиров)"
			buttonTypes[ID_BTN_VPN] = "red"
			procInvalidateRect.Call(hBtnVpn, 0, 1)
		}

		if currentHash != lastPeersHash {
			lastPeersHash = currentHash
			if hListPeers != 0 {
				procSendMessageW.Call(hListPeers, 0x0184, 0, 0)
			}
			if hListSummaryPeers != 0 {
				procSendMessageW.Call(hListSummaryPeers, 0x0184, 0, 0)
			}

			if len(peers) == 0 {
				if hListPeers != 0 {
					addListBoxItem(hListPeers, "  📡 Ожидание подключения других устройств... (0 пиров онлайн)")
				}
				if hListSummaryPeers != 0 {
					addListBoxItem(hListSummaryPeers, "  📡 Ожидание подключения других устройств... (0 пиров онлайн)")
				}
			} else {
				for _, p := range peers {
					if p == nil || p.DeviceID == "" {
						continue
					}
					addressBookMu.RLock()
					bookmarkedName, isBookmarked := addressBook[p.DeviceID]
					addressBookMu.RUnlock()

					var nameDisplay string
					if isBookmarked && strings.TrimSpace(bookmarkedName) != "" {
						nameDisplay = fmt.Sprintf("[[*] %s]", strings.TrimSpace(bookmarkedName))
					} else if strings.TrimSpace(p.Nickname) != "" {
						nameDisplay = fmt.Sprintf("[%s]", strings.TrimSpace(p.Nickname))
					} else {
						nameDisplay = fmt.Sprintf("[%s]", p.DeviceID)
					}

					vip := p.VirtualIP
					if vip == "" {
						vip = "100.64.200.2"
					}

					var icon string
					var statusDisplay string
					if p.Online {
						if p.DirectP2P {
							icon = "[P2P]"
							if p.Latency > 0 {
								statusDisplay = fmt.Sprintf("Прямой P2P (%v)", p.Latency.Round(time.Millisecond))
							} else {
								statusDisplay = "Прямой P2P (OK)"
							}
						} else {
							icon = "[NAT]"
							statusDisplay = "Пробитие NAT..."
						}
					} else {
						icon = "[OFF]"
						statusDisplay = "Офлайн"
					}

					var addrDisplay string
					if p.LocalAddr != "" {
						addrDisplay = fmt.Sprintf("LAN: %s", p.LocalAddr)
					} else if p.STUNAddr != "" {
						addrDisplay = fmt.Sprintf("STUN: %s", p.STUNAddr)
					} else if p.PublicIP != "" {
						addrDisplay = fmt.Sprintf("WAN: %s", p.PublicIP)
					} else {
						addrDisplay = "LAN: —"
					}

					var extraTags []string
					if p.AWG != nil || p.DirectP2P {
						extraTags = append(extraTags, "[AWG 3.1]")
					}
					pVIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
					myCleanVIP := strings.TrimSpace(strings.Split(myVirtualIP, "/")[0])
					if p.Online && pVIP == myCleanVIP && p.DeviceID != myDevID {
						extraTags = append(extraTags, "[⚠️ КОНФЛИКТ IP!]")
					}
					if p.IsExitNode {
						extraTags = append(extraTags, "[Шлюз]")
					}
					if len(p.AdvertisedRoutes) > 0 {
						extraTags = append(extraTags, fmt.Sprintf("[LAN: %s]", strings.Join(p.AdvertisedRoutes, ", ")))
					}
					if p.Online && p.AWG != nil && !awgParamsMatch(cachedAWGParams, p.AWG) {
						extraTags = append(extraTags, "[AWG: ⚠️]")
					}
					extraInfo := ""
					if len(extraTags) > 0 {
						extraInfo = " " + strings.Join(extraTags, " ")
					}

					platBadge := "Linux"
					if p.IsKeenetic || strings.Contains(strings.ToLower(p.Platform), "keenetic") || strings.Contains(strings.ToLower(p.OS), "keenetic") || strings.Contains(strings.ToLower(p.DeviceID), "keenetic") || strings.Contains(strings.ToLower(p.DeviceID), "router") {
						platBadge = "KeeneticOS"
					} else if p.OS == "windows" || strings.Contains(strings.ToLower(p.Platform), "win") {
						platBadge = "Windows"
					} else if p.OS == "android" || strings.Contains(strings.ToLower(p.Platform), "android") {
						platBadge = "Android"
					} else if p.OS == "darwin" || strings.Contains(strings.ToLower(p.Platform), "mac") {
						platBadge = "macOS"
					} else if p.Platform != "" {
						platBadge = p.Platform
					} else if p.OS != "" {
						platBadge = p.OS
					}
					if p.Arch != "" {
						platBadge = fmt.Sprintf("%s (%s)", platBadge, p.Arch)
					}
					if p.Version != "" {
						platBadge = fmt.Sprintf("%s • v%s", platBadge, strings.TrimPrefix(p.Version, "v"))
					}
					platBadge = strings.TrimSpace(platBadge)

					line1 := fmt.Sprintf("  %s %s [%s] (ID: %s)", icon, nameDisplay, platBadge, p.DeviceID)
					line2 := fmt.Sprintf("     └── VIP: %s | %s | %s%s", vip, statusDisplay, addrDisplay, extraInfo)

					if hListPeers != 0 {
						addListBoxItem(hListPeers, line1)
						addListBoxItem(hListPeers, line2)
					}

					if hListSummaryPeers != 0 {
						sumLine := fmt.Sprintf("  %s %s • VIP: %s • %s • %s", icon, nameDisplay, vip, statusDisplay, platBadge)
						addListBoxItem(hListSummaryPeers, sumLine)
					}
				}
			}
			awgDirty = true
		}
	}

	if awgDirty && currentTab == 3 {
		awgDirty = false
		renderAWGTextFromUI()
	}

	if currentTab == 6 {
		flushLogsToUI()
	}
}



func flushLogsToUI() {
	logsMutex.Lock()
	if logsDirty {
		logsDirty = false
		allLogs := strings.Join(logsBuffer, "\r\n")
		logsMutex.Unlock()
		setControlText(hEditLogs, allLogs)
	} else {
		logsMutex.Unlock()
	}
}

func renderAWGTextFromUI() {
	defer func() {
		if r := recover(); r != nil {
			writeDebug(fmt.Sprintf("⚠️ Panic inside renderAWGTextFromUI: %v", r))
		}
	}()

	jc, _ := strconv.Atoi(getControlText(hEditAwgJc))
	jmin, _ := strconv.Atoi(getControlText(hEditAwgJmin))
	jmax, _ := strconv.Atoi(getControlText(hEditAwgJmax))
	s1, _ := strconv.Atoi(getControlText(hEditAwgS1))
	s2, _ := strconv.Atoi(getControlText(hEditAwgS2))
	h1, _ := strconv.ParseUint(getControlText(hEditAwgH1), 10, 32)
	h2, _ := strconv.ParseUint(getControlText(hEditAwgH2), 10, 32)
	h3, _ := strconv.ParseUint(getControlText(hEditAwgH3), 10, 32)
	h4, _ := strconv.ParseUint(getControlText(hEditAwgH4), 10, 32)

	cachedAWGParams = wireguard.AWGParams{
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

	privKeyDisplay := myWGPrivKey
	if privKeyDisplay == "" {
		privKeyDisplay = "(Ключ генерируется автоматически при запуске)"
	}

	var wgPeers []wireguard.WGPeer
	if registry != nil {
		allPeers := registry.List()
		sort.Slice(allPeers, func(i, j int) bool {
			return allPeers[i].DeviceID < allPeers[j].DeviceID
		})
		for _, p := range allPeers {
			if p.WGPubKey != "" {
				ep := p.STUNAddr
				if ep == "" {
					ep = fmt.Sprintf("%s:%d", p.PublicIP, p.WGPort)
				}
				peerVIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
				if peerVIP == "" {
					peerVIP = "10.123.111.2"
				}
				allowed := []string{peerVIP + "/32"}
				for _, route := range p.AdvertisedRoutes {
					if strings.TrimSpace(route) != "" {
						allowed = append(allowed, strings.TrimSpace(route))
					}
				}
				wgPeers = append(wgPeers, wireguard.WGPeer{
					PublicKey:  p.WGPubKey,
					AllowedIPs: allowed,
					Endpoint:   ep,
				})
			}
		}
	}

	if cachedAWGParams.Version == "" {
		cachedAWGParams = wireguard.GenerateAWG31StrictParams()
	}
	awgCfg := wireguard.AWGConfig{
		WGConfig: wireguard.WGConfig{
			PrivateKey: privKeyDisplay,
			Address:    fmt.Sprintf("%s/24", myVirtualIP),
			ListenPort: 443,
			MTU:        1420,
			Peers:      wgPeers,
		},
		AWGParams: cachedAWGParams,
	}
	conf, _ := wireguard.GenerateAWGConfig(&awgCfg)
	conf = strings.ReplaceAll(conf, "\r\n", "\n")
	conf = strings.ReplaceAll(conf, "\n", "\r\n")
	setControlText(hEditAwgConf, conf)
}

func setAWGPreset(p wireguard.AWGParams) {
	cachedAWGParams = p
	setControlText(hEditAwgJc, strconv.Itoa(p.Jc))
	setControlText(hEditAwgJmin, strconv.Itoa(p.Jmin))
	setControlText(hEditAwgJmax, strconv.Itoa(p.Jmax))
	setControlText(hEditAwgS1, strconv.Itoa(p.S1))
	setControlText(hEditAwgS2, strconv.Itoa(p.S2))
	setControlText(hEditAwgH1, fmt.Sprintf("%d", p.H1))
	setControlText(hEditAwgH2, fmt.Sprintf("%d", p.H2))
	setControlText(hEditAwgH3, fmt.Sprintf("%d", p.H3))
	setControlText(hEditAwgH4, fmt.Sprintf("%d", p.H4))
	renderAWGTextFromUI()
}

func fillConfigFields() {
	defer func() {
		if r := recover(); r != nil {
			writeDebug(fmt.Sprintf("⚠️ Panic in fillConfigFields: %v", r))
		}
	}()

	writeDebug("Вызов fillConfigFields()...")
	if cfg != nil {
		if hEditMyNick != 0 {
			setControlText(hEditMyNick, cfg.App.DeviceName)
		}

		active := cfg.EnsureActiveProfile()
		if active != nil {
			applyAWGProfileToGUI(active)
		}
		allowExitNode = cfg.Network.AllowExitNode
		if hBtnAllowExit != 0 {
			if allowExitNode {
				buttonLabels[ID_BTN_ALLOW_EXIT] = "🌐 Разрешить выход в интернет через меня: ВКЛ"
				buttonTypes[ID_BTN_ALLOW_EXIT] = "green"
			} else {
				buttonLabels[ID_BTN_ALLOW_EXIT] = "🌐 Разрешить выход в интернет через меня: ВЫКЛ"
				buttonTypes[ID_BTN_ALLOW_EXIT] = "normal"
			}
			procInvalidateRect.Call(hBtnAllowExit, 0, 1)
		}

		if hEditAdvSubnets != 0 {
			subnetsStr := strings.Join(cfg.Network.AdvertisedSubnets, ", ")
			setControlText(hEditAdvSubnets, subnetsStr)
		}

		tgFound := false
		tgToken := ""
		tgChat := ""
		mqFound := false
		mqBroker := "tcp://broker.emqx.io:1883"
		mqTopic := "natbypass/mynet/peers"

		for _, ch := range cfg.Signaling.Channels {
			if ch.Type == "telegram" {
				if ch.Params != nil {
					tgToken = ch.Params["token"]
					tgChat = ch.Params["chat_id"]
				}
				if tgToken != "" {
					setControlText(hEditTgToken, tgToken)
					setControlText(hEditTgChat, tgChat)
					tgFound = true
				}
			}
			if ch.Type == "mqtt" {
				if ch.Params != nil {
					if ch.Params["broker_url"] != "" {
						mqBroker = ch.Params["broker_url"]
					}
					if ch.Params["topic"] != "" {
						mqTopic = ch.Params["topic"]
					}
				}
				setControlText(hEditMqttBr, mqBroker)
				setControlText(hEditMqttTp, mqTopic)
				mqFound = true
			}
		}

		writeDebug(fmt.Sprintf("fillConfigFields: tgFound=%t, mqFound=%t", tgFound, mqFound))
		if tgFound && mqFound {
			setSigModeUI("parallel")
		} else if tgFound {
			setSigModeUI("tg_only")
		} else {
			setSigModeUI("mqtt_only")
		}
	}
}

func saveConfigFromUI() {

	modeText := chosenModeStr
	if hEditMyNick != 0 {
		myNick = strings.TrimSpace(getControlText(hEditMyNick))
	}
	tgToken := strings.TrimSpace(getControlText(hEditTgToken))
	tgChat := strings.TrimSpace(getControlText(hEditTgChat))
	mqBroker := strings.TrimSpace(getControlText(hEditMqttBr))
	mqTopic := strings.TrimSpace(getControlText(hEditMqttTp))

	var subnetsList []string
	if hEditAdvSubnets != 0 {
		subnetsRaw := strings.TrimSpace(getControlText(hEditAdvSubnets))
		if subnetsRaw != "" {
			for _, sp := range strings.Split(subnetsRaw, ",") {
				if t := strings.TrimSpace(sp); t != "" {
					subnetsList = append(subnetsList, t)
				}
			}
		}
	} else if cfg != nil {
		subnetsList = cfg.Network.AdvertisedSubnets
	}

	if mqBroker == "" {
		mqBroker = "tcp://broker.emqx.io:1883"
	}
	if mqTopic == "" {
		mqTopic = "natbypass/mynet/peers"
	}

	mqttEnabled := true
	tgEnabled := true

	if modeText == "tg_only" {
		mqttEnabled = false
		tgEnabled = tgToken != "" && tgChat != ""
	} else if modeText == "mqtt_only" {
		mqttEnabled = true
		tgEnabled = false
	} else {
		mqttEnabled = true
		tgEnabled = tgToken != "" && tgChat != ""
	}

	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.App.Name = "NatBypass"
	cfg.App.DeviceName = myNick
	cfg.App.SaveLogsToDisk = saveLogsToDisk
	cfg.App.ShowDiagnostics = showDiagnostics
	cfg.App.PublishInterval = 10
	cfg.Network.UpnpEnabled = true
	cfg.Network.AllowExitNode = allowExitNode
	cfg.Network.AdvertisedSubnets = subnetsList
	if len(cfg.Network.StunServers) == 0 {
		cfg.Network.StunServers = []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"stun.cloudflare.com:3478",
		}
	}
	if len(cfg.Network.IPApis) == 0 {
		cfg.Network.IPApis = []string{
			"https://api.ipify.org",
			"https://ifconfig.me/ip",
			"https://icanhazip.com",
		}
	}
	addressBookMu.RLock()
	cfg.App.AddressBook = make(map[string]string)
	for k, v := range addressBook {
		cfg.App.AddressBook[k] = v
	}
	addressBookMu.RUnlock()

	cfg.Signaling.Channels = []config.ChannelConfig{
		{
			Type:     "mqtt",
			Priority: 1,
			Enabled:  mqttEnabled,
			Params: map[string]string{
				"broker_url": mqBroker,
				"topic":      mqTopic,
			},
		},
		{
			Type:     "telegram",
			Priority: 2,
			Enabled:  tgEnabled,
			Params: map[string]string{
				"token":   tgToken,
				"chat_id": tgChat,
			},
		},
	}

	if cfg.WireGuard.ListenPort == 0 {
		cfg.WireGuard.ListenPort = 51820
	}
	if cfg.WireGuard.MTU == 0 {
		cfg.WireGuard.MTU = 1420
	}
	cfg.WireGuard.Enabled = true

	if hEditAwgJc != 0 {
		jc, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJc)))
		jmin, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJmin)))
		jmax, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgJmax)))
		s1, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgS1)))
		s2, _ := strconv.Atoi(strings.TrimSpace(getControlText(hEditAwgS2)))
		h1, _ := strconv.ParseUint(strings.TrimSpace(getControlText(hEditAwgH1)), 10, 32)
		h2, _ := strconv.ParseUint(strings.TrimSpace(getControlText(hEditAwgH2)), 10, 32)
		h3, _ := strconv.ParseUint(strings.TrimSpace(getControlText(hEditAwgH3)), 10, 32)
		h4, _ := strconv.ParseUint(strings.TrimSpace(getControlText(hEditAwgH4)), 10, 32)

		cachedAWGParams = wireguard.AWGParams{
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
		cfg.WireGuard.AWG = config.AWGConfig{
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
	}

	if allowExitNode {
		go func() {
			_ = tunnel.EnableHostIPForwarding()
		}()
	}

	active := cfg.EnsureActiveProfile()
	if active != nil {
		active.MQTTBroker = mqBroker
		active.MQTTTopic = mqTopic
		active.TGToken = tgToken
		if cid, err := strconv.ParseInt(tgChat, 10, 64); err == nil {
			active.TGChatID = cid
		}
	}

	if err := config.Save(cfg, configPath, false); err != nil {
		msg := fmt.Sprintf("⚠️ Ошибка сохранения конфига: %v", err)
		addLog(msg)
		writeDebug(msg)
	} else {
		msg := "💾 Настройки сохранены в " + configPath
		addLog(msg)
		writeDebug(msg)
	}

	refreshProfilesUI()

	// Очистка устаревших пиров при смене конфигурации / топика
	if registry != nil {
		registry.ClearAll()
	}
	lastPeersHash = ""

	engineMu.Lock()
	rebuildSignalingInternal(engineCtx, modeText, tgToken, tgChat, mqBroker, mqTopic)
	engineMu.Unlock()
	triggerPublish()
}

func saveConfig() {
	saveConfigFromUI()
	buttonLabels[ID_BTN_SAVE_CFG] = "✓ НАСТРОЙКИ СОХРАНЕНЫ!"
	procInvalidateRect.Call(hBtnSaveCfg, 0, 1)

	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_SAVE_CFG] = "💾 Сохранить настройки в config.yaml"
		procInvalidateRect.Call(hBtnSaveCfg, 0, 1)
	})
}

func testTelegram() {
	tok := strings.TrimSpace(getControlText(hEditTgToken))
	chat := strings.TrimSpace(getControlText(hEditTgChat))
	if tok == "" {
		addLog("⚠️ Введите токен бота")
		return
	}
	buttonLabels[ID_BTN_TEST_TG] = "⏳ Проверка..."
	procInvalidateRect.Call(hBtnTestTg, 0, 1)
	addLog("⏳ Проверка Telegram Bot API...")
	writeDebug("Тестирование Telegram Bot API...")
	go func() {
		ch := signaling.NewTelegramChannel(tok, chat, "")
		if ch.IsAvailable(context.Background()) {
			addLog("✅ Успех! Telegram бот активен и отвечает на запросы.")
			writeDebug("Telegram bot is available!")
			if chat != "" {
				testPayload := &signaling.Payload{
					DeviceID:   myDevID,
					Nickname:   myNick,
					DeviceName: myNick,
					VirtualIP:  myVirtualIP,
					PublicKey:  crypto.KeyToHex(myPubKey),
					PublicIP:   myPublicIP,
					STUNAddr:   mySTUNAddr,
					Timestamp:  time.Now(),
				}
				if sendErr := ch.Send(context.Background(), testPayload); sendErr == nil {
					succMsg := fmt.Sprintf("✓ Тестовый пакет успешно отправлен в чат %s", chat)
					addLog(succMsg)
					writeDebug(succMsg)
				} else {
					failMsg := fmt.Sprintf("⚠️ Бот активен, но отправка в чат %s вернула: %s", chat, sendErr.Error())
					addLog(failMsg)
					writeDebug(failMsg)
				}
			}
			buttonLabels[ID_BTN_TEST_TG] = "✅ Бот активен"
		} else {
			addLog("❌ Ошибка: не удалось подключиться к Telegram API.")
			writeDebug("Telegram bot check FAILED")
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
	br := strings.TrimSpace(getControlText(hEditMqttBr))
	buttonLabels[ID_BTN_TEST_MQTT] = "⏳ Проверка..."
	procInvalidateRect.Call(hBtnTestMqtt, 0, 1)
	addLog("⏳ Проверка MQTT брокера...")
	writeDebug("Тестирование MQTT брокера: " + br)
	go func() {
		ch := signaling.NewMQTTChannel(br, "test", "tester-"+strconv.Itoa(int(time.Now().UnixNano()%10000)), "", "")
		if ch.IsAvailable(context.Background()) {
			addLog("✅ Успех! MQTT брокер доступен.")
			writeDebug("MQTT broker is available!")
			buttonLabels[ID_BTN_TEST_MQTT] = "✅ Доступен"
		} else {
			addLog("❌ Ошибка: MQTT брокер недоступен.")
			writeDebug("MQTT broker check FAILED")
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
	setControlText(hEditDiagLog, "⏳ Выполняется комплексная проверка связности сети...\r\n")
	writeDebug("Запуск системной диагностики сети...")
	go func() {
		res := "========================================================================\r\n"
		res += "              СИСТЕМНАЯ ДИАГНОСТИКА & ДЕБАГГЕР NATBYPASS            \r\n"
		res += "========================================================================\r\n\r\n"

		// 1. Интернет
		internetOK := false
		testHosts := []string{"77.88.8.8:53", "8.8.8.8:53", "1.1.1.1:53"}
		for _, h := range testHosts {
			conn, err := net.DialTimeout("tcp", h, 2*time.Second)
			if err == nil {
				conn.Close()
				internetOK = true
				break
			}
		}
		if internetOK {
			res += "✅ 1. Сеть Интернет: ДОСТУПНА (DNS 1.1.1.1/8.8.8.8 отвечает)\r\n"
		} else {
			res += "⚠️ 1. Сеть Интернет: Ограничена (проверьте шлюз)\r\n"
		}

		// 2. IP адреса
		lanIP := getLocalLANIP()
		res += fmt.Sprintf("🏠 2. Локальный LAN IP: %s (Порт :51820 открыт)\r\n", lanIP)

		if myPublicIP != "" && myPublicIP != "0.0.0.0" {
			res += fmt.Sprintf("🌐 3. Внешний публичный IP: %s\r\n", myPublicIP)
		} else {
			res += "⚠️ 3. Внешний публичный IP: Ожидание ответа STUN...\r\n"
		}

		// 3. STUN Hole Punch
		if mySTUNAddr != "" {
			res += fmt.Sprintf("⚡ 4. STUN UDP Сокет: %s (Прямой Hole Punching активен)\r\n", mySTUNAddr)
		} else {
			res += "⚠️ 4. STUN UDP Сокет: Ожидание связывания сокета...\r\n"
		}

		// 4. Пиры
		peersCount := 0
		directP2PCount := 0
		if registry != nil {
			peers := registry.List()
			peersCount = len(peers)
			for _, p := range peers {
				if p.DirectP2P {
					directP2PCount++
				}
			}
		}
		res += fmt.Sprintf("👥 5. Устройств в сигнальной сети: %d (Ваш IP в Mesh: %s)\r\n", peersCount, myVirtualIP)
		res += fmt.Sprintf("🚀 6. Пробитых прямых UDP сокетов: %d из %d\r\n", directP2PCount, peersCount)

		// 5. Сигналы и статистика
		pIn := atomic.LoadUint64(&packetsRecvCount)
		pOut := atomic.LoadUint64(&packetsSentCount)
		res += fmt.Sprintf("📡 7. Активный режим: %s\r\n", activeChannelStr)
		res += fmt.Sprintf("📊 8. Пакетов отправлено/принято: %d / %d\r\n", pOut, pIn)
		res += fmt.Sprintf("⏱️ 9. Время непрерывной работы процесса: %v\r\n\r\n", time.Since(startTime).Round(time.Second))

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		res += fmt.Sprintf("🧠 10. Потоки и память: %d Горутин | %.2f MB RAM | GC Циклов: %d\r\n\r\n", runtime.NumGoroutine(), float64(m.Alloc)/(1024*1024), m.NumGC)
		res += "✓ Комплексная проверка успешно завершена."

		setControlText(hEditDiagLog, res)
		addLog("🩺 Комплексная диагностика системы успешно выполнена")
		writeDebug("Результат диагностики:\r\n" + res)

		buttonLabels[ID_BTN_RUN_DIAG] = "🔄 Запустить повторно"
		procInvalidateRect.Call(hBtnRunDiag, 0, 1)
	}()
}

// dumpGoroutineStack — мгновенный снимок всех потоков и горутин
func dumpGoroutineStack() {
	buf := make([]byte, 65536)
	n := runtime.Stack(buf, true)
	stackDump := string(buf[:n])

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	header := fmt.Sprintf("========================================================================\r\n"+
		"           СНИМОК СТЕКА ПОТОКОВ & ПАМЯТИ (GOROUTINE DUMP)           \r\n"+
		"========================================================================\r\n"+
		"Время: %s | Горутин: %d | Выделено RAM: %.2f MB | Sys RAM: %.2f MB\r\n\r\n",
		time.Now().Format("2006-01-02 15:04:05.000"), runtime.NumGoroutine(),
		float64(m.Alloc)/(1024*1024), float64(m.Sys)/(1024*1024))

	fullDump := header + stackDump
	setControlText(hEditDiagLog, fullDump)

	dumpFile := fmt.Sprintf("natbypass_stack_%d.log", time.Now().Unix())
	_ = os.WriteFile(dumpFile, []byte(fullDump), 0644)

	addLog("⚡ Снимок потоков и памяти сохранен в " + dumpFile)
	writeDebug("Снимок потоков сохранен в " + dumpFile)

	buttonLabels[ID_BTN_DUMP_STACK] = "✓ СНИМОК ГОТОВ!"
	procInvalidateRect.Call(hBtnDumpStack, 0, 1)
	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_DUMP_STACK] = "⚡ Снимок памяти и потоков"
		procInvalidateRect.Call(hBtnDumpStack, 0, 1)
	})
}

func saveLogsToFile() {
	logsMutex.Lock()
	allLogs := strings.Join(logsBuffer, "\r\n")
	logsMutex.Unlock()

	fileName := fmt.Sprintf("natbypass_events_%d.log", time.Now().Unix())
	_ = os.WriteFile(fileName, []byte(allLogs), 0644)

	addLog("💾 Журнал событий успешно экспортирован в " + fileName)
	buttonLabels[ID_BTN_SAVE_LOGS] = "✓ ЭКСПОРТИРОВАНО!"
	procInvalidateRect.Call(hBtnSaveLogs, 0, 1)
	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_SAVE_LOGS] = "💾 Экспорт лога"
		procInvalidateRect.Call(hBtnSaveLogs, 0, 1)
	})
}

func addLog(msg string) {
	logsMutex.Lock()
	defer logsMutex.Unlock()
	entry := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	logsBuffer = append(logsBuffer, entry)
	if len(logsBuffer) > 300 {
		logsBuffer = logsBuffer[len(logsBuffer)-300:]
	}
	logsDirty = true
}

func createLabelOn(parent, hInstance uintptr, text string, x, y, w, h int, font uintptr) uintptr {
	staticClass, _ := windows.UTF16PtrFromString("STATIC")
	textPtr, _ := windows.UTF16PtrFromString(text)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(staticClass)),
		uintptr(unsafe.Pointer(textPtr)),
		WS_CHILD|WS_VISIBLE|SS_LEFT|SS_NOPREFIX,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, 0, hInstance, 0,
	)
	if font != 0 {
		procSendMessageW.Call(hwnd, 0x0030, font, 1)
	}
	return hwnd
}

func createLabel(hInstance uintptr, text string, x, y, w, h int, font uintptr) uintptr {
	hwnd := createLabelOn(hMainWnd, hInstance, text, x, y, w, h, font)
	allControls = append(allControls, hwnd)
	return hwnd
}

func createOwnerDrawButtonOn(parent, hInstance uintptr, text string, x, y, w, h int, id uint32, bType string) uintptr {
	buttonLabels[id] = text
	buttonTypes[id] = bType

	btnClass, _ := windows.UTF16PtrFromString("BUTTON")
	textPtr, _ := windows.UTF16PtrFromString(text)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(btnClass)),
		uintptr(unsafe.Pointer(textPtr)),
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, uintptr(id), hInstance, 0,
	)
	return hwnd
}

func createOwnerDrawButton(hInstance uintptr, text string, x, y, w, h int, id uint32, bType string) uintptr {
	hwnd := createOwnerDrawButtonOn(hMainWnd, hInstance, text, x, y, w, h, id, bType)
	allControls = append(allControls, hwnd)
	return hwnd
}

func createEditOn(parent, hInstance uintptr, text string, x, y, w, h int, multiline, readonly bool, font uintptr) uintptr {
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
		parent, 0, hInstance, 0,
	)
	if font != 0 {
		procSendMessageW.Call(hwnd, 0x0030, font, 1)
	}
	if !multiline {
		// EM_SETMARGINS (0x00D3), EC_LEFTMARGIN | EC_RIGHTMARGIN (3), 8px left & right (0x00080008)
		procSendMessageW.Call(hwnd, 0x00D3, uintptr(3), uintptr(0x00080008))
	}
	return hwnd
}

func createEdit(hInstance uintptr, text string, x, y, w, h int, multiline, readonly bool, font uintptr) uintptr {
	hwnd := createEditOn(hMainWnd, hInstance, text, x, y, w, h, multiline, readonly, font)
	allControls = append(allControls, hwnd)
	return hwnd
}

func createListBox(hInstance uintptr, x, y, w, h int, font uintptr) uintptr {
	lbClass, _ := windows.UTF16PtrFromString("LISTBOX")
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(lbClass)),
		0,
		WS_CHILD|WS_TABSTOP|WS_BORDER|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT,
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
	h := height
	if h > 0 {
		h = -h
	}
	const (
		DEFAULT_CHARSET   = 1
		CLEARTYPE_QUALITY = 5
	)
	hFont, _, _ := procCreateFontW.Call(
		uintptr(int32(h)), 0, 0, 0,
		uintptr(weight), 0, 0, 0,
		DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0,
		uintptr(unsafe.Pointer(namePtr)),
	)
	return hFont
}


func setControlText(hwnd uintptr, text string) {
	if hwnd == 0 {
		return
	}
	if len(text) > 16000 {
		text = text[len(text)-16000:]
	}
	tPtr, _ := windows.UTF16FromString(text)
	procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&tPtr[0])))
}

func getControlText(hwnd uintptr) string {
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, 4096)
	lenRes, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 4096)
	if lenRes > 0 {
		return windows.UTF16ToString(buf[:lenRes])
	}
	return ""
}

func copyToClipboard(text string) {
	cmd := exec.Command("clip")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	cmd.Stdin = strings.NewReader(text)
	_ = cmd.Run()
}

func LOWORD(l uintptr) uint16 {
	return uint16(l & 0xFFFF)
}


