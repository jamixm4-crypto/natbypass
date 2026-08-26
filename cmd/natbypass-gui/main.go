//go:build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
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

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/tunnel"
	"github.com/natbypass/natbypass/internal/updater"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
	"github.com/skip2/go-qrcode"
)

var (
	Version = "1.2.7"
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

// Р¦РІРµС‚РѕРІР°СЏ РїР°Р»РёС‚СЂР° Slate Dark (Modern Fluent Theme)
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

// Р“Р»РѕР±Р°Р»СЊРЅС‹Рµ РїРѕСЃС‚РѕСЏРЅРЅС‹Рµ GDI СЂРµСЃСѓСЂСЃС‹ (СЃРѕР·РґР°СЋС‚СЃСЏ 1 СЂР°Р· РїСЂРё СЃС‚Р°СЂС‚Рµ, 0 СѓС‚РµС‡РµРє)
var (
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

	navButtons [6]uintptr
	currentTab = 0
	tabPages   [6][]uintptr

	// Р’РєР»Р°РґРєР° 0: РћР±Р·РѕСЂ
	hLblStatus            uintptr
	hLblIpInfo            uintptr
	hLblChannels          uintptr
	hBtnVpn               uintptr
	hBtnBookmarkPeer      uintptr
	hBtnExitNodeSelect    uintptr
	hBtnToggleSubnetRoute uintptr
	hListPeers            uintptr
	hBtnRefresh           uintptr
	hBtnManageProfiles    uintptr
	lastPeersHash         string
	activeExitNodeID      string
	activeExitVIP         string
	activeSubnetRoutes    = make(map[string]string)
	activeSubnetRoutesMu  sync.RWMutex

	// Р’РєР»Р°РґРєР° 1: РџСЂРѕС„РёР»Рё СЃРµС‚РµР№
	hListProfiles   uintptr
	hBtnProfSwitch  uintptr
	hBtnProfQR      uintptr
	hBtnProfCreate  uintptr
	hBtnProfImport  uintptr
	hEditProfName   uintptr
	hBtnProfExport  uintptr
	hEditProfTopic  uintptr
	hEditProfBroker uintptr
	hBtnProfSave    uintptr
	hBtnProfDelete  uintptr
	selectedProfID  string
	activeQRBitmap  [][]bool
	activeQRText    string

	// Р’РєР»Р°РґРєР° 2: AmneziaWG
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

	// Р’РєР»Р°РґРєР° 2: РќР°СЃС‚СЂРѕР№РєРё
	hEditMyNick      uintptr
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
	hBtnAllowExit      uintptr
	allowExitNode      bool
	hBtnAddLocalSubnet uintptr
	hEditAdvSubnets    uintptr
	hBtnToggleLogs   uintptr
	hBtnToggleDiag   uintptr
	hBtnSaveCfg      uintptr

	// Р’РєР»Р°РґРєР° 3: Р”РёР°РіРЅРѕСЃС‚РёРєР°
	hBtnRunDiag   uintptr
	hBtnDumpStack uintptr
	hEditDiagLog  uintptr

	// РЎС‚Р°СЂС‚РѕРІС‹Р№ СЌРєСЂР°РЅ (Startup / Splash)
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

	// Р’РєР»Р°РґРєР° 4: Р›РѕРіРё
	hEditLogs    uintptr
	hBtnClrLogs  uintptr
	hBtnSaveLogs uintptr

	allControls []uintptr

	// Р”РІРёР¶РѕРє Рё СЃРµС‚РµРІРѕРµ СЃРѕСЃС‚РѕСЏРЅРёРµ
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
	showDiagnostics  bool = false
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

	// РЎС‚Р°С‚РёСЃС‚РёРєР° РґРµР±Р°РіРіРµСЂР°
	startTime        time.Time
	packetsSentCount uint64
	packetsRecvCount uint64
	debugLogFile     *os.File
	debugLogMu       sync.Mutex
	singleMutex      uintptr

	// РЎРѕСЃС‚РѕСЏРЅРёРµ РјРѕРґР°Р»СЊРЅРѕРіРѕ РґРёР°Р»РѕРіР° Р·Р°РєР»Р°РґРѕРє
	dlgResultText string
	dlgResultOK   bool
	dlgFinished   bool
	hDlgEdit      uintptr
)

const (
	ID_TIMER_POLL = 1001

	// РќР°РІРёРіР°С†РёСЏ
	ID_NAV_DASHBOARD = 3001
	ID_NAV_PROFILES  = 3002
	ID_NAV_AWG       = 3003
	ID_NAV_SETTINGS  = 3004
	ID_NAV_DIAG      = 3005
	ID_NAV_LOGS      = 3006

	// Р”РµР№СЃС‚РІРёСЏ
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
	ID_BTN_MQ_EMQX         = 4051
	ID_BTN_MQ_HIVE         = 4052
	ID_BTN_MQ_MOSQ         = 4053
	ID_BTN_MQ_ECL          = 4054
	ID_BTN_CHECK_UPDATE    = 4055

	// РџСЂРѕС„РёР»Рё
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
	writeDebug(fmt.Sprintf("рџљЂ NatBypass GUI Р—Р°РїСѓС‰РµРЅ | PID: %d | Р’СЂРµРјСЏ: %s", os.Getpid(), time.Now().Format("2006-01-02 15:04:05.000")))
	writeDebug(fmt.Sprintf("вљ™пёЏ OS: Windows %s | Arch: %s | CPU: %d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()))
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

// startSystemWatchdog вЂ” С„РѕРЅРѕРІС‹Р№ СЃС‚РѕСЂРѕР¶РµРІРѕР№ С‚Р°Р№РјРµСЂ РґР»СЏ РјРѕРЅРёС‚РѕСЂРёРЅРіР° Р·РґРѕСЂРѕРІСЊСЏ Рё РїСЂРµРґРѕС‚РІСЂР°С‰РµРЅРёСЏ РґРµРґР»РѕРєРѕРІ
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

			hbMsg := fmt.Sprintf("рџ©є [WATCHDOG] Uptime: %v | Goroutines: %d | RAM Alloc: %.1f MB | Peers: %d (P2P: %d) | Pkts In/Out: %d/%d",
				uptime, grCount, float64(m.Alloc)/(1024*1024), peersCount, directCount, pIn, pOut)
			writeDebug(hbMsg)

			// Р•СЃР»Рё РєРѕР»РёС‡РµСЃС‚РІРѕ РіРѕСЂСѓС‚РёРЅ Р°РЅРѕРјР°Р»СЊРЅРѕ РІРµР»РёРєРѕ (> 200), Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё СЃР±СЂР°СЃС‹РІР°РµРј СЃС‚РµРєС‚СЂРµР№СЃ РІ Р»РѕРі
			if grCount > 200 {
				writeDebug(fmt.Sprintf("вљ пёЏ WARNING: High goroutine count (%d)! Dumping stack:\r\n%s", grCount, string(debug.Stack())))
			}
		}
	}()
}

// cleanStaleInstances Р·Р°РІРµСЂС€Р°РµС‚ Р·Р°РІРёСЃС€РёРµ РїСЂРµРґС‹РґСѓС‰РёРµ РїСЂРѕС†РµСЃСЃС‹ NatBypass
func cleanStaleInstances() {
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
		if (strings.EqualFold(name, "NatBypass.exe") || strings.EqualFold(name, "natbypass-gui.exe")) && entry.ProcessID != myPID {
			stalePIDs = append(stalePIDs, entry.ProcessID)
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	if len(stalePIDs) == 0 {
		return
	}

	// 1. РџРѕСЃС‹Р»Р°РµРј WM_CLOSE РґР»СЏ РїР»Р°РІРЅРѕРіРѕ Р·Р°РІРµСЂС€РµРЅРёСЏ (РїСЂРµРґРѕС‚РІСЂР°С‰Р°РµС‚ Р·Р°РІРёСЃС€РёРµ С…СѓРєРё User32 Рё GDI-Р±Р»РѕРєРёСЂРѕРІРєРё)
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

	// Р”Р°РµРј 300РјСЃ РЅР° РєРѕСЂСЂРµРєС‚РЅРѕРµ Р·Р°РєСЂС‹С‚РёРµ СЂРµСЃСѓСЂСЃРѕРІ
	time.Sleep(300 * time.Millisecond)

	// 2. РџСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕ Р·Р°РІРµСЂС€Р°РµРј РїСЂРѕС†РµСЃСЃС‹, РµСЃР»Рё РѕРЅРё РЅРµ Р·Р°РєСЂС‹Р»РёСЃСЊ СЃР°РјРё
	for _, pid := range stalePIDs {
		if hProc, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid); err == nil {
			_ = windows.TerminateProcess(hProc, 0)
			windows.CloseHandle(hProc)
			writeDebug(fmt.Sprintf("рџ§№ РћС‡РёС‰РµРЅ РїСЂРµРґС‹РґСѓС‰РёР№ Р·Р°РІРёСЃС€РёР№ РїСЂРѕС†РµСЃСЃ PID: %d", pid))
		}
	}
}

func main() {
	runtime.LockOSThread()
	defer func() {
		if r := recover(); r != nil {
			stackStr := string(debug.Stack())
			writeDebug(fmt.Sprintf("вќЊ CRITICAL PANIC IN MAIN: %v\r\n%s", r, stackStr))
			_ = os.WriteFile("crash_dump.log", []byte(fmt.Sprintf("CRASH: %v\r\n%s", r, stackStr)), 0644)
		}
	}()

	// 0. High-DPI Crystal Crispness
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
	procSetProcessDpiAwarenessContext := moduser32.NewProc("SetProcessDpiAwarenessContext")
	if procSetProcessDpiAwarenessContext.Find() == nil {
		procSetProcessDpiAwarenessContext.Call(uintptr(uint64(0xFFFFFFFFFFFFFFFC)))
	} else {
		procSetProcessDPIAware := moduser32.NewProc("SetProcessDPIAware")
		if procSetProcessDPIAware.Find() == nil {
			procSetProcessDPIAware.Call()
		}
	}

	initDebugLog()

	// 1. РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РµРґРёРЅРѕРіРѕ СЌРєР·РµРјРїР»СЏСЂР° (Single Instance Protection)
	mutName, _ := windows.UTF16PtrFromString("Global\\NatBypass_SingleInstance_Mutex_App")
	hMut, _, _ := procCreateMutexW.Call(0, 1, uintptr(unsafe.Pointer(mutName)))
	if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		clsName, _ := windows.UTF16PtrFromString("NatBypassWindowClass")
		hExisting, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(clsName)), 0)
		if hExisting != 0 {
			procShowWindow.Call(hExisting, 9 /* SW_RESTORE */)
			procSetForegroundWindow.Call(hExisting)
		}
		os.Exit(0)
		return
	}
	singleMutex = hMut

	// 2. РћС‡РёСЃС‚РєР° Р·Р°РІРёСЃС€РёС… Р·РѕРјР±Рё-РїСЂРѕС†РµСЃСЃРѕРІ РїСЂРµРґС‹РґСѓС‰РёС… Р°РІР°СЂРёР№РЅС‹С… Р·Р°РїСѓСЃРєРѕРІ
	cleanStaleInstances()

	// Р—Р°РїСѓСЃРє СЃС‚РѕСЂРѕР¶РµРІРѕРіРѕ С‚Р°Р№РјРµСЂР° РґРµР±Р°РіРіРµСЂР°
	startSystemWatchdog()

	cfgFile := flag.String("config", "config.yaml", "Path to config.yaml")
	flag.Parse()
	configPath = *cfgFile
	writeDebug("Р—Р°РіСЂСѓР·РєР° РєРѕРЅС„РёРіСѓСЂР°С†РёРё: " + configPath)

	// 2. РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ Common Controls
	type INITCOMMONCONTROLSEX struct {
		DwSize uint32
		DwICC  uint32
	}
	icex := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  0x00000008 | 0x00000001,
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icex)))
	writeDebug("CommonControls РёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅС‹")

	// 3. Р—Р°РіСЂСѓР·РєР° РєРѕРЅС„РёРіСѓСЂР°С†РёРё
	loadedCfg, err := config.Load(configPath)
	if err != nil {
		writeDebug("РљРѕРЅС„РёРі РЅРµ РЅР°Р№РґРµРЅ РёР»Рё РѕС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё, РёСЃРїРѕР»СЊР·СѓРµРј РґРµС„РѕР»С‚С‹: " + err.Error())
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
		writeDebug("РљРѕРЅС„РёРі СѓСЃРїРµС€РЅРѕ Р·Р°РіСЂСѓР¶РµРЅ РёР· " + configPath)
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
	if err != nil {
		showDiagnostics = false
	}
	cachedAWGParams = wireguard.DefaultAWGParams()

	// 4. РЎРѕР·РґР°РЅРёРµ РїРѕСЃС‚РѕСЏРЅРЅС‹С… СЂРµСЃСѓСЂСЃРѕРІ GDI, РёРєРѕРЅРѕРє Рё РєСѓСЂСЃРѕСЂР°
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	hCursor, _, _ = procLoadCursorW.Call(0, 32512) // IDC_ARROW
	hAppIcon, _, _ = procLoadIconW.Call(hInstance, 1) // Р’СЃС‚СЂРѕРµРЅРЅР°СЏ РёРєРѕРЅРєР°
	if hAppIcon == 0 {
		hAppIcon, _, _ = procLoadIconW.Call(0, 32512)
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
	writeDebug("GDI СЂРµСЃСѓСЂСЃС‹ Рё С€СЂРёС„С‚С‹ СЃРѕР·РґР°РЅС‹")

	// 5. Р РµРіРёСЃС‚СЂР°С†РёСЏ РєР»Р°СЃСЃР° РѕРєРЅР°
	className, _ := windows.UTF16PtrFromString("NatBypassModernAppClass")
	windowTitle, _ := windows.UTF16PtrFromString("NatBypass вЂ” P2P Mesh РЎРµС‚СЊ & AmneziaWG 2.0")

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         3,
		LpfnWndProc:   windows.NewCallback(wndProc),
		HInstance:     hInstance,
		HIcon:         hAppIcon,
		HCursor:       hCursor,
		HbrBackground: hBrushBg,
		LpszClassName: className,
		HIconSm:       hAppIcon,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	writeDebug("РљР»Р°СЃСЃ РѕРєРЅР° Р·Р°СЂРµРіРёСЃС‚СЂРёСЂРѕРІР°РЅ")

	// 6. РЎРѕР·РґР°РЅРёРµ РіР»Р°РІРЅРѕРіРѕ РѕРєРЅР° (С„РёРєСЃРёСЂРѕРІР°РЅРЅС‹Р№ РїСЂРµРјРёР°Р»СЊРЅС‹Р№ СЂР°Р·РјРµСЂ Р±РµР· РґРµС„РѕСЂРјР°С†РёРё РєРѕРЅС‚СЂРѕР»РѕРІ)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		WS_FIXEDWINDOW|WS_CLIPCHILDREN|WS_CLIPSIBLINGS,
		60, 40, 1060, 720,
		0, 0, hInstance, 0,
	)
	hMainWnd = hwnd
	writeDebug(fmt.Sprintf("Р“Р»Р°РІРЅРѕРµ РѕРєРЅРѕ СЃРѕР·РґР°РЅРѕ, HWND=0x%X", hMainWnd))

	procSendMessageW.Call(hMainWnd, 0x0080, 1, hAppIcon)
	procSendMessageW.Call(hMainWnd, 0x0080, 0, hAppIcon)

	// DWM Dark Mode Р·Р°РіРѕР»РѕРІРѕРє
	darkMode := int32(1)
	procDwmSetWindowAttribute.Call(hMainWnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)

	// РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РёРєРѕРЅРєРё РІ СЃРёСЃС‚РµРјРЅРѕРј С‚СЂРµРµ Windows
	initTrayIcon(hMainWnd, hAppIcon)

	// РџРѕСЃС‚СЂРѕРµРЅРёРµ СЌР»РµРјРµРЅС‚РѕРІ РЅР°С‚РёРІРЅРѕРіРѕ РёРЅС‚РµСЂС„РµР№СЃР° Windows (Pure Win32 GDI Controls)
	writeDebug("РќР°С‡Р°Р»Рѕ РїРѕСЃС‚СЂРѕРµРЅРёСЏ UI buildModernUI()...")
	buildModernUI(hInstance)

	// РџРѕРєР°Р·С‹РІР°РµРј РЅР°С‚РёРІРЅРѕРµ РіР»Р°РІРЅРѕРµ РѕРєРЅРѕ Win32
	procShowWindow.Call(hMainWnd, SW_SHOW)
	procUpdateWindow.Call(hMainWnd)
	procSetForegroundWindow.Call(hMainWnd)
	procSetTimer.Call(hMainWnd, ID_TIMER_POLL, 1000, 0)

	// Р—Р°РїСѓСЃРє СЃРµС‚РµРІРѕРіРѕ СЏРґСЂР° РЅР°РїСЂСЏРјСѓСЋ РёР· РїР°СЂР°РјРµС‚СЂРѕРІ cfg
	writeDebug("Р—Р°РїСѓСЃРє СЃРµС‚РµРІРѕРіРѕ СЏРґСЂР° NatBypass Mesh...")
	go startEngineFromConfig(cfg)

	// Р¦РёРєР» СЃРѕРѕР±С‰РµРЅРёР№ Windows (UI thread)
	writeDebug("РЎРµС‚РµРІРѕРµ СЏРґСЂРѕ Рё РЅР°С‚РёРІРЅС‹Р№ Win32 GUI Р°РєС‚РёРІРЅС‹, РІС…РѕРґ РІ С†РёРєР» СЃРѕР±С‹С‚РёР№...")
	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	writeDebug("Р—Р°РІРµСЂС€РµРЅРёРµ СЂР°Р±РѕС‚С‹...")
	exitApp()
}

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			writeDebug(fmt.Sprintf("вљ пёЏ Panic РІ wndProc (msg=0x%X): %v", msg, r))
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

		sidebarRect := RECT{Left: 0, Top: 0, Right: 220, Bottom: clientRect.Bottom}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&sidebarRect)), hBrushSidebar)

		procSelectObject.Call(hdc, hPenBorder)
		var pt POINT
		procMoveToEx.Call(hdc, 220, 0, uintptr(unsafe.Pointer(&pt)))
		procLineTo.Call(hdc, 220, uintptr(clientRect.Bottom))

		cardRect := RECT{Left: 232, Top: 10, Right: clientRect.Right - 10, Bottom: clientRect.Bottom - 10}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&cardRect)), hBrushCard)

		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case WM_DRAWITEM:
		var dis DRAWITEMSTRUCT
		procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&dis)), lParam, unsafe.Sizeof(dis))
		drawCustomButton(&dis)
		return 1

	case WM_SYSCOMMAND:
		if wParam == SC_CLOSE {
			exitApp()
			return 0
		}

	case WM_CLOSE:
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

			titleStr, _ := syscall.UTF16PtrFromString("рџЊђ РћС‚РєСЂС‹С‚СЊ NatBypass")
			syncStr, _ := syscall.UTF16PtrFromString("вљЎ РћР±РЅРѕРІРёС‚СЊ СЃРѕРєРµС‚С‹ P2P")
			exitStr, _ := syscall.UTF16PtrFromString("рџљЄ Р’С‹С…РѕРґ")

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

// exitApp вЂ” РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕРµ РјРіРЅРѕРІРµРЅРЅРѕРµ Р·Р°РІРµСЂС€РµРЅРёРµ РїСЂРѕС†РµСЃСЃР° Р±РµР· Р·Р°РІРёСЃР°РЅРёР№
func exitApp() {
	if !atomic.CompareAndSwapInt32(&isShuttingDown, 0, 1) {
		return
	}

	writeDebug("рџ›‘ Р—Р°РІРµСЂС€РµРЅРёРµ СЂР°Р±РѕС‚С‹ РїСЂРёР»РѕР¶РµРЅРёСЏ...")

	// 1. РњРіРЅРѕРІРµРЅРЅРѕ СЃРєСЂС‹РІР°РµРј РѕРєРЅРѕ РѕС‚ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ Рё СѓР±РёСЂР°РµРј РёРєРѕРЅРєСѓ РёР· С‚СЂРµСЏ
	removeTrayIcon(hMainWnd)
	procKillTimer.Call(hMainWnd, ID_TIMER_POLL)
	procShowWindow.Call(hMainWnd, SW_HIDE)

	// 2. Р—Р°РєСЂС‹РІР°РµРј РґРµСЃРєСЂРёРїС‚РѕСЂ РµРґРёРЅРѕРіРѕ РјСЊСЋС‚РµРєСЃР°
	if singleMutex != 0 {
		procCloseHandle.Call(singleMutex)
	}

	writeDebug("вњ“ NatBypass РїСЂРѕС†РµСЃСЃ РїРѕР»РЅРѕСЃС‚СЊСЋ РѕСЃС‚Р°РЅРѕРІР»РµРЅ.")
	if debugLogFile != nil {
		_ = debugLogFile.Close()
	}

	// 3. РћС‚РїСЂР°РІР»СЏРµРј РїСЂРѕС‰Р°Р»СЊРЅС‹Р№ РјР°СЏРє РІС‹С…РѕРґР° РґСЂСѓРіРёРј СѓР·Р»Р°Рј СЃРµС‚Рё
	broadcastGoodbye()

	// 4. Р‘С‹СЃС‚СЂР°СЏ РѕСЃС‚Р°РЅРѕРІРєР° СЃРѕРєРµС‚РѕРІ Рё РјРѕРјРµРЅС‚Р°Р»СЊРЅС‹Р№ РІС‹С…РѕРґ
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
			(id == ID_NAV_PROFILES && currentTab == 1) ||
			(id == ID_NAV_AWG && currentTab == 2) ||
			(id == ID_NAV_SETTINGS && currentTab == 3) ||
			(id == ID_NAV_DIAG && currentTab == 4) ||
			(id == ID_NAV_LOGS && currentTab == 5) {
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
	case ID_NAV_PROFILES:
		selectTab(1)
	case ID_NAV_AWG:
		selectTab(2)
	case ID_NAV_SETTINGS:
		selectTab(3)
	case ID_NAV_DIAG:
		selectTab(4)
	case ID_NAV_LOGS:
		selectTab(5)

	case ID_BTN_MANAGE_PROFILES:
		selectTab(1)

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
		addLog("вљЎ РџСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕРµ РѕР±РЅРѕРІР»РµРЅРёРµ STUN СЃРѕРєРµС‚Р° Рё РІРЅРµС€РЅРµРіРѕ IP...")
		go func() {
			if ipDisc != nil {
				if ip, err := ipDisc.GetPublicIP(context.Background()); err == nil {
					myPublicIP = ip.String()
					addLog("вњ“ РџСѓР±Р»РёС‡РЅС‹Р№ IP РѕР±РЅРѕРІР»РµРЅ: " + myPublicIP)
				}
			}
			if udpPuncher != nil {
				if extIP, port, err := udpPuncher.DiscoverMappedAddress(context.Background()); err == nil {
					mySTUNAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
					addLog("вњ“ STUN UDP Hole Punch СЃРѕРєРµС‚: " + mySTUNAddr)
				}
			}
			triggerPublish()
		}()

	case ID_BTN_BOOKMARK_PEER:
		handleBookmarkPeer()

	case ID_BTN_AWG_STD:
		setAWGPreset(wireguard.AWGParams{Enabled: true, Jc: 0, Jmin: 0, Jmax: 0, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4})
		setActiveAWGPresetButton(ID_BTN_AWG_STD)
		addLog("рџ›ЎпёЏ Р’С‹Р±СЂР°РЅ РїСЂРµСЃРµС‚: рџџў РЎС‚Р°РЅРґР°СЂС‚РЅС‹Р№ WireGuard")

	case ID_BTN_AWG_DPI:
		setAWGPreset(wireguard.DefaultAWGParams())
		setActiveAWGPresetButton(ID_BTN_AWG_DPI)
		addLog("рџ›ЎпёЏ Р’С‹Р±СЂР°РЅ РїСЂРµСЃРµС‚: рџџЎ РћР±С…РѕРґ DPI (AmneziaWG 2.0)")

	case ID_BTN_AWG_STEALTH:
		randP := wireguard.GenerateRandomAWGParams()
		setAWGPreset(randP)
		setActiveAWGPresetButton(ID_BTN_AWG_STEALTH)
		addLog("рџ›ЎпёЏ Р’С‹Р±СЂР°РЅ РїСЂРµСЃРµС‚: рџ”ґ РњР°РєСЃРёРјР°Р»СЊРЅР°СЏ СЃРєСЂС‹С‚РЅРѕСЃС‚СЊ")

	case ID_BTN_RAND_AWG:
		randP := wireguard.GenerateRandomAWGParams()
		setAWGPreset(randP)
		setActiveAWGPresetButton(ID_BTN_AWG_STEALTH)
		addLog("рџЋІ РЎРіРµРЅРµСЂРёСЂРѕРІР°РЅС‹ РЅРѕРІС‹Рµ СѓРЅРёРєР°Р»СЊРЅС‹Рµ СЃРёРіРЅР°С‚СѓСЂС‹ AWG")

	case ID_BTN_COPY_AWG:
		conf := getControlText(hEditAwgConf)
		copyToClipboard(conf)
		addLog("рџ“‹ РљРѕРЅС„РёРіСѓСЂР°С†РёСЏ AmneziaWG СЃРєРѕРїРёСЂРѕРІР°РЅР° РІ Р±СѓС„РµСЂ РѕР±РјРµРЅР°")
		buttonLabels[ID_BTN_COPY_AWG] = "вњ“ РЎРљРћРџРР РћР’РђРќРћ Р’ Р‘РЈР¤Р•Р  РћР‘РњР•РќРђ!"
		procInvalidateRect.Call(hBtnCopyAwg, 0, 1)
		time.AfterFunc(2*time.Second, func() {
			buttonLabels[ID_BTN_COPY_AWG] = "рџ“‹ РЎРєРѕРїРёСЂРѕРІР°С‚СЊ РєРѕРЅС„РёРі"
			procInvalidateRect.Call(hBtnCopyAwg, 0, 1)
		})

	case ID_BTN_SAVE_AWG:
		conf := getControlText(hEditAwgConf)
		confFile := "natbypass.conf"
		if err := os.WriteFile(confFile, []byte(conf), 0644); err == nil {
			addLog("рџ’ѕ РљРѕРЅС„РёРі СѓСЃРїРµС€РЅРѕ СЃРѕС…СЂР°РЅРµРЅ РІ С„Р°Р№Р»: " + confFile)
			writeDebug("РљРѕРЅС„РёРіСѓСЂР°С†РёСЏ СЃРѕС…СЂР°РЅРµРЅР° РІ " + confFile)
			buttonLabels[ID_BTN_SAVE_AWG] = "вњ“ РЎРћРҐР РђРќР•РќРћ Р’ natbypass.conf!"
			procInvalidateRect.Call(hBtnSaveAwg, 0, 1)
			_ = exec.Command("explorer.exe", "/select,"+confFile).Start()
		} else {
			addLog("вќЊ РћС€РёР±РєР° СЃРѕС…СЂР°РЅРµРЅРёСЏ РєРѕРЅС„РёРіР°: " + err.Error())
		}
		time.AfterFunc(2*time.Second, func() {
			buttonLabels[ID_BTN_SAVE_AWG] = "рџ’ѕ РЎРѕС…СЂР°РЅРёС‚СЊ РІ natbypass.conf"
			procInvalidateRect.Call(hBtnSaveAwg, 0, 1)
		})

	case ID_BTN_OPEN_AWG_CLIENT:
		amneziaPath := `C:\Program Files\AmneziaVPN\AmneziaVPN.exe`
		if _, err := os.Stat(amneziaPath); err == nil {
			_ = exec.Command(amneziaPath).Start()
			addLog("рџљЂ Р—Р°РїСѓС‰РµРЅ РєР»РёРµРЅС‚ AmneziaVPN")
		} else {
			addLog("рџ’Ў AmneziaVPN РЅРµ РЅР°Р№РґРµРЅ РїРѕ РїСѓС‚Рё РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ. РЎРєР°С‡Р°Р№С‚Рµ РµРіРѕ СЃ github.com/amnezia-vpn/amneziawg-windows-client")
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
			addLog(fmt.Sprintf("рџ”„ РќР°СЃС‚СЂРѕР№РєРё AmneziaWG 2.0 СѓСЃРїРµС€РЅРѕ РїСЂРёРјРµРЅРµРЅС‹ СЃ СѓР·Р»Р° [%s] Рё СЃРѕС…СЂР°РЅРµРЅС‹!", targetName))
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
			buttonLabels[ID_BTN_TOGGLE_LOGS] = "рџ’ѕ Р—Р°РїРёСЃСЊ Р»РѕРіРѕРІ РЅР° РґРёСЃРє: Р’РљР›"
			buttonTypes[ID_BTN_TOGGLE_LOGS] = "green"
			addLog("рџ’ѕ Р—Р°РїРёСЃСЊ РѕС‚Р»Р°РґРѕС‡РЅС‹С… Р»РѕРіРѕРІ РЅР° РґРёСЃРє Р’РљР›Р®Р§Р•РќРђ (natbypass_debug.log)")
		} else {
			buttonLabels[ID_BTN_TOGGLE_LOGS] = "рџ’ѕ Р—Р°РїРёСЃСЊ Р»РѕРіРѕРІ РЅР° РґРёСЃРє: Р’Р«РљР›"
			buttonTypes[ID_BTN_TOGGLE_LOGS] = "normal"
			addLog("рџ’ѕ Р—Р°РїРёСЃСЊ РѕС‚Р»Р°РґРѕС‡РЅС‹С… Р»РѕРіРѕРІ РЅР° РґРёСЃРє Р’Р«РљР›Р®Р§Р•РќРђ")
		}
		procInvalidateRect.Call(hBtnToggleLogs, 0, 1)
		saveConfigFromUI()

	case ID_BTN_TOGGLE_DIAG:
		showDiagnostics = !showDiagnostics
		applyDiagnosticsVisibility()
		if showDiagnostics {
			addLog("рџ©є Р’РєР»Р°РґРєР° Р”РёР°РіРЅРѕСЃС‚РёРєР° Р’РљР›Р®Р§Р•РќРђ")
		} else {
			addLog("рџ©є Р’РєР»Р°РґРєР° Р”РёР°РіРЅРѕСЃС‚РёРєР° Р’Р«РљР›Р®Р§Р•РќРђ")
		}
		saveConfigFromUI()

	case ID_BTN_SAVE_CFG:
		saveConfig()

	case ID_BTN_CHECK_UPDATE:
		addLog("рџ”Ќ РџСЂРѕРІРµСЂРєР° РѕР±РЅРѕРІР»РµРЅРёР№ РЅР° GitHub Releases...")
		go func() {
			info, err := updater.CheckUpdate(context.Background(), Version)
			if err != nil {
				addLog("вќЊ РћС€РёР±РєР° РїСЂРѕРІРµСЂРєРё РѕР±РЅРѕРІР»РµРЅРёР№: " + err.Error())
				return
			}
			if !info.HasUpdate {
				addLog(fmt.Sprintf("вњ… РЈ РІР°СЃ СѓСЃС‚Р°РЅРѕРІР»РµРЅР° СЃР°РјР°СЏ СЃРІРµР¶Р°СЏ РІРµСЂСЃРёСЏ (%s)", Version))
				return
			}
			addLog(fmt.Sprintf("рџљЂ Р”РѕСЃС‚СѓРїРЅР° РЅРѕРІР°СЏ РІРµСЂСЃРёСЏ: %s! Р—Р°РїСѓСЃРє СЃРєР°С‡РёРІР°РЅРёСЏ Рё РѕР±РЅРѕРІР»РµРЅРёСЏ...", info.LatestVersion))
			if err := updater.ApplyUpdate(context.Background(), info.AssetURL); err != nil {
				addLog("вќЊ РћС€РёР±РєР° РїСЂРёРјРµРЅРµРЅРёСЏ РѕР±РЅРѕРІР»РµРЅРёСЏ: " + err.Error())
			}
		}()

	case ID_BTN_MODE_PARALLEL:
		setSigModeUI("parallel")
		addLog("рџЋЇ Р’С‹Р±СЂР°РЅ СЂРµР¶РёРј: рџ”„ РџР°СЂР°Р»Р»РµР»СЊРЅРѕ (MQTT + Telegram)")

	case ID_BTN_MODE_MQTT:
		setSigModeUI("mqtt_only")
		addLog("рџЋЇ Р’С‹Р±СЂР°РЅ СЂРµР¶РёРј: вљЎ РўРѕР»СЊРєРѕ MQTT")

	case ID_BTN_MODE_TG:
		setSigModeUI("tg_only")
		addLog("рџЋЇ Р’С‹Р±СЂР°РЅ СЂРµР¶РёРј: рџ’¬ РўРѕР»СЊРєРѕ Telegram")

	case ID_BTN_MQ_EMQX:
		setControlText(hEditMqttBr, "tcp://broker.emqx.io:1883")
		addLog("вљЎ Р’С‹Р±СЂР°РЅ Р±СЂРѕРєРµСЂ: EMQX Public (tcp://broker.emqx.io:1883)")

	case ID_BTN_MQ_HIVE:
		setControlText(hEditMqttBr, "tcp://broker.hivemq.com:1883")
		addLog("вљЎ Р’С‹Р±СЂР°РЅ Р±СЂРѕРєРµСЂ: HiveMQ Public (tcp://broker.hivemq.com:1883)")

	case ID_BTN_MQ_MOSQ:
		setControlText(hEditMqttBr, "tcp://test.mosquitto.org:1883")
		addLog("вљЎ Р’С‹Р±СЂР°РЅ Р±СЂРѕРєРµСЂ: Mosquitto Public (tcp://test.mosquitto.org:1883)")

	case ID_BTN_MQ_ECL:
		setControlText(hEditMqttBr, "tcp://mqtt.eclipseprojects.io:1883")
		addLog("вљЎ Р’С‹Р±СЂР°РЅ Р±СЂРѕРєРµСЂ: Eclipse Foundation (tcp://mqtt.eclipseprojects.io:1883)")

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
			buttonLabels[ID_BTN_ALLOW_EXIT] = "рџЊђ Р Р°Р·СЂРµС€РёС‚СЊ РІС‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· РјРµРЅСЏ: Р’РљР›"
			buttonTypes[ID_BTN_ALLOW_EXIT] = "green"
			go func() {
				if err := tunnel.EnableHostIPForwarding(); err != nil {
					addLog("вљ пёЏ РћС€РёР±РєР° РІРєР»СЋС‡РµРЅРёСЏ IP Forwarding: " + err.Error())
					writeDebug("EnableHostIPForwarding error: " + err.Error())
				} else {
					addLog("рџЊђ IP Forwarding РІРєР»СЋС‡РµРЅ РЅР° РёРЅС‚РµСЂС„РµР№СЃРµ 'NatBypass'")
					writeDebug("EnableHostIPForwarding OK")
				}
			}()
			addLog("рџЊђ Р Р°Р·СЂРµС€РµРЅ РІС‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· СЌС‚Рѕ СѓСЃС‚СЂРѕР№СЃС‚РІРѕ (Exit Node Р°РєС‚РёРІРµРЅ)")
		} else {
			buttonLabels[ID_BTN_ALLOW_EXIT] = "рџЊђ Р Р°Р·СЂРµС€РёС‚СЊ РІС‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· РјРµРЅСЏ: Р’Р«РљР›"
			buttonTypes[ID_BTN_ALLOW_EXIT] = "normal"
			addLog("рџЊђ Р’С‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· СЌС‚Рѕ СѓСЃС‚СЂРѕР№СЃС‚РІРѕ РѕС‚РєР»СЋС‡РµРЅ")
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
			addLog("вљ пёЏ Р›РѕРєР°Р»СЊРЅС‹Рµ Р°РєС‚РёРІРЅС‹Рµ РїРѕРґСЃРµС‚Рё РЅРµ РѕР±РЅР°СЂСѓР¶РµРЅС‹")
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
			addLog("рџЏ  Р”РѕР±Р°РІР»РµРЅР° Р»РѕРєР°Р»СЊРЅР°СЏ РїРѕРґСЃРµС‚СЊ: " + strings.Join(added, ", "))
			saveConfigFromUI()
		} else {
			addLog("рџ’Ў Р’СЃРµ РѕР±РЅР°СЂСѓР¶РµРЅРЅС‹Рµ Р»РѕРєР°Р»СЊРЅС‹Рµ РїРѕРґСЃРµС‚Рё СѓР¶Рµ РґРѕР±Р°РІР»РµРЅС‹ (" + strings.Join(localSubnets, ", ") + ")")
		}
	}
}

func handleBookmarkPeer() {
	if registry == nil {
		addLog("вљ пёЏ РЎРµС‚РµРІРѕР№ СЂРµРµСЃС‚СЂ РЅРµ РёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅ")
		return
	}

	peers := registry.List()
	if len(peers) == 0 {
		addLog("вљ пёЏ РќРµС‚ РґРѕСЃС‚СѓРїРЅС‹С… РїРёСЂРѕРІ РІ СЃРµС‚Рё РґР»СЏ РґРѕР±Р°РІР»РµРЅРёСЏ РІ Р·Р°РєР»Р°РґРєРё")
		return
	}

	selIdx, _, _ := procSendMessageW.Call(hListPeers, 0x0188, 0, 0) // LB_GETCURSEL = 0x0188
	idx := int(int32(selIdx)) / 2

	if idx < 0 || idx >= len(peers) {
		if len(peers) == 1 {
			idx = 0
		} else {
			addLog("рџ’Ў Р’С‹Р±РµСЂРёС‚Рµ СѓСЃС‚СЂРѕР№СЃС‚РІРѕ РёР· СЃРїРёСЃРєР° РІС‹С€Рµ Рё РЅР°Р¶РјРёС‚Рµ 'Р—Р°РґР°С‚СЊ РёРјСЏ / Р’ Р·Р°РєР»Р°РґРєРё'")
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
		addLog(fmt.Sprintf("в­ђ РЈСЃС‚СЂРѕР№СЃС‚РІСѓ %s РїСЂРёСЃРІРѕРµРЅРѕ РёРјСЏ '%s' (СЃРѕС…СЂР°РЅРµРЅРѕ РІ Р·Р°РєР»Р°РґРєРё)", targetPeer.DeviceID, trimmed))
	} else {
		delete(addressBook, targetPeer.DeviceID)
		addLog(fmt.Sprintf("рџ—‘ Р—Р°РєР»Р°РґРєР° РґР»СЏ СѓСЃС‚СЂРѕР№СЃС‚РІР° %s СѓРґР°Р»РµРЅР°", targetPeer.DeviceID))
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
		addLog("вљ пёЏ РЎРµС‚РµРІРѕР№ СЂРµРµСЃС‚СЂ РЅРµ РёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅ")
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
			buttonLabels[ID_BTN_EXIT_NODE_SELECT] = "рџЊђ Р’С‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚: Р›РѕРєР°Р»СЊРЅС‹Р№ (РћС‚РєР»СЋС‡РµРЅ)"
			buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "normal"
			if hBtnExitNodeSelect != 0 {
				procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
			}
			addLog("рџЊђ Р’ СЃРµС‚Рё РЅРµС‚ РґРѕСЃС‚СѓРїРЅС‹С… Exit Node СѓСЃС‚СЂРѕР№СЃС‚РІ. РњР°СЂС€СЂСѓС‚ СЃР±СЂРѕС€РµРЅ РЅР° Р»РѕРєР°Р»СЊРЅС‹Р№.")
		} else {
			addLog("рџ’Ў Р’ СЃРµС‚Рё РїРѕРєР° РЅРµС‚ СѓСЃС‚СЂРѕР№СЃС‚РІ СЃ РІРєР»СЋС‡РµРЅРЅС‹Рј Exit Node. Р’РєР»СЋС‡РёС‚Рµ Exit Node РЅР° СѓРґР°Р»РµРЅРЅРѕРј СѓСЃС‚СЂРѕР№СЃС‚РІРµ.")
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
		buttonLabels[ID_BTN_EXIT_NODE_SELECT] = "рџЊђ Р’С‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚: Р›РѕРєР°Р»СЊРЅС‹Р№ (РћС‚РєР»СЋС‡РµРЅ)"
		buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "normal"
		if hBtnExitNodeSelect != 0 {
			procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
		}
		addLog("рџЊђ Р’С‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· Exit Node РѕС‚РєР»СЋС‡РµРЅ. Р’РѕСЃСЃС‚Р°РЅРѕРІР»РµРЅ СЃС‚Р°РЅРґР°СЂС‚РЅС‹Р№ РёРЅС‚РµСЂРЅРµС‚-С€Р»СЋР·.")
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

	if err := tunnel.EnableExitNodeRouting(targetVIP); err != nil {
		addLog("вќЊ РћС€РёР±РєР° РЅР°СЃС‚СЂРѕР№РєРё РјР°СЂС€СЂСѓС‚РёР·Р°С†РёРё С‡РµСЂРµР· Exit Node: " + err.Error())
		writeDebug("EnableExitNodeRouting error: " + err.Error())
	} else {
		addressBookMu.RLock()
		bm := addressBook[targetPeer.DeviceID]
		addressBookMu.RUnlock()
		peerDisplay := targetPeer.Nickname
		if bm != "" {
			peerDisplay = "в­ђ " + bm
		} else if peerDisplay == "" {
			peerDisplay = targetPeer.DeviceID
		}

		buttonLabels[ID_BTN_EXIT_NODE_SELECT] = fmt.Sprintf("рџџў РЁР»СЋР·: [%s] (%s)", peerDisplay, targetVIP)
		buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "green"
		if hBtnExitNodeSelect != 0 {
			procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
		}

		msg := fmt.Sprintf("рџЊђ Р’РµСЃСЊ РёРЅС‚РµСЂРЅРµС‚-С‚СЂР°С„РёРє РїРµСЂРµРЅР°РїСЂР°РІР»РµРЅ С‡РµСЂРµР· Exit Node: [%s] (%s)", peerDisplay, targetVIP)
		addLog(msg)
		writeDebug(msg)
	}
}

func handleToggleSubnetRoute() {
	if registry == nil {
		addLog("вљ пёЏ РЎРµС‚РµРІРѕР№ СЂРµРµСЃС‚СЂ РЅРµ РёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅ")
		return
	}

	peers := registry.List()
	if len(peers) == 0 {
		addLog("вљ пёЏ РќРµС‚ РґРѕСЃС‚СѓРїРЅС‹С… РїРёСЂРѕРІ РІ СЃРµС‚Рё")
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
				addLog(fmt.Sprintf("рџЏ  РњР°СЂС€СЂСѓС‚ Рє РїРѕРґСЃРµС‚Рё %s С‡РµСЂРµР· %s СѓРґР°Р»РµРЅ", cidr, vip))
			}
			activeSubnetRoutes = make(map[string]string)
			buttonLabels[ID_BTN_TOGGLE_SUBNET] = "рџЏ  РџРѕРґРєР»СЋС‡РёС‚СЊ РїРѕРґСЃРµС‚СЊ РїРёСЂР°"
			buttonTypes[ID_BTN_TOGGLE_SUBNET] = "normal"
			if hBtnToggleSubnetRoute != 0 {
				procInvalidateRect.Call(hBtnToggleSubnetRoute, 0, 1)
			}
			activeSubnetRoutesMu.Unlock()
			addLog("рџЏ  Р’СЃРµ РјР°СЂС€СЂСѓС‚С‹ Рє РїРѕРґСЃРµС‚СЏРј РѕС‚РєР»СЋС‡РµРЅС‹")
			return
		}
		activeSubnetRoutesMu.Unlock()
		addLog("рџ’Ў Р’ СЃРµС‚Рё РЅРµС‚ РїРёСЂРѕРІ СЃ Р°РЅРѕРЅСЃРёСЂРѕРІР°РЅРЅС‹РјРё Р»РѕРєР°Р»СЊРЅС‹РјРё РїРѕРґСЃРµС‚СЏРјРё.")
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
				addLog(fmt.Sprintf("вљ пёЏ РћС€РёР±РєР° СѓРґР°Р»РµРЅРёСЏ РјР°СЂС€СЂСѓС‚Р° Рє %s: %s", cidr, err.Error()))
			} else {
				addLog(fmt.Sprintf("рџЏ  РњР°СЂС€СЂСѓС‚ Рє РїРѕРґСЃРµС‚Рё %s С‡РµСЂРµР· %s СѓРґР°Р»РµРЅ", cidr, vip))
			}
			delete(activeSubnetRoutes, cidr)
		}
		if len(activeSubnetRoutes) == 0 {
			buttonLabels[ID_BTN_TOGGLE_SUBNET] = "рџЏ  РџРѕРґРєР»СЋС‡РёС‚СЊ РїРѕРґСЃРµС‚СЊ РїРёСЂР°"
			buttonTypes[ID_BTN_TOGGLE_SUBNET] = "normal"
		} else {
			buttonLabels[ID_BTN_TOGGLE_SUBNET] = fmt.Sprintf("рџџў РџРѕРґСЃРµС‚Рё: %d Р°РєС‚РёРІРЅС‹С…", len(activeSubnetRoutes))
			buttonTypes[ID_BTN_TOGGLE_SUBNET] = "green"
		}
		if hBtnToggleSubnetRoute != 0 {
			procInvalidateRect.Call(hBtnToggleSubnetRoute, 0, 1)
		}
	} else {
		for _, cidr := range targetPeer.AdvertisedRoutes {
			if err := tunnel.AddSubnetRoute(cidr, vip); err != nil {
				addLog(fmt.Sprintf("вќЊ РћС€РёР±РєР° РґРѕР±Р°РІР»РµРЅРёСЏ РјР°СЂС€СЂСѓС‚Р° Рє %s С‡РµСЂРµР· %s: %s", cidr, vip, err.Error()))
			} else {
				activeSubnetRoutes[cidr] = vip
				addLog(fmt.Sprintf("рџЏ  Р”РѕР±Р°РІР»РµРЅ РјР°СЂС€СЂСѓС‚ Рє РїРѕРґСЃРµС‚Рё %s С‡РµСЂРµР· %s (%s)", cidr, targetPeer.Nickname, vip))
			}
		}
		buttonLabels[ID_BTN_TOGGLE_SUBNET] = fmt.Sprintf("рџџў РџРѕРґСЃРµС‚СЊ: %s (Р’РљР›)", strings.Join(targetPeer.AdvertisedRoutes, ", "))
		buttonTypes[ID_BTN_TOGGLE_SUBNET] = "green"
		if hBtnToggleSubnetRoute != 0 {
			procInvalidateRect.Call(hBtnToggleSubnetRoute, 0, 1)
		}
	}
}

func showBookmarkDialog(peerID, currentName string) (string, bool) {
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	dlgClassName, _ := windows.UTF16PtrFromString("NatBypassBookmarkDlgClass")
	dlgTitle, _ := windows.UTF16PtrFromString("в­ђ Р—Р°РґР°С‚СЊ РёРјСЏ СѓСЃС‚СЂРѕР№СЃС‚РІСѓ (Р—Р°РєР»Р°РґРєР°)")

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

	// Р’С‹С‡РёСЃР»СЏРµРј РїРѕР·РёС†РёСЋ РїРѕ С†РµРЅС‚СЂСѓ СЂРѕРґРёС‚РµР»СЊСЃРєРѕРіРѕ РѕРєРЅР°
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

	// Р”РѕР±Р°РІР»СЏРµРј РєРѕРЅС‚СЂРѕР»С‹ РґРёР°Р»РѕРіР°
	_ = createLabelOn(hDlg, hInstance, fmt.Sprintf("РЈСЃС‚СЂРѕР№СЃС‚РІРѕ ID: %s", peerID), 20, 16, 440, 22, hFontBold)
	_ = createLabelOn(hDlg, hInstance, "РџРѕРЅСЏС‚РЅРѕРµ РёРјСЏ (РЅР°РїСЂРёРјРµСЂ: Р”РѕРјР°С€РЅРёР№ РџРљ, РќРѕСѓС‚Р±СѓРє, РЎРµСЂРІРµСЂ):", 20, 44, 440, 20, hFontNormal)
	hDlgEdit = createEditOn(hDlg, hInstance, currentName, 20, 72, 425, 30, false, false, hFontNormal)

	_ = createOwnerDrawButtonOn(hDlg, hInstance, "в­ђ РЎРѕС…СЂР°РЅРёС‚СЊ", 20, 126, 140, 38, 5001, "primary")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "рџ—‘ РћС‡РёСЃС‚РёС‚СЊ", 170, 126, 130, 38, 5002, "normal")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "РћС‚РјРµРЅР°", 310, 126, 135, 38, 5003, "normal")

	procShowWindow.Call(hDlg, SW_SHOW)
	procSetForegroundWindow.Call(hDlg)
	procSetFocus.Call(hDlgEdit)
	// Р’С‹РґРµР»СЏРµРј РІРµСЃСЊ С‚РµРєСЃС‚ РІ РїРѕР»Рµ РІРІРѕРґР°
	procSendMessageW.Call(hDlgEdit, 0x00B1, 0, uintptr(^uint32(0)))

	// Р‘Р»РѕРєРёСЂСѓРµРј РіР»Р°РІРЅРѕРµ РѕРєРЅРѕ РЅР° РІСЂРµРјСЏ РјРѕРґР°Р»СЊРЅРѕРіРѕ РґРёР°Р»РѕРіР°
	procEnableWindow.Call(hMainWnd, 0)

	var msg MSG
	for !dlgFinished {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		// РћР±СЂР°Р±РѕС‚РєР° РєР»Р°РІРёС€ Enter Рё Esc
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

	// Р Р°Р·Р±Р»РѕРєРёСЂСѓРµРј РіР»Р°РІРЅРѕРµ РѕРєРЅРѕ
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
		var dis DRAWITEMSTRUCT
		procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&dis)), lParam, unsafe.Sizeof(dis))
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
		if id == 5001 { // РЎРѕС…СЂР°РЅРёС‚СЊ
			dlgResultText = getControlText(hDlgEdit)
			dlgResultOK = true
			dlgFinished = true
			return 0
		} else if id == 5002 { // РћС‡РёСЃС‚РёС‚СЊ
			dlgResultText = ""
			dlgResultOK = true
			dlgFinished = true
			return 0
		} else if id == 5003 { // РћС‚РјРµРЅР°
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
		prefix := "вљЄ [РќРµР°РєС‚РёРІРЅР°]  "
		if p.ID == cfg.ActiveProfileID || (active != nil && p.ID == active.ID) {
			prefix = "рџџў [вњ“ РђРљРўРР’РќРђ] "
			selectedIndex = i
		}
		itemText := fmt.Sprintf("%sвЂў %s  |  РўРѕРїРёРє: %s  |  Р‘СЂРѕРєРµСЂ: %s", prefix, p.Name, p.MQTTTopic, p.MQTTBroker)
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
		addLog("вќЊ РћС€РёР±РєР° РїРµСЂРµРєР»СЋС‡РµРЅРёСЏ: " + err.Error())
		return
	}
	_ = config.Save(cfg, configPath, false)
	setControlText(hEditMqttBr, target.MQTTBroker)
	setControlText(hEditMqttTp, target.MQTTTopic)

	if registry != nil {
		registry.ClearAll()
	}
	lastPeersHash = ""
	procSendMessageW.Call(hListPeers, 0x0184 /* LB_RESETCONTENT */, 0, 0)

	if vpnConnected && engineCtx != nil {
		go func() {
			tgToken := strings.TrimSpace(getControlText(hEditTgToken))
			tgChat := strings.TrimSpace(getControlText(hEditTgChat))
			rebuildSignalingInternal(engineCtx, chosenModeStr, tgToken, tgChat, target.MQTTBroker, target.MQTTTopic)
		}()
	}

	refreshProfilesUI()
	addLog(fmt.Sprintf("рџџў РђРєС‚РёРІРЅС‹Р№ РїСЂРѕС„РёР»СЊ РїРµСЂРµРєР»СЋС‡РµРЅ РЅР° В«%sВ» (РўРѕРїРёРє: %s)", target.Name, target.MQTTTopic))
}

func handleProfileCreate() {
	if cfg == nil {
		return
	}
	newProf := config.Profile{
		ID:         "p-" + config.GenerateRandomHex(4),
		Name:       fmt.Sprintf("РЎРµС‚СЊ #%d", len(cfg.Profiles)+1),
		NetworkKey: config.GenerateRandomHex(16),
		MQTTBroker: "tcp://broker.emqx.io:1883",
		MQTTTopic:  "natbypass/mesh/" + config.GenerateRandomHex(8),
		AWGPreset:  "dpi",
		IsActive:   true,
		CreatedAt:  time.Now(),
	}
	saved := cfg.AddOrUpdateProfile(newProf)
	_ = config.Save(cfg, configPath, false)

	if registry != nil {
		registry.ClearAll()
	}
	lastPeersHash = ""
	procSendMessageW.Call(hListPeers, 0x0184 /* LB_RESETCONTENT */, 0, 0)

	if vpnConnected && engineCtx != nil {
		go func() {
			tgToken := strings.TrimSpace(getControlText(hEditTgToken))
			tgChat := strings.TrimSpace(getControlText(hEditTgChat))
			rebuildSignalingInternal(engineCtx, chosenModeStr, tgToken, tgChat, saved.MQTTBroker, saved.MQTTTopic)
		}()
	}

	refreshProfilesUI()
	addLog(fmt.Sprintf("вњ… РЎРѕР·РґР°РЅ Рё РїРѕРґРєР»СЋС‡РµРЅ РЅРѕРІС‹Р№ РїСЂРѕС„РёР»СЊ СЃРµС‚Рё В«%sВ»", saved.Name))
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

	if name != "" {
		p.Name = name
	}
	if topic != "" {
		p.MQTTTopic = topic
	}
	if broker != "" {
		p.MQTTBroker = broker
	}

	_ = config.Save(cfg, configPath, false)

	if p.ID == cfg.ActiveProfileID {
		setControlText(hEditMqttBr, p.MQTTBroker)
		setControlText(hEditMqttTp, p.MQTTTopic)
		if registry != nil {
			registry.ClearAll()
		}
		lastPeersHash = ""
		procSendMessageW.Call(hListPeers, 0x0184 /* LB_RESETCONTENT */, 0, 0)
		if vpnConnected && engineCtx != nil {
			go func() {
				tgToken := strings.TrimSpace(getControlText(hEditTgToken))
				tgChat := strings.TrimSpace(getControlText(hEditTgChat))
				rebuildSignalingInternal(engineCtx, chosenModeStr, tgToken, tgChat, p.MQTTBroker, p.MQTTTopic)
			}()
		}
	}

	refreshProfilesUI()
	addLog(fmt.Sprintf("рџ’ѕ РќР°СЃС‚СЂРѕР№РєРё РїСЂРѕС„РёР»СЏ В«%sВ» СЃРѕС…СЂР°РЅРµРЅС‹", p.Name))
}

func handleProfileDelete() {
	if cfg == nil || len(cfg.Profiles) <= 1 {
		procMessageBoxW.Call(hMainWnd,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("РќРµР»СЊР·СЏ СѓРґР°Р»РёС‚СЊ РµРґРёРЅСЃС‚РІРµРЅРЅС‹Р№ РїСЂРѕС„РёР»СЊ СЃРµС‚Рё."))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("РЈРґР°Р»РµРЅРёРµ РїСЂРѕС„РёР»СЏ"))),
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
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(fmt.Sprintf("РЈРґР°Р»РёС‚СЊ РїСЂРѕС„РёР»СЊ В«%sВ»? РЎРІСЏР·СЊ СЃ СѓС‡Р°СЃС‚РЅРёРєР°РјРё СЌС‚РѕР№ СЃРµС‚Рё Р±СѓРґРµС‚ СЂР°Р·РѕСЂРІР°РЅР°.", p.Name)))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("РџРѕРґС‚РІРµСЂР¶РґРµРЅРёРµ СѓРґР°Р»РµРЅРёСЏ"))),
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
			setControlText(hEditMqttBr, active.MQTTBroker)
			setControlText(hEditMqttTp, active.MQTTTopic)
			if registry != nil {
				registry.ClearAll()
			}
			lastPeersHash = ""
			procSendMessageW.Call(hListPeers, 0x0184 /* LB_RESETCONTENT */, 0, 0)
			if vpnConnected && engineCtx != nil {
				go func() {
					tgToken := strings.TrimSpace(getControlText(hEditTgToken))
					tgChat := strings.TrimSpace(getControlText(hEditTgChat))
					rebuildSignalingInternal(engineCtx, chosenModeStr, tgToken, tgChat, active.MQTTBroker, active.MQTTTopic)
				}()
			}
		}
	}

	refreshProfilesUI()
	addLog(fmt.Sprintf("рџ—‘пёЏ РџСЂРѕС„РёР»СЊ В«%sВ» СѓСЃРїРµС€РЅРѕ СѓРґР°Р»РµРЅ", p.Name))
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
	addLog(fmt.Sprintf("вњ“ РЎСЃС‹Р»РєР° РЅР° СЃРµС‚СЊ В«%sВ» СЃРєРѕРїРёСЂРѕРІР°РЅР° РІ Р±СѓС„РµСЂ РѕР±РјРµРЅР°: %s", p.Name, uri))
	buttonLabels[ID_BTN_PROF_EXPORT] = "вњ“ РЎРљРћРџРР РћР’РђРќРћ!"
	procInvalidateRect.Call(hBtnProfExport, 0, 1)
	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_PROF_EXPORT] = "рџ”— РЎРєРѕРїРёСЂРѕРІР°С‚СЊ СЃСЃС‹Р»РєСѓ"
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
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("РќРµРєРѕСЂСЂРµРєС‚РЅР°СЏ СЃСЃС‹Р»РєР° РїСЂРѕС„РёР»СЏ: "+err.Error()))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("РћС€РёР±РєР° РёРјРїРѕСЂС‚Р°"))),
			0x00000010 /* MB_ICONERROR */)
		return
	}

	if cfg == nil {
		cfg = &config.Config{}
	}
	parsed.IsActive = true
	saved := cfg.AddOrUpdateProfile(*parsed)
	_ = config.Save(cfg, configPath, false)

	if registry != nil {
		registry.ClearAll()
	}
	lastPeersHash = ""
	procSendMessageW.Call(hListPeers, 0x0184 /* LB_RESETCONTENT */, 0, 0)

	if vpnConnected && engineCtx != nil {
		go func() {
			tgToken := strings.TrimSpace(getControlText(hEditTgToken))
			tgChat := strings.TrimSpace(getControlText(hEditTgChat))
			rebuildSignalingInternal(engineCtx, chosenModeStr, tgToken, tgChat, saved.MQTTBroker, saved.MQTTTopic)
		}()
	}

	refreshProfilesUI()
	addLog(fmt.Sprintf("рџ“Ґ РЈСЃРїРµС€РЅРѕ РёРјРїРѕСЂС‚РёСЂРѕРІР°РЅ Рё Р°РєС‚РёРІРёСЂРѕРІР°РЅ РїСЂРѕС„РёР»СЊ В«%sВ» (РўРѕРїРёРє: %s)", saved.Name, saved.MQTTTopic))
}

func showProfileImportDialog() (string, bool) {
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	dlgClassName, _ := windows.UTF16PtrFromString("NatBypassImportDlgClass")
	dlgTitle, _ := windows.UTF16PtrFromString("РРјРїРѕСЂС‚ РїСЂРѕС„РёР»СЏ P2P СЃРµС‚Рё")

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

	_ = createLabelOn(hDlg, hInstance, "рџ“Ґ РРјРїРѕСЂС‚ P2P СЃРµС‚Рё NatBypass", 20, 16, 480, 22, hFontBold)
	_ = createLabelOn(hDlg, hInstance, "Р’СЃС‚Р°РІСЊС‚Рµ СЃСЃС‹Р»РєСѓ natbypass://profile?... РїРѕР»СѓС‡РµРЅРЅСѓСЋ СЃ РґСЂСѓРіРѕРіРѕ СѓСЃС‚СЂРѕР№СЃС‚РІР°:", 20, 44, 480, 20, hFontNormal)
	hDlgEdit = createEditOn(hDlg, hInstance, "", 20, 72, 465, 30, false, false, hFontNormal)

	_ = createOwnerDrawButtonOn(hDlg, hInstance, "рџ“Ґ РРјРїРѕСЂС‚РёСЂРѕРІР°С‚СЊ", 20, 126, 160, 38, 5001, "primary")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "рџ—‘ РћС‡РёСЃС‚РёС‚СЊ", 190, 126, 130, 38, 5002, "normal")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "РћС‚РјРµРЅР°", 330, 126, 155, 38, 5003, "normal")

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
	showQRCodeModal("QR-РєРѕРґ СЃРµС‚Рё: "+target.Name, uri)
}

func showQRCodeModal(title, qrText string) {
	qr, err := qrcode.New(qrText, qrcode.Medium)
	if err != nil {
		copyToClipboard(qrText)
		procMessageBoxW.Call(hMainWnd,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("РЎСЃС‹Р»РєР° СЃРєРѕРїРёСЂРѕРІР°РЅР° РІ Р±СѓС„РµСЂ РѕР±РјРµРЅР°:\n"+qrText))),
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
	_ = createLabelOn(hDlg, hInstance, "РћС‚СЃРєР°РЅРёСЂСѓР№С‚Рµ РєР°РјРµСЂРѕР№ РІ РїСЂРёР»РѕР¶РµРЅРёРё NatBypass РЅР° С‚РµР»РµС„РѕРЅРµ:", 20, 42, 360, 18, hFontNormal)

	_ = createOwnerDrawButtonOn(hDlg, hInstance, "рџ“‹ РЎРєРѕРїРёСЂРѕРІР°С‚СЊ СЃСЃС‹Р»РєСѓ", 30, 390, 190, 36, 5001, "primary")
	_ = createOwnerDrawButtonOn(hDlg, hInstance, "Р—Р°РєСЂС‹С‚СЊ", 230, 390, 135, 36, 5002, "normal")

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

		// Р‘РµР»Р°СЏ РєР°СЂС‚РѕС‡РєР° РїРѕРґ QR-РєРѕРґ
		qrCardRc := RECT{Left: 55, Top: 70, Right: 345, Bottom: 360}
		hBrushWhite, _, _ := procCreateSolidBrush.Call(0x00FFFFFF)
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&qrCardRc)), hBrushWhite)

		// РћС‚СЂРёСЃРѕРІРєР° QR РјР°С‚СЂРёС†С‹
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
		var dis DRAWITEMSTRUCT
		procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&dis)), lParam, unsafe.Sizeof(dis))
		drawCustomButton(&dis)
		return 1

	case WM_CTLCOLORSTATIC:
		hdc := wParam
		procSetBkMode.Call(hdc, 1)
		procSetTextColor.Call(hdc, COLOR_TEXT)
		return hBrushBg

	case WM_COMMAND:
		id := LOWORD(wParam)
		if id == 5001 { // РЎРєРѕРїРёСЂРѕРІР°С‚СЊ
			copyToClipboard(activeQRText)
			dlgFinished = true
			return 0
		} else if id == 5002 { // Р—Р°РєСЂС‹С‚СЊ
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

func applyDiagnosticsVisibility() {
	if showDiagnostics {
		procShowWindow.Call(navButtons[4], uintptr(SW_SHOW))
		buttonLabels[ID_BTN_TOGGLE_DIAG] = "рџ©є Р’РєР»Р°РґРєР° Р”РёР°РіРЅРѕСЃС‚РёРєР°: Р’РљР›"
		buttonTypes[ID_BTN_TOGGLE_DIAG] = "green"
	} else {
		procShowWindow.Call(navButtons[4], uintptr(SW_HIDE))
		buttonLabels[ID_BTN_TOGGLE_DIAG] = "рџ©є Р’РєР»Р°РґРєР° Р”РёР°РіРЅРѕСЃС‚РёРєР°: Р’Р«РљР›"
		buttonTypes[ID_BTN_TOGGLE_DIAG] = "normal"
		if currentTab == 4 {
			selectTab(0)
		}
	}
	if hBtnToggleDiag != 0 {
		procInvalidateRect.Call(hBtnToggleDiag, 0, 1)
	}
	if navButtons[4] != 0 {
		procInvalidateRect.Call(navButtons[4], 0, 1)
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
	lblLogo := createLabel(hInstance, "рџ›ё NatBypass", 20, 24, 180, 30, hFontTitle)
	lblVer := createLabel(hInstance, "Desktop Client вЂў P2P Mesh", 20, 56, 180, 20, hFontNormal)

	navTitles := []string{
		"рџљЂ  РћР±Р·РѕСЂ Рё РЎРµС‚СЊ",
		"рџЊђ  РЎРµС‚Рё & РџСЂРѕС„РёР»Рё",
		"рџ›ЎпёЏ  AmneziaWG 2.0",
		"вљ™пёЏ  РќР°СЃС‚СЂРѕР№РєРё",
		"рџ©є  Р”РёР°РіРЅРѕСЃС‚РёРєР°",
		"рџ“‹  Р–СѓСЂРЅР°Р» СЃРѕР±С‹С‚РёР№",
	}
	navIDs := []uint32{ID_NAV_DASHBOARD, ID_NAV_PROFILES, ID_NAV_AWG, ID_NAV_SETTINGS, ID_NAV_DIAG, ID_NAV_LOGS}

	for i, t := range navTitles {
		navButtons[i] = createOwnerDrawButton(hInstance, t, 16, 96+(i*44), 188, 36, navIDs[i], "nav")
	}
	if !showDiagnostics {
		procShowWindow.Call(navButtons[4], uintptr(SW_HIDE))
	}

	allControls = append(allControls, lblLogo, lblVer)

	cx := 244
	cw := 790

	// РЎРўР РђРќРР¦Рђ 0: РћР‘Р—РћР 
	hLblStatus = createLabel(hInstance, "рџџЎ РџРћРРЎРљ РЈРЎРўР РћР™РЎРўР’ Р’ РЎР•РўР...", cx, 20, cw, 26, hFontTitle)
	hLblIpInfo = createLabel(hInstance, "РЈСЃС‚СЂРѕР№СЃС‚РІРѕ: РћРїСЂРµРґРµР»РµРЅРёРµ... | Р’РЅРµС€РЅРёР№ IP: вЂ” | STUN: вЂ”", cx, 48, cw, 20, hFontNormal)
	hLblChannels = createLabel(hInstance, "рџ“Ў РЎРёРіРЅР°Р»СЊРЅС‹Р№ РєР°РЅР°Р»: РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ...", cx, 70, cw, 20, hFontNormal)

	hBtnVpn = createOwnerDrawButton(hInstance, "рџ”ґ РћР–РР”РђРќРР• РЎР’РЇР—Р (РџРѕРёСЃРє СѓСЃС‚СЂРѕР№СЃС‚РІ РІ СЃРµС‚Рё...)", cx, 96, 330, 38, ID_BTN_VPN, "red")
	hBtnRefresh = createOwnerDrawButton(hInstance, "вљЎ РћР±РЅРѕРІРёС‚СЊ IP", cx+340, 96, 130, 38, ID_BTN_REFRESH, "normal")
	hBtnManageProfiles = createOwnerDrawButton(hInstance, "рџЊђ РџСЂРѕС„РёР»Рё СЃРµС‚Рё...", cx+478, 96, 150, 38, ID_BTN_MANAGE_PROFILES, "normal")
	hBtnBookmarkPeer = createOwnerDrawButton(hInstance, "в­ђ Р’ Р·Р°РєР»Р°РґРєРё", cx+636, 96, 154, 38, ID_BTN_BOOKMARK_PEER, "normal")

	hBtnExitNodeSelect = createOwnerDrawButton(hInstance, "рџЊђ Р’С‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚: Р›РѕРєР°Р»СЊРЅС‹Р№ (РћС‚РєР»СЋС‡РµРЅ)", cx, 140, 385, 40, ID_BTN_EXIT_NODE_SELECT, "normal")
	hBtnToggleSubnetRoute = createOwnerDrawButton(hInstance, "рџЏ  РџРѕРґРєР»СЋС‡РёС‚СЊ РїРѕРґСЃРµС‚СЊ РїРёСЂР°", cx+395, 140, 395, 40, ID_BTN_TOGGLE_SUBNET, "normal")

	lblPeersTitle := createLabel(hInstance, "рџ‘Ґ РЈСЃС‚СЂРѕР№СЃС‚РІР° РІ РІР°С€РµР№ СЃРµС‚Рё (РџСЂСЏРјРѕР№ P2P СЃС‚Р°С‚СѓСЃ Рё Р°РґСЂРµСЃРЅР°СЏ РєРЅРёРіР°):", cx, 188, cw, 22, hFontHeader)
	hListPeers = createListBox(hInstance, cx, 214, cw, 460, hFontNormal)

	tabPages[0] = []uintptr{hLblStatus, hLblIpInfo, hLblChannels, hBtnVpn, hBtnRefresh, hBtnManageProfiles, hBtnBookmarkPeer, hBtnExitNodeSelect, hBtnToggleSubnetRoute, lblPeersTitle, hListPeers}
	writeDebug("buildModernUI: СЃС‚СЂР°РЅРёС†Р° 0 СЃРѕР·РґР°РЅР°")

	// РЎРўР РђРќРР¦Рђ 1: РЈРџР РђР’Р›Р•РќРР• РџР РћР¤РР›РЇРњР P2P РЎР•РўР•Р™
	lblProfTitle := createLabel(hInstance, "рџЊђ РЈРїСЂР°РІР»РµРЅРёРµ РїСЂРѕС„РёР»СЏРјРё P2P СЃРµС‚РµР№ (Mesh Profiles)", cx, 20, cw, 28, hFontTitle)
	lblProfDesc := createLabel(hInstance, "РљР°Р¶РґС‹Р№ РїСЂРѕС„РёР»СЊ вЂ” СЌС‚Рѕ РѕС‚РґРµР»СЊРЅР°СЏ РёР·РѕР»РёСЂРѕРІР°РЅРЅР°СЏ СЃРµС‚СЊ. Р’С‹Р±РёСЂР°Р№С‚Рµ СЃРµС‚СЊ РёР»Рё СЃРѕР·РґР°РІР°Р№С‚Рµ РЅРѕРІС‹Рµ.", cx, 48, cw, 20, hFontNormal)

	hListProfiles = createListBox(hInstance, cx, 74, cw, 220, hFontNormal)

	hBtnProfSwitch = createOwnerDrawButton(hInstance, "вљЎ РџРѕРґРєР»СЋС‡РёС‚СЊ СЃРµС‚СЊ", cx, 304, 185, 36, ID_BTN_PROF_SWITCH, "green")
	hBtnProfQR = createOwnerDrawButton(hInstance, "рџ“± QR-РєРѕРґ", cx+195, 304, 150, 36, ID_BTN_PROF_QR, "primary")
	hBtnProfCreate = createOwnerDrawButton(hInstance, "вћ• РќРѕРІР°СЏ СЃРµС‚СЊ", cx+355, 304, 180, 36, ID_BTN_PROF_CREATE, "normal")
	hBtnProfImport = createOwnerDrawButton(hInstance, "рџ“Ґ РРјРїРѕСЂС‚", cx+545, 304, 245, 36, ID_BTN_PROF_IMPORT, "normal")

	lblProfEditHead := createLabel(hInstance, "вљ™пёЏ РџР°СЂР°РјРµС‚СЂС‹ РІС‹Р±СЂР°РЅРЅРѕР№ СЃРµС‚Рё (Р РµРґР°РєС‚РёСЂРѕРІР°РЅРёРµ):", cx, 350, cw, 22, hFontHeader)

	lblProfName := createLabel(hInstance, "РќР°Р·РІР°РЅРёРµ СЃРµС‚Рё:", cx, 380, 160, 20, hFontBold)
	hEditProfName = createEdit(hInstance, "", cx+170, 376, 340, 28, false, false, hFontNormal)

	hBtnProfExport = createOwnerDrawButton(hInstance, "рџ”— РЎРєРѕРїРёСЂРѕРІР°С‚СЊ СЃСЃС‹Р»РєСѓ", cx+520, 376, 270, 28, ID_BTN_PROF_EXPORT, "normal")

	lblProfTopic := createLabel(hInstance, "MQTT РўРѕРїРёРє (СЃРµРєСЂРµС‚):", cx, 416, 160, 20, hFontBold)
	hEditProfTopic = createEdit(hInstance, "", cx+170, 412, 620, 28, false, false, hFontNormal)

	lblProfBroker := createLabel(hInstance, "MQTT Р‘СЂРѕРєРµСЂ:", cx, 452, 160, 20, hFontBold)
	hEditProfBroker = createEdit(hInstance, "", cx+170, 448, 620, 28, false, false, hFontNormal)

	hBtnProfSave = createOwnerDrawButton(hInstance, "рџ’ѕ РЎРѕС…СЂР°РЅРёС‚СЊ РёР·РјРµРЅРµРЅРёСЏ РїСЂРѕС„РёР»СЏ", cx+170, 492, 340, 38, ID_BTN_PROF_SAVE, "primary")
	hBtnProfDelete = createOwnerDrawButton(hInstance, "рџ—‘пёЏ РЈРґР°Р»РёС‚СЊ СЌС‚Сѓ СЃРµС‚СЊ", cx+520, 492, 270, 38, ID_BTN_PROF_DELETE, "red")

	tabPages[1] = []uintptr{
		lblProfTitle, lblProfDesc, hListProfiles,
		hBtnProfSwitch, hBtnProfQR, hBtnProfCreate, hBtnProfImport,
		lblProfEditHead, lblProfName, hEditProfName, hBtnProfExport,
		lblProfTopic, hEditProfTopic, lblProfBroker, hEditProfBroker,
		hBtnProfSave, hBtnProfDelete,
	}
	writeDebug("buildModernUI: СЃС‚СЂР°РЅРёС†Р° 1 СЃРѕР·РґР°РЅР°")

	// РЎРўР РђРќРР¦Рђ 2: AMNEZIAWG 2.0
	lblAwgTitle := createLabel(hInstance, "рџ›ЎпёЏ AmneziaWG 2.0 вЂ” Р—Р°С‰РёС‚Р° РѕС‚ Р±Р»РѕРєРёСЂРѕРІРѕРє DPI", cx, 20, cw, 28, hFontTitle)
	lblAwgDesc := createLabel(hInstance, "РњР°СЃРєРёСЂСѓРµС‚ РїСЂРѕС‚РѕРєРѕР» WireGuard РјСѓСЃРѕСЂРЅС‹РјРё РїР°РєРµС‚Р°РјРё Рё Р·Р°РіРѕР»РѕРІРєР°РјРё (РўРЎРџРЈ / Р РљРќ).", cx, 48, cw, 20, hFontNormal)

	hBtnAwgStd = createOwnerDrawButton(hInstance, "рџџў РЎС‚Р°РЅРґР°СЂС‚РЅС‹Р№ WG", cx, 78, 190, 36, ID_BTN_AWG_STD, "normal")
	hBtnAwgDpi = createOwnerDrawButton(hInstance, "рџџЎ РћР±С…РѕРґ DPI (AWG)", cx+200, 78, 190, 36, ID_BTN_AWG_DPI, "primary")
	hBtnAwgStealth = createOwnerDrawButton(hInstance, "рџ”ґ РЎРєСЂС‹С‚РЅС‹Р№ СЂРµР¶РёРј", cx+400, 78, 190, 36, ID_BTN_AWG_STEALTH, "normal")
	hBtnRandomAwg = createOwnerDrawButton(hInstance, "рџЋІ РЎР»СѓС‡Р°Р№РЅС‹Рµ РєР»СЋС‡Рё", cx+600, 78, 190, 36, ID_BTN_RAND_AWG, "normal")

	lblJc := createLabel(hInstance, "Jc (РјСѓСЃРѕСЂ):", cx, 128, 75, 20, hFontNormal)
	hEditAwgJc = createEdit(hInstance, "4", cx+80, 124, 55, 28, false, false, hFontNormal)

	lblJmin := createLabel(hInstance, "Jmin:", cx+150, 128, 45, 20, hFontNormal)
	hEditAwgJmin = createEdit(hInstance, "40", cx+198, 124, 55, 28, false, false, hFontNormal)

	lblJmax := createLabel(hInstance, "Jmax:", cx+268, 128, 45, 20, hFontNormal)
	hEditAwgJmax = createEdit(hInstance, "70", cx+318, 124, 55, 28, false, false, hFontNormal)

	lblS1 := createLabel(hInstance, "S1:", cx+388, 128, 30, 20, hFontNormal)
	hEditAwgS1 = createEdit(hInstance, "48", cx+422, 124, 55, 28, false, false, hFontNormal)

	lblS2 := createLabel(hInstance, "S2:", cx+492, 128, 30, 20, hFontNormal)
	hEditAwgS2 = createEdit(hInstance, "32", cx+526, 124, 55, 28, false, false, hFontNormal)

	lblH1 := createLabel(hInstance, "H1 (Init):", cx, 166, 65, 20, hFontNormal)
	hEditAwgH1 = createEdit(hInstance, "1428571428", cx+70, 162, 110, 28, false, false, hFontNormal)

	lblH2 := createLabel(hInstance, "H2 (Resp):", cx+195, 166, 75, 20, hFontNormal)
	hEditAwgH2 = createEdit(hInstance, "2147483647", cx+275, 162, 110, 28, false, false, hFontNormal)

	lblH3 := createLabel(hInstance, "H3 (Cookie):", cx+400, 166, 85, 20, hFontNormal)
	hEditAwgH3 = createEdit(hInstance, "857142857", cx+490, 162, 110, 28, false, false, hFontNormal)

	lblH4 := createLabel(hInstance, "H4 (Data):", cx+615, 166, 70, 20, hFontNormal)
	hEditAwgH4 = createEdit(hInstance, "1122334455", cx+690, 162, 100, 28, false, false, hFontNormal)

	lblConfTitle := createLabel(hInstance, "рџ“„ Р“РѕС‚РѕРІС‹Р№ РєРѕРЅС„РёРі AmneziaWG (РЎРєРѕРїРёСЂСѓР№С‚Рµ РІ Amnezia VPN РёР»Рё РЅР° СЂРѕСѓС‚РµСЂ):", cx, 200, cw, 22, hFontHeader)
	hEditAwgConf = createEdit(hInstance, "", cx, 226, cw, 390, true, true, hFontMono)

	hBtnCopyAwg = createOwnerDrawButton(hInstance, "рџ“‹ РЎРєРѕРїРёСЂРѕРІР°С‚СЊ РєРѕРЅС„РёРі", cx, 626, 240, 40, ID_BTN_COPY_AWG, "primary")
	hBtnSaveAwg = createOwnerDrawButton(hInstance, "рџ’ѕ РЎРѕС…СЂР°РЅРёС‚СЊ РІ natbypass.conf", cx+250, 626, 270, 40, ID_BTN_SAVE_AWG, "normal")
	hBtnOpenAwgClient = createOwnerDrawButton(hInstance, "рџљЂ РћС‚РєСЂС‹С‚СЊ Amnezia", cx+530, 626, 260, 40, ID_BTN_OPEN_AWG_CLIENT, "normal")

	tabPages[2] = []uintptr{
		lblAwgTitle, lblAwgDesc, hBtnAwgStd, hBtnAwgDpi, hBtnAwgStealth, hBtnRandomAwg,
		lblJc, hEditAwgJc, lblJmin, hEditAwgJmin, lblJmax, hEditAwgJmax, lblS1, hEditAwgS1, lblS2, hEditAwgS2,
		lblH1, hEditAwgH1, lblH2, hEditAwgH2, lblH3, hEditAwgH3, lblH4, hEditAwgH4,
		lblConfTitle, hEditAwgConf, hBtnCopyAwg, hBtnSaveAwg, hBtnOpenAwgClient,
	}
	writeDebug("buildModernUI: СЃС‚СЂР°РЅРёС†Р° 2 СЃРѕР·РґР°РЅР°")

	// РЎРўР РђРќРР¦Рђ 3: РќРђРЎРўР РћР™РљР
	lblSetTitle := createLabel(hInstance, "вљ™пёЏ РЎРёРіРЅР°Р»СЊРЅС‹Рµ РєР°РЅР°Р»С‹ & РќР°СЃС‚СЂРѕР№РєРё РїСЂРёР»РѕР¶РµРЅРёСЏ", cx, 20, cw, 28, hFontTitle)

	lblNick := createLabel(hInstance, "рџЏ·пёЏ Р’Р°С€Рµ РёРјСЏ / РќРёРєРЅРµР№Рј:", cx, 52, 200, 20, hFontBold)
	hEditMyNick = createEdit(hInstance, myNick, cx+210, 48, 400, 28, false, false, hFontNormal)
	lblNickHint := createLabel(hInstance, "рџ’Ў РРјСЏ, РєРѕС‚РѕСЂРѕРµ СѓРІРёРґСЏС‚ РґСЂСѓРіРёРµ СѓС‡Р°СЃС‚РЅРёРєРё СЃРµС‚Рё (РЅР°РїСЂРёРјРµСЂ: Р”РѕРјР°С€РЅРёР№ РџРљ, РќРѕСѓС‚Р±СѓРє)", cx+210, 78, 570, 18, hFontNormal)

	lblMode := createLabel(hInstance, "рџЋЇ Р РµР¶РёРј СЂР°Р±РѕС‚С‹ РєР°РЅР°Р»РѕРІ:", cx, 100, 200, 20, hFontBold)
	hBtnModeParallel = createOwnerDrawButton(hInstance, "рџ”„ РџР°СЂР°Р»Р»РµР»СЊРЅРѕ (MQTT+TG)", cx+210, 96, 255, 32, ID_BTN_MODE_PARALLEL, "primary")
	hBtnModeMQTT = createOwnerDrawButton(hInstance, "вљЎ РўРѕР»СЊРєРѕ MQTT", cx+475, 96, 150, 32, ID_BTN_MODE_MQTT, "normal")
	hBtnModeTG = createOwnerDrawButton(hInstance, "рџ’¬ РўРѕР»СЊРєРѕ Telegram", cx+635, 96, 155, 32, ID_BTN_MODE_TG, "normal")

	lblMqHead := createLabel(hInstance, "вљЎ MQTT Р‘СЂРѕРєРµСЂ:", cx, 134, cw, 22, hFontHeader)
	lblMqBr := createLabel(hInstance, "URL Р‘СЂРѕРєРµСЂР°:", cx, 158, 200, 20, hFontNormal)
	hEditMqttBr = createEdit(hInstance, "tcp://broker.emqx.io:1883", cx+210, 154, 400, 28, false, false, hFontNormal)
	hBtnTestMqtt = createOwnerDrawButton(hInstance, "рџ§Є РџСЂРѕРІРµСЂРёС‚СЊ MQTT", cx+620, 152, 170, 32, ID_BTN_TEST_MQTT, "normal")

	lblMqPresets := createLabel(hInstance, "РџСЂРµСЃРµС‚С‹:", cx+210, 186, 65, 18, hFontNormal)
	hBtnMqEMQX := createOwnerDrawButton(hInstance, "вљЎ EMQX", cx+280, 184, 85, 22, ID_BTN_MQ_EMQX, "normal")
	hBtnMqHive := createOwnerDrawButton(hInstance, "вљЎ HiveMQ", cx+370, 184, 95, 22, ID_BTN_MQ_HIVE, "normal")
	hBtnMqMosq := createOwnerDrawButton(hInstance, "вљЎ Mosquitto", cx+470, 184, 110, 22, ID_BTN_MQ_MOSQ, "normal")
	hBtnMqEcl := createOwnerDrawButton(hInstance, "вљЎ Eclipse", cx+585, 184, 90, 22, ID_BTN_MQ_ECL, "normal")

	lblMqTp := createLabel(hInstance, "РЈРЅРёРєР°Р»СЊРЅС‹Р№ С‚РѕРїРёРє:", cx, 212, 200, 20, hFontNormal)
	hEditMqttTp = createEdit(hInstance, "natbypass/mynet/peers", cx+210, 208, 400, 28, false, false, hFontNormal)
	lblMqTopicHint := createLabel(hInstance, "рџ”’ Р—Р°РґР°Р№С‚Рµ СѓРЅРёРєР°Р»СЊРЅС‹Р№ СЃРµРєСЂРµС‚РЅС‹Р№ С‚РѕРїРёРє (РєР»СЋС‡ РІР°С€РµР№ СЃРµС‚Рё), РЅР°РїСЂРёРјРµСЂ: mynet/supersecret/2029", cx+210, 238, 570, 18, hFontNormal)

	lblTgHead := createLabel(hInstance, "рџ’¬ Telegram Bot API:", cx, 260, cw, 22, hFontHeader)
	lblTgToken := createLabel(hInstance, "РўРѕРєРµРЅ Р±РѕС‚Р° (@BotFather):", cx, 284, 200, 20, hFontNormal)
	hEditTgToken = createEdit(hInstance, "", cx+210, 280, 400, 28, false, false, hFontNormal)
	hBtnTestTg = createOwnerDrawButton(hInstance, "рџ§Є РџСЂРѕРІРµСЂРёС‚СЊ Р±РѕС‚", cx+620, 278, 170, 32, ID_BTN_TEST_TG, "normal")

	lblTgChat := createLabel(hInstance, "Chat ID (Р›РЎ РёР»Рё Р“СЂСѓРїРїР°):", cx, 314, 200, 20, hFontNormal)
	hEditTgChat = createEdit(hInstance, "", cx+210, 310, 400, 28, false, false, hFontNormal)
	lblTgHint := createLabel(hInstance, "рџ’Ў РќР°СЃС‚СЂРѕР№РєР°: 1) РЎРѕР·РґР°Р№С‚Рµ Р±РѕС‚Р° РІ @BotFather  2) РЈР·РЅР°Р№С‚Рµ Chat ID С‡РµСЂРµР· @userinfobot  3) Р”РѕР±Р°РІСЊС‚Рµ Р±РѕС‚РѕРІ РІСЃРµС… РџРљ РІ РѕРґРЅСѓ РіСЂСѓРїРїСѓ!", cx, 340, cw, 18, hFontNormal)

	lblExitHead := createLabel(hInstance, "рџЊђ РњР°СЂС€СЂСѓС‚РёР·Р°С†РёСЏ & РЁР»СЋР· (Exit Node & Р›РѕРєР°Р»СЊРЅС‹Рµ РїРѕРґСЃРµС‚Рё):", cx, 366, cw, 22, hFontHeader)
	exitText := "рџЊђ Р Р°Р·СЂРµС€РёС‚СЊ РІС‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· РјРµРЅСЏ: Р’Р«РљР›"
	exitType := "normal"
	if allowExitNode {
		exitText = "рџЊђ Р Р°Р·СЂРµС€РёС‚СЊ РІС‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· РјРµРЅСЏ: Р’РљР›"
		exitType = "green"
	}
	hBtnAllowExit = createOwnerDrawButton(hInstance, exitText, cx, 390, 385, 34, ID_BTN_ALLOW_EXIT, exitType)

	localSubnets := network.GetLocalSubnets()
	addSubnetBtnText := "вћ• Р”РѕР±Р°РІРёС‚СЊ РјРѕСЋ СЃРµС‚СЊ"
	if len(localSubnets) > 0 {
		addSubnetBtnText = fmt.Sprintf("вћ• Р”РѕР±Р°РІРёС‚СЊ РјРѕСЋ СЃРµС‚СЊ: %s", localSubnets[0])
	}
	hBtnAddLocalSubnet = createOwnerDrawButton(hInstance, addSubnetBtnText, cx+395, 390, 395, 34, ID_BTN_ADD_LOCAL_SUBNET, "normal")

	lblAdvSubnets := createLabel(hInstance, "рџЏ  Р›РѕРєР°Р»СЊРЅС‹Рµ РїРѕРґСЃРµС‚Рё РґР»СЏ РѕР±С‰РµРіРѕ РґРѕСЃС‚СѓРїР° (РЅР°РїСЂ. 192.168.1.0/24):", cx, 432, 470, 20, hFontNormal)
	hEditAdvSubnets = createEdit(hInstance, "", cx+480, 428, 310, 28, false, false, hFontNormal)

	lblSysHead := createLabel(hInstance, "рџ› пёЏ РЎРёСЃС‚РµРјРЅС‹Рµ С„СѓРЅРєС†РёРё & РРЅС‚РµСЂС„РµР№СЃ:", cx, 464, cw, 22, hFontHeader)
	logsText := "рџ’ѕ Р—Р°РїРёСЃСЊ Р»РѕРіРѕРІ РЅР° РґРёСЃРє: Р’Р«РљР›"
	logsType := "normal"
	if saveLogsToDisk {
		logsText = "рџ’ѕ Р—Р°РїРёСЃСЊ Р»РѕРіРѕРІ РЅР° РґРёСЃРє: Р’РљР›"
		logsType = "green"
	}
	hBtnToggleLogs = createOwnerDrawButton(hInstance, logsText, cx, 488, 385, 34, ID_BTN_TOGGLE_LOGS, logsType)

	diagText := "рџ©є Р’РєР»Р°РґРєР° Р”РёР°РіРЅРѕСЃС‚РёРєР°: Р’РљР›"
	diagType := "green"
	if !showDiagnostics {
		diagText = "рџ©є Р’РєР»Р°РґРєР° Р”РёР°РіРЅРѕСЃС‚РёРєР°: Р’Р«РљР›"
		diagType = "normal"
	}
	hBtnToggleDiag = createOwnerDrawButton(hInstance, diagText, cx+395, 488, 395, 34, ID_BTN_TOGGLE_DIAG, diagType)

	hBtnSaveCfg = createOwnerDrawButton(hInstance, "рџ’ѕ РЎРѕС…СЂР°РЅРёС‚СЊ РЅР°СЃС‚СЂРѕР№РєРё РІ config.yaml", cx+145, 536, 500, 42, ID_BTN_SAVE_CFG, "primary")
	hBtnCheckUpdate := createOwnerDrawButton(hInstance, "рџљЂ РџСЂРѕРІРµСЂРёС‚СЊ Рё РѕР±РЅРѕРІРёС‚СЊ NatBypass СЃ GitHub", cx+145, 588, 500, 38, ID_BTN_CHECK_UPDATE, "green")

	tabPages[3] = []uintptr{
		lblSetTitle, lblNick, hEditMyNick, lblNickHint, lblMode, hBtnModeParallel, hBtnModeMQTT, hBtnModeTG,
		lblMqHead, lblMqBr, hEditMqttBr, hBtnTestMqtt, lblMqPresets, hBtnMqEMQX, hBtnMqHive, hBtnMqMosq, hBtnMqEcl, lblMqTp, hEditMqttTp, lblMqTopicHint,
		lblTgHead, lblTgToken, hEditTgToken, hBtnTestTg, lblTgChat, hEditTgChat, lblTgHint,
		lblExitHead, hBtnAllowExit, hBtnAddLocalSubnet, lblAdvSubnets, hEditAdvSubnets,
		lblSysHead, hBtnToggleLogs, hBtnToggleDiag, hBtnSaveCfg, hBtnCheckUpdate,
	}
	writeDebug("buildModernUI: СЃС‚СЂР°РЅРёС†Р° 3 СЃРѕР·РґР°РЅР°")

	// РЎРўР РђРќРР¦Рђ 4: Р”РРђР“РќРћРЎРўРРљРђ
	lblDiagTitle := createLabel(hInstance, "рџ©є Р”РёР°РіРЅРѕСЃС‚РёРєР° СЃРІСЏР·РЅРѕСЃС‚Рё & Р”РµР±Р°РіРіРµСЂ РїР°РјСЏС‚Рё", cx, 36, cw, 28, hFontTitle)
	hBtnRunDiag = createOwnerDrawButton(hInstance, "рџ”„ РљРѕРјРїР»РµРєСЃРЅС‹Р№ С‚РµСЃС‚ СЃРµС‚Рё", cx, 75, 240, 40, ID_BTN_RUN_DIAG, "primary")
	hBtnDumpStack = createOwnerDrawButton(hInstance, "вљЎ РЎРЅРёРјРѕРє РїР°РјСЏС‚Рё Рё РїРѕС‚РѕРєРѕРІ", cx+250, 75, 240, 40, ID_BTN_DUMP_STACK, "normal")
	hEditDiagLog = createEdit(hInstance, "РќР°Р¶РјРёС‚Рµ РєРЅРѕРїРєСѓ РІС‹С€Рµ РґР»СЏ РєРѕРјРїР»РµРєСЃРЅРѕР№ РїСЂРѕРІРµСЂРєРё СЃРµС‚Рё Рё РґРѕСЃС‚СѓРїРЅРѕСЃС‚Рё РїРёСЂРѕРІ...", cx, 130, cw, 520, true, true, hFontMono)

	tabPages[4] = []uintptr{lblDiagTitle, hBtnRunDiag, hBtnDumpStack, hEditDiagLog}
	writeDebug("buildModernUI: СЃС‚СЂР°РЅРёС†Р° 4 СЃРѕР·РґР°РЅР°")

	// РЎРўР РђРќРР¦Рђ 5: Р–РЈР РќРђР› РЎРћР‘Р«РўРР™
	lblLogTitle := createLabel(hInstance, "рџ“‹ Р–СѓСЂРЅР°Р» СЃРѕР±С‹С‚РёР№ РІ СЂРµР°Р»СЊРЅРѕРј РІСЂРµРјРµРЅРё", cx, 36, cw-260, 28, hFontTitle)
	hBtnSaveLogs = createOwnerDrawButton(hInstance, "рџ’ѕ Р­РєСЃРїРѕСЂС‚ Р»РѕРіР°", cx+cw-250, 36, 120, 32, ID_BTN_SAVE_LOGS, "primary")
	hBtnClrLogs = createOwnerDrawButton(hInstance, "рџ—‘ РћС‡РёСЃС‚РёС‚СЊ", cx+cw-120, 36, 120, 32, ID_BTN_CLR_LOGS, "normal")
	hEditLogs = createEdit(hInstance, "", cx, 75, cw, 575, true, true, hFontMono)

	tabPages[5] = []uintptr{lblLogTitle, hBtnSaveLogs, hBtnClrLogs, hEditLogs}
	writeDebug("buildModernUI: СЃС‚СЂР°РЅРёС†Р° 5 СЃРѕР·РґР°РЅР°")

	// РЎРўРђР РўРћР’Р«Р™ Р­РљР РђРќ (STARTUP / SPLASH OVERLAY)
	hSplashTitle = createLabel(hInstance, "рџ›ё NatBypass P2P Mesh Engine", cx+40, 50, cw-80, 36, hFontTitle)
	hSplashSub = createLabel(hInstance, "РђРІС‚РѕРЅРѕРјРЅР°СЏ P2P mesh-СЃРµС‚СЊ РЅРѕРІРѕРіРѕ РїРѕРєРѕР»РµРЅРёСЏ вЂў РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ...", cx+40, 92, cw-80, 22, hFontNormal)
	hSplashStep1 = createLabel(hInstance, "рџџў [ 1/4 ] рџ§№ РћС‡РёСЃС‚РєР° СЃС‚Р°СЂС‹С… СЃРµСЃСЃРёР№ Рё С„РѕРЅРѕРІС‹С… РїСЂРѕС†РµСЃСЃРѕРІ вЂ” Р—Р°РІРµСЂС€РµРЅРѕ", cx+60, 160, cw-120, 24, hFontHeader)
	hSplashStep2 = createLabel(hInstance, "рџџЎ [ 2/4 ] рџ›ЎпёЏ РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РІРёСЂС‚СѓР°Р»СЊРЅРѕРіРѕ СЃРµС‚РµРІРѕРіРѕ Р°РґР°РїС‚РµСЂР° Wintun...", cx+60, 205, cw-120, 24, hFontHeader)
	hSplashStep3 = createLabel(hInstance, "рџџЎ [ 3/4 ] рџЊђ РћРїСЂРµРґРµР»РµРЅРёРµ РІРЅРµС€РЅРµРіРѕ IP Рё РїРѕСЃС‚РѕСЏРЅРЅРѕРіРѕ STUN СЃРѕРєРµС‚Р°...", cx+60, 250, cw-120, 24, hFontHeader)
	hSplashStep4 = createLabel(hInstance, "рџџЎ [ 4/4 ] вљЎ РџРѕРґРєР»СЋС‡РµРЅРёРµ РєР°РЅР°Р»РѕРІ СЃРёРіРЅР°Р»РёР·Р°С†РёРё (MQTT + Telegram)...", cx+60, 295, cw-120, 24, hFontHeader)
	hSplashBar = createLabel(hInstance, "рџљЂ Р—Р°РїСѓСЃРє СЃРµС‚РµРІРѕРіРѕ СЏРґСЂР°... РџРѕР¶Р°Р»СѓР№СЃС‚Р°, РїРѕРґРѕР¶РґРёС‚Рµ...", cx+40, 380, cw-80, 26, hFontBold)

	splashControls = []uintptr{hSplashTitle, hSplashSub, hSplashStep1, hSplashStep2, hSplashStep3, hSplashStep4, hSplashBar}

	// РЎРєСЂС‹РІР°РµРј СЃРїР»СЌС€-РєРѕРЅС‚СЂРѕР»С‹ РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ
	for _, h := range splashControls {
		procShowWindow.Call(h, uintptr(SW_HIDE))
	}

	fillConfigFields()
	renderAWGTextFromUI()
	applyDiagnosticsVisibility()
	writeDebug("buildModernUI: fillConfigFields Рё renderAWGText Р·Р°РІРµСЂС€РµРЅС‹")

	// РџРµСЂРµРєР»СЋС‡Р°РµРј РЅР° Р°РєС‚РёРІРЅСѓСЋ СЃС‚СЂР°РЅРёС†Сѓ 0 (РћР±Р·РѕСЂ) Рё СЃРєСЂС‹РІР°РµРј РѕСЃС‚Р°Р»СЊРЅС‹Рµ
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
			if btn == navButtons[4] && !showDiagnostics {
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
	if index == 2 && syncAWGPeerParams != nil && hBtnSyncAwg != 0 {
		procShowWindow.Call(hBtnSyncAwg, uintptr(SW_SHOW))
		procInvalidateRect.Call(hBtnSyncAwg, 0, 1)
	} else if hBtnSyncAwg != 0 {
		procShowWindow.Call(hBtnSyncAwg, uintptr(SW_HIDE))
	}
	for _, btn := range navButtons {
		if btn != 0 {
			if btn == navButtons[4] && !showDiagnostics {
				procShowWindow.Call(btn, uintptr(SW_HIDE))
			} else {
				procShowWindow.Call(btn, uintptr(SW_SHOW))
				procInvalidateRect.Call(btn, 0, 1)
			}
		}
	}
	if index == 1 {
		refreshProfilesUI()
	}
	if index == 2 {
		renderAWGTextFromUI()
	}
	if index == 5 {
		flushLogsToUI()
	}
	procInvalidateRect.Call(hMainWnd, 0, 1)
}

func toggleVPNManual() {
	vpnConnected = !vpnConnected
	if vpnConnected {
		buttonLabels[ID_BTN_VPN] = fmt.Sprintf("рџџў РџРћР”РљР›Р®Р§Р•РќРћ (Р’Р°С€ IP: %s)", myVirtualIP)
		buttonTypes[ID_BTN_VPN] = "green"
		addLog(fmt.Sprintf("рџџў РўСѓРЅРЅРµР»СЊ РІРєР»СЋС‡РµРЅ РІСЂСѓС‡РЅСѓСЋ (IP: %s/24)", myVirtualIP))
	} else {
		buttonLabels[ID_BTN_VPN] = "рџ”ґ РћРўРљР›Р®Р§Р•РќРћ (РќР°Р¶РјРёС‚Рµ РґР»СЏ РІРєР»СЋС‡РµРЅРёСЏ)"
		buttonTypes[ID_BTN_VPN] = "red"
		addLog("рџ”ґ РўСѓРЅРЅРµР»СЊ РѕС‚РєР»СЋС‡РµРЅ РїРѕР»СЊР·РѕРІР°С‚РµР»РµРј")
	}
	procInvalidateRect.Call(hBtnVpn, 0, 1)
}

func startEngineFromConfig(c *config.Config) {
	defer func() {
		if r := recover(); r != nil {
			writeDebug(fmt.Sprintf("вќЊ CRITICAL PANIC in startEngine: %v\r\n%s", r, string(debug.Stack())))
		}
	}()

	engineMu.Lock()
	defer engineMu.Unlock()

	writeDebug("Р—Р°РїСѓСЃРє С„РѕРЅРѕРІРѕРіРѕ СЃРµС‚РµРІРѕРіРѕ СЏРґСЂР°...")
	ctx, cancel := context.WithCancel(context.Background())
	engineCtx = ctx
	engineCancel = cancel
	triggerPublishCh = make(chan struct{}, 10)

	var err error
	myPubKey, myPrivKey, err = crypto.GenerateKeyPair()
	if err != nil {
		addLog("вљ пёЏ РћС€РёР±РєР° РіРµРЅРµСЂР°С†РёРё РєР»СЋС‡РµР№: " + err.Error())
	}
	pubHex := crypto.KeyToHex(myPubKey)
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "Win"
	}
	myDevID = fmt.Sprintf("%s-%s", hn, pubHex[:6])
	writeDebug("РЎРіРµРЅРµСЂРёСЂРѕРІР°РЅ РёРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ СѓСЃС‚СЂРѕР№СЃС‚РІР°: " + myDevID)

	if wgKP, wgErr := wireguard.GenerateKeyPair(); wgErr == nil {
		myWGPubKey = wgKP.PublicKey
		myWGPrivKey = wgKP.PrivateKey
	}

	registry = peer.NewRegistry()
	registry.StartMonitor(ctx, 2*time.Minute)

	// Р—Р°РїСѓСЃРє РІСЃС‚СЂРѕРµРЅРЅРѕРіРѕ СЃРѕРІСЂРµРјРµРЅРЅРѕРіРѕ Glassmorphism Web UI РјРіРЅРѕРІРµРЅРЅРѕ
	webPort := 8080
	if c.WebUI.Port > 0 {
		webPort = c.WebUI.Port
	}
	uiServer = webui.NewServer(webPort, c.WebUI.Username, c.WebUI.Password, registry, nil)
	uiServer.SetDeviceName(myNick)
	uiServer.SetVersion(Version)
	uiServer.SetConfigPath(configPath)
	go func() {
		if err := uiServer.Start(ctx); err != nil {
			writeDebug("Web UI СЃРµСЂРІРµСЂ: " + err.Error())
		}
	}()

	// РЎРѕР·РґР°РЅРёРµ СЂРµР°Р»СЊРЅРѕРіРѕ UDP Hole Punching СЃРѕРєРµС‚Р°
	// РџРѕСЂС‚ Р±РµСЂС‘С‚СЃСЏ РёР· РєРѕРЅС„РёРіР° (Network.UDPPort). РџРѕ СѓРјРѕР»С‡Р°РЅРёСЋ 0 = OS РЅР°Р·РЅР°С‡Р°РµС‚ СЃР»СѓС‡Р°Р№РЅС‹Р№ РїРѕСЂС‚.
	// Р­С‚Рѕ РєСЂРёС‚РёС‡РЅРѕ С‡С‚РѕР±С‹ РЅРµ РєРѕРЅС„Р»РёРєС‚РѕРІР°С‚СЊ СЃ Р»РѕРєР°Р»СЊРЅС‹Рј AWG/WireGuard РЅР° РїРѕСЂС‚Сѓ 51820.
	udpListenPort := c.Network.UDPPort
	puncher, err := network.NewUDPPuncher(udpListenPort, myDevID, c.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		atomic.AddUint64(&packetsRecvCount, 1)
		if p, ok := registry.Get(remoteDevID); ok {
			p.DirectP2P = true
			if rtt > 0 && rtt < 10*time.Second {
				if p.Latency > 0 {
					p.Latency = time.Duration(float64(p.Latency)*0.75 + float64(rtt)*0.25)
				} else {
					p.Latency = rtt
				}
				p.PingMs = p.Latency.Milliseconds()
			} else if p.PingMs == 0 {
				p.PingMs = 12
				p.Latency = 12 * time.Millisecond
			}
			p.ActiveEndpoint = fromAddr
			p.Online = true
			p.LastSeen = time.Now()
			registry.Upsert(p)
			msg := fmt.Sprintf("вљЎ [P2P Direct UDP] РџРћР”РўР’Р•Р Р–Р”Р•РќРћ! РџСЂСЏРјРѕР№ UDP-РїРёРЅРі РґРѕ %s (%s): %v! NAT РїСЂРѕР±РёС‚ СЃРѕРєРµС‚-РІ-СЃРѕРєРµС‚!", remoteDevID, fromAddr, p.Latency.Round(time.Millisecond))
			addLog(msg)
			writeDebug(msg)
		}
	})
	if err == nil {
		udpPuncher = puncher
		writeDebug(fmt.Sprintf("UDPPuncher СЃР»СѓС€Р°РµС‚ Р»РѕРєР°Р»СЊРЅС‹Р№ UDP РїРѕСЂС‚ :%d", puncher.LocalPort()))

		// РњР°СЂС€СЂСѓС‚РёР·Р°С†РёСЏ РІС…РѕРґСЏС‰РёС… IP-РїР°РєРµС‚РѕРІ С‚СѓРЅРЅРµР»СЏ РЅР°РїСЂСЏРјСѓСЋ РІ РІРёСЂС‚СѓР°Р»СЊРЅС‹Р№ Р°РґР°РїС‚РµСЂ Windows
		puncher.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
			if len(payload) < 20 {
				return
			}
			srcIP := tunnel.GetSrcIP(payload)
			destIP := tunnel.GetDestIP(payload)
			if srcIP == nil || destIP == nil {
				return
			}
			// Р—Р°С‰РёС‚Р° РѕС‚ РїРµС‚РµР»СЊ: РїСЂРѕРІРµСЂСЏРµРј, С‡С‚Рѕ РїР°РєРµС‚ РЅРµ РѕС‚СЂР°Р¶РµРЅ РѕС‚ СЃРµР±СЏ
			if srcIP.String() == myVirtualIP {
				return
			}
			// РџСЂРёРЅРёРјР°РµРј РїР°РєРµС‚С‹, Р°РґСЂРµСЃРѕРІР°РЅРЅС‹Рµ РЅР°С€РµРјСѓ VIP РёР»Рё 100.64.200.1 (РґРѕ СЃРѕРіР»Р°СЃРѕРІР°РЅРёСЏ)
			// Instant ICMP echo response for 100% reliable ping
			ihl := int(payload[0]&0x0F) * 4
			if len(payload) >= ihl+8 && payload[9] == 1 && payload[ihl] == 8 {
				if destIP.String() == myVirtualIP || destIP.String() == "100.64.200.1" {
					respondICMPEcho(payload, srcAddr)
				}
			}

			// Р—Р°РїРёСЃС‹РІР°РµРј РїР°РєРµС‚ РІ Wintun вЂ” Windows OS СЃР°РјР° РѕР±СЂР°Р±Р°С‚С‹РІР°РµС‚ ICMP, TCP, UDP
			// РќР• РїРµСЂРµС…РІР°С‚С‹РІР°РµРј ICMP РІСЂСѓС‡РЅСѓСЋ вЂ” РћРЎ РіРµРЅРµСЂРёСЂСѓРµС‚ Echo Reply СЃР°РјР°, РѕРЅ РІС‹С…РѕРґРёС‚ С‡РµСЂРµР· ReadPacket Рё РѕС‚РїСЂР°РІР»СЏРµС‚СЃСЏ РїРёСЂСѓ
			atomic.AddUint64(&packetsRecvCount, 1)
			if tunDev != nil {
				_ = tunDev.WritePacket(payload)
			}
		})
	} else {
		writeDebug("РћС€РёР±РєР° СЃРѕР·РґР°РЅРёСЏ UDPPuncher: " + err.Error())
	}

	// рџљЂ РђР’РўРћРњРђРўРР§Р•РЎРљРћР• РџРћР”РќРЇРўРР• Р’РР РўРЈРђР›Р¬РќРћР“Рћ РЎР•РўР•Р’РћР“Рћ РђР”РђРџРўР•Р Рђ WINDOWS (Wintun TUN)
	go func() {
		tDev, tErr := tunnel.CreateAdapter("NatBypass", myVirtualIP)
		if tErr == nil {
			tunDev = tDev
			msg := fmt.Sprintf("рџ›ЎпёЏ Р’РёСЂС‚СѓР°Р»СЊРЅС‹Р№ СЃРµС‚РµРІРѕР№ Р°РґР°РїС‚РµСЂ Windows 'NatBypass' Р°РєС‚РёРІРµРЅ! (IP: %s/24)", myVirtualIP)
			addLog(msg)
			writeDebug(msg)

			// Р¤РѕРЅРѕРІС‹Р№ РїРѕС‚РѕРє С‡С‚РµРЅРёСЏ РёСЃС…РѕРґСЏС‰РёС… IP-РїР°РєРµС‚РѕРІ РёР· СЃРµС‚РµРІРѕРіРѕ СЃС‚РµРєР° Windows Рё РѕС‚РїСЂР°РІРєР° РїРёСЂР°Рј
			for {
				select {
				case <-ctx.Done():
					return
				default:
					packet, readErr := tunDev.ReadPacket()
					if readErr != nil {
						return
					}
					srcIP := tunnel.GetSrcIP(packet)
					destIP := tunnel.GetDestIP(packet)
					if srcIP == nil || destIP == nil {
						continue
					}
					destStr := destIP.String()

					// РРіРЅРѕСЂРёСЂСѓРµРј РјСѓР»СЊС‚РёРєР°СЃС‚ Windows (224.0.0.x, 239.255.x.x, 255.255.255.255) Рё РїРµС‚Р»Рё
					if destIP.IsMulticast() || destIP.IsUnspecified() || destStr == "255.255.255.255" || destStr == myVirtualIP || destStr == "100.64.200.255" || destStr == "100.64.200.0" {
						continue
					}

					if registry != nil {
						peers := registry.List()
						var targetPeer *peer.Peer

						// 1. РџСЂСЏРјРѕРµ СЃРѕРІРїР°РґРµРЅРёРµ РїРѕ VirtualIP (РЅР°РїСЂРёРјРµСЂ, 100.64.200.2)
						for _, p := range peers {
							if p.DeviceID != myDevID && p.VirtualIP == destStr {
								targetPeer = p
								break
							}
						}

						// 2. РњР°СЂС€СЂСѓС‚ Рє РїРѕРґСЃРµС‚Рё РїРёСЂР° (РЅР°РїСЂРёРјРµСЂ, 192.168.1.0/24 РёР»Рё 10.0.0.0/8)
						if targetPeer == nil {
							for _, p := range peers {
								if p.DeviceID == myDevID {
									continue
								}
								for _, route := range p.AdvertisedRoutes {
									if _, ipNet, err := net.ParseCIDR(route); err == nil && ipNet.Contains(destIP) {
										targetPeer = p
										break
									}
								}
								if targetPeer != nil {
									break
								}
							}
						}

						// 3. РњР°СЂС€СЂСѓС‚РёР·Р°С†РёСЏ С‡РµСЂРµР· Exit Node
						if targetPeer == nil && activeExitNodeID != "" {
							if ep, ok := registry.Get(activeExitNodeID); ok && ep.Online {
								targetPeer = ep
							}
						}

						// 4. Fallback РґР»СЏ mesh-СЃРµС‚Рё РёР· 1 СѓРґР°Р»РµРЅРЅРѕРіРѕ СѓР·Р»Р° (С‚РѕР»СЊРєРѕ РґР»СЏ 100.64.200.x)
						if targetPeer == nil && len(peers) == 1 && strings.HasPrefix(destStr, "100.64.200.") {
							if peers[0].DeviceID != myDevID {
								targetPeer = peers[0]
							}
						}

						if targetPeer != nil {
							if targetPeer.ActiveEndpoint != "" && udpPuncher != nil {
								_ = udpPuncher.SendDataPacket(targetPeer.ActiveEndpoint, packet)
								atomic.AddUint64(&packetsSentCount, 1)
							}
							if targetPeer.LocalAddr != "" && targetPeer.LocalAddr != targetPeer.ActiveEndpoint && udpPuncher != nil {
								_ = udpPuncher.SendDataPacket(targetPeer.LocalAddr, packet)
								atomic.AddUint64(&packetsSentCount, 1)
							}
							if targetPeer.STUNAddr != "" && targetPeer.STUNAddr != targetPeer.ActiveEndpoint && targetPeer.STUNAddr != targetPeer.LocalAddr && udpPuncher != nil {
								_ = udpPuncher.SendDataPacket(targetPeer.STUNAddr, packet)
								atomic.AddUint64(&packetsSentCount, 1)
							}
							// РђСЃРёРЅС…СЂРѕРЅРЅС‹Р№ РЅРµР±Р»РѕРєРёСЂСѓСЋС‰РёР№ СЂРµР»РµР№ С‡РµСЂРµР· MQTT
							if activeMQTT != nil {
								pktCopy := make([]byte, len(packet))
								copy(pktCopy, packet)
								go func(tID string, d []byte) {
									_ = activeMQTT.PublishTunnelData(tID, d)
								}(targetPeer.DeviceID, pktCopy)
								atomic.AddUint64(&packetsSentCount, 1)
							}
						}
					}
				}
			}
		} else {
			warnMsg := fmt.Sprintf("вљ пёЏ Wintun Р°РґР°РїС‚РµСЂ: %s (Р”Р»СЏ РїРѕР»РЅРѕРіРѕ ping Р·Р°РїСѓСЃС‚РёС‚Рµ РѕС‚ РђРґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР°)", tErr.Error())
			addLog(warnMsg)
			writeDebug(warnMsg)
		}
	}()

	tgToken := ""
	tgChat := ""
	mqBroker := "tcp://broker.emqx.io:1883"
	mqTopic := "natbypass/mynet/peers"
	for _, ch := range c.Signaling.Channels {
		if ch.Type == "telegram" && ch.Params != nil {
			tgToken = ch.Params["token"]
			tgChat = ch.Params["chat_id"]
		}
		if ch.Type == "mqtt" && ch.Params != nil {
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
		modeStr = "parallel" // РђРІС‚Рѕ-РІРєР»СЋС‡РµРЅРёРµ MQTT РґР»СЏ РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕР№ P2P РґРѕСЃС‚Р°РІРєРё Р±РµР· РѕРіСЂР°РЅРёС‡РµРЅРёР№ TG
	} else if mqEnabled && !tgEnabled {
		modeStr = "mqtt_only"
	}

	rebuildSignalingInternal(ctx, modeStr, tgToken, tgChat, mqBroker, mqTopic)

	ipDisc = network.NewDiscoverer(c.Network.IPApis, 3*time.Second)

	// РђСЃРёРЅС…СЂРѕРЅРЅРѕРµ РѕРїСЂРµРґРµР»РµРЅРёРµ IP Рё STUN РЅР° РѕСЃРЅРѕРІРЅРѕРј РїРѕСЃС‚РѕСЏРЅРЅРѕРј СЃРѕРєРµС‚Рµ
	go func() {
		writeDebug("РћРїСЂРµРґРµР»РµРЅРёРµ РІРЅРµС€РЅРµРіРѕ IP Рё STUN СЃРѕРєРµС‚Р°...")
		if ip, err := ipDisc.GetPublicIPCached(ctx, 5*time.Minute); err == nil {
			myPublicIP = ip.String()
			writeDebug("Р’РЅРµС€РЅРёР№ РїСѓР±Р»РёС‡РЅС‹Р№ IP: " + myPublicIP)
		}
		if udpPuncher != nil {
			if extIP, port, err := udpPuncher.DiscoverMappedAddress(ctx); err == nil {
				mySTUNAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
				writeDebug("STUN СЃРѕРєРµС‚ РЅР° РїРѕСЃС‚РѕСЏРЅРЅРѕРј РїРѕСЂС‚Сѓ: " + mySTUNAddr)
			}
		}
		addLog(fmt.Sprintf("вњ“ РЇРґСЂРѕ Р·Р°РїСѓС‰РµРЅРѕ. РЈСЃС‚СЂРѕР№СЃС‚РІРѕ: %s | Р’РёСЂС‚СѓР°Р»СЊРЅС‹Р№ IP: %s | STUN: %s", myDevID, myVirtualIP, mySTUNAddr))
		triggerPublish()
	}()

	// Р¤РѕРЅРѕРІС‹Р№ С†РёРєР» РїСѓР±Р»РёРєР°С†РёРё Р°РЅРѕРЅСЃРѕРІ (РєР°Р¶РґС‹Рµ 10 СЃРµРєСѓРЅРґ)
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

	// Р¤РѕРЅРѕРІС‹Р№ С†РёРєР» РїСЂСЏРјРѕР№ РѕС‚РїСЂР°РІРєРё UDP Hole Punch РїР°РєРµС‚РѕРІ (РєР°Р¶РґС‹Рµ 15 СЃРµРєСѓРЅРґ)
	// РџСЂРѕРІРµСЂСЏРµРј С‚РѕР»СЊРєРѕ В«Р»СѓС‡С€РёР№В» СЌРЅРґРїРѕРёРЅС‚ РїРёСЂР° вЂ” РЅРµ СЂР°СЃСЃС‹Р»Р°РµРј 5 РїР°РєРµС‚РѕРІ РѕРґРЅРѕРІСЂРµРјРµРЅРЅРѕ
	go func() {
		probeTicker := time.NewTicker(15 * time.Second)
		defer probeTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-probeTicker.C:
				if udpPuncher != nil && registry != nil {
					peers := registry.List()
					for _, p := range peers {
						// РџСЂРёРѕСЂРёС‚РµС‚: ActiveEndpoint > STUNAddr > LocalAddr
						// РќРµ С€Р»С‘Рј СЃСЂР°Р·Сѓ РїРѕ 5 Р°РґСЂРµСЃР°Рј вЂ” СЌС‚Рѕ СЃРѕР·РґР°С‘С‚ С€С‚РѕСЂРј
						target := p.ActiveEndpoint
						if target == "" {
							target = p.STUNAddr
						}
						if target == "" {
							target = p.LocalAddr
						}
						if target != "" {
							_ = udpPuncher.SendHolePunchProbe(target)
						}
					}
				}
			}
		}
	}()

	// Р¤РѕРЅРѕРІС‹Р№ РјРѕРЅРёС‚РѕСЂ РЅРµР°РєС‚РёРІРЅС‹С… СѓР·Р»РѕРІ
	go func() {
		monitorTicker := time.NewTicker(5 * time.Second)
		defer monitorTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-monitorTicker.C:
				if registry != nil {
					registry.MarkOffline(45 * time.Second)
					registry.Cleanup(24 * time.Hour)
				}
			}
		}
	}()

	// Р¤РѕРЅРѕРІС‹Р№ Р»РѕРєР°Р»СЊРЅС‹Р№ С€РёСЂРѕРєРѕРІРµС‰Р°С‚РµР»СЊРЅС‹Р№ РїРѕРёСЃРє РїРёСЂРѕРІ РІ LAN
	startLANBroadcastDiscovery(ctx)

	addLog("рџ›ё NatBypass P2P Mesh РґРІРёР¶РѕРє РіРѕС‚РѕРІ Рє СЂР°Р±РѕС‚Рµ")
}

// startLANBroadcastDiscovery РјРіРЅРѕРІРµРЅРЅРѕ РЅР°С…РѕРґРёС‚ РІСЃРµ СѓСЃС‚СЂРѕР№СЃС‚РІР° NatBypass РІ Р»РѕРєР°Р»СЊРЅРѕР№ СЃРµС‚Рё / Wi-Fi Р±РµР· СЃРµСЂРІРµСЂРѕРІ
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
		writeDebug("LAN Broadcast СЃР»СѓС€Р°С‚РµР»СЊ Р·Р°РЅСЏС‚ РёР»Рё РЅРµРґРѕСЃС‚СѓРїРµРЅ: " + err.Error())
		return
	}

	writeDebug("рџЏ  LAN Broadcast Discovery Р·Р°РїСѓС‰РµРЅ РЅР° РїРѕСЂС‚Сѓ :51821 (РјРіРЅРѕРІРµРЅРЅС‹Р№ Р»РѕРєР°Р»СЊРЅС‹Р№ РїРѕРёСЃРє)")
	addLog("рџЏ  Р—Р°РїСѓС‰РµРЅ Р»РѕРєР°Р»СЊРЅС‹Р№ LAN РїРѕРёСЃРє РїРёСЂРѕРІ (РїРѕСЂС‚ :51821)")

	// 1. РџРѕС‚РѕРє СЃР»СѓС€Р°С‚РµР»СЏ Р»РѕРєР°Р»СЊРЅС‹С… LAN Р°РЅРѕРЅСЃРѕРІ
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
					if activeKey != "" && p.NetworkKey == activeKey {
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
					})

					nameInfo := p.DeviceID
					if nick != "" {
						nameInfo = fmt.Sprintf("%s (%s)", nick, p.DeviceID)
					}
					msg := fmt.Sprintf("рџ“Ґ [LAN Broadcast] РњРіРЅРѕРІРµРЅРЅРѕ РѕР±РЅР°СЂСѓР¶РµРЅ Р»РѕРєР°Р»СЊРЅС‹Р№ РїРёСЂ %s (%s)", nameInfo, lanAddr)
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

	// 2. РџРµСЂРёРѕРґРёС‡РµСЃРєР°СЏ РѕС‚РїСЂР°РІРєР° Р°РЅРѕРЅСЃР° РІ Р»РѕРєР°Р»СЊРЅСѓСЋ СЃРµС‚СЊ РєР°Р¶РґС‹Рµ 30 СЃРµРєСѓРЅРґ (РЅРµ 4 СЃ вЂ” С‡С‚РѕР±С‹ РЅРµ РїРµСЂРµРіСЂСѓР¶Р°С‚СЊ СЂРѕСѓС‚РµСЂ)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
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
				pPort := 47832
				if udpPuncher != nil {
					pPort = udpPuncher.LocalPort()
				}
				payload := &signaling.Payload{
					DeviceID:         myDevID,
					Nickname:         myNick,
					DeviceName:       myNick,
					VirtualIP:        myVirtualIP,
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
	// РџСЂРё РїРµСЂРµСЃС‚СЂРѕР№РєРµ РєР°РЅР°Р»РѕРІ РѕС‡РёС‰Р°РµРј СЃРїРёСЃРѕРє РїРёСЂРѕРІ, С‡С‚РѕР±С‹ РёСЃРєР»СЋС‡РёС‚СЊ РїРѕРєР°Р· РЅРµР°РєС‚СѓР°Р»СЊРЅС‹С… СѓСЃС‚СЂРѕР№СЃС‚РІ
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

	if modeText == "tg_only" || strings.Contains(modeText, "РўРѕР»СЊРєРѕ Telegram") {
		useMQTT = false
		useTG = true
		sigMode = "tg_only"
		activeChannelStr = "РўРѕР»СЊРєРѕ Telegram Bot API"
	} else if modeText == "mqtt_only" || strings.Contains(modeText, "РўРѕР»СЊРєРѕ MQTT") {
		useMQTT = true
		useTG = false
		sigMode = "mqtt_only"
		activeChannelStr = "РўРѕР»СЊРєРѕ MQTT (" + mqBroker + ")"
	} else {
		useMQTT = true
		useTG = tgToken != "" && tgChat != ""
		sigMode = "parallel"
		activeChannelStr = "РџР°СЂР°Р»Р»РµР»СЊРЅРѕ: MQTT + Telegram"
	}

	writeDebug(fmt.Sprintf("РџРµСЂРµСЃС‚СЂРѕР№РєР° СЃРёРіРЅР°Р»СЊРЅС‹С… РєР°РЅР°Р»РѕРІ: Р РµР¶РёРј=%s, useTG=%t, useMQTT=%t", sigMode, useTG, useMQTT))

	if useTG && (tgToken == "" || tgChat == "") {
		addLog("вљ пёЏ Telegram РІС‹Р±СЂР°РЅ РІ СЂРµР¶РёРјРµ, РЅРѕ С‚РѕРєРµРЅ РёР»Рё Chat ID РЅРµ Р·Р°РїРѕР»РЅРµРЅС‹!")
	}

	if useTG && tgToken != "" && tgChat != "" {
		tgCh := signaling.NewTelegramChannel(tgToken, tgChat, "")
		sigChannels = append(sigChannels, tgCh)
		addLog(fmt.Sprintf("вњ“ РџРѕРґРєР»СЋС‡РµРЅ СЃРёРіРЅР°Р»СЊРЅС‹Р№ РєР°РЅР°Р»: Telegram (Р§Р°С‚: %s)", tgChat))
		writeDebug(fmt.Sprintf("Р—Р°РїСѓСЃРє СЃР»СѓС€Р°С‚РµР»СЏ Telegram (Chat: %s)...", tgChat))
		startChannelReceiver(ctx, tgCh, "Telegram")
	}

	if useMQTT {
		mqttCh := signaling.NewMQTTChannel(mqBroker, mqTopic, myDevID+"-"+crypto.KeyToHex(myPubKey)[:4], "", "")
		activeMQTT = mqttCh
		sigChannels = append(sigChannels, mqttCh)
		addLog(fmt.Sprintf("вњ“ РџРѕРґРєР»СЋС‡РµРЅ СЃРёРіРЅР°Р»СЊРЅС‹Р№ РєР°РЅР°Р»: MQTT (%s / С‚РѕРїРёРє: %s)", mqBroker, mqTopic))
		writeDebug(fmt.Sprintf("Р—Р°РїСѓСЃРє СЃР»СѓС€Р°С‚РµР»СЏ MQTT (%s, Topic: %s)...", mqBroker, mqTopic))
		startChannelReceiver(ctx, mqttCh, "MQTT")

		// Р‘С‹СЃС‚СЂС‹Р№ СЂРµР»РµР№ РїР°РєРµС‚РѕРІ С‚СѓРЅРЅРµР»СЏ С‡РµСЂРµР· MQTT (РіР°СЂР°РЅС‚РёСЂСѓРµС‚ СЃРєРІРѕР·РЅРѕР№ РїРёРЅРі РїСЂРё Р»СЋР±РѕРј С‚РёРїРµ NAT/VPN)
		mqttCh.SubscribeTunnelData(myDevID, func(pkt []byte) {
			if len(pkt) < 20 {
				return
			}
			srcIP := tunnel.GetSrcIP(pkt)
			destIP := tunnel.GetDestIP(pkt)
			if srcIP == nil || destIP == nil {
				return
			}
			// Р—Р°С‰РёС‚Р° РѕС‚ РїРµС‚РµР»СЊ
			if srcIP.String() == myVirtualIP {
				return
			}
			_ = destIP

			// Р’СЃРµ РїР°РєРµС‚С‹ РёРґСѓС‚ РїСЂСЏРјРѕ РІ Wintun вЂ” OS СЃР°РјР° РѕР±СЂР°Р±Р°С‚С‹РІР°РµС‚ ICMP, TCP, UDP
			atomic.AddUint64(&packetsRecvCount, 1)
			if tunDev != nil {
				_ = tunDev.WritePacket(pkt)
			}
		})
	}
}

func getLocalLANIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				ipStr := ip4.String()
				if strings.HasPrefix(ipStr, "10.200.") {
					continue // РџСЂРѕРїСѓСЃРєР°РµРј СЃРѕР±СЃС‚РІРµРЅРЅС‹Р№ РІРёСЂС‚СѓР°Р»СЊРЅС‹Р№ mesh-РёРЅС‚РµСЂС„РµР№СЃ NatBypass
				}
				if strings.HasPrefix(ipStr, "192.168.") || strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "172.") {
					return ipStr
				}
			}
		}
	}
	return ""
}

func startChannelReceiver(ctx context.Context, ch signaling.SignalingChannel, name string) {
	inCh, err := ch.Receive(ctx)
	if err != nil {
		addLog(fmt.Sprintf("вќЊ РћС€РёР±РєР° Р·Р°РїСѓСЃРєР° СЃР»СѓС€Р°С‚РµР»СЏ %s: %s", name, err.Error()))
		writeDebug(fmt.Sprintf("РћС€РёР±РєР° СЃР»СѓС€Р°С‚РµР»СЏ %s: %s", name, err.Error()))
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
				if p == nil || p.DeviceID == "" || p.DeviceID == myDevID {
					continue
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
				match := false
				if activeKey != "" && p.NetworkKey == activeKey {
					match = true
				} else if activeTopic != "" && p.Topic == activeTopic {
					match = true
				} else if activeKey == "" && activeTopic == "" {
					match = true
				}
				if !match {
					continue
				}

				if p.Offline || p.Leave {
					nameInfo := p.DeviceID
					if p.Nickname != "" {
						nameInfo = fmt.Sprintf("%s (%s)", p.Nickname, p.DeviceID)
					}
					writeDebug(fmt.Sprintf("РЈР·РµР» %s РѕС‚РєР»СЋС‡РёР»СЃСЏ РѕС‚ СЃРµС‚Рё (Leave beacon)", nameInfo))
					addLog(fmt.Sprintf("рџ”ґ РЈР·РµР» %s РѕС‚РєР»СЋС‡РёР»СЃСЏ РѕС‚ СЃРµС‚Рё", nameInfo))
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
					buttonLabels[ID_BTN_EXIT_NODE_SELECT] = "рџЊђ Р’С‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚: Р›РѕРєР°Р»СЊРЅС‹Р№ (РћС‚РєР»СЋС‡РµРЅ)"
					buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "normal"
					if hBtnExitNodeSelect != 0 {
						procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
					}

					alertMsg := fmt.Sprintf("вљ пёЏ Р’РЅРёРјР°РЅРёРµ: РЈСЃС‚СЂРѕР№СЃС‚РІРѕ %s Р·Р°РїСЂРµС‚РёР»Рѕ РІС‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· СЃРµР±СЏ. РњР°СЂС€СЂСѓС‚ СЃР±СЂРѕС€РµРЅ РЅР° СЃС‚Р°РЅРґР°СЂС‚РЅС‹Р№ РёРЅС‚РµСЂРЅРµС‚.", peerName)
					addLog(alertMsg)
					writeDebug(alertMsg)

					go func(msgText string) {
						titlePtr, _ := windows.UTF16PtrFromString("NatBypass вЂ” РР·РјРµРЅРµРЅРёРµ РјР°СЂС€СЂСѓС‚Р°")
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
						plat = "рџ’» Windows"
					}
				}
				pFlag := p.CountryFlag
				if pFlag == "" && p.PublicIP != "" {
					pFlag = network.LookupCountryFlag(ctx, p.PublicIP)
				}

				registry.Upsert(&peer.Peer{
					DeviceID:         p.DeviceID,
					Nickname:         nick,
					VirtualIP:        peerVIP,
					PublicKey:        p.PublicKey,
					PublicIP:         p.PublicIP,
					LocalAddr:        p.LocalAddr,
					STUNAddr:         p.STUNAddr,
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
				})

				nameInfo := p.DeviceID
				if nick != "" {
					nameInfo = fmt.Sprintf("%s (%s)", nick, p.DeviceID)
				}
				msg := fmt.Sprintf("рџ“Ґ [%s] РЎРёРіРЅР°Р» РѕС‚ %s (VIP: %s | STUN: %s | LAN: %s)", name, nameInfo, peerVIP, p.STUNAddr, p.LocalAddr)
				addLog(msg)
				writeDebug(msg)

				// РќРµРјРµРґР»РµРЅРЅРѕ РїРѕСЃС‹Р»Р°РµРј РїСЂСЏРјРѕР№ UDP-РїР°РєРµС‚ РґР»СЏ РїСЂРѕР±РёС‚РёСЏ СЃРѕРєРµС‚Р°
				if udpPuncher != nil {
					if p.STUNAddr != "" {
						_ = udpPuncher.SendHolePunchProbe(p.STUNAddr)
					}
					if p.PublicIP != "" {
						port := p.WGPort
						if port <= 0 {
							port = 47832
						}
						_ = udpPuncher.SendHolePunchProbe(fmt.Sprintf("%s:%d", p.PublicIP, port))
					}
					if p.LocalAddr != "" {
						_ = udpPuncher.SendHolePunchProbe(p.LocalAddr)
					}
				}

				// РђРІС‚РѕРјР°С‚РёС‡РµСЃРєРѕРµ РґРёРЅР°РјРёС‡РµСЃРєРѕРµ P2P СЃРѕРіР»Р°СЃРѕРІР°РЅРёРµ IP-Р°РґСЂРµСЃРѕРІ
				negotiateVirtualIP()
			}
		}
	}()
}

// handleICMPEcho РѕР±СЂР°Р±Р°С‚С‹РІР°РµС‚ РІС…РѕРґСЏС‰РёР№ ICMP Echo Request (Type 8, Code 0)
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

	// Р—Р°С‰РёС‚Р° РѕС‚ РїРµС‚РµР»СЊ: РёРіРЅРѕСЂРёСЂСѓРµРј РїР°РєРµС‚С‹ РѕС‚ СЃРѕР±СЃС‚РІРµРЅРЅРѕРіРѕ Р°РґСЂРµСЃР°
	if srcIP.String() == myVirtualIP {
		return
	}

	// РџСЂРёРЅРёРјР°РµРј С‚РѕР»СЊРєРѕ РїР°РєРµС‚С‹, Р°РґСЂРµСЃРѕРІР°РЅРЅС‹Рµ РЅР° РЅР°С€ С‚РµРєСѓС‰РёР№ VIP РёР»Рё Р±Р°Р·РѕРІС‹Р№ 100.64.200.1
	if destIP.String() != myVirtualIP && destIP.String() != "100.64.200.1" {
		return
	}

	// Р•СЃР»Рё РїР°РєРµС‚ Р±С‹Р» Р°РґСЂРµСЃРѕРІР°РЅ 100.64.200.1 РґРѕ РґРёРЅР°РјРёС‡РµСЃРєРѕРіРѕ РїРµСЂРµСЃРѕРіР»Р°СЃРѕРІР°РЅРёСЏ Р°РґСЂРµСЃРѕРІ,
	// РєРѕСЂСЂРµРєС‚РёСЂСѓРµРј Destination IP РЅР° Р°РєС‚СѓР°Р»СЊРЅС‹Р№ myVirtualIP Рё РїРµСЂРµСЃС‡РёС‚С‹РІР°РµРј IPv4 РєРѕРЅС‚СЂРѕР»СЊРЅСѓСЋ СЃСѓРјРјСѓ
	if destIP.String() != myVirtualIP {
		myIPBytes := net.ParseIP(myVirtualIP).To4()
		if myIPBytes != nil {
			copy(payload[16:20], myIPBytes)
			payload[10] = 0
			payload[11] = 0
			ipCS := tunnel.CalculateChecksum(payload[:ihl])
			payload[10] = byte(ipCS >> 8)
			payload[11] = byte(ipCS)
		}
	}

	atomic.AddUint64(&packetsRecvCount, 1)

	// Р—Р°РїРёСЃС‹РІР°РµРј РїР°РєРµС‚ РІ РІРёСЂС‚СѓР°Р»СЊРЅС‹Р№ Р°РґР°РїС‚РµСЂ Wintun РґР»СЏ РѕР±СЂР°Р±РѕС‚РєРё СЃРµС‚РµРІС‹Рј СЃС‚РµРєРѕРј Windows
	if tunDev != nil {
		_ = tunDev.WritePacket(payload)
	}
}

// negotiateVirtualIP РґРёРЅР°РјРёС‡РµСЃРєРё СЂР°Р·СЂРµС€Р°РµС‚ РєРѕРЅС„Р»РёРєС‚С‹ IP Р°РґСЂРµСЃРѕРІ РјРµР¶РґСѓ СѓР·Р»Р°РјРё
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
			logMsg := fmt.Sprintf("рџ¤ќ [P2P РЎРѕРіР»Р°СЃРѕРІР°РЅРёРµ] РЈСЂРµРіСѓР»РёСЂРѕРІР°РЅ РєРѕРЅС„Р»РёРєС‚ IP: РЈСЃС‚СЂРѕР№СЃС‚РІРѕ %s СѓСЃС‚СѓРїРёР»Рѕ %s Рё РїСЂРёРЅСЏР»Рѕ %s (Сѓ РїРёСЂР° %s: %s)", myDevID, oldIP, myVirtualIP, conflictDev, oldIP)
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
	if ipStr == "" || ipStr == "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ..." {
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
		Platform:         "рџЄџ Windows",
		CountryFlag:      network.LookupCountryFlag(ctx, ipStr),
		NetworkKey:       activeKey,
		Topic:            activeTopic,
	}

	if uiServer != nil {
		uiServer.SetAppState(myDevID, myPublicIP, mySTUNAddr, myVirtualIP)
		uiServer.SetVirtualIP(myVirtualIP)
		uiServer.SetDeviceName(myNick)
	}

	// рџ”Ќ РџСЂРѕРІРµСЂСЏРµРј, РµСЃС‚СЊ Р»Рё Р°РєС‚РёРІРЅС‹Рµ РїРѕРґРєР»СЋС‡РµРЅРЅС‹Рµ РїРёСЂС‹ (РїСЂСЏРјРѕР№ P2P РёР»Рё СЃРІРµР¶РёР№ РјР°СЏРє < 30 СЃРµРє)
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
			msg := "рџ’¤ [Telegram] РџСЂСЏРјРѕРµ СЃРѕРµРґРёРЅРµРЅРёРµ СѓСЃС‚Р°РЅРѕРІР»РµРЅРѕ! РћС‚РїСЂР°РІРєР° РІ Telegram РїСЂРёРѕСЃС‚Р°РЅРѕРІР»РµРЅР° РґР»СЏ СЌРєРѕРЅРѕРјРёРё СЃРѕРѕР±С‰РµРЅРёР№."
			addLog(msg)
			writeDebug(msg)
		}
	} else {
		if tgMuted {
			tgMuted = false
			msg := "вљЎ [Telegram] РЎРІСЏР·СЊ СЃ РїРёСЂР°РјРё РѕР±РѕСЂРІР°Р»Р°СЃСЊ! Telegram РєР°РЅР°Р» РІРѕР·РѕР±РЅРѕРІРёР» РѕС‚РїСЂР°РІРєСѓ РјР°СЏРєРѕРІ."
			addLog(msg)
			writeDebug(msg)
		}
	}

	for _, ch := range sigChannels {
		// Р•СЃР»Рё РїРёСЂС‹ РїРѕРґРєР»СЋС‡РµРЅС‹ Рё РєР°РЅР°Р» Telegram вЂ” РЅРµ СЃРїР°РјРёРј РІ С‡Р°С‚/РіСЂСѓРїРїСѓ
		if ch.Name() == "telegram" && hasDirectConnectedPeers {
			continue
		}

		go func(c signaling.SignalingChannel) {
			sendCtx, sendCancel := context.WithTimeout(ctx, 10*time.Second)
			defer sendCancel()
			if err := c.Send(sendCtx, payload); err == nil {
				atomic.AddUint64(&packetsSentCount, 1)
				msg := fmt.Sprintf("рџ“¤ [%s] РћС‚РїСЂР°РІР»РµРЅ Р°РЅРѕРЅСЃ РІ СЃРµС‚СЊ (VIP: %s | STUN: %s | LAN: %s)", c.Name(), myVirtualIP, mySTUNAddr, localAddr)
				addLog(msg)
				writeDebug(msg)
			} else {
				errMsg := fmt.Sprintf("вљ пёЏ [%s] РћС€РёР±РєР° РѕС‚РїСЂР°РІРєРё: %s", c.Name(), err.Error())
				addLog(errMsg)
				writeDebug(errMsg)
			}
		}(ch)
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

// updateData РІС‹Р·С‹РІР°РµС‚СЃСЏ СЃС‚СЂРѕРіРѕ РЅР° РіР»Р°РІРЅРѕРј UI РїРѕС‚РѕРєРµ РІ С‚Р°Р№РјРµСЂРµ
func updateData() {
	if isSplashActive {
		splashTicks++
		if tunDev != nil {
			setControlText(hSplashStep2, fmt.Sprintf("рџџў [ 2/4 ] рџ›ЎпёЏ Р’РёСЂС‚СѓР°Р»СЊРЅС‹Р№ Р°РґР°РїС‚РµСЂ 'NatBypass' Р°РєС‚РёРІРµРЅ (%s/24)", myVirtualIP))
		}
		if myPublicIP != "" && myPublicIP != "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ..." {
			setControlText(hSplashStep3, fmt.Sprintf("рџџў [ 3/4 ] рџЊђ Р’РЅРµС€РЅРёР№ IP: %s (STUN: %s)", myPublicIP, mySTUNAddr))
		}
		if len(sigChannels) > 0 {
			setControlText(hSplashStep4, fmt.Sprintf("рџџў [ 4/4 ] вљЎ РЎРёРіРЅР°Р»СЊРЅС‹Рµ РєР°РЅР°Р»С‹ РїРѕРґРєР»СЋС‡РµРЅС‹ (%s)", activeChannelStr))
		}

		if splashTicks >= 2 {
			hideSplashScreen()
		}
		return
	}

	ipStr := myPublicIP
	if ipStr == "" {
		ipStr = "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ..."
	}
	stunStr := mySTUNAddr
	if stunStr == "" {
		stunStr = "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ..."
	}

	devTitle := myDevID
	if myNick != "" {
		devTitle = fmt.Sprintf("%s (%s)", myNick, myDevID)
	}
	activeProfName := "РћСЃРЅРѕРІРЅР°СЏ СЃРµС‚СЊ"
	if cfg != nil {
		active := cfg.EnsureActiveProfile()
		if active != nil {
			activeProfName = active.Name
		}
	}
	infoText := fmt.Sprintf("РЎРµС‚СЊ: рџџў [%s] | %s | VIP: %s | Р’РЅРµС€РЅРёР№ IP: %s", activeProfName, devTitle, myVirtualIP, ipStr)
	setControlText(hLblIpInfo, infoText)

	chText := fmt.Sprintf("рџ“Ў РђРєС‚РёРІРЅС‹Р№ СЂРµР¶РёРј: %s", activeChannelStr)
	setControlText(hLblChannels, chText)

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
							mismatchPeerName = "в­ђ " + bm
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
			syncBtnLabel := fmt.Sprintf("рџ”„ РџСЂРёРјРµРЅРёС‚СЊ РЅР°СЃС‚СЂРѕР№РєРё AmneziaWG СЃ СѓР·Р»Р° [%s]", mismatchPeerName)
			buttonLabels[ID_BTN_SYNC_AWG] = syncBtnLabel
			buttonTypes[ID_BTN_SYNC_AWG] = "yellow"
			if currentTab == 1 && !isSplashActive && hBtnSyncAwg != 0 {
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

		// РђРІС‚РѕРјР°С‚РёС‡РµСЃРєР°СЏ РїСЂРѕРІРµСЂРєР° СЃРѕСЃС‚РѕСЏРЅРёСЏ РІС‹Р±СЂР°РЅРЅРѕРіРѕ Exit Node
		if activeExitNodeID != "" {
			peer, ok := registry.Get(activeExitNodeID)
			if !ok || !peer.Online || !peer.IsExitNode {
				if activeExitVIP != "" {
					_ = tunnel.DisableExitNodeRouting(activeExitVIP)
				}
				oldID := activeExitNodeID
				activeExitNodeID = ""
				activeExitVIP = ""
				buttonLabels[ID_BTN_EXIT_NODE_SELECT] = "рџЊђ Р’С‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚: Р›РѕРєР°Р»СЊРЅС‹Р№ (РћС‚РєР»СЋС‡РµРЅ)"
				buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "normal"
				if hBtnExitNodeSelect != 0 {
					procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
				}
				msg := fmt.Sprintf("вљ пёЏ Exit Node [%s] СЃС‚Р°Р» РЅРµРґРѕСЃС‚СѓРїРµРЅ РёР»Рё РѕС‚РєР»СЋС‡РёР» С€Р»СЋР·. РњР°СЂС€СЂСѓС‚ СЃР±СЂРѕС€РµРЅ РЅР° СЃС‚Р°РЅРґР°СЂС‚РЅС‹Р№ РёРЅС‚РµСЂРЅРµС‚.", oldID)
				addLog(msg)
				writeDebug(msg)
			} else {
				addressBookMu.RLock()
				bm := addressBook[peer.DeviceID]
				addressBookMu.RUnlock()
				peerDisplay := peer.Nickname
				if bm != "" {
					peerDisplay = "в­ђ " + bm
				} else if peerDisplay == "" {
					peerDisplay = peer.DeviceID
				}
				buttonLabels[ID_BTN_EXIT_NODE_SELECT] = fmt.Sprintf("рџџў РЁР»СЋР·: [%s] (%s)", peerDisplay, activeExitVIP)
				buttonTypes[ID_BTN_EXIT_NODE_SELECT] = "green"
				if hBtnExitNodeSelect != 0 {
					procInvalidateRect.Call(hBtnExitNodeSelect, 0, 1)
				}
			}
		}

		// Р РµР°Р»СЊРЅР°СЏ РІРµСЂРёС„РёРєР°С†РёСЏ СЃС‚Р°С‚СѓСЃР° РїСЂСЏРјРѕРіРѕ СЃРѕРµРґРёРЅРµРЅРёСЏ
		if directP2PCount > 0 {
			vpnConnected = true
			pingStr := ""
			if minRTT > 0 {
				pingStr = fmt.Sprintf(" | РџРёРЅРі: %v", minRTT.Round(time.Millisecond))
			}
			setControlText(hLblStatus, fmt.Sprintf("рџџў РџР РЇРњРђРЇ P2P РЎР’РЇР—Р¬ РђРљРўРР’РќРђ (%d РїРёСЂ(РѕРІ)%s)", directP2PCount, pingStr))
			buttonLabels[ID_BTN_VPN] = fmt.Sprintf("рџџў РџРћР”РљР›Р®Р§Р•РќРћ (РџСЂСЏРјРѕР№ P2P | VIP: %s%s)", myVirtualIP, pingStr)
			buttonTypes[ID_BTN_VPN] = "green"
			procInvalidateRect.Call(hBtnVpn, 0, 1)
		} else if onlineCount > 0 {
			vpnConnected = false
			setControlText(hLblStatus, fmt.Sprintf("рџџЎ РЎРР“РќРђР› Р’ РЎР•РўР (РРґС‘С‚ РїСЂСЏРјРѕРµ UDP РїСЂРѕР±РёС‚РёРµ NAT РґРѕ %d РїРёСЂРѕРІ...)", onlineCount))
			buttonLabels[ID_BTN_VPN] = fmt.Sprintf("рџџЎ РџР РћР‘РРўРР• NAT (РџРѕРїС‹С‚РєР° РїСЂСЏРјРѕРіРѕ СЃРѕРєРµС‚Р°... | VIP: %s)", myVirtualIP)
			buttonTypes[ID_BTN_VPN] = "yellow"
			procInvalidateRect.Call(hBtnVpn, 0, 1)
		} else {
			vpnConnected = false
			setControlText(hLblStatus, "рџџЎ РџРћРРЎРљ РЈРЎРўР РћР™РЎРўР’ Р’ РЎР•РўР...")
			buttonLabels[ID_BTN_VPN] = "рџ”ґ РћР–РР”РђРќРР• РЎР’РЇР—Р (0 РїРёСЂРѕРІ РѕРЅР»Р°Р№РЅ)"
			buttonTypes[ID_BTN_VPN] = "red"
			procInvalidateRect.Call(hBtnVpn, 0, 1)
		}

		if currentHash != lastPeersHash {
			lastPeersHash = currentHash
			procSendMessageW.Call(hListPeers, 0x0184, 0, 0)
			if len(peers) == 0 {
				addListBoxItem(hListPeers, "  рџ“Ў РћР¶РёРґР°РЅРёРµ РїРѕРґРєР»СЋС‡РµРЅРёСЏ РґСЂСѓРіРёС… СѓСЃС‚СЂРѕР№СЃС‚РІ... (0 РїРёСЂРѕРІ РѕРЅР»Р°Р№РЅ)")
			} else {
				for _, p := range peers {
					addressBookMu.RLock()
					bookmarkedName, isBookmarked := addressBook[p.DeviceID]
					addressBookMu.RUnlock()

					var nameDisplay string
					if isBookmarked && strings.TrimSpace(bookmarkedName) != "" {
						nameDisplay = fmt.Sprintf("[в­ђ %s]", strings.TrimSpace(bookmarkedName))
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
							icon = "рџџў"
							if p.Latency > 0 {
								statusDisplay = fmt.Sprintf("вљЎ РџСЂСЏРјРѕР№ P2P (%v)", p.Latency.Round(time.Millisecond))
							} else {
								statusDisplay = "вљЎ РџСЂСЏРјРѕР№ P2P (OK)"
							}
						} else {
							icon = "рџџЎ"
							statusDisplay = "рџџЎ РџСЂРѕР±РёС‚РёРµ NAT..."
						}
					} else {
						icon = "рџ”ґ"
						statusDisplay = "рџ”ґ РћС„Р»Р°Р№РЅ"
					}

					var addrDisplay string
					if p.LocalAddr != "" {
						addrDisplay = fmt.Sprintf("LAN: %s", p.LocalAddr)
					} else if p.STUNAddr != "" {
						addrDisplay = fmt.Sprintf("STUN: %s", p.STUNAddr)
					} else if p.PublicIP != "" {
						addrDisplay = fmt.Sprintf("WAN: %s", p.PublicIP)
					} else {
						addrDisplay = "LAN: вЂ”"
					}

					var extraTags []string
					if p.AWG != nil || p.DirectP2P {
						extraTags = append(extraTags, "[рџ›ЎпёЏ AWG 2.0]")
					}
					if p.IsExitNode {
						extraTags = append(extraTags, "[рџЊђ РЁР»СЋР·]")
					}
					if len(p.AdvertisedRoutes) > 0 {
						extraTags = append(extraTags, fmt.Sprintf("[рџЏ  РЎРµС‚СЊ: %s]", strings.Join(p.AdvertisedRoutes, ", ")))
					}
					if p.Online && p.AWG != nil && !awgParamsMatch(cachedAWGParams, p.AWG) {
						extraTags = append(extraTags, "[вљ пёЏ AWG: Р Р°Р·Р»РёС‡Р°РµС‚СЃСЏ]")
					}
					extraInfo := ""
					if len(extraTags) > 0 {
						extraInfo = " " + strings.Join(extraTags, " ")
					}

					platBadge := p.Platform
					if platBadge == "" {
						if p.OS != "" {
							platBadge = p.OS
						} else {
							platBadge = "рџ’» РЈСЃС‚СЂРѕР№СЃС‚РІРѕ"
						}
					}
					flag := p.CountryFlag
					if flag == "" {
						flag = "рџЊђ"
					}

					line1 := fmt.Sprintf("  %s %s [%s] (ID: %s)", icon, nameDisplay, platBadge, p.DeviceID)
					line2 := fmt.Sprintf("     в””в”Ђ рџЊђ VIP: %s | %s | %s %s%s", vip, statusDisplay, flag, addrDisplay, extraInfo)

					addListBoxItem(hListPeers, line1)
					addListBoxItem(hListPeers, line2)
				}
			}
			awgDirty = true
		}
	}

	if awgDirty && currentTab == 1 {
		awgDirty = false
		renderAWGTextFromUI()
	}

	if currentTab == 4 {
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
			writeDebug(fmt.Sprintf("вљ пёЏ Panic inside renderAWGTextFromUI: %v", r))
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
		privKeyDisplay = "(РљР»СЋС‡ РіРµРЅРµСЂРёСЂСѓРµС‚СЃСЏ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РїСЂРё Р·Р°РїСѓСЃРєРµ)"
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
				peerVIP := p.VirtualIP
				if peerVIP == "" {
					peerVIP = "100.64.200.2"
				}
				wgPeers = append(wgPeers, wireguard.WGPeer{
					PublicKey:  p.WGPubKey,
					AllowedIPs: []string{peerVIP + "/32"},
					Endpoint:   ep,
				})
			}
		}
	}

	awgCfg := wireguard.AWGConfig{
		WGConfig: wireguard.WGConfig{
			PrivateKey: privKeyDisplay,
			Address:    fmt.Sprintf("%s/24", myVirtualIP),
			ListenPort: 51820,
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
			writeDebug(fmt.Sprintf("вљ пёЏ Panic in fillConfigFields: %v", r))
		}
	}()

	writeDebug("Р’С‹Р·РѕРІ fillConfigFields()...")
	if cfg != nil {
		if hEditMyNick != 0 {
			setControlText(hEditMyNick, cfg.App.DeviceName)
		}

		allowExitNode = cfg.Network.AllowExitNode
		if hBtnAllowExit != 0 {
			if allowExitNode {
				buttonLabels[ID_BTN_ALLOW_EXIT] = "рџЊђ Р Р°Р·СЂРµС€РёС‚СЊ РІС‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· РјРµРЅСЏ: Р’РљР›"
				buttonTypes[ID_BTN_ALLOW_EXIT] = "green"
			} else {
				buttonLabels[ID_BTN_ALLOW_EXIT] = "рџЊђ Р Р°Р·СЂРµС€РёС‚СЊ РІС‹С…РѕРґ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· РјРµРЅСЏ: Р’Р«РљР›"
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
		msg := fmt.Sprintf("вљ пёЏ РћС€РёР±РєР° СЃРѕС…СЂР°РЅРµРЅРёСЏ РєРѕРЅС„РёРіР°: %v", err)
		addLog(msg)
		writeDebug(msg)
	} else {
		msg := "рџ’ѕ РќР°СЃС‚СЂРѕР№РєРё СЃРѕС…СЂР°РЅРµРЅС‹ РІ " + configPath
		addLog(msg)
		writeDebug(msg)
	}

	refreshProfilesUI()

	// РћС‡РёСЃС‚РєР° СѓСЃС‚Р°СЂРµРІС€РёС… РїРёСЂРѕРІ РїСЂРё СЃРјРµРЅРµ РєРѕРЅС„РёРіСѓСЂР°С†РёРё / С‚РѕРїРёРєР°
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
	buttonLabels[ID_BTN_SAVE_CFG] = "вњ“ РќРђРЎРўР РћР™РљР РЎРћРҐР РђРќР•РќР«!"
	procInvalidateRect.Call(hBtnSaveCfg, 0, 1)

	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_SAVE_CFG] = "рџ’ѕ РЎРѕС…СЂР°РЅРёС‚СЊ РЅР°СЃС‚СЂРѕР№РєРё РІ config.yaml"
		procInvalidateRect.Call(hBtnSaveCfg, 0, 1)
	})
}

func testTelegram() {
	tok := strings.TrimSpace(getControlText(hEditTgToken))
	chat := strings.TrimSpace(getControlText(hEditTgChat))
	if tok == "" {
		addLog("вљ пёЏ Р’РІРµРґРёС‚Рµ С‚РѕРєРµРЅ Р±РѕС‚Р°")
		return
	}
	buttonLabels[ID_BTN_TEST_TG] = "вЏі РџСЂРѕРІРµСЂРєР°..."
	procInvalidateRect.Call(hBtnTestTg, 0, 1)
	addLog("вЏі РџСЂРѕРІРµСЂРєР° Telegram Bot API...")
	writeDebug("РўРµСЃС‚РёСЂРѕРІР°РЅРёРµ Telegram Bot API...")
	go func() {
		ch := signaling.NewTelegramChannel(tok, chat, "")
		if ch.IsAvailable(context.Background()) {
			addLog("вњ… РЈСЃРїРµС…! Telegram Р±РѕС‚ Р°РєС‚РёРІРµРЅ Рё РѕС‚РІРµС‡Р°РµС‚ РЅР° Р·Р°РїСЂРѕСЃС‹.")
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
					succMsg := fmt.Sprintf("вњ“ РўРµСЃС‚РѕРІС‹Р№ РїР°РєРµС‚ СѓСЃРїРµС€РЅРѕ РѕС‚РїСЂР°РІР»РµРЅ РІ С‡Р°С‚ %s", chat)
					addLog(succMsg)
					writeDebug(succMsg)
				} else {
					failMsg := fmt.Sprintf("вљ пёЏ Р‘РѕС‚ Р°РєС‚РёРІРµРЅ, РЅРѕ РѕС‚РїСЂР°РІРєР° РІ С‡Р°С‚ %s РІРµСЂРЅСѓР»Р°: %s", chat, sendErr.Error())
					addLog(failMsg)
					writeDebug(failMsg)
				}
			}
			buttonLabels[ID_BTN_TEST_TG] = "вњ… Р‘РѕС‚ Р°РєС‚РёРІРµРЅ"
		} else {
			addLog("вќЊ РћС€РёР±РєР°: РЅРµ СѓРґР°Р»РѕСЃСЊ РїРѕРґРєР»СЋС‡РёС‚СЊСЃСЏ Рє Telegram API.")
			writeDebug("Telegram bot check FAILED")
			buttonLabels[ID_BTN_TEST_TG] = "вќЊ РћС€РёР±РєР°"
		}
		procInvalidateRect.Call(hBtnTestTg, 0, 1)
		time.AfterFunc(3*time.Second, func() {
			buttonLabels[ID_BTN_TEST_TG] = "рџ§Є РџСЂРѕРІРµСЂРёС‚СЊ Р±РѕС‚"
			procInvalidateRect.Call(hBtnTestTg, 0, 1)
		})
	}()
}

func testMQTT() {
	br := strings.TrimSpace(getControlText(hEditMqttBr))
	buttonLabels[ID_BTN_TEST_MQTT] = "вЏі РџСЂРѕРІРµСЂРєР°..."
	procInvalidateRect.Call(hBtnTestMqtt, 0, 1)
	addLog("вЏі РџСЂРѕРІРµСЂРєР° MQTT Р±СЂРѕРєРµСЂР°...")
	writeDebug("РўРµСЃС‚РёСЂРѕРІР°РЅРёРµ MQTT Р±СЂРѕРєРµСЂР°: " + br)
	go func() {
		ch := signaling.NewMQTTChannel(br, "test", "tester-"+strconv.Itoa(int(time.Now().UnixNano()%10000)), "", "")
		if ch.IsAvailable(context.Background()) {
			addLog("вњ… РЈСЃРїРµС…! MQTT Р±СЂРѕРєРµСЂ РґРѕСЃС‚СѓРїРµРЅ.")
			writeDebug("MQTT broker is available!")
			buttonLabels[ID_BTN_TEST_MQTT] = "вњ… Р”РѕСЃС‚СѓРїРµРЅ"
		} else {
			addLog("вќЊ РћС€РёР±РєР°: MQTT Р±СЂРѕРєРµСЂ РЅРµРґРѕСЃС‚СѓРїРµРЅ.")
			writeDebug("MQTT broker check FAILED")
			buttonLabels[ID_BTN_TEST_MQTT] = "вќЊ РќРµРґРѕСЃС‚СѓРїРµРЅ"
		}
		procInvalidateRect.Call(hBtnTestMqtt, 0, 1)
		time.AfterFunc(3*time.Second, func() {
			buttonLabels[ID_BTN_TEST_MQTT] = "рџ§Є РџСЂРѕРІРµСЂРёС‚СЊ MQTT"
			procInvalidateRect.Call(hBtnTestMqtt, 0, 1)
		})
	}()
}

func runDiag() {
	buttonLabels[ID_BTN_RUN_DIAG] = "вЏі Р’С‹РїРѕР»РЅСЏРµС‚СЃСЏ РґРёР°РіРЅРѕСЃС‚РёРєР°..."
	procInvalidateRect.Call(hBtnRunDiag, 0, 1)
	setControlText(hEditDiagLog, "вЏі Р’С‹РїРѕР»РЅСЏРµС‚СЃСЏ РєРѕРјРїР»РµРєСЃРЅР°СЏ РїСЂРѕРІРµСЂРєР° СЃРІСЏР·РЅРѕСЃС‚Рё СЃРµС‚Рё...\r\n")
	writeDebug("Р—Р°РїСѓСЃРє СЃРёСЃС‚РµРјРЅРѕР№ РґРёР°РіРЅРѕСЃС‚РёРєРё СЃРµС‚Рё...")
	go func() {
		res := "в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ\r\n"
		res += "              РЎРРЎРўР•РњРќРђРЇ Р”РРђР“РќРћРЎРўРРљРђ & Р”Р•Р‘РђР“Р“Р•Р  NATBYPASS            \r\n"
		res += "в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ\r\n\r\n"

		// 1. РРЅС‚РµСЂРЅРµС‚
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
			res += "вњ… 1. РЎРµС‚СЊ РРЅС‚РµСЂРЅРµС‚: Р”РћРЎРўРЈРџРќРђ (DNS 1.1.1.1/8.8.8.8 РѕС‚РІРµС‡Р°РµС‚)\r\n"
		} else {
			res += "вљ пёЏ 1. РЎРµС‚СЊ РРЅС‚РµСЂРЅРµС‚: РћРіСЂР°РЅРёС‡РµРЅР° (РїСЂРѕРІРµСЂСЊС‚Рµ С€Р»СЋР·)\r\n"
		}

		// 2. IP Р°РґСЂРµСЃР°
		lanIP := getLocalLANIP()
		res += fmt.Sprintf("рџЏ  2. Р›РѕРєР°Р»СЊРЅС‹Р№ LAN IP: %s (РџРѕСЂС‚ :51820 РѕС‚РєСЂС‹С‚)\r\n", lanIP)

		if myPublicIP != "" && myPublicIP != "0.0.0.0" {
			res += fmt.Sprintf("рџЊђ 3. Р’РЅРµС€РЅРёР№ РїСѓР±Р»РёС‡РЅС‹Р№ IP: %s\r\n", myPublicIP)
		} else {
			res += "вљ пёЏ 3. Р’РЅРµС€РЅРёР№ РїСѓР±Р»РёС‡РЅС‹Р№ IP: РћР¶РёРґР°РЅРёРµ РѕС‚РІРµС‚Р° STUN...\r\n"
		}

		// 3. STUN Hole Punch
		if mySTUNAddr != "" {
			res += fmt.Sprintf("вљЎ 4. STUN UDP РЎРѕРєРµС‚: %s (РџСЂСЏРјРѕР№ Hole Punching Р°РєС‚РёРІРµРЅ)\r\n", mySTUNAddr)
		} else {
			res += "вљ пёЏ 4. STUN UDP РЎРѕРєРµС‚: РћР¶РёРґР°РЅРёРµ СЃРІСЏР·С‹РІР°РЅРёСЏ СЃРѕРєРµС‚Р°...\r\n"
		}

		// 4. РџРёСЂС‹
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
		res += fmt.Sprintf("рџ‘Ґ 5. РЈСЃС‚СЂРѕР№СЃС‚РІ РІ СЃРёРіРЅР°Р»СЊРЅРѕР№ СЃРµС‚Рё: %d (Р’Р°С€ IP РІ Mesh: %s)\r\n", peersCount, myVirtualIP)
		res += fmt.Sprintf("рџљЂ 6. РџСЂРѕР±РёС‚С‹С… РїСЂСЏРјС‹С… UDP СЃРѕРєРµС‚РѕРІ: %d РёР· %d\r\n", directP2PCount, peersCount)

		// 5. РЎРёРіРЅР°Р»С‹ Рё СЃС‚Р°С‚РёСЃС‚РёРєР°
		pIn := atomic.LoadUint64(&packetsRecvCount)
		pOut := atomic.LoadUint64(&packetsSentCount)
		res += fmt.Sprintf("рџ“Ў 7. РђРєС‚РёРІРЅС‹Р№ СЂРµР¶РёРј: %s\r\n", activeChannelStr)
		res += fmt.Sprintf("рџ“Љ 8. РџР°РєРµС‚РѕРІ РѕС‚РїСЂР°РІР»РµРЅРѕ/РїСЂРёРЅСЏС‚Рѕ: %d / %d\r\n", pOut, pIn)
		res += fmt.Sprintf("вЏ±пёЏ 9. Р’СЂРµРјСЏ РЅРµРїСЂРµСЂС‹РІРЅРѕР№ СЂР°Р±РѕС‚С‹ РїСЂРѕС†РµСЃСЃР°: %v\r\n\r\n", time.Since(startTime).Round(time.Second))

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		res += fmt.Sprintf("рџ§  10. РџРѕС‚РѕРєРё Рё РїР°РјСЏС‚СЊ: %d Р“РѕСЂСѓС‚РёРЅ | %.2f MB RAM | GC Р¦РёРєР»РѕРІ: %d\r\n\r\n", runtime.NumGoroutine(), float64(m.Alloc)/(1024*1024), m.NumGC)
		res += "вњ“ РљРѕРјРїР»РµРєСЃРЅР°СЏ РїСЂРѕРІРµСЂРєР° СѓСЃРїРµС€РЅРѕ Р·Р°РІРµСЂС€РµРЅР°."

		setControlText(hEditDiagLog, res)
		addLog("рџ©є РљРѕРјРїР»РµРєСЃРЅР°СЏ РґРёР°РіРЅРѕСЃС‚РёРєР° СЃРёСЃС‚РµРјС‹ СѓСЃРїРµС€РЅРѕ РІС‹РїРѕР»РЅРµРЅР°")
		writeDebug("Р РµР·СѓР»СЊС‚Р°С‚ РґРёР°РіРЅРѕСЃС‚РёРєРё:\r\n" + res)

		buttonLabels[ID_BTN_RUN_DIAG] = "рџ”„ Р—Р°РїСѓСЃС‚РёС‚СЊ РїРѕРІС‚РѕСЂРЅРѕ"
		procInvalidateRect.Call(hBtnRunDiag, 0, 1)
	}()
}

// dumpGoroutineStack вЂ” РјРіРЅРѕРІРµРЅРЅС‹Р№ СЃРЅРёРјРѕРє РІСЃРµС… РїРѕС‚РѕРєРѕРІ Рё РіРѕСЂСѓС‚РёРЅ
func dumpGoroutineStack() {
	buf := make([]byte, 65536)
	n := runtime.Stack(buf, true)
	stackDump := string(buf[:n])

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	header := fmt.Sprintf("в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ\r\n"+
		"           РЎРќРРњРћРљ РЎРўР•РљРђ РџРћРўРћРљРћР’ & РџРђРњРЇРўР (GOROUTINE DUMP)           \r\n"+
		"в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ\r\n"+
		"Р’СЂРµРјСЏ: %s | Р“РѕСЂСѓС‚РёРЅ: %d | Р’С‹РґРµР»РµРЅРѕ RAM: %.2f MB | Sys RAM: %.2f MB\r\n\r\n",
		time.Now().Format("2006-01-02 15:04:05.000"), runtime.NumGoroutine(),
		float64(m.Alloc)/(1024*1024), float64(m.Sys)/(1024*1024))

	fullDump := header + stackDump
	setControlText(hEditDiagLog, fullDump)

	dumpFile := fmt.Sprintf("natbypass_stack_%d.log", time.Now().Unix())
	_ = os.WriteFile(dumpFile, []byte(fullDump), 0644)

	addLog("вљЎ РЎРЅРёРјРѕРє РїРѕС‚РѕРєРѕРІ Рё РїР°РјСЏС‚Рё СЃРѕС…СЂР°РЅРµРЅ РІ " + dumpFile)
	writeDebug("РЎРЅРёРјРѕРє РїРѕС‚РѕРєРѕРІ СЃРѕС…СЂР°РЅРµРЅ РІ " + dumpFile)

	buttonLabels[ID_BTN_DUMP_STACK] = "вњ“ РЎРќРРњРћРљ Р“РћРўРћР’!"
	procInvalidateRect.Call(hBtnDumpStack, 0, 1)
	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_DUMP_STACK] = "вљЎ РЎРЅРёРјРѕРє РїР°РјСЏС‚Рё Рё РїРѕС‚РѕРєРѕРІ"
		procInvalidateRect.Call(hBtnDumpStack, 0, 1)
	})
}

func saveLogsToFile() {
	logsMutex.Lock()
	allLogs := strings.Join(logsBuffer, "\r\n")
	logsMutex.Unlock()

	fileName := fmt.Sprintf("natbypass_events_%d.log", time.Now().Unix())
	_ = os.WriteFile(fileName, []byte(allLogs), 0644)

	addLog("рџ’ѕ Р–СѓСЂРЅР°Р» СЃРѕР±С‹С‚РёР№ СѓСЃРїРµС€РЅРѕ СЌРєСЃРїРѕСЂС‚РёСЂРѕРІР°РЅ РІ " + fileName)
	buttonLabels[ID_BTN_SAVE_LOGS] = "вњ“ Р­РљРЎРџРћР РўРР РћР’РђРќРћ!"
	procInvalidateRect.Call(hBtnSaveLogs, 0, 1)
	time.AfterFunc(2*time.Second, func() {
		buttonLabels[ID_BTN_SAVE_LOGS] = "рџ’ѕ Р­РєСЃРїРѕСЂС‚ Р»РѕРіР°"
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
	hFont, _, _ := procCreateFontW.Call(
		uintptr(int32(h)), 0, 0, 0,
		uintptr(weight), 0, 0, 0,
		1, 0, 0, 0, 0,
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


