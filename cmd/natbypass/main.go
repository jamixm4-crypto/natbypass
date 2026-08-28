package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/daemon"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/tray"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
)
var (
	Version   = "1.8.6"
	Commit    = "release"
	BuildDate = "unknown"

	// Р’С€РёС‚С‹Рµ СѓРјРѕР»С‡Р°РЅРёСЏ (Р·Р°РґР°СЋС‚СЃСЏ С‡РµСЂРµР· build-win.ps1 / build-linux.sh)
	DefaultTgToken    = "" // РўРѕРєРµРЅ Telegram-Р±РѕС‚Р°
	DefaultTgChatID   = "" // ID С‡Р°С‚Р°/РєР°РЅР°Р»Р° Telegram
	DefaultMQTTBroker = "" // URL MQTT-Р±СЂРѕРєРµСЂР°
	DefaultMQTTTopic  = "" // MQTT-С‚РѕРїРёРє
	DefaultWebhookURL = "" // URL HTTP Webhook
	DefaultDeviceID   = "" // РРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ СѓСЃС‚СЂРѕР№СЃС‚РІР°
	DefaultWebUIPort  = "8080"
	DefaultWebUIUser  = "admin"
	DefaultWebUIPass  = ""
	DefaultLogLevel   = "info"
)

var (
	configFile string
	logLevel   string
	noWebUI    bool
	webUIPort  int
	useTray    bool
)

func main() {
	// Р•СЃР»Рё РїСЂРѕС†РµСЃСЃ Р·Р°РїСѓС‰РµРЅ РїРѕРґ СѓРїСЂР°РІР»РµРЅРёРµРј Windows Service Manager
	if daemon.IsWindowsService() {
		err := daemon.RunService(func(ctx context.Context) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				cfg = buildDefaultConfig()
			}
			applyBuiltinDefaults(cfg)
			return runEngine(ctx, cfg, false)
		})
		if err != nil {
			os.Exit(1)
		}
		return
	}

	rootCmd := &cobra.Command{
		Use:   "natbypass",
		Short: "NatBypass вЂ” РѕР±С…РѕРґ NAT Рё РѕСЂРіР°РЅРёР·Р°С†РёСЏ P2P-РґРѕСЃС‚СѓРїР°",
		Long: fmt.Sprintf(`NatBypass v%s (%s) вЂ” РєСЂРѕСЃСЃРїР»Р°С‚С„РѕСЂРјРµРЅРЅС‹Р№ РёРЅСЃС‚СЂСѓРјРµРЅС‚ 
РґР»СЏ РѕР±С…РѕРґР° NAT (РІРєР»СЋС‡Р°СЏ РґРІРѕР№РЅРѕР№ NAT / CGNAT) С‡РµСЂРµР· РјСѓР»СЊС‚РёРєР°РЅР°Р»СЊРЅСѓСЋ СЃРёРіРЅР°Р»РёР·Р°С†РёСЋ.

РџРѕРґРґРµСЂР¶РёРІР°РµРјС‹Рµ РєР°РЅР°Р»С‹: Telegram, MQTT, HTTP Webhook, DNS TXT
РџРѕРґРґРµСЂР¶РёРІР°РµРјС‹Рµ РїР»Р°С‚С„РѕСЂРјС‹: Windows, Linux (amd64/arm64/mips/mipsle), Android, iOS`, Version, Commit),
		RunE: func(cmd *cobra.Command, args []string) error {
			// РџРѕ СѓРјРѕР»С‡Р°РЅРёСЋ РїСЂРё Р·Р°РїСѓСЃРєРµ Р±РµР· Р°СЂРіСѓРјРµРЅС‚РѕРІ (РґРІРѕР№РЅРѕР№ РєР»РёРє РїРѕ .exe) Р·Р°РїСѓСЃРєР°РµРј СЃРµСЂРІРёСЃ
			cfg, err := config.Load(configFile)
			if err != nil {
				if os.IsNotExist(err) {
					cfg = buildDefaultConfig()
				} else {
					return fmt.Errorf("РѕС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё РєРѕРЅС„РёРіР°: %w", err)
				}
			}
			applyBuiltinDefaults(cfg)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if runtime.GOOS == "windows" {
				p := cfg.WebUI.Port
				if webUIPort > 0 { p = webUIPort }
				if p == 0 { p = 8080 }
				if !acquireSingleInstanceMutex(p) {
					return nil
				}
			}
			return runEngine(ctx, cfg, runtime.GOOS == "windows")
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yaml", "РїСѓС‚СЊ Рє config.yaml")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "СѓСЂРѕРІРµРЅСЊ Р»РѕРіРёСЂРѕРІР°РЅРёСЏ: debug/info/warn/error")
	rootCmd.PersistentFlags().BoolVar(&noWebUI, "no-webui", false, "РѕС‚РєР»СЋС‡РёС‚СЊ Web UI")
	rootCmd.PersistentFlags().IntVar(&webUIPort, "port", 0, "РїРµСЂРµРѕРїСЂРµРґРµР»РёС‚СЊ РїРѕСЂС‚ Web UI")

	rootCmd.AddCommand(
		newStartCmd(),
		newGuiCmd(),
		newServiceCmd(),
		newStopCmd(),
		newStatusCmd(),
		newKeygenCmd(),
		newWGCmd(),
		newInstallCmd(),
		newAntGravityCmd(),
		newKonamiCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// в”Ђв”Ђ start в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Р—Р°РїСѓСЃС‚РёС‚СЊ NatBypass (РѕСЃРЅРѕРІРЅРѕР№ С†РёРєР»)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				if os.IsNotExist(err) {
					cfg = buildDefaultConfig()
					ensureConfigFileExists(configFile)
				} else {
					return fmt.Errorf("РѕС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё РєРѕРЅС„РёРіР°: %w", err)
				}
			}
			applyBuiltinDefaults(cfg)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			return runEngine(ctx, cfg, useTray)
		},
	}
	cmd.Flags().BoolVarP(&useTray, "tray", "t", runtime.GOOS == "windows", "СЃРІРѕСЂР°С‡РёРІР°С‚СЊ РІ СЃРёСЃС‚РµРјРЅС‹Р№ С‚СЂРµР№ (Windows)")
	return cmd
}

// в”Ђв”Ђ gui (Р·Р°РїСѓСЃРє СЃ С‚СЂРµРµРј РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newGuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gui",
		Short: "Р—Р°РїСѓСЃС‚РёС‚СЊ NatBypass РІ РіСЂР°С„РёС‡РµСЃРєРѕРј СЂРµР¶РёРјРµ СЃ РёРєРѕРЅРєРѕР№ РІ С‚СЂРµРµ",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				cfg = buildDefaultConfig()
				ensureConfigFileExists(configFile)
			}
			applyBuiltinDefaults(cfg)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			return runEngine(ctx, cfg, true)
		},
	}
}

// в”Ђв”Ђ service (Windows Service СѓРїСЂР°РІР»РµРЅРёРµ) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newServiceCmd() *cobra.Command {
	svcCmd := &cobra.Command{
		Use:   "service",
		Short: "РЈРїСЂР°РІР»РµРЅРёРµ СЃР»СѓР¶Р±РѕР№ Windows (install, uninstall, start, stop, status)",
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "РЈСЃС‚Р°РЅРѕРІРёС‚СЊ NatBypass РєР°Рє СЃРёСЃС‚РµРјРЅСѓСЋ СЃР»СѓР¶Р±Сѓ Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.InstallService(configFile)
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° СѓСЃС‚Р°РЅРѕРІРєРё СЃР»СѓР¶Р±С‹: %w", err)
			}
			fmt.Println("вњ“ РЎР»СѓР¶Р±Р° NatBypass СѓСЃРїРµС€РЅРѕ СѓСЃС‚Р°РЅРѕРІР»РµРЅР° РІ Windows!")
			fmt.Println("  РўРёРї Р·Р°РїСѓСЃРєР°: РђРІС‚РѕРјР°С‚РёС‡РµСЃРєРё")
			fmt.Println("  Р”Р»СЏ Р·Р°РїСѓСЃРєР° РІС‹РїРѕР»РЅРёС‚Рµ: natbypass service start")
			return nil
		},
	}

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "РЈРґР°Р»РёС‚СЊ СЃР»СѓР¶Р±Сѓ NatBypass РёР· Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.UninstallService()
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° СѓРґР°Р»РµРЅРёСЏ СЃР»СѓР¶Р±С‹: %w", err)
			}
			fmt.Println("вњ“ РЎР»СѓР¶Р±Р° NatBypass СѓРґР°Р»РµРЅР° РёР· СЃРёСЃС‚РµРјС‹.")
			return nil
		},
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Р—Р°РїСѓСЃС‚РёС‚СЊ СѓСЃС‚Р°РЅРѕРІР»РµРЅРЅСѓСЋ СЃР»СѓР¶Р±Сѓ Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.StartWindowsService()
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° Р·Р°РїСѓСЃРєР° СЃР»СѓР¶Р±С‹: %w", err)
			}
			fmt.Println("вњ“ РЎР»СѓР¶Р±Р° NatBypass Р·Р°РїСѓС‰РµРЅР°.")
			return nil
		},
	}

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "РћСЃС‚Р°РЅРѕРІРёС‚СЊ СЃР»СѓР¶Р±Сѓ Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.StopWindowsService()
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° РѕСЃС‚Р°РЅРѕРІРєРё СЃР»СѓР¶Р±С‹: %w", err)
			}
			fmt.Println("вњ“ РЎР»СѓР¶Р±Р° NatBypass РѕСЃС‚Р°РЅРѕРІР»РµРЅР°.")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "РџСЂРѕРІРµСЂРёС‚СЊ СЃС‚Р°С‚СѓСЃ СЃР»СѓР¶Р±С‹ Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := daemon.QueryServiceStatus()
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° РїРѕР»СѓС‡РµРЅРёСЏ СЃС‚Р°С‚СѓСЃР° СЃР»СѓР¶Р±С‹: %w", err)
			}
			fmt.Printf("РЎС‚Р°С‚СѓСЃ СЃР»СѓР¶Р±С‹ Windows: %s\n", st)
			return nil
		},
	}

	svcCmd.AddCommand(installCmd, uninstallCmd, startCmd, stopCmd, statusCmd)
	return svcCmd
}

// в”Ђв”Ђ РћСЃРЅРѕРІРЅРѕР№ РґРІРёР¶РѕРє в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func runEngine(ctx context.Context, cfg *config.Config, enableTray bool) error {
	setupLogging(cfg.App.LogLevel, cfg.App.LogFile)
	log.Info().
		Str("version", Version).
		Str("commit", Commit).
		Str("config", configFile).
		Msg("Р—Р°РїСѓСЃРє NatBypass")

	pubKey, privKey, err := loadOrGenerateKeys(cfg)
	if err != nil {
		return fmt.Errorf("РѕС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё РєР»СЋС‡РµР№: %w", err)
	}
	log.Info().Str("public_key", crypto.KeyToHex(pubKey)).Msg("NaCl РєР»СЋС‡Рё Р·Р°РіСЂСѓР¶РµРЅС‹")

	deviceID := cfg.App.DeviceID
	if deviceID == "" {
		if hn, err := os.Hostname(); err == nil && hn != "" {
			deviceID = hn
		} else {
			deviceID = generateDeviceID(pubKey)
		}
	}
	log.Info().Str("device_id", deviceID).Msg("РРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ СѓСЃС‚СЂРѕР№СЃС‚РІР°")

	myVirtualIP := "100.64.200.1"
	if cfg.Network.Address != "" {
		myVirtualIP = strings.Split(cfg.Network.Address, "/")[0]
	} else if activeProf := cfg.EnsureActiveProfile(); activeProf != nil && activeProf.VirtualIP != "" {
		myVirtualIP = strings.Split(activeProf.VirtualIP, "/")[0]
	} else {
		h := sha256.Sum256([]byte(deviceID))
		octet := int(h[0]%250) + 2
		myVirtualIP = fmt.Sprintf("100.64.200.%d", octet)
	}

	engineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	registry := peer.NewRegistry()
	registry.StartMonitor(engineCtx, 2*time.Minute)

	channels, err := buildSignalingChannels(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("РћС€РёР±РєР° РїР°СЂСЃРёРЅРіР° РєР°РЅР°Р»РѕРІ, РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ РїСѓР±Р»РёС‡РЅС‹Р№ СЂРµР·РµСЂРІРЅС‹Р№ РєР°РЅР°Р»")
	}
	if len(channels) == 0 {
		log.Warn().Msg("вљ пёЏ РЎРёРіРЅР°Р»СЊРЅС‹Рµ РєР°РЅР°Р»С‹ РЅРµ РЅР°СЃС‚СЂРѕРµРЅС‹ РІ РєРѕРЅС„РёРіРµ. Р’РєР»СЋС‡РµРЅ СЂРµР·РµСЂРІРЅС‹Р№ РїСѓР±Р»РёС‡РЅС‹Р№ MQTT Р±СЂРѕРєРµСЂ (topic: natbypass/public/peers). Р’С‹ РјРѕР¶РµС‚Рµ РЅР°СЃС‚СЂРѕРёС‚СЊ Р»РёС‡РЅС‹Р№ Telegram-Р±РѕС‚ РІ Web UI (http://localhost:8080) РёР»Рё С„Р°Р№Р»Рµ config.yaml")
		channels = append(channels, signaling.NewMQTTChannel("tcp://mqtt.eclipseprojects.io:1883", "natbypass/public/peers", deviceID, "", ""))
	}
	sigMgr := signaling.NewFallbackManager(channels)
	log.Info().Int("channels", len(channels)).Str("current", sigMgr.CurrentChannel()).Msg("РЎРёРіРЅР°Р»СЊРЅС‹Рµ РєР°РЅР°Р»С‹ РёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅС‹")

	port := cfg.WebUI.Port
	if webUIPort > 0 {
		port = webUIPort
	}
	if port == 0 {
		port = 8080
	}

	var uiServer *webui.Server
	if !noWebUI && cfg.WebUI.Enabled {
		uiServer = webui.NewServer(port, cfg.WebUI.Username, cfg.WebUI.Password, registry, sigMgr)
		uiServer.SetConfigPath(configFile)
		uiServer.SetAppState(deviceID, "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ...", "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ...")
		uiServer.SetDeviceName(deviceID)
		uiServer.SetVersion(Version)
		uiServer.SetVirtualIP(myVirtualIP)
		uiServer.AddEvent("info", "NatBypass Р·Р°РїСѓС‰РµРЅ", "version="+Version)
		go func() {
			if err := uiServer.Start(engineCtx); err != nil {
				log.Error().Err(err).Msg("Web UI РѕСЃС‚Р°РЅРѕРІР»РµРЅ")
			}
		}()
	}

	var stunAddr string
	var publicIP net.IP = net.IPv4(0, 0, 0, 0)
	ipDisc := network.NewDiscoverer(cfg.Network.IPApis, time.Duration(cfg.Network.IPTimeout)*time.Second)

	udpListenPort := cfg.Network.UDPPort
	if udpListenPort <= 0 {
		udpListenPort = 47832
	}
	udpPuncher, punchErr := network.NewUDPPuncher(udpListenPort, deviceID, cfg.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		log.Info().Str("peer", remoteDevID).Float64("rtt_ms", float64(rtt.Microseconds())/1000.0).Str("from", fromAddr).Msg("⚡ [P2P Direct UDP] ПОДТВЕРЖДЕНО! Прямой UDP-пинг установлен")
		if p, ok := registry.Get(remoteDevID); ok && p != nil {
			p.Latency = rtt
			p.ActiveEndpoint = fromAddr
			registry.Upsert(p)
		}
	})
	if punchErr == nil && udpPuncher != nil {
		log.Info().Int("port", udpPuncher.LocalPort()).Msg("UDPPuncher активен (постоянный сокет)")
		defer udpPuncher.Close()
	}

	// Р¤РѕРЅРѕРІРѕРµ РїРµСЂРІРѕРЅР°С‡Р°Р»СЊРЅРѕРµ РѕРїСЂРµРґРµР»РµРЅРёРµ IP Рё STUN
	go func() {
		if ip, err := ipDisc.GetPublicIPCached(engineCtx, 5*time.Minute); err == nil {
			publicIP = ip
			log.Info().Str("ip", publicIP.String()).Msg("РџСѓР±Р»РёС‡РЅС‹Р№ IP РѕРїСЂРµРґРµР»С‘РЅ")
		}

		if udpPuncher != nil {
			if extIP, port, err := udpPuncher.DiscoverMappedAddress(engineCtx); err == nil && extIP != nil {
				stunAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
				log.Info().Str("stun_addr", stunAddr).Msg("STUN сокет определён через UDPPuncher")
			}
		}
		stunClient := network.NewSTUNClient(cfg.Network.StunServers)
		if stunIP, stunPort, stunErr := stunClient.GetMappedAddress(engineCtx); stunErr == nil {
			stunAddr = fmt.Sprintf("%s:%d", stunIP.String(), stunPort)
			log.Info().Str("stun_addr", stunAddr).Msg("STUN Р°РґСЂРµСЃ РѕРїСЂРµРґРµР»С‘РЅ")
		}

		if cfg.Network.UpnpEnabled {
			upnpClient := network.NewUPnPClient()
			if upnpClient.IsAvailable() {
				log.Info().Msg("UPnP РґРѕСЃС‚СѓРїРµРЅ")
			}
		}

		if uiServer != nil {
			uiServer.SetAppState(deviceID, publicIP.String(), stunAddr)
		}
	}()

	var wgPubKey string
	var wgPort int
	if cfg.WireGuard.Enabled {
		wgKP, wgErr := wireguard.GenerateKeyPair()
		if wgErr == nil {
			wgPubKey = wgKP.PublicKey
			wgPort = cfg.WireGuard.ListenPort
		}
	}

	publishInterval := time.Duration(cfg.App.PublishInterval) * time.Second
	if publishInterval == 0 {
		publishInterval = 8 * time.Second
	}

	// Р¦РёРєР» РїСѓР±Р»РёРєР°С†РёРё
	go func() {
		ticker := time.NewTicker(publishInterval)
		defer ticker.Stop()
		for {
			select {
			case <-engineCtx.Done():
				return
			case <-ticker.C:
				ip, _ := ipDisc.GetPublicIPCached(engineCtx, publishInterval/2)
				var awgParams *signaling.AWGParams
				if cfg.WireGuard.AWG.Enabled {
					awgParams = &signaling.AWGParams{
						Jc:   cfg.WireGuard.AWG.Jc,
						Jmin: cfg.WireGuard.AWG.Jmin,
						Jmax: cfg.WireGuard.AWG.Jmax,
						S1:   cfg.WireGuard.AWG.S1,
						S2:   cfg.WireGuard.AWG.S2,
						H1:   fmt.Sprintf("%d", cfg.WireGuard.AWG.H1),
						H2:   fmt.Sprintf("%d", cfg.WireGuard.AWG.H2),
						H3:   fmt.Sprintf("%d", cfg.WireGuard.AWG.H3),
						H4:   fmt.Sprintf("%d", cfg.WireGuard.AWG.H4),
					}
				}
				if udpPuncher != nil {
					if extIP, port, err := udpPuncher.DiscoverMappedAddress(engineCtx); err == nil && extIP != nil {
						stunAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
					}
					for _, peerObj := range registry.List() {
						if peerObj.STUNAddr != "" {
							_ = udpPuncher.SendKeepAlive(peerObj.STUNAddr)
						}
					}
				}
				if uiServer != nil {
					uiServer.SetAppState(deviceID, ip.String(), stunAddr)
					uiServer.SetVirtualIP(myVirtualIP)
				}
				payload := &signaling.Payload{
					DeviceID:  deviceID,
					PublicKey: crypto.KeyToHex(pubKey),
					PublicIP:  ip.String(),
					STUNAddr:  stunAddr,
					WGPubKey:  wgPubKey,
					WGPort:    wgPort,
					Timestamp: time.Now(),
					VirtualIP: myVirtualIP,
					AWG:       awgParams,
				}
				encrypted, encErr := signaling.EncryptPayload(payload, pubKey, privKey)
				if encErr != nil {
					continue
				}
				sigMgr.Send(engineCtx, encrypted)
			}
		}
	}()

	// Р¦РёРєР» РїСЂРёРµРјР°
	inCh, err := sigMgr.Receive(engineCtx)
	if err == nil {
		go func() {
			for {
				select {
				case <-engineCtx.Done():
					return
				case p, ok := <-inCh:
					if !ok {
						return
					}
					if len(p.Encrypted) > 0 {
						decrypted, decErr := signaling.DecryptPayload(p, pubKey, privKey)
						if decErr == nil {
							p = decrypted
						}
					}
					if p.DeviceID == deviceID {
						continue
					}
					if p.STUNAddr != "" && udpPuncher != nil {
						_ = udpPuncher.SendHolePunchProbe(p.STUNAddr)
					}
					registry.Upsert(&peer.Peer{
						DeviceID:  p.DeviceID,
						PublicKey: p.PublicKey,
						PublicIP:  p.PublicIP,
						STUNAddr:  p.STUNAddr,
						WGPubKey:  p.WGPubKey,
						WGPort:    p.WGPort,
						VirtualIP: p.VirtualIP,
						IsExitNode: p.IsExitNode,
						AdvertisedRoutes: p.AdvertisedRoutes,
						LastSeen:  p.Timestamp,
						Online:    true,
						AWG:       p.AWG,
					})
				}
			}
		}()
	}

	// SIGHUP РїРµСЂРµР·Р°РіСЂСѓР·РєР° РєРѕРЅС„РёРіР°
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			log.Info().Msg("SIGHUP: РїРµСЂРµР·Р°РіСЂСѓР·РєР° РєРѕРЅС„РёРіР°...")
			config.Reload(cfg, configFile)
		}
	}()

	// Р•СЃР»Рё РІРєР»СЋС‡РµРЅ СЂРµР¶РёРј С‚СЂРµСЏ (РЅР° Windows)
	if enableTray && runtime.GOOS == "windows" {
		trayApp := tray.NewTray(tray.TrayOptions{
			WebUIPort:  port,
			ConfigPath: configFile,
			GetWebUIPort: func() int {
				if uiServer != nil {
					return uiServer.GetPort()
				}
				return port
			},
			OnRefreshIP: func() {
				ipDisc.GetPublicIP(engineCtx)
			},
			OnExit: func() {
				cancel()
			},
			GetStatusText: func() string {
				ch := sigMgr.CurrentChannel()
				if ch == "" {
					ch = "РЅРµС‚"
				}
				return fmt.Sprintf("рџ’Ў РЎС‚Р°С‚СѓСЃ: РћРЅР»Р°Р№РЅ (РљР°РЅР°Р»: %s)", ch)
			},
		})
		log.Info().Msg("Р—Р°РїСѓС‰РµРЅ СЃРёСЃС‚РµРјРЅС‹Р№ С‚СЂРµР№ Windows")
		return trayApp.Run(engineCtx)
	}

	// РљРѕРЅСЃРѕР»СЊРЅС‹Р№ СЂРµР¶РёРј (РѕР¶РёРґР°РЅРёРµ SIGINT/SIGTERM)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Р—Р°РІРµСЂС€РµРЅРёРµ СЂР°Р±РѕС‚С‹...")
	cancel()
	time.Sleep(300 * time.Millisecond)
	return nil
}

// в”Ђв”Ђ stop в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "РћСЃС‚Р°РЅРѕРІРёС‚СЊ СЂР°Р±РѕС‚Р°СЋС‰РёР№ РґРµРјРѕРЅ",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё РєРѕРЅС„РёРіР°: %w", err)
			}
			data, err := os.ReadFile(cfg.Daemon.PidFile)
			if err != nil {
				return fmt.Errorf("PID С„Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ (%s): РґРµРјРѕРЅ РЅРµ Р·Р°РїСѓС‰РµРЅ?", cfg.Daemon.PidFile)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				return fmt.Errorf("РЅРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ PID: %w", err)
			}
			proc, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("РїСЂРѕС†РµСЃСЃ РЅРµ РЅР°Р№РґРµРЅ: %w", err)
			}
			if err := proc.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° РѕС‚РїСЂР°РІРєРё SIGTERM: %w", err)
			}
			fmt.Printf("РЎРёРіРЅР°Р» SIGTERM РѕС‚РїСЂР°РІР»РµРЅ РїСЂРѕС†РµСЃСЃСѓ %d\n", pid)
			return nil
		},
	}
}

// в”Ђв”Ђ status в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "РџРѕРєР°Р·Р°С‚СЊ СЃС‚Р°С‚СѓСЃ СЂР°Р±РѕС‚Р°СЋС‰РµРіРѕ РґРµРјРѕРЅР°",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё РєРѕРЅС„РёРіР°: %w", err)
			}
			data, err := os.ReadFile(cfg.Daemon.PidFile)
			if err != nil {
				fmt.Println("РЎС‚Р°С‚СѓСЃ: РќР• Р—РђРџРЈР©Р•Рќ")
				return nil
			}
			pid, _ := strconv.Atoi(string(data))
			proc, err := os.FindProcess(pid)
			if err != nil || proc.Signal(syscall.Signal(0)) != nil {
				fmt.Printf("РЎС‚Р°С‚СѓСЃ: РћРЎРўРђРќРћР’Р›Р•Рќ (РїРѕСЃР»РµРґРЅРёР№ PID: %d)\n", pid)
				return nil
			}
			fmt.Printf("РЎС‚Р°С‚СѓСЃ: Р—РђРџРЈР©Р•Рќ (PID: %d)\n", pid)
			fmt.Printf("Web UI: http://localhost:%d\n", cfg.WebUI.Port)
			return nil
		},
	}
}

// в”Ђв”Ђ keygen в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "РЎРіРµРЅРµСЂРёСЂРѕРІР°С‚СЊ NaCl РєР»СЋС‡РµРІСѓСЋ РїР°СЂСѓ",
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := crypto.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° РіРµРЅРµСЂР°С†РёРё РєР»СЋС‡РµР№: %w", err)
			}
			fmt.Println("# NaCl/Box РєР»СЋС‡РµРІР°СЏ РїР°СЂР° (X25519 + XSalsa20-Poly1305)")
			fmt.Printf("public_key:  %s\n", crypto.KeyToHex(pub))
			fmt.Printf("private_key: %s\n", crypto.KeyToHex(priv))
			fmt.Println("")
			fmt.Println("# Р”РѕР±Р°РІСЊС‚Рµ РІ config.yaml СЂР°Р·РґРµР» crypto:")
			fmt.Printf("# crypto:\n#   public_key: \"%s\"\n#   private_key: \"%s\"\n",
				crypto.KeyToHex(pub), crypto.KeyToHex(priv))
			return nil
		},
	}
}

// в”Ђв”Ђ wg в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newWGCmd() *cobra.Command {
	wgCmd := &cobra.Command{
		Use:   "wg",
		Short: "РћРїРµСЂР°С†РёРё СЃ WireGuard",
	}

	wgKeygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "РЎРіРµРЅРµСЂРёСЂРѕРІР°С‚СЊ WireGuard РєР»СЋС‡РµРІСѓСЋ РїР°СЂСѓ",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := wireguard.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° РіРµРЅРµСЂР°С†РёРё WG РєР»СЋС‡РµР№: %w", err)
			}
			fmt.Println("# WireGuard РєР»СЋС‡РµРІР°СЏ РїР°СЂР°")
			fmt.Printf("PrivateKey = %s\n", kp.PrivateKey)
			fmt.Printf("PublicKey  = %s\n", kp.PublicKey)
			return nil
		},
	}

	wgConfigCmd := &cobra.Command{
		Use:   "config",
		Short: "РЎРіРµРЅРµСЂРёСЂРѕРІР°С‚СЊ WireGuard mesh РєРѕРЅС„РёРі",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := wireguard.GenerateKeyPair()
			if err != nil {
				return err
			}
			wgCfg := &wireguard.WGConfig{
				InterfaceName: "wg0",
				PrivateKey:    kp.PrivateKey,
				Address:       "10.200.0.1/24",
				ListenPort:    51820,
				DNS:           "",
				MTU:           1420,
			}
			conf, err := wireguard.GenerateWGConfig(wgCfg)
			if err != nil {
				return err
			}
			fmt.Println(conf)
			return nil
		},
	}

	wgCmd.AddCommand(wgKeygenCmd, wgConfigCmd)
	return wgCmd
}

// в”Ђв”Ђ install в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "РЈСЃС‚Р°РЅРѕРІРёС‚СЊ РєР°Рє СЃРёСЃС‚РµРјРЅС‹Р№ СЃРµСЂРІРёСЃ (Linux: systemd, procd, entware)",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcType, _ := cmd.Flags().GetString("service")
			return installService(svcType)
		},
	}
	cmd.Flags().String("service", "systemd", "С‚РёРї СЃРµСЂРІРёСЃР°: systemd|procd|entware")
	return cmd
}

func installService(svcType string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, _ = filepath.Abs(exePath)

	switch svcType {
	case "systemd":
		unit := fmt.Sprintf(`[Unit]
Description=NatBypass вЂ” РѕР±С…РѕРґ NAT Рё P2P-РґРѕСЃС‚СѓРї
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s start --config /etc/natbypass/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, exePath)
		if err := os.MkdirAll("/etc/natbypass", 0755); err != nil {
			return err
		}
		if err := os.WriteFile("/etc/systemd/system/natbypass.service", []byte(unit), 0644); err != nil {
			return err
		}
		fmt.Println("вњ“ systemd unit СѓСЃС‚Р°РЅРѕРІР»РµРЅ: /etc/systemd/system/natbypass.service")
		fmt.Println("Р’С‹РїРѕР»РЅРёС‚Рµ: systemctl daemon-reload && systemctl enable --now natbypass")

	case "procd":
		fmt.Println("Р”Р»СЏ OpenWrt: СЃРєРѕРїРёСЂСѓР№С‚Рµ scripts/init/natbypass.procd РІ /etc/init.d/natbypass")
		fmt.Println("Р—Р°С‚РµРј: chmod +x /etc/init.d/natbypass && /etc/init.d/natbypass enable && /etc/init.d/natbypass start")

	case "entware":
		fmt.Println("Р”Р»СЏ Keenetic/Entware: СЃРєРѕРїРёСЂСѓР№С‚Рµ scripts/init/S99natbypass РІ /opt/etc/init.d/S99natbypass")
		fmt.Println("Р—Р°С‚РµРј: chmod +x /opt/etc/init.d/S99natbypass && /opt/etc/init.d/S99natbypass start")

	default:
		return fmt.Errorf("РЅРµРёР·РІРµСЃС‚РЅС‹Р№ С‚РёРї СЃРµСЂРІРёСЃР°: %s", svcType)
	}
	return nil
}

// в”Ђв”Ђ antigravity EASTER EGG в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newAntGravityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "antigravity",
		Short: "рџљЂ Easter Egg",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`
       .---.
      /     \
      \.@-@./       NatBypass v%s
      /` + "`" + `\_/` + "`" + `\      РћР±С…РѕРґРёРј РіСЂР°РІРёС‚Р°С†РёСЋ NAT!
     //  _  \\
    | \     / |     Р’РґРѕС…РЅРѕРІР»РµРЅРѕ: import antigravity (Python)
   /` + "`" + `\_` + "`" + `Y` + "`" + `_/` + "`" + `\    
  /  |  |  |  \    Р РµР¶РёРј РЅРµРІРµСЃРѕРјРѕСЃС‚Рё: РђРљРўРР’РР РћР’РђРќ
  ` + "`" + `--|--|--` + "`" + `    Р’СЃРµ РїР°РєРµС‚С‹ С‚РµРїРµСЂСЊ Р»РµС‚СЏС‚ РЅР°РїСЂСЏРјСѓСЋ!

  "Р›СЋР±РѕР№ РґРѕСЃС‚Р°С‚РѕС‡РЅРѕ РїСЂРѕРґРІРёРЅСѓС‚С‹Р№ NAT
   РЅРµРѕС‚Р»РёС‡РёРј РѕС‚ СЃС‚РµРЅС‹." вЂ” РђСЂС‚СѓСЂ РљР»Р°СЂРє (РїРѕС‡С‚Рё)

  double NAT? CGNAT? РќРµ РїСЂРѕР±Р»РµРјР°!   рџ›ё
`, Version)
		},
	}
}

// в”Ђв”Ђ konami EASTER EGG в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newKonamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "konami",
		Short: "рџЋ® God Mode",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(`
  в†‘ в†‘ в†“ в†“ в†ђ в†’ в†ђ в†’ B A  вЂ”  РљРћР” Р’Р’Р•Р”РЃРќ!
  в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
  в•‘       Р Р•Р–РРњ Р‘РћР“Рђ РђРљРўРР’РР РћР’РђРќ       в•‘
  в• в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•Ј
  в•‘  РЎРєСЂС‹С‚С‹Рµ РЅР°СЃС‚СЂРѕР№РєРё NatBypass:      в•‘
  в•‘                                    в•‘
  в•‘  --paranoid     РўСЂРѕР№РЅРѕРµ С€РёС„СЂРѕРІР°РЅРёРµ в•‘
  в•‘  --ghost        Р‘РµР· Р»РѕРіРѕРІ РІРѕРѕР±С‰Рµ   в•‘
  в•‘  --turbo        РРЅС‚РµСЂРІР°Р» 1 СЃРµРє     в•‘
  в•‘  --mesh-all     РЎРѕРµРґРёРЅРёС‚СЊ РІСЃРµС…     в•‘
  в•‘  --obfs4        РћР±С„СѓСЃРєР°С†РёСЏ С‚СЂР°С„РёРєР° в•‘
  в•‘  --chaos-mode   РЎР»СѓС‡Р°Р№РЅС‹Р№ РєР°РЅР°Р»    в•‘
  в•‘                                    в•‘
  в•‘  (СЌС‚Рё С„Р»Р°РіРё СЃСѓС‰РµСЃС‚РІСѓСЋС‚ РІ РјРµС‡С‚Р°С…)   в•‘
  в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ
`)
		},
	}
}

// в”Ђв”Ђ version в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "РџРѕРєР°Р·Р°С‚СЊ РІРµСЂСЃРёСЋ",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("NatBypass %s (commit: %s, built: %s)\n", Version, Commit, BuildDate)
		},
	}
}

// в”Ђв”Ђ helpers в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func setupLogging(level, logFile string) {
	zerolog.TimeFieldFormat = time.RFC3339

	var lvl zerolog.Level
	switch level {
	case "debug":
		lvl = zerolog.DebugLevel
	case "warn":
		lvl = zerolog.WarnLevel
	case "error":
		lvl = zerolog.ErrorLevel
	default:
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)

	if logFile == "" && runtime.GOOS == "windows" {
		if exe, err := os.Executable(); err == nil {
			logFile = filepath.Join(filepath.Dir(exe), "natbypass.log")
		}
	}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			console := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}
			multi := zerolog.MultiLevelWriter(console, f)
			log.Logger = zerolog.New(multi).With().Timestamp().Logger()
			return
		}
	}
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).
		With().Timestamp().Logger()
}

func loadOrGenerateKeys(cfg *config.Config) ([32]byte, [32]byte, error) {
	if cfg.Crypto.PublicKey != "" && cfg.Crypto.PrivateKey != "" {
		pub, err := crypto.HexToKey(cfg.Crypto.PublicKey)
		if err != nil {
			return [32]byte{}, [32]byte{}, fmt.Errorf("РЅРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РїСѓР±Р»РёС‡РЅС‹Р№ РєР»СЋС‡: %w", err)
		}
		priv, err := crypto.HexToKey(cfg.Crypto.PrivateKey)
		if err != nil {
			return [32]byte{}, [32]byte{}, fmt.Errorf("РЅРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РїСЂРёРІР°С‚РЅС‹Р№ РєР»СЋС‡: %w", err)
		}
		return pub, priv, nil
	}

	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	return pub, priv, nil
}

func generateDeviceID(pubKey [32]byte) string {
	hex := crypto.KeyToHex(pubKey)
	if len(hex) >= 12 {
		return "dev-" + hex[:12]
	}
	return "dev-unknown"
}

func buildSignalingChannels(cfg *config.Config) ([]signaling.SignalingChannel, error) {
	var channels []signaling.SignalingChannel

	for _, chCfg := range cfg.Signaling.Channels {
		if !chCfg.Enabled {
			continue
		}
		var ch signaling.SignalingChannel
		switch chCfg.Type {
		case "telegram":
			token := chCfg.Params["token"]
			chatID := chCfg.Params["chat_id"]
			proxy := chCfg.Params["proxy"]
			if token == "" || chatID == "" {
				continue
			}
			ch = signaling.NewTelegramChannel(token, chatID, proxy)

		case "mqtt":
			brokerURL := chCfg.Params["broker_url"]
			if brokerURL == "" {
				brokerURL = chCfg.Params["broker"]
			}
			topic := chCfg.Params["topic"]
			clientID := chCfg.Params["client_id"]
			username := chCfg.Params["username"]
			if username == "" {
				username = chCfg.Params["user"]
			}
			password := chCfg.Params["password"]
			if password == "" {
				password = chCfg.Params["pass"]
			}
			if brokerURL == "" || topic == "" {
				continue
			}
			ch = signaling.NewMQTTChannel(brokerURL, topic, clientID, username, password)

		case "webhook":
			postURL := chCfg.Params["post_url"]
			pollURL := chCfg.Params["poll_url"]
			secret := chCfg.Params["secret"]
			if postURL == "" {
				continue
			}
			ch = signaling.NewWebhookChannel(postURL, pollURL, secret)

		case "dns":
			cfToken := chCfg.Params["cf_api_token"]
			zoneID := chCfg.Params["zone_id"]
			recordName := chCfg.Params["record_name"]
			if cfToken == "" || zoneID == "" || recordName == "" {
				continue
			}
			ch = signaling.NewDNSChannel(cfToken, zoneID, recordName)

		default:
			continue
		}
		channels = append(channels, ch)
	}
	_ = json.Marshal

	return channels, nil
}

func buildDefaultConfig() *config.Config {
	cfg := &config.Config{}

	cfg.App.LogLevel        = ifEmpty(DefaultLogLevel, "info")
	cfg.App.DeviceID        = DefaultDeviceID
	cfg.App.PublishInterval = 8

	// Автогенерация уникального профиля сети со случайным топиком
	p := config.GenerateDefaultProfile("Основная сеть")
	cfg.Profiles = []config.Profile{p}
	cfg.ActiveProfileID = p.ID
	cfg.SyncSignalingWithProfile(&p)

	cfg.WebUI.Enabled  = true
	cfg.WebUI.Username = ifEmpty(DefaultWebUIUser, "admin")
	cfg.WebUI.Password = DefaultWebUIPass
	port := 8080
	if DefaultWebUIPort != "" {
		if p, err := strconv.Atoi(DefaultWebUIPort); err == nil {
			port = p
		}
	}
	cfg.WebUI.Port = port

	cfg.Network.UpnpEnabled = true
	cfg.Network.IPTimeout   = 10
	cfg.Network.StunServers = []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun.cloudflare.com:3478",
	}
	cfg.Network.IPApis = []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}

	if DefaultTgToken != "" {
		cfg.Signaling.Channels = append(cfg.Signaling.Channels, config.ChannelConfig{
			Type:     "telegram",
			Priority: 1,
			Enabled:  true,
			Params: map[string]string{
				"token":   DefaultTgToken,
				"chat_id": DefaultTgChatID,
			},
		})
	}
	if DefaultMQTTBroker != "" {
		topic := ifEmpty(DefaultMQTTTopic, "natbypass/default/peers")
		cfg.Signaling.Channels = append(cfg.Signaling.Channels, config.ChannelConfig{
			Type:     "mqtt",
			Priority: 2,
			Enabled:  true,
			Params: map[string]string{
				"broker_url": DefaultMQTTBroker,
				"topic":      topic,
			},
		})
	}
	if DefaultWebhookURL != "" {
		cfg.Signaling.Channels = append(cfg.Signaling.Channels, config.ChannelConfig{
			Type:     "webhook",
			Priority: 3,
			Enabled:  true,
			Params: map[string]string{
				"post_url": DefaultWebhookURL,
				"poll_url": DefaultWebhookURL,
			},
		})
	}

	cfg.WireGuard.Enabled    = false
	cfg.WireGuard.Interface  = "wg0"
	cfg.WireGuard.ListenPort = 51820
	cfg.WireGuard.MTU        = 1420

	cfg.Daemon.PidFile = "/var/run/natbypass.pid"
	return cfg
}

func applyBuiltinDefaults(cfg *config.Config) {
	if cfg.App.LogLevel == "" {
		cfg.App.LogLevel = ifEmpty(DefaultLogLevel, "info")
	}
	if cfg.App.DeviceID == "" && DefaultDeviceID != "" {
		cfg.App.DeviceID = DefaultDeviceID
	}
	if cfg.WebUI.Username == "" {
		cfg.WebUI.Username = ifEmpty(DefaultWebUIUser, "admin")
	}
	if cfg.WebUI.Password == "" && DefaultWebUIPass != "" {
		cfg.WebUI.Password = DefaultWebUIPass
	}
	if cfg.WebUI.Port == 0 && DefaultWebUIPort != "" {
		if p, err := strconv.Atoi(DefaultWebUIPort); err == nil {
			cfg.WebUI.Port = p
		}
	}
	if len(cfg.Signaling.Channels) == 0 {
		tmp := buildDefaultConfig()
		cfg.Signaling.Channels = tmp.Signaling.Channels
	}
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func ensureConfigFileExists(path string) {
	if path == "" {
		path = "config.yaml"
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		sample := `# ============================================================
# NatBypass вЂ” РљРѕРЅС„РёРіСѓСЂР°С†РёРѕРЅРЅС‹Р№ С„Р°Р№Р»
# ============================================================

app:
  name: "NatBypass"
  version: "1.0.0"
  log_level: "info"
  publish_interval: 60

web_ui:
  enabled: true
  port: 8080
  username: "admin"
  password: ""

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
      enabled: false
      params:
        token: ""      # Р’СЃС‚Р°РІСЊС‚Рµ С‚РѕРєРµРЅ РѕС‚ @BotFather (РЅР°РїСЂРёРјРµСЂ: 7123456789:AAF...)
        chat_id: ""    # ID РїСЂРёРІР°С‚РЅРѕР№ РіСЂСѓРїРїС‹/РєР°РЅР°Р»Р° (РЅР°РїСЂРёРјРµСЂ: -1001234567890)
    - type: "mqtt"
      priority: 2
      enabled: true
      params:
        broker_url: "tcp://mqtt.eclipseprojects.io:1883"
        topic: "natbypass/public/peers"

wireguard:
  enabled: false
  interface: "wg0"
  listen_port: 51820
`
		_ = os.WriteFile(path, []byte(sample), 0644)
	}
}