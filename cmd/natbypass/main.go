package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
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
	"github.com/natbypass/natbypass/internal/diagnostic"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/tray"
	"github.com/natbypass/natbypass/internal/tunnel"
	"github.com/natbypass/natbypass/internal/updater"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
)

// Р—Р°РїРѕР»РЅСЏРµС‚СЃСЏ РїСЂРё СЃР±РѕСЂРєРµ С‡РµСЂРµР· -ldflags -X
var (
	Version   = "1.2.7"
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
	// РЈСЃС‚Р°РЅР°РІР»РёРІР°РµРј СЂР°Р±РѕС‡СѓСЋ РґРёСЂРµРєС‚РѕСЂРёСЋ РЅР° РїР°РїРєСѓ СЃ РёСЃРїРѕР»РЅСЏРµРјС‹Рј С„Р°Р№Р»РѕРј (РІР°Р¶РЅРѕ РґР»СЏ Windows)
	if exe, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exe))
	}

	// РџРµСЂРµС…РІР°С‚С‹РІР°РµРј Р»СЋР±СѓСЋ РїР°РЅРёРєСѓ Рё РїРёС€РµРј РІ Р»РѕРі-С„Р°Р№Р» вЂ” РІР°Р¶РЅРѕ РґР»СЏ windowsgui РіРґРµ РєРѕРЅСЃРѕР»Рё РЅРµС‚
	defer func() {
		if r := recover(); r != nil {
			_ = os.WriteFile("natbypass-crash.log",
				[]byte(fmt.Sprintf("PANIC: %v\nTime: %s\n", r, time.Now().Format(time.RFC3339))),
				0644)
		}
	}()

	// РРЅРёС†РёР°Р»РёР·РёСЂСѓРµРј Р»РѕРіРёСЂРѕРІР°РЅРёРµ вЂ” РЅР° Windows Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РїРёС€РµС‚ РІ natbypass.log СЂСЏРґРѕРј СЃ exe
	setupLogging("info", "")

	// РђРІС‚РѕРјР°С‚РёС‡РµСЃРєРёР№ Р·Р°РїСЂРѕСЃ РїСЂР°РІ РђРґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР° С‡РµСЂРµР· UAC РЅР° Windows РїСЂРё РѕР±С‹С‡РЅРѕРј Р·Р°РїСѓСЃРєРµ
	ensureAdminOnWindows()

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
			firstLaunch := (err != nil || cfg == nil)
			if firstLaunch {
				cfg = buildDefaultConfig()
			}
			applyBuiltinDefaults(cfg)
			// РџСЂРё РїРµСЂРІРѕРј Р·Р°РїСѓСЃРєРµ СЃСЂР°Р·Сѓ СЃРѕС…СЂР°РЅСЏРµРј РєРѕРЅС„РёРі вЂ” С‡С‚РѕР±С‹ WebUI РјРѕРі СЂРµРґР°РєС‚РёСЂРѕРІР°С‚СЊ РїСЂРѕС„РёР»СЊ
			if firstLaunch {
				_ = config.Save(cfg, configFile, runtime.GOOS == "windows")
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

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
		newUpdateCmd(),
		newSetTopicCmd(),
		newSetTelegramCmd(),
		newAntGravityCmd(),
		newKonamiCmd(),
		newVersionCmd(),
		newDiagCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// в”Ђв”Ђ set-topic в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newSetTopicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-topic [topic]",
		Short: "РЈСЃС‚Р°РЅРѕРІРёС‚СЊ РЅРѕРІС‹Р№ MQTT С‚РѕРїРёРє Рё РїСЂРёРјРµРЅРёС‚СЊ РЅР°СЃС‚СЂРѕР№РєРё",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			newTopic := args[0]
			cfgPath := configFile
			if cfgPath == "config.yaml" && runtime.GOOS == "linux" {
				if _, err := os.Stat("/etc/natbypass/config.yaml"); err == nil {
					cfgPath = "/etc/natbypass/config.yaml"
				} else if _, err := os.Stat("/opt/etc/natbypass/config.yaml"); err == nil {
					cfgPath = "/opt/etc/natbypass/config.yaml"
				}
			}
			cfg, err := config.Load(cfgPath)
			if err != nil || cfg == nil {
				cfg = buildDefaultConfig()
			}
			hasMqtt := false
			for i, ch := range cfg.Signaling.Channels {
				if ch.Type == "mqtt" {
					hasMqtt = true
					if ch.Params == nil { ch.Params = make(map[string]string) }
					ch.Params["topic"] = newTopic
					ch.Enabled = true
					cfg.Signaling.Channels[i] = ch
				}
			}
			if !hasMqtt {
				cfg.Signaling.Channels = append(cfg.Signaling.Channels, config.ChannelConfig{
					Type:    "mqtt",
					Enabled: true,
					Params:  map[string]string{"broker_url": "tcp://broker.emqx.io:1883", "topic": newTopic},
				})
			}
			if err := config.Save(cfg, cfgPath, runtime.GOOS == "windows"); err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° Р·Р°РїРёСЃРё %s: %w", cfgPath, err)
			}
			fmt.Printf("вњ“ MQTT С‚РѕРїРёРє СѓСЃРїРµС€РЅРѕ РѕР±РЅРѕРІР»РµРЅ РЅР°: %s (С„Р°Р№Р»: %s)\n", newTopic, cfgPath)
			if runtime.GOOS == "linux" {
				if _, err := os.Stat("/etc/systemd/system/natbypass.service"); err == nil {
					_ = exec.Command("systemctl", "restart", "natbypass").Run()
					fmt.Println("вњ“ РЎР»СѓР¶Р±Р° systemd РїРµСЂРµР·Р°РїСѓС‰РµРЅР°.")
				} else if _, err := os.Stat("/opt/etc/init.d/S99natbypass"); err == nil {
					_ = exec.Command("/opt/etc/init.d/S99natbypass", "restart").Run()
					fmt.Println("вњ“ РЎР»СѓР¶Р±Р° Keenetic Entware РїРµСЂРµР·Р°РїСѓС‰РµРЅР°.")
				}
			}
			return nil
		},
	}
}

// в”Ђв”Ђ set-telegram в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newSetTelegramCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-telegram [token] [chat_id]",
		Short: "РЈСЃС‚Р°РЅРѕРІРёС‚СЊ С‚РѕРєРµРЅ Рё chat_id Telegram Р±РѕС‚Р°",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			token, chatID := args[0], args[1]
			cfgPath := configFile
			if cfgPath == "config.yaml" && runtime.GOOS == "linux" {
				if _, err := os.Stat("/etc/natbypass/config.yaml"); err == nil {
					cfgPath = "/etc/natbypass/config.yaml"
				} else if _, err := os.Stat("/opt/etc/natbypass/config.yaml"); err == nil {
					cfgPath = "/opt/etc/natbypass/config.yaml"
				}
			}
			cfg, err := config.Load(cfgPath)
			if err != nil || cfg == nil {
				cfg = buildDefaultConfig()
			}
			hasTg := false
			for i, ch := range cfg.Signaling.Channels {
				if ch.Type == "telegram" {
					hasTg = true
					if ch.Params == nil { ch.Params = make(map[string]string) }
					ch.Params["token"] = token
					ch.Params["chat_id"] = chatID
					ch.Enabled = true
					cfg.Signaling.Channels[i] = ch
				}
			}
			if !hasTg {
				cfg.Signaling.Channels = append(cfg.Signaling.Channels, config.ChannelConfig{
					Type:    "telegram",
					Enabled: true,
					Params:  map[string]string{"token": token, "chat_id": chatID},
				})
			}
			if err := config.Save(cfg, cfgPath, runtime.GOOS == "windows"); err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° Р·Р°РїРёСЃРё %s: %w", cfgPath, err)
			}
			fmt.Printf("вњ“ Telegram Р±РѕС‚ СѓСЃРїРµС€РЅРѕ РЅР°СЃС‚СЂРѕРµРЅ (С„Р°Р№Р»: %s)\n", cfgPath)
			if runtime.GOOS == "linux" {
				if _, err := os.Stat("/etc/systemd/system/natbypass.service"); err == nil {
					_ = exec.Command("systemctl", "restart", "natbypass").Run()
					fmt.Println("вњ“ РЎР»СѓР¶Р±Р° systemd РїРµСЂРµР·Р°РїСѓС‰РµРЅР°.")
				}
			}
			return nil
		},
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

// в”Ђв”Ђ update в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newUpdateCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "РџСЂРѕРІРµСЂРёС‚СЊ Рё СѓСЃС‚Р°РЅРѕРІРёС‚СЊ РѕР±РЅРѕРІР»РµРЅРёРµ NatBypass СЃ GitHub",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("рџ”Ќ РџСЂРѕРІРµСЂРєР° РѕР±РЅРѕРІР»РµРЅРёР№ (С‚РµРєСѓС‰Р°СЏ РІРµСЂСЃРёСЏ: %s)...\n", Version)
			info, err := updater.CheckUpdate(context.Background(), Version)
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° РїСЂРѕРІРµСЂРєРё РѕР±РЅРѕРІР»РµРЅРёР№: %w", err)
			}
			if !info.HasUpdate && !force {
				fmt.Printf("вњ… РЈ РІР°СЃ СѓСЃС‚Р°РЅРѕРІР»РµРЅР° Р°РєС‚СѓР°Р»СЊРЅР°СЏ РІРµСЂСЃРёСЏ (%s, СЂРµР»РёР·: %s)\n", Version, info.PublishedAt)
				fmt.Println("рџ’Ў РСЃРїРѕР»СЊР·СѓР№С‚Рµ 'natbypass update --force' РґР»СЏ РїСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕР№ РїРµСЂРµСѓСЃС‚Р°РЅРѕРІРєРё СЃРІРµР¶РµРіРѕ Р±РёР»РґР°.")
				return nil
			}
			if info.HasUpdate {
				fmt.Printf("рџљЂ РќР°Р№РґРµРЅР° РЅРѕРІР°СЏ РІРµСЂСЃРёСЏ: %s (РѕРїСѓР±Р»РёРєРѕРІР°РЅР°: %s)\n", info.LatestVersion, info.PublishedAt)
			} else {
				fmt.Printf("рџ”„ РџСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕРµ РѕР±РЅРѕРІР»РµРЅРёРµ РґРѕ РїРѕСЃР»РµРґРЅРµРіРѕ Р±РёР»РґР° СЂРµР»РёР·Р° (%s, РѕРїСѓР±Р»РёРєРѕРІР°РЅ: %s)\n", info.LatestVersion, info.PublishedAt)
			}
			fmt.Printf("рџ“¦ Р¤Р°Р№Р» РґР»СЏ РІР°С€РµР№ СЃРёСЃС‚РµРјС‹: %s (%d KB)\n", info.AssetName, info.AssetSize/1024)
			if info.ReleaseNotes != "" {
				fmt.Printf("\nрџ“ќ РћРїРёСЃР°РЅРёРµ РёР·РјРµРЅРµРЅРёР№:\n%s\n\n", info.ReleaseNotes)
			}
			fmt.Println(">> РЎРєР°С‡РёРІР°РЅРёРµ Рё РїСЂРёРјРµРЅРµРЅРёРµ РѕР±РЅРѕРІР»РµРЅРёСЏ...")
			err = updater.ApplyUpdate(context.Background(), info.AssetURL)
			if err != nil {
				return fmt.Errorf("РѕС€РёР±РєР° РїСЂРёРјРµРЅРµРЅРёСЏ РѕР±РЅРѕРІР»РµРЅРёСЏ: %w", err)
			}
			fmt.Println("рџЋ‰ РћР±РЅРѕРІР»РµРЅРёРµ СѓСЃРїРµС€РЅРѕ СѓСЃС‚Р°РЅРѕРІР»РµРЅРѕ! РЎР»СѓР¶Р±Р° РїРµСЂРµР·Р°РїСѓС‰РµРЅР°.")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "РїСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕ РїРµСЂРµСѓСЃС‚Р°РЅРѕРІРёС‚СЊ РїРѕСЃР»РµРґРЅРёР№ Р±РёР»Рґ, РґР°Р¶Рµ РµСЃР»Рё РІРµСЂСЃРёРё СЃРѕРІРїР°РґР°СЋС‚")
	return cmd
}

// в”Ђв”Ђ РћСЃРЅРѕРІРЅРѕР№ РґРІРёР¶РѕРє в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func runEngine(ctx context.Context, cfg *config.Config, enableTray bool) error {
	port := cfg.WebUI.Port
	if webUIPort > 0 {
		port = webUIPort
	}
	if port == 0 {
		port = 8080
	}

	if runtime.GOOS == "windows" {
		if !acquireSingleInstanceMutex(port) {
			log.Warn().Msg("вљ пёЏ Р­РєР·РµРјРїР»СЏСЂ NatBypass СѓР¶Рµ Р·Р°РїСѓС‰РµРЅ. РћС‚РєСЂС‹РІР°РµРј СЃСѓС‰РµСЃС‚РІСѓСЋС‰СѓСЋ РїР°РЅРµР»СЊ СѓРїСЂР°РІР»РµРЅРёСЏ...")
			return nil
		}
		defer releaseSingleInstanceMutex()
	}

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

	engineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	registry := peer.NewRegistry()
	registry.StartMonitor(engineCtx, 30*time.Second)

	// РћРїСЂРµРґРµР»СЏРµРј С‚РѕРїРёРє РёР· Р°РєС‚РёРІРЅРѕРіРѕ РїСЂРѕС„РёР»СЏ (РїСЂРё РЅР°Р»РёС‡РёРё), РёРЅР°С‡Рµ вЂ” СѓРЅРёРєР°Р»СЊРЅС‹Р№ РЅР° РѕСЃРЅРѕРІРµ deviceID
	activeProf := cfg.EnsureActiveProfile()
	defaultTopic := fmt.Sprintf("natbypass/%s/peers", deviceID[:min8(len(deviceID), 8)])
	if activeProf != nil && activeProf.MQTTTopic != "" {
		defaultTopic = activeProf.MQTTTopic
	}

	channels, err := buildSignalingChannels(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("РћС€РёР±РєР° РїР°СЂСЃРёРЅРіР° РєР°РЅР°Р»РѕРІ, РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ СЂРµР·РµСЂРІРЅС‹Р№ РєР°РЅР°Р»")
	}
	if len(channels) == 0 {
		log.Info().Str("topic", defaultTopic).Msg("вљ™пёЏ РЎРёРіРЅР°Р»СЊРЅС‹Рµ РєР°РЅР°Р»С‹ РЅРµ РЅР°СЃС‚СЂРѕРµРЅС‹. РСЃРїРѕР»СЊР·СѓСЋ РїРµСЂСЃРѕРЅР°Р»СЊРЅС‹Р№ С‚РѕРїРёРє MQTT.")
		channels = append(channels, signaling.NewMQTTChannel("tcp://broker.emqx.io:1883", defaultTopic, deviceID, "", ""))
	} else {
		// РџСЂРёРјРµРЅСЏРµРј С‚РѕРїРёРє Р°РєС‚РёРІРЅРѕРіРѕ РїСЂРѕС„РёР»СЏ РєРѕ РІСЃРµРј MQTT-РєР°РЅР°Р»Р°Рј РїСЂРё СЃС‚Р°СЂС‚Рµ
		if activeProf != nil && activeProf.MQTTTopic != "" {
			for _, ch := range channels {
				if mqCh, ok := ch.(*signaling.MQTTChannel); ok {
					mqCh.UpdateTopic(activeProf.MQTTTopic)
				}
			}
		}
	}
	sigMgr := signaling.NewFallbackManager(channels)
	log.Info().Int("channels", len(channels)).Str("current", sigMgr.CurrentChannel()).Str("topic", defaultTopic).Msg("РЎРёРіРЅР°Р»СЊРЅС‹Рµ РєР°РЅР°Р»С‹ РёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅС‹")

	port = cfg.WebUI.Port
	if webUIPort > 0 {
		port = webUIPort
	}
	if port == 0 {
		port = 8080
	}

	// рџљЂ РђРІС‚РѕРјР°С‚РёС‡РµСЃРєРѕРµ СЃРѕР·РґР°РЅРёРµ РІРёСЂС‚СѓР°Р»СЊРЅРѕРіРѕ СЃРµС‚РµРІРѕРіРѕ РёРЅС‚РµСЂС„РµР№СЃР° (nb0 РЅР° Linux / NatBypass РЅР° Windows)
	myVIPNum := 1
	for _, b := range []byte(deviceID) {
		myVIPNum = (myVIPNum*31 + int(b)) % 250
	}
	if myVIPNum == 0 {
		myVIPNum = 1
	}
	myVirtualIP := fmt.Sprintf("100.64.200.%d", myVIPNum)

	var uiServer *webui.Server
	if !noWebUI {
		uiServer = webui.NewServer(port, cfg.WebUI.Username, cfg.WebUI.Password, registry, sigMgr)
		uiServer.SetConfigPath(configFile)
		uiServer.SetAppState(deviceID, "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ...", "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ...", myVirtualIP)
		uiServer.SetVirtualIP(myVirtualIP)
		uiServer.SetDeviceName(deviceID)
		uiServer.SetVersion(Version)
		uiServer.AddEvent("info", "NatBypass Р·Р°РїСѓС‰РµРЅ", "version="+Version)

		uiServer.SetOnProfileSwitch(func(p *config.Profile) error {
			if p == nil {
				return nil
			}
			log.Info().Str("profile", p.Name).Str("topic", p.MQTTTopic).Msg("вљЎ Р”РёРЅР°РјРёС‡РµСЃРєРѕРµ РїРµСЂРµРєР»СЋС‡РµРЅРёРµ РїСЂРѕС„РёР»СЏ СЃРµС‚Рё")
			if sigMgr != nil && p.MQTTTopic != "" {
				sigMgr.UpdateMQTTTopic(p.MQTTTopic)
			}
			registry.ClearAll()
			return nil
		})

		go func() {
			if err := uiServer.Start(engineCtx); err != nil {
				log.Error().Err(err).Msg("Web UI РѕСЃС‚Р°РЅРѕРІР»РµРЅ")
			}
		}()
		if runtime.GOOS == "windows" {
			openAppWindow(port)
		}
	}

	adapterName := "nb0"
	if runtime.GOOS == "windows" {
		adapterName = "NatBypass"
	}
	tunDev, tErr := tunnel.CreateAdapter(adapterName, myVirtualIP)
	if tErr == nil {
		log.Info().Str("adapter", adapterName).Str("vip", myVirtualIP).Msg("рџ›ЎпёЏ Р’РёСЂС‚СѓР°Р»СЊРЅС‹Р№ СЃРµС‚РµРІРѕР№ РёРЅС‚РµСЂС„РµР№СЃ РїРѕРґРЅСЏС‚! РџСЂСЏРјРѕР№ РґРѕСЃС‚СѓРї Рє СѓСЃС‚СЂРѕР№СЃС‚РІСѓ Р°РєС‚РёРІРёСЂРѕРІР°РЅ")
		if uiServer != nil {
			uiServer.AddEvent("info", "РЎРµС‚РµРІРѕР№ РёРЅС‚РµСЂС„РµР№СЃ "+adapterName+" РїРѕРґРЅСЏС‚", "IP: "+myVirtualIP+"/24")
		}
	} else {
		log.Warn().Err(tErr).Msg("РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕРґРЅСЏС‚СЊ РІРёСЂС‚СѓР°Р»СЊРЅС‹Р№ РёРЅС‚РµСЂС„РµР№СЃ TUN (С‚СЂРµР±СѓСЋС‚СЃСЏ РїСЂР°РІР° root РёР»Рё Р·Р°РіСЂСѓР¶РµРЅРЅС‹Р№ РјРѕРґСѓР»СЊ tun)")
	}

	var puncher *network.UDPPuncher
	// РСЃРїРѕР»СЊР·СѓРµРј РїРѕСЂС‚ 47832 РґР»СЏ РїСЂРѕР±РёРІРєРё NAT вЂ” РѕС‚РґРµР»СЊРЅС‹Р№ РѕС‚ WireGuard (51820),
	// С‡С‚РѕР±С‹ РёР·Р±РµР¶Р°С‚СЊ РєРѕРЅС„Р»РёРєС‚Р° РїРѕСЂС‚РѕРІ Рё СЃРѕС…СЂР°РЅРёС‚СЊ РїСЂР°РІРёР»СЊРЅС‹Р№ STUN-Р°РґСЂРµСЃ РІ РјР°СЏРєРµ.
	puncher, err = network.NewUDPPuncher(47832, deviceID, cfg.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		log.Info().Str("peer", remoteDevID).Dur("rtt", rtt).Str("from", fromAddr).Msg("вљЎ [P2P Direct UDP] РџРћР”РўР’Р•Р Р–Р”Р•РќРћ! РџСЂСЏРјРѕР№ UDP-РїРёРЅРі")
		if p, ok := registry.Get(remoteDevID); ok {
			p.DirectP2P = true
			// РћР±РЅРѕРІР»СЏРµРј ActiveEndpoint Рё STUNAddr СЂРµР°Р»СЊРЅС‹Рј Р°РґСЂРµСЃРѕРј РёСЃС‚РѕС‡РЅРёРєР° UDP-РїР°РєРµС‚Р°.
			// fromAddr вЂ” СЌС‚Рѕ Р Р•РђР›Р¬РќР«Р™ Р°РґСЂРµСЃ РїРёСЂР° Р·Р° NAT, РѕРЅ С‚РѕС‡РЅРµРµ С‡РµРј STUNAddr РёР· РјР°СЏРєР°
			// (РѕСЃРѕР±РµРЅРЅРѕ РїСЂРё symmetric NAT РіРґРµ mapped port СЂР°Р·РЅС‹Р№ РґР»СЏ РєР°Р¶РґРѕРіРѕ destination).
			p.ActiveEndpoint = fromAddr
			p.STUNAddr = fromAddr // в†ђ РєР»СЋС‡РµРІРѕРµ: С‚РµРїРµСЂСЊ keepalive Р±СѓРґРµС‚ РґРѕР»Р±РёС‚СЊ РїСЂР°РІРёР»СЊРЅС‹Р№ РїРѕСЂС‚
			if rtt > 0 && rtt < 10*time.Second {
				if p.Latency > 0 {
					p.Latency = time.Duration(float64(p.Latency)*0.75 + float64(rtt)*0.25)
				} else {
					p.Latency = rtt
				}
				p.PingMs = p.Latency.Milliseconds()
			}
			p.Online = true
			p.LastSeen = time.Now()
			registry.Upsert(p)

			// Р’СЃС‚СЂРµС‡РЅС‹Р№ Р·РѕРЅРґ РЅР° РѕР±РЅР°СЂСѓР¶РµРЅРЅС‹Р№ СЃРѕРєРµС‚ РґР»СЏ РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕРіРѕ РїРѕРґС‚РІРµСЂР¶РґРµРЅРёСЏ СЃРѕ СЃС‚РѕСЂРѕРЅС‹ СЃРјР°СЂС‚С„РѕРЅР°/РєР»РёРµРЅС‚Р°
			if puncher != nil {
				go func(targetAddr string) {
					for i := 0; i < 3; i++ {
						_ = puncher.SendHolePunchProbe(targetAddr)
						time.Sleep(50 * time.Millisecond)
					}
				}(fromAddr)
			}
		}
	})
	if err == nil {
		log.Info().Int("port", puncher.LocalPort()).Msg("UDPPuncher Р°РєС‚РёРІРµРЅ")
		puncher.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
			if tunDev != nil {
				_ = tunDev.WritePacket(payload)
			}
		})
	}

	// рџ“Ў РџРѕРґРїРёСЃРєР° РЅР° СЂРµР»РµР№ С‚СѓРЅРЅРµР»СЊРЅС‹С… РїР°РєРµС‚РѕРІ С‡РµСЂРµР· MQTT РґР»СЏ РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕРіРѕ P2P
	for _, ch := range channels {
		if mqCh, isMq := ch.(*signaling.MQTTChannel); isMq {
			mqCh.SubscribeTunnelData(deviceID, func(pkt []byte) {
				if len(pkt) < 20 {
					return
				}
				srcIP := tunnel.GetSrcIP(pkt)
				destIP := tunnel.GetDestIP(pkt)
				if srcIP == nil || destIP == nil {
					return
				}
				if srcIP.String() == myVirtualIP {
					return
				}
				if destIP.String() != myVirtualIP && destIP.String() != "100.64.200.1" {
					return
				}
				if tunDev != nil {
					_ = tunDev.WritePacket(pkt)
				}
			})
		}
	}

	// Р¤РѕРЅРѕРІС‹Р№ РїРѕС‚РѕРє С‡С‚РµРЅРёСЏ РёСЃС…РѕРґСЏС‰РёС… IP-РїР°РєРµС‚РѕРІ РёР· СЃРµС‚РµРІРѕРіРѕ СЃС‚РµРєР° РћРЎ Рё РїРµСЂРµСЃС‹Р»РєР° РїРёСЂР°Рј
	if tunDev != nil {
		go func() {
			for {
				select {
				case <-engineCtx.Done():
					return
				default:
					packet, readErr := tunDev.ReadPacket()
					if readErr != nil {
						return
					}
					destIP := tunnel.GetDestIP(packet)
					if destIP == nil {
						continue
					}
					destStr := destIP.String()
					if !strings.HasPrefix(destStr, "100.64.200.") || destStr == "100.64.200.255" || destStr == myVirtualIP {
						continue
					}
					if registry != nil {
						peers := registry.List()
						for _, p := range peers {
							if p.DeviceID != deviceID && (p.VirtualIP == destStr || len(peers) == 1) {
								if puncher != nil {
									if p.ActiveEndpoint != "" {
										_ = puncher.SendDataPacket(p.ActiveEndpoint, packet)
									}
									if p.STUNAddr != "" && p.STUNAddr != p.ActiveEndpoint {
										_ = puncher.SendDataPacket(p.STUNAddr, packet)
									}
								}
								// Dual-path relay fallback via MQTT
								for _, ch := range channels {
									if mqCh, isMq := ch.(*signaling.MQTTChannel); isMq {
										_ = mqCh.PublishTunnelData(p.DeviceID, packet)
									}
								}
							}
						}
					}
				}
			}
		}()
	}

	// Р¤РѕРЅРѕРІС‹Р№ С†РёРєР» РїРµСЂРёРѕРґРёС‡РµСЃРєРѕРіРѕ РїСЂРѕР±РёС‚РёСЏ NAT Рё РїРѕРґРґРµСЂР¶Р°РЅРёСЏ СЃРѕРєРµС‚РѕРІ Р¶РёРІС‹РјРё (KeepAlive)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		// Р’СЃРїРѕРјРѕРіР°С‚РµР»СЊРЅР°СЏ С„СѓРЅРєС†РёСЏ: 3 РїСЂРѕР±С‹ РЅР° РѕРґРёРЅ Р°РґСЂРµСЃ СЃ РёРЅС‚РµСЂРІР°Р»РѕРј 150РјСЃ
		probe3 := func(addr string) {
			if addr == "" {
				return
			}
			for i := 0; i < 3; i++ {
				_ = puncher.SendHolePunchProbe(addr)
				if i < 2 {
					time.Sleep(150 * time.Millisecond)
				}
			}
		}
		for {
			select {
			case <-engineCtx.Done():
				return
			case <-ticker.C:
				if puncher != nil && registry != nil {
					for _, p := range registry.List() {
						if p.Online && p.DeviceID != deviceID {
							go func(peer *peer.Peer) {
								if peer.ActiveEndpoint != "" {
									probe3(peer.ActiveEndpoint)
								}
								if peer.STUNAddr != "" && peer.STUNAddr != peer.ActiveEndpoint {
									probe3(peer.STUNAddr)
								}
								if peer.IPv6Addr != "" && peer.IPv6Addr != peer.ActiveEndpoint {
									probe3(peer.IPv6Addr)
								}
								if peer.LocalAddr != "" && peer.LocalAddr != peer.ActiveEndpoint {
									probe3(peer.LocalAddr)
								}
								if peer.PublicIP != "" {
									probe3(fmt.Sprintf("%s:47832", peer.PublicIP))
									probe3(fmt.Sprintf("%s:51820", peer.PublicIP))
									if peer.WGPort > 0 && peer.WGPort != 47832 && peer.WGPort != 51820 {
										probe3(fmt.Sprintf("%s:%d", peer.PublicIP, peer.WGPort))
									}
								}
							}(p)
						}
					}
				}
			}
		}
	}()

	// рџЏ  LAN Broadcast Discovery (Р»РѕРєР°Р»СЊРЅС‹Р№ РїРѕРёСЃРє Р·Р° <0.1СЃ)
	go func() {
		lAddr, _ := net.ResolveUDPAddr("udp4", ":51821")
		conn, err := net.ListenUDP("udp4", lAddr)
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			for {
				n, src, rErr := conn.ReadFromUDP(buf)
				if rErr != nil {
					return
				}
				parts := strings.Split(string(buf[:n]), "|")
				if len(parts) >= 2 && parts[0] == "NATBYPASS_LAN" && parts[1] != deviceID {
					log.Info().Str("peer", parts[1]).Str("addr", src.String()).Msg("рџЏ  [LAN Discovery] РћР±РЅР°СЂСѓР¶РµРЅ Р»РѕРєР°Р»СЊРЅС‹Р№ РїРёСЂ")
					if puncher != nil {
						puncher.SendHolePunchProbe(src.String())
					}
				}
			}
		}
	}()

	var stunAddr string
	var ipv6Addr string
	var publicIP net.IP = net.IPv4(0, 0, 0, 0)
	ipDisc := network.NewDiscoverer(cfg.Network.IPApis, time.Duration(cfg.Network.IPTimeout)*time.Second)

	triggerPublishCh := make(chan struct{}, 10)
	triggerPublish := func() {
		select {
		case triggerPublishCh <- struct{}{}:
		default:
		}
	}

	// Р¤РѕРЅРѕРІРѕРµ РѕРїСЂРµРґРµР»РµРЅРёРµ IP Рё STUN вЂ” РїРѕСЃР»Рµ СѓСЃРїРµС…Р° СЃСЂР°Р·Сѓ РїСѓР±Р»РёРєСѓРµРј РјР°СЏРє СЃРѕ СЃРІРµР¶РёРј STUN-Р°РґСЂРµСЃРѕРј
	go func() {
		if ip, err := ipDisc.GetPublicIPCached(engineCtx, 5*time.Minute); err == nil {
			publicIP = ip
			log.Info().Str("ip", publicIP.String()).Msg("РџСѓР±Р»РёС‡РЅС‹Р№ IP РѕРїСЂРµРґРµР»С‘РЅ")
			triggerPublish() // СЃСЂР°Р·Сѓ РїСѓР±Р»РёРєСѓРµРј СЃ СЂРµР°Р»СЊРЅС‹Рј IP
		}

		if v6 := network.GetPublicIPv6(engineCtx); v6 != "" {
			puncherPort := 47832
			if puncher != nil {
				puncherPort = puncher.LocalPort()
			}
			ipv6Addr = fmt.Sprintf("[%s]:%d", v6, puncherPort)
			log.Info().Str("ipv6", ipv6Addr).Msg("Р“Р»РѕР±Р°Р»СЊРЅС‹Р№ IPv6 Р°РґСЂРµСЃ РѕРїСЂРµРґРµР»С‘РЅ (P2P Р±РµР· CGNAT РґР»СЏ РјРѕР±РёР»СЊРЅС‹С… СЃРµС‚РµР№)")
			triggerPublish()
		}

		if puncher != nil {
			if sIP, sPort, sErr := puncher.DiscoverMappedAddress(engineCtx); sErr == nil && sIP != nil {
				stunAddr = fmt.Sprintf("%s:%d", sIP.String(), sPort)
				log.Info().Str("stun_addr", stunAddr).Msg("STUN СЃРѕРєРµС‚ РѕРїСЂРµРґРµР»С‘РЅ С‡РµСЂРµР· UDPPuncher")
				triggerPublish() // СЃСЂР°Р·Сѓ РїСѓР±Р»РёРєСѓРµРј СЃРѕ STUN-Р°РґСЂРµСЃРѕРј вЂ” РєСЂРёС‚РёС‡РµСЃРєРё РІР°Р¶РЅРѕ РґР»СЏ hole punch!
			}
		}
		if stunAddr == "" {
			stunClient := network.NewSTUNClient(cfg.Network.StunServers)
			if stunIP, stunPort, stunErr := stunClient.GetMappedAddress(engineCtx); stunErr == nil {
				stunAddr = fmt.Sprintf("%s:%d", stunIP.String(), stunPort)
				log.Info().Str("stun_addr", stunAddr).Msg("STUN Р°РґСЂРµСЃ РѕРїСЂРµРґРµР»С‘РЅ")
				triggerPublish() // РїСѓР±Р»РёРєСѓРµРј Рё РїРѕ СЂРµР·РµСЂРІРЅРѕРјСѓ STUN
			}
		}

		if cfg.Network.UpnpEnabled {
			go func() {
				upnpClient := network.NewUPnPClient()
				if err := upnpClient.AddPortMapping(engineCtx, 47832, 47832, "UDP", "NatBypass P2P Puncher", 3600); err == nil {
					log.Info().Int("port", 47832).Msg("вњ… [UPnP] РџРѕСЂС‚ 47832 UDP СѓСЃРїРµС€РЅРѕ РѕС‚РєСЂС‹С‚ РЅР° СЂРѕСѓС‚РµСЂРµ (Full Cone P2P Р°РєС‚РёРІРµРЅ)")
				}
				if cfg.WireGuard.ListenPort > 0 {
					_ = upnpClient.AddPortMapping(engineCtx, cfg.WireGuard.ListenPort, cfg.WireGuard.ListenPort, "UDP", "NatBypass WireGuard", 3600)
				}
			}()
		}

		if uiServer != nil {
			uiServer.SetAppState(deviceID, publicIP.String(), stunAddr, myVirtualIP)
			uiServer.SetVirtualIP(myVirtualIP)
		}
		triggerPublish()
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
	if publishInterval <= 0 || publishInterval > 15*time.Second {
		publishInterval = 8 * time.Second
	}

	// РњРіРЅРѕРІРµРЅРЅС‹Рµ СЃС‚Р°СЂС‚РѕРІС‹Рµ Р°РЅРѕРЅСЃС‹
	go func() {
		time.Sleep(300 * time.Millisecond)
		triggerPublish()
		time.Sleep(1500 * time.Millisecond)
		triggerPublish()
		time.Sleep(4 * time.Second)
		triggerPublish()
	}()

	// Р¦РёРєР» РїСѓР±Р»РёРєР°С†РёРё Р°РЅРѕРЅСЃРѕРІ
	go func() {
		ticker := time.NewTicker(publishInterval)
		defer ticker.Stop()
		for {
			select {
			case <-engineCtx.Done():
				return
			case <-ticker.C:
				triggerPublish()
			case <-triggerPublishCh:
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
				nick := cfg.App.DeviceName
				if uiServer != nil {
					if dName := uiServer.GetDeviceName(); dName != "" {
						nick = dName
					}
				}
				rawOS, platformName, osEmoji := network.DetectPlatform()
				flag := network.LookupCountryFlag(engineCtx, ip.String())
				lanIP := network.GetLocalLANIP()
				localAddr := ""
				if lanIP != "" {
					// РСЃРїРѕР»СЊР·СѓРµРј РїРѕСЂС‚ puncher (47832), Р° РЅРµ wgPort вЂ” wgPort=0 РµСЃР»Рё WireGuard РІС‹РєР»СЋС‡РµРЅ,
					// Р° РґС‹СЂСЏРІРёС‚СЊ NAT РЅР°РґРѕ РёРјРµРЅРЅРѕ С‡РµСЂРµР· РїРѕСЂС‚, РЅР° РєРѕС‚РѕСЂРѕРј СЃР»СѓС€Р°РµС‚ puncher
					puncherPort := 47832
					if puncher != nil {
						puncherPort = puncher.LocalPort()
					}
					localAddr = fmt.Sprintf("%s:%d", lanIP, puncherPort)
				}
				activeProf := cfg.EnsureActiveProfile()
				activeKey := ""
				activeTopic := ""
				if activeProf != nil {
					activeKey = activeProf.NetworkKey
					activeTopic = activeProf.MQTTTopic
				}
				payload := &signaling.Payload{
					DeviceID:         deviceID,
					Nickname:         nick,
					DeviceName:       nick,
					VirtualIP:        myVirtualIP,
					PublicKey:        crypto.KeyToHex(pubKey),
					PublicIP:         ip.String(),
					LocalAddr:        localAddr,
					STUNAddr:         stunAddr,
					IPv6Addr:         ipv6Addr,
					WGPubKey:         wgPubKey,
					WGPort:           wgPort,
					IsExitNode:       cfg.Network.AllowExitNode,
					AdvertisedRoutes: cfg.Network.AdvertisedSubnets,
					Timestamp:        time.Now(),
					AWG:              awgParams,
					OS:               rawOS,
					Platform:         osEmoji + " " + platformName,
					CountryFlag:      flag,
					NetworkKey:       activeKey,
					Topic:            activeTopic,
				}
				_ = sigMgr.Send(engineCtx, payload)

				// LAN Broadcast Ping
				if bcastAddr, bErr := net.ResolveUDPAddr("udp4", "255.255.255.255:51821"); bErr == nil {
					bConn, bConnErr := net.DialUDP("udp4", nil, bcastAddr)
					if bConnErr == nil {
						bConn.Write([]byte(fmt.Sprintf("NATBYPASS_LAN|%s|%s", deviceID, stunAddr)))
						bConn.Close()
					}
				}
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
					if p.DeviceID == "" || p.DeviceID == deviceID {
						continue
					}

					activeProf := cfg.EnsureActiveProfile()
					if activeProf != nil {
						match := false
						if activeProf.MQTTTopic != "" && p.Topic == activeProf.MQTTTopic {
							match = true
						} else if activeProf.NetworkKey != "" && p.NetworkKey == activeProf.NetworkKey {
							match = true
						} else if p.Topic == "" && p.NetworkKey == "" {
							match = true
						} else if activeProf.MQTTTopic == "" && activeProf.NetworkKey == "" {
							match = true
						}
						if !match {
							continue
						}
					}

					if p.Offline || p.Leave {
						log.Info().Str("peer", p.DeviceID).Msg("рџ”ґ РЈР·РµР» РѕС‚РєР»СЋС‡РёР»СЃСЏ РѕС‚ СЃРµС‚Рё (Leave beacon)")
						registry.Delete(p.DeviceID)
						if uiServer != nil {
							uiServer.AddEvent("peer_offline", "РЈР·РµР» "+p.DeviceID+" РѕС‚РєР»СЋС‡РёР»СЃСЏ", "")
						}
						continue
					}

					peerVIP := p.VirtualIP
					if peerVIP == "" {
						pNum := 1
						for _, b := range []byte(p.DeviceID) {
							pNum = (pNum*31 + int(b)) % 250
						}
						if pNum == 0 {
							pNum = 2
						}
						if pNum == myVIPNum {
							pNum = (myVIPNum % 250) + 1
						}
						peerVIP = fmt.Sprintf("100.64.200.%d", pNum)
					}

					osName := p.OS
					plat := p.Platform
					if plat == "" {
						if osName != "" {
							plat = osName
						} else {
							plat = "рџ’» РЈСЃС‚СЂРѕР№СЃС‚РІРѕ"
						}
					}
					pFlag := p.CountryFlag
					if pFlag == "" && p.PublicIP != "" {
						pFlag = network.LookupCountryFlag(engineCtx, p.PublicIP)
					}

					registry.Upsert(&peer.Peer{
						DeviceID:         p.DeviceID,
						Nickname:         p.Nickname,
						VirtualIP:        peerVIP,
						PublicKey:        p.PublicKey,
						PublicIP:         p.PublicIP,
						LocalAddr:        p.LocalAddr,
						STUNAddr:         p.STUNAddr,
						IPv6Addr:         p.IPv6Addr,
						WGPubKey:         p.WGPubKey,
						WGPort:           p.WGPort,
						DirectP2P:        p.DirectP2P,
						ActiveEndpoint:   p.ActiveEndpoint,
						PingMs:           p.PingMs,
						IsExitNode:       p.IsExitNode,
						AdvertisedRoutes: p.AdvertisedRoutes,
						LastSeen:         time.Now(),
						Online:           true,
						AWG:              p.AWG,
						OS:               osName,
						Platform:         plat,
						CountryFlag:      pFlag,
						Channel:          p.Channel,
					})

					log.Info().Str("peer", p.DeviceID).Str("vip", peerVIP).Str("stun", p.STUNAddr).Msg("рџ“Ґ [P2P Signal] РћР±РЅР°СЂСѓР¶РµРЅ РїРёСЂ РІ СЃРёРіРЅР°Р»СЊРЅРѕР№ СЃРµС‚Рё")
					if uiServer != nil {
						uiServer.AddEvent("peer_online", "РћР±РЅР°СЂСѓР¶РµРЅ СѓР·РµР»: "+p.DeviceID, "VIP: "+peerVIP)
					}

					// РќРµРјРµРґР»РµРЅРЅС‹Р№ burst hole-punch Рє РїРёСЂСѓ + РІСЃС‚СЂРµС‡РЅР°СЏ РїСѓР±Р»РёРєР°С†РёСЏ РЅР°С€РµРіРѕ РјР°СЏРєР°
					if puncher != nil {
						go func(peer *signaling.Payload) {
							// РЎС‚СЂРѕРёРј СЃРїРёСЃРѕРє Р°РґСЂРµСЃРѕРІ РґР»СЏ РїСЂРѕР±РёРІРєРё:
							// 1. STUNAddr вЂ” STUN-mapped Р°РґСЂРµСЃ РїРѕСЂС‚Р° puncher
							// 2. IPv6Addr вЂ” РїСЂСЏРјРѕР№ РіР»РѕР±Р°Р»СЊРЅС‹Р№ IPv6 Р°РґСЂРµСЃ (Р±РµР· CGNAT)
							// 3. LocalAddr вЂ” LAN IP РїРёСЂР°
							// 4. PublicIP:47832 (Windows default) Рё PublicIP:51820 (Mobile/Linux default)
							// 5. PublicIP:WGPort вЂ” РµСЃР»Рё WireGuard РІРєР»СЋС‡РµРЅ Сѓ РїРёСЂР°
							addrs := []string{peer.STUNAddr, peer.LocalAddr}
							if peer.IPv6Addr != "" {
								addrs = append(addrs, peer.IPv6Addr)
							}
							if peer.PublicIP != "" {
								addrs = append(addrs, fmt.Sprintf("%s:47832", peer.PublicIP))
								addrs = append(addrs, fmt.Sprintf("%s:51820", peer.PublicIP))
								if peer.WGPort > 0 && peer.WGPort != 47832 && peer.WGPort != 51820 {
									addrs = append(addrs, fmt.Sprintf("%s:%d", peer.PublicIP, peer.WGPort))
								}
							}
							// 5 СЃРµСЂРёР№ СЃ РёРЅС‚РµСЂРІР°Р»РѕРј 200РјСЃ = 1 СЃРµРєСѓРЅРґР° Р°РєС‚РёРІРЅРѕР№ РїСЂРѕР±РёРІРєРё
							for burst := 0; burst < 5; burst++ {
								for _, addr := range addrs {
									if addr != "" {
										_ = puncher.SendHolePunchProbe(addr)
									}
								}
								if burst < 4 {
									time.Sleep(200 * time.Millisecond)
								}
							}
						}(p)
						// РџСѓР±Р»РёРєСѓРµРј РЅР°С€ СЃРІРµР¶РёР№ РјР°СЏРє вЂ” РїРёСЂ РїРѕР»СѓС‡РёС‚ РЅР°С€ STUN Рё СЃРјРѕР¶РµС‚ РїСЂРѕР±РёС‚СЊСЃСЏ Рє РЅР°Рј
						triggerPublish()
					}
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
				Address:       "100.64.200.1/24",
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

// в”Ђв”Ђ diag в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newDiagCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diag",
		Short: "Р—Р°РїСѓСЃС‚РёС‚СЊ РіР»СѓР±РѕРєСѓСЋ Р°РїРїР°СЂР°С‚РЅСѓСЋ Рё СЃРёСЃС‚РµРјРЅСѓСЋ РґРёР°РіРЅРѕСЃС‚РёРєСѓ РѕР±РѕСЂСѓРґРѕРІР°РЅРёСЏ",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("================================================================")
			fmt.Println("       рџ©є NatBypass вЂ” РќРёР·РєРѕСѓСЂРѕРІРЅРµРІР°СЏ РґРёР°РіРЅРѕСЃС‚РёРєР° СЃРёСЃС‚РµРјС‹        ")
			fmt.Println("================================================================")
			fmt.Println()

			rep := diagnostic.RunFullDiagnostics()
			fmt.Printf("РҐРѕСЃС‚: %s | РћРЎ: %s | РђСЂС…РёС‚РµРєС‚СѓСЂР°: %s\n", rep.Hostname, rep.OS, rep.Arch)
			fmt.Printf("РџСЂР°РІР° РђРґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР°: %v\n\n", rep.IsAdmin)

			for i, item := range rep.Items {
				statusIcon := "рџџў"
				if !item.Passed {
					statusIcon = "рџ”ґ"
				}
				fmt.Printf("[%d/8] %s %s (%d ms)\n", i+1, statusIcon, item.Name, item.Elapsed.Milliseconds())
				fmt.Printf("      %s\n", item.Message)
				if item.Details != "" {
					fmt.Printf("      РџРѕРґСЂРѕР±РЅРѕСЃС‚Рё: %s\n", item.Details)
				}
				fmt.Println()
			}

			fmt.Println("================================================================")
			fmt.Println("    вљЎ RFC 4787 / STUN РђРЅР°Р»РёР· С‚РёРїР° NAT Рё С€Р°РЅСЃРѕРІ DirectP2P      ")
			fmt.Println("================================================================")
			fmt.Println("РўРµСЃС‚РёСЂРѕРІР°РЅРёРµ С‚СЂР°РЅСЃР»СЏС†РёРё РїРѕСЂС‚РѕРІ...")

			natInfo, err := diagnostic.ClassifyNATBehavior()
			if err != nil {
				fmt.Printf("вљ пёЏ РћС€РёР±РєР° С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ NAT: %v\n", err)
			} else {
				fmt.Printf("вЂў Р’РЅРµС€РЅРёР№ IP Р°РґСЂРµСЃ:      %s\n", natInfo.PublicIP)
				fmt.Printf("вЂў РўРёРї NAT СЂРѕСѓС‚РµСЂР°:       %s\n", natInfo.NATType)
				fmt.Printf("вЂў РџРѕРІРµРґРµРЅРёРµ РїРѕСЂС‚РѕРІ (EIM):%s\n", natInfo.MappingType)
				fmt.Printf("вЂў Р’РµСЂРѕСЏС‚РЅРѕСЃС‚СЊ DirectP2P: %s\n", natInfo.P2PFeasibility)
				fmt.Printf("вЂў Р РµРєРѕРјРµРЅРґР°С†РёСЏ:          %s\n", natInfo.Recommendation)
			}

			fmt.Println("================================================================")
			if rep.AllPassed {
				fmt.Println("вњ… Р’СЃРµ Р±Р°Р·РѕРІС‹Рµ С‚РµСЃС‚С‹ РїСЂРѕР№РґРµРЅС‹! РћР±РѕСЂСѓРґРѕРІР°РЅРёРµ Рё СЃРµС‚СЊ РіРѕС‚РѕРІС‹ Рє СЂР°Р±РѕС‚Рµ.")
			} else {
				fmt.Println("вљ пёЏ РћР±РЅР°СЂСѓР¶РµРЅС‹ СЃРёСЃС‚РµРјРЅС‹Рµ Р·Р°РјРµС‡Р°РЅРёСЏ. РћР·РЅР°РєРѕРјСЊС‚РµСЃСЊ СЃ РїРѕРґСЃРєР°Р·РєР°РјРё РІС‹С€Рµ.")
			}
			fmt.Println("================================================================")
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

func min8(a, b int) int {
	if a < b {
		return a
	}
	return b
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
			topic := chCfg.Params["topic"]
			clientID := chCfg.Params["client_id"]
			username := chCfg.Params["username"]
			password := chCfg.Params["password"]
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
	cfg.App.PublishInterval = 60

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
        broker_url: "tcp://broker.emqx.io:1883"
        topic: "natbypass/mynet/peers"

wireguard:
  enabled: false
  interface: "wg0"
  listen_port: 51820
`
		_ = os.WriteFile(path, []byte(sample), 0644)
	}
}
