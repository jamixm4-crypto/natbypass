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
	"sync"
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
	"github.com/natbypass/natbypass/internal/tunnel"
	"github.com/natbypass/natbypass/internal/updater"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
)

// Заполняется при сборке через -ldflags -X
var (
	Version   = "1.2.7"
	Commit    = "release"
	BuildDate = "unknown"

	// Вшитые умолчания (задаются через build-win.ps1 / build-linux.sh)
	DefaultTgToken    = "" // Токен Telegram-бота
	DefaultTgChatID   = "" // ID чата/канала Telegram
	DefaultMQTTBroker = "" // URL MQTT-брокера
	DefaultMQTTTopic  = "" // MQTT-топик
	DefaultWebhookURL = "" // URL HTTP Webhook
	DefaultDeviceID   = "" // дентификатор устройства
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
	// Устанавливаем рабочую директорию на папку с исполняемым файлом (важно для Windows)
	if exe, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exe))
	}

	// Перехватываем любую панику и пишем в лог-файл — важно для windowsgui где консоли нет
	defer func() {
		if r := recover(); r != nil {
			_ = os.WriteFile("natbypass-crash.log",
				[]byte(fmt.Sprintf("PANIC: %v\nTime: %s\n", r, time.Now().Format(time.RFC3339))),
				0644)
		}
	}()

	// нициализируем логирование — на Windows автоматически пишет в natbypass.log рядом с exe
	setupLogging("info", "")

	// Автоматический запрос прав Администратора через UAC на Windows при обычном запуске
	ensureAdminOnWindows()

	// Если процесс запущен под управлением Windows Service Manager
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
		Short: "NatBypass — обход NAT и организация P2P-доступа",
		Long: fmt.Sprintf(`NatBypass v%s (%s) — кроссплатформенный инструмент 
для обхода NAT (включая двойной NAT / CGNAT) через мультиканальную сигнализацию.

Поддерживаемые каналы: Telegram, MQTT, HTTP Webhook, DNS TXT
Поддерживаемые платформы: Windows, Linux (amd64/arm64/mips/mipsle), Android, iOS`, Version, Commit),
		RunE: func(cmd *cobra.Command, args []string) error {
			// По умолчанию при запуске без аргументов (двойной клик по .exe) запускаем сервис
			cfg, err := config.Load(configFile)
			firstLaunch := (err != nil || cfg == nil)
			if firstLaunch {
				cfg = buildDefaultConfig()
			}
			applyBuiltinDefaults(cfg)
			// При первом запуске сразу сохраняем конфиг — чтобы WebUI мог редактировать профиль
			if firstLaunch {
				_ = config.Save(cfg, configFile, runtime.GOOS == "windows")
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			return runEngine(ctx, cfg, runtime.GOOS == "windows")
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yaml", "путь к config.yaml")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "уровень логирования: debug/info/warn/error")
	rootCmd.PersistentFlags().BoolVar(&noWebUI, "no-webui", false, "отключить Web UI")
	rootCmd.PersistentFlags().IntVar(&webUIPort, "port", 0, "переопределить порт Web UI")

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
		Short: "Установить новый MQTT топик и применить настройки",
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
				return fmt.Errorf("ошибка записи %s: %w", cfgPath, err)
			}
			fmt.Printf("✓ MQTT топик успешно обновлен на: %s (файл: %s)\n", newTopic, cfgPath)
			if runtime.GOOS == "linux" {
				if _, err := os.Stat("/etc/systemd/system/natbypass.service"); err == nil {
					_ = exec.Command("systemctl", "restart", "natbypass").Run()
					fmt.Println("✓ Служба systemd перезапущена.")
				} else if _, err := os.Stat("/opt/etc/init.d/S99natbypass"); err == nil {
					_ = exec.Command("/opt/etc/init.d/S99natbypass", "restart").Run()
					fmt.Println("✓ Служба Keenetic Entware перезапущена.")
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
		Short: "Установить токен и chat_id Telegram бота",
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
				return fmt.Errorf("ошибка записи %s: %w", cfgPath, err)
			}
			fmt.Printf("✓ Telegram бот успешно настроен (файл: %s)\n", cfgPath)
			if runtime.GOOS == "linux" {
				if _, err := os.Stat("/etc/systemd/system/natbypass.service"); err == nil {
					_ = exec.Command("systemctl", "restart", "natbypass").Run()
					fmt.Println("✓ Служба systemd перезапущена.")
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
		Short: "Запустить NatBypass (основной цикл)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				if os.IsNotExist(err) {
					cfg = buildDefaultConfig()
					ensureConfigFileExists(configFile)
				} else {
					return fmt.Errorf("ошибка загрузки конфига: %w", err)
				}
			}
			applyBuiltinDefaults(cfg)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			return runEngine(ctx, cfg, useTray)
		},
	}
	cmd.Flags().BoolVarP(&useTray, "tray", "t", runtime.GOOS == "windows", "сворачивать в системный трей (Windows)")
	return cmd
}

// ── gui (запуск с треем по умолчанию) ──────────────────────────
func newGuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gui",
		Short: "Запустить NatBypass в графическом режиме с иконкой в трее",
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

// ── service (Windows Service управление) ────────────────────────
func newServiceCmd() *cobra.Command {
	svcCmd := &cobra.Command{
		Use:   "service",
		Short: "Управление службой Windows (install, uninstall, start, stop, status)",
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Установить NatBypass как системную службу Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.InstallService(configFile)
			if err != nil {
				return fmt.Errorf("ошибка установки службы: %w", err)
			}
			fmt.Println("✓ Служба NatBypass успешно установлена в Windows!")
			fmt.Println("  Тип запуска: Автоматически")
			fmt.Println("  Для запуска выполните: natbypass service start")
			return nil
		},
	}

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Удалить службу NatBypass из Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.UninstallService()
			if err != nil {
				return fmt.Errorf("ошибка удаления службы: %w", err)
			}
			fmt.Println("✓ Служба NatBypass удалена из системы.")
			return nil
		},
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Запустить установленную службу Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.StartWindowsService()
			if err != nil {
				return fmt.Errorf("ошибка запуска службы: %w", err)
			}
			fmt.Println("✓ Служба NatBypass запущена.")
			return nil
		},
	}

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Остановить службу Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.StopWindowsService()
			if err != nil {
				return fmt.Errorf("ошибка остановки службы: %w", err)
			}
			fmt.Println("✓ Служба NatBypass остановлена.")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Проверить статус службы Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := daemon.QueryServiceStatus()
			if err != nil {
				return fmt.Errorf("ошибка получения статуса службы: %w", err)
			}
			fmt.Printf("Статус службы Windows: %s\n", st)
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
		Short: "Проверить и установить обновление NatBypass с GitHub",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("🔍 Проверка обновлений (текущая версия: %s)...\n", Version)
			info, err := updater.CheckUpdate(context.Background(), Version)
			if err != nil {
				return fmt.Errorf("ошибка проверки обновлений: %w", err)
			}
			if !info.HasUpdate && !force {
				fmt.Printf("✅ У вас установлена актуальная версия (%s, релиз: %s)\n", Version, info.PublishedAt)
				fmt.Println("💡 спользуйте 'natbypass update --force' для принудительной переустановки свежего билда.")
				return nil
			}
			if info.HasUpdate {
				fmt.Printf("🚀 Найдена новая версия: %s (опубликована: %s)\n", info.LatestVersion, info.PublishedAt)
			} else {
				fmt.Printf("🔄 Принудительное обновление до последнего билда релиза (%s, опубликован: %s)\n", info.LatestVersion, info.PublishedAt)
			}
			fmt.Printf("📦 Файл для вашей системы: %s (%d KB)\n", info.AssetName, info.AssetSize/1024)
			if info.ReleaseNotes != "" {
				fmt.Printf("\n📝 Описание изменений:\n%s\n\n", info.ReleaseNotes)
			}
			fmt.Println(">> Скачивание и применение обновления...")
			err = updater.ApplyUpdate(context.Background(), info.AssetURL)
			if err != nil {
				return fmt.Errorf("ошибка применения обновления: %w", err)
			}
			fmt.Println("🎉 Обновление успешно установлено! Служба перезапущена.")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "принудительно переустановить последний билд, даже если версии совпадают")
	return cmd
}

// ── Основной движок ───────────────────────────────────────────
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
			log.Warn().Msg("⚠️ Экземпляр NatBypass уже запущен. Открываем существующую панель управления...")
			return nil
		}
		defer releaseSingleInstanceMutex()
	}

	setupLogging(cfg.App.LogLevel, cfg.App.LogFile)
	log.Info().
		Str("version", Version).
		Str("commit", Commit).
		Str("config", configFile).
		Msg("Запуск NatBypass")

	pubKey, privKey, err := loadOrGenerateKeys(cfg)
	if err != nil {
		return fmt.Errorf("ошибка загрузки ключей: %w", err)
	}
	log.Info().Str("public_key", crypto.KeyToHex(pubKey)).Msg("NaCl ключи загружены")

	deviceID := cfg.App.DeviceID
	if deviceID == "" {
		if hn, err := os.Hostname(); err == nil && hn != "" {
			deviceID = hn
		} else {
			deviceID = generateDeviceID(pubKey)
		}
	}
	log.Info().Str("device_id", deviceID).Msg("дентификатор устройства")

	engineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	registry := peer.NewRegistry()
	registry.StartMonitor(engineCtx, 30*time.Second)

	// Определяем топик из активного профиля (при наличии), иначе — уникальный на основе deviceID
	hadProfiles := len(cfg.Profiles) > 0
	activeProf := cfg.EnsureActiveProfile()
	if !hadProfiles && activeProf != nil {
		_ = config.Save(cfg, configFile, runtime.GOOS == "windows")
	}
	defaultTopic := fmt.Sprintf("natbypass/%s/peers", deviceID[:min8(len(deviceID), 8)])
	if activeProf != nil && activeProf.MQTTTopic != "" {
		defaultTopic = activeProf.MQTTTopic
	}

	channels, err := buildSignalingChannels(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("Ошибка парсинга каналов, используется резервный канал")
	}
	if len(channels) == 0 {
		log.Info().Str("topic", defaultTopic).Msg("⚙️ Сигнальные каналы не настроены. спользую персональный топик MQTT.")
		channels = append(channels, signaling.NewMQTTChannel("tcp://broker.emqx.io:1883", defaultTopic, deviceID, "", ""))
	} else {
		// Применяем топик активного профиля ко всем MQTT-каналам при старте
		if activeProf != nil && activeProf.MQTTTopic != "" {
			for _, ch := range channels {
				if mqCh, ok := ch.(*signaling.MQTTChannel); ok {
					mqCh.UpdateTopic(activeProf.MQTTTopic)
				}
			}
		}
	}
	sigMgr := signaling.NewFallbackManager(channels)
	log.Info().Int("channels", len(channels)).Str("current", sigMgr.CurrentChannel()).Str("topic", defaultTopic).Msg("Сигнальные каналы инициализированы")

	port = cfg.WebUI.Port
	if webUIPort > 0 {
		port = webUIPort
	}
	if port == 0 {
		port = 8080
	}

	// 🚀 Автоматическое создание виртуального сетевого интерфейса (nb0 на Linux / NatBypass на Windows)
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
		uiServer.SetAppState(deviceID, "Определяется...", "Определяется...", myVirtualIP)
		uiServer.SetVirtualIP(myVirtualIP)
		uiServer.SetDeviceName(deviceID)
		uiServer.SetVersion(Version)
		uiServer.AddEvent("info", "NatBypass запущен", "version="+Version)

		uiServer.SetOnProfileSwitch(func(p *config.Profile) error {
			if p == nil {
				return nil
			}
			log.Info().Str("profile", p.Name).Str("topic", p.MQTTTopic).Msg("⚡ Динамическое переключение профиля сети")
			if sigMgr != nil && p.MQTTTopic != "" {
				sigMgr.UpdateMQTTTopic(p.MQTTTopic)
			}
			registry.ClearAll()
			return nil
		})

		go func() {
			if err := uiServer.Start(engineCtx); err != nil {
				log.Error().Err(err).Msg("Web UI остановлен")
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
		log.Info().Str("adapter", adapterName).Str("vip", myVirtualIP).Msg("🛡️ Виртуальный сетевой интерфейс поднят! Прямой доступ к устройству активирован")
		if uiServer != nil {
			uiServer.AddEvent("info", "Сетевой интерфейс "+adapterName+" поднят", "IP: "+myVirtualIP+"/24")
		}
	} else {
		log.Warn().Err(tErr).Msg("Не удалось поднять виртуальный интерфейс TUN (требуются права root или загруженный модуль tun)")
	}

	var puncher *network.UDPPuncher
	// спользуем порт 47832 для пробивки NAT — отдельный от WireGuard (51820),
	// чтобы избежать конфликта портов и сохранить правильный STUN-адрес в маяке.
	puncher, err = network.NewUDPPuncher(47832, deviceID, cfg.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		if p, ok := registry.Get(remoteDevID); ok {
			wasDirect := p.DirectP2P
			p.DirectP2P = true
			p.ActiveEndpoint = fromAddr
			p.STUNAddr = fromAddr
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

			// Логируем только при первом успешном переходе в Direct P2P или раз в минуту
			if !wasDirect {
				log.Info().Str("peer", remoteDevID).Dur("rtt", p.Latency).Str("from", fromAddr).Msg("⚡ [P2P Direct UDP] ПОДТВЕРЖДЕНО! Прямой UDP-пинг установлен")
			}
		}
	})
	if err == nil {
		log.Info().Int("port", puncher.LocalPort()).Msg("UDPPuncher активен")
		puncher.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
			if len(payload) < 20 {
				return
			}
			srcIP := tunnel.GetSrcIP(payload)
			if srcIP != nil && srcIP.String() == myVirtualIP {
				return // Защита от петель
			}
			if tunDev != nil {
				_ = tunDev.WritePacket(payload)
			}
		})
	}

	// 📡 Подписка на релей туннельных пакетов через MQTT для гарантированного P2P
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

	// Фоновый поток чтения исходящих IP-пакетов из сетевого стека ОС и пересылка пирам
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
									if p.LocalAddr != "" && p.LocalAddr != p.ActiveEndpoint {
										_ = puncher.SendDataPacket(p.LocalAddr, packet)
									}
									if p.STUNAddr != "" && p.STUNAddr != p.ActiveEndpoint && p.STUNAddr != p.LocalAddr {
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

	// Фоновый цикл периодического пробития NAT и поддержания сокетов живыми (KeepAlive)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		// Вспомогательная функция: 3 пробы на один адрес с интервалом 150мс
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

	var stunAddr string
	var ipv6Addr string
	var publicIP net.IP = net.IPv4(0, 0, 0, 0)
	ipDisc := network.NewDiscoverer(cfg.Network.IPApis, time.Duration(cfg.Network.IPTimeout)*time.Second)

	// Фоновый периодический анонс в LAN (раз в 60 секунд)
	go func() {
		lanTicker := time.NewTicker(60 * time.Second)
		defer lanTicker.Stop()
		for {
			select {
			case <-engineCtx.Done():
				return
			case <-lanTicker.C:
				if bcastAddr, bErr := net.ResolveUDPAddr("udp4", "255.255.255.255:51821"); bErr == nil {
					pPort := 47832
					if puncher != nil {
						pPort = puncher.LocalPort()
					}
					localTarget := fmt.Sprintf("%s:%d", publicIP.String(), pPort)
					if stunAddr != "" {
						localTarget = stunAddr
					}
					if bConn, bConnErr := net.DialUDP("udp4", nil, bcastAddr); bConnErr == nil {
						_, _ = bConn.Write([]byte(fmt.Sprintf("NATBYPASS_LAN|%s|%s", deviceID, localTarget)))
						_ = bConn.Close()
					}
				}
			}
		}
	}()

	// 🏠 LAN Broadcast Discovery (локальный поиск в локальной сети)
	go func() {
		lAddr, _ := net.ResolveUDPAddr("udp4", ":51821")
		conn, err := net.ListenUDP("udp4", lAddr)
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 2048)
			for {
				n, src, rErr := conn.ReadFromUDP(buf)
				if rErr != nil {
					return
				}
				dataStr := string(buf[:n])
				parts := strings.Split(dataStr, "|")
				if len(parts) >= 2 && parts[0] == "NATBYPASS_LAN" && parts[1] != deviceID {
					peerID := parts[1]
					targetAddr := ""
					if len(parts) >= 3 && parts[2] != "" {
						targetAddr = parts[2]
					} else {
						targetAddr = src.String()
					}

					p, exists := registry.Get(peerID)
					if exists {
						// Пир уже известен из сигнального канала — обновляем локальный адрес и статус
						p.LastSeen = time.Now()
						p.Online = true
						p.LocalAddr = targetAddr
						if p.ActiveEndpoint == "" {
							p.ActiveEndpoint = targetAddr
						}
						registry.Upsert(p)
					}

					if puncher != nil && targetAddr != "" {
						_ = puncher.SendHolePunchProbe(targetAddr)
					}
				}
			}
		}
	}()

	triggerPublishCh := make(chan struct{}, 10)
	triggerPublish := func() {
		select {
		case triggerPublishCh <- struct{}{}:
		default:
		}
	}

	// Фоновое определение IP и STUN — после успеха сразу публикуем маяк со свежим STUN-адресом
	go func() {
		if ip, err := ipDisc.GetPublicIPCached(engineCtx, 5*time.Minute); err == nil {
			publicIP = ip
			log.Info().Str("ip", publicIP.String()).Msg("Публичный IP определён")
			triggerPublish() // сразу публикуем с реальным IP
		}

		if v6 := network.GetPublicIPv6(engineCtx); v6 != "" {
			puncherPort := 47832
			if puncher != nil {
				puncherPort = puncher.LocalPort()
			}
			ipv6Addr = fmt.Sprintf("[%s]:%d", v6, puncherPort)
			log.Info().Str("ipv6", ipv6Addr).Msg("Глобальный IPv6 адрес определён (P2P без CGNAT для мобильных сетей)")
			triggerPublish()
		}

		if puncher != nil {
			if sIP, sPort, sErr := puncher.DiscoverMappedAddress(engineCtx); sErr == nil && sIP != nil {
				stunAddr = fmt.Sprintf("%s:%d", sIP.String(), sPort)
				log.Info().Str("stun_addr", stunAddr).Msg("STUN сокет определён через UDPPuncher")
				triggerPublish() // сразу публикуем со STUN-адресом — критически важно для hole punch!
			}
		}
		if stunAddr == "" {
			stunClient := network.NewSTUNClient(cfg.Network.StunServers)
			if stunIP, stunPort, stunErr := stunClient.GetMappedAddress(engineCtx); stunErr == nil {
				stunAddr = fmt.Sprintf("%s:%d", stunIP.String(), stunPort)
				log.Info().Str("stun_addr", stunAddr).Msg("STUN адрес определён")
				triggerPublish() // публикуем и по резервному STUN
			}
		}

		if cfg.Network.UpnpEnabled {
			go func() {
				upnpClient := network.NewUPnPClient()
				if err := upnpClient.AddPortMapping(engineCtx, 47832, 47832, "UDP", "NatBypass P2P Puncher", 3600); err == nil {
					log.Info().Int("port", 47832).Msg("✅ [UPnP] Порт 47832 UDP успешно открыт на роутере (Full Cone P2P активен)")
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

	// Мгновенные стартовые анонсы
	go func() {
		time.Sleep(300 * time.Millisecond)
		triggerPublish()
		time.Sleep(1500 * time.Millisecond)
		triggerPublish()
		time.Sleep(4 * time.Second)
		triggerPublish()
	}()

	// Цикл публикации анонсов
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
					// спользуем порт puncher (47832), а не wgPort — wgPort=0 если WireGuard выключен,
					// а дырявить NAT надо именно через порт, на котором слушает puncher
					puncherPort := 47832
					if puncher != nil {
						puncherPort = puncher.LocalPort()
					}
					localAddr = fmt.Sprintf("%s:%d", lanIP, puncherPort)
				}
				// Всегда перечитываем актуальный конфиг (для мгновенного применения Exit Node и подсетей)
				if latestCfg, err := config.Load(configFile); err == nil && latestCfg != nil {
					cfg = latestCfg
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

				// Сквозное шифрование (E2E) сетевым ключом профиля
				if activeProf != nil && activeKey != "" {
					kBytes := activeProf.GetNetworkKeyBytes()
					rawJson, _ := json.Marshal(payload)
					if encBlob, encErr := crypto.EncryptSelf(rawJson, kBytes); encErr == nil {
						payload.Encrypted = encBlob
					}
				}

				_ = sigMgr.Send(engineCtx, payload)

				// LAN Broadcast Ping выполняется в отдельном фоновом цикле раз в 60 секунд
			}
		}
	}()

	// Цикл приема
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
						// 1. Попытка расшифровать сетевым ключом профиля (E2E)
						activeProf := cfg.EnsureActiveProfile()
						if activeProf != nil {
							kBytes := activeProf.GetNetworkKeyBytes()
							if decBytes, err := crypto.DecryptSelf(p.Encrypted, kBytes); err == nil {
								var inner signaling.Payload
								if err := json.Unmarshal(decBytes, &inner); err == nil {
									p = &inner
								}
							}
						}
						// 2. Fallback на асимметричную NaCl коробку
						if len(p.Encrypted) > 0 {
							decrypted, decErr := signaling.DecryptPayload(p, pubKey, privKey)
							if decErr == nil {
								p = decrypted
							}
						}
					}

					// Проверка коллизий IP-адресов в mesh-сети
					if p.VirtualIP != "" && p.VirtualIP == myVirtualIP && p.DeviceID != deviceID {
						// Если коллизия обнаружена, узел с большим ID переназначает свой IP на свободный
						if deviceID > p.DeviceID {
							taken := make(map[string]bool)
							if registry != nil {
								for _, regPeer := range registry.List() {
									taken[regPeer.VirtualIP] = true
								}
							}
							for oct := 10; oct < 250; oct++ {
								candidate := fmt.Sprintf("100.64.200.%d", oct)
								if !taken[candidate] && candidate != p.VirtualIP {
									myVirtualIP = candidate
									if activeProf := cfg.EnsureActiveProfile(); activeProf != nil {
										activeProf.VirtualIP = myVirtualIP
										_ = config.Save(cfg, configFile, false)
									}
									if uiServer != nil {
										uiServer.SetVirtualIP(myVirtualIP)
									}
									if tunDev != nil {
										_ = tunDev.SetVirtualIP(myVirtualIP)
									}
									break
								}
							}
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
						log.Info().Str("peer", p.DeviceID).Msg("🔴 Узел отключился от сети (Leave beacon)")
						registry.Delete(p.DeviceID)
						if uiServer != nil {
							uiServer.AddEvent("peer_offline", "Узел "+p.DeviceID+" отключился", "")
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
							plat = "💻 Устройство"
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

					log.Info().Str("peer", p.DeviceID).Str("vip", peerVIP).Str("stun", p.STUNAddr).Msg("📥 [P2P Signal] Обнаружен пир в сигнальной сети")
					if uiServer != nil {
						uiServer.AddEvent("peer_online", "Обнаружен узел: "+p.DeviceID, "VIP: "+peerVIP)
					}

					// Немедленный burst hole-punch к пиру + встречная публикация нашего маяка
					if puncher != nil {
						go func(peer *signaling.Payload) {
							// Строим список адресов для пробивки:
							// 1. STUNAddr — STUN-mapped адрес порта puncher
							// 2. IPv6Addr — прямой глобальный IPv6 адрес (без CGNAT)
							// 3. LocalAddr — LAN IP пира
							// 4. PublicIP:47832 (Windows default) и PublicIP:51820 (Mobile/Linux default)
							// 5. PublicIP:WGPort — если WireGuard включен у пира
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
							// 5 серий с интервалом 200мс = 1 секунда активной пробивки
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
						// Публикуем наш свежий маяк — пир получит наш STUN и сможет пробиться к нам
						triggerPublish()
					}
				}
			}
		}()
	}

	// SIGHUP перезагрузка конфига
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			log.Info().Msg("SIGHUP: перезагрузка конфига...")
			config.Reload(cfg, configFile)
		}
	}()

	// Ожидание завершения (SIGINT/SIGTERM или context cancel)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigChan:
	case <-engineCtx.Done():
	}

	log.Info().Msg("Завершение работы...")
	cancel()
	closeLogging()
	time.Sleep(200 * time.Millisecond)
	return nil
}

// в”Ђв”Ђ stop в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Остановить работающий демон",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("ошибка загрузки конфига: %w", err)
			}
			data, err := os.ReadFile(cfg.Daemon.PidFile)
			if err != nil {
				return fmt.Errorf("PID файл не найден (%s): демон не запущен?", cfg.Daemon.PidFile)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				return fmt.Errorf("некорректный PID: %w", err)
			}
			proc, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("процесс не найден: %w", err)
			}
			if err := proc.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("ошибка отправки SIGTERM: %w", err)
			}
			fmt.Printf("Сигнал SIGTERM отправлен процессу %d\n", pid)
			return nil
		},
	}
}

// в”Ђв”Ђ status в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Показать статус работающего демона",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("ошибка загрузки конфига: %w", err)
			}
			data, err := os.ReadFile(cfg.Daemon.PidFile)
			if err != nil {
				fmt.Println("Статус: НЕ ЗАПУЩЕН")
				return nil
			}
			pid, _ := strconv.Atoi(string(data))
			proc, err := os.FindProcess(pid)
			if err != nil || proc.Signal(syscall.Signal(0)) != nil {
				fmt.Printf("Статус: ОСТАНОВЛЕН (последний PID: %d)\n", pid)
				return nil
			}
			fmt.Printf("Статус: ЗАПУЩЕН (PID: %d)\n", pid)
			fmt.Printf("Web UI: http://localhost:%d\n", cfg.WebUI.Port)
			return nil
		},
	}
}

// в”Ђв”Ђ keygen в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Сгенерировать NaCl ключевую пару",
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := crypto.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("ошибка генерации ключей: %w", err)
			}
			fmt.Println("# NaCl/Box ключевая пара (X25519 + XSalsa20-Poly1305)")
			fmt.Printf("public_key:  %s\n", crypto.KeyToHex(pub))
			fmt.Printf("private_key: %s\n", crypto.KeyToHex(priv))
			fmt.Println("")
			fmt.Println("# Добавьте в config.yaml раздел crypto:")
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
		Short: "Операции с WireGuard",
	}

	wgKeygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Сгенерировать WireGuard ключевую пару",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := wireguard.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("ошибка генерации WG ключей: %w", err)
			}
			fmt.Println("# WireGuard ключевая пара")
			fmt.Printf("PrivateKey = %s\n", kp.PrivateKey)
			fmt.Printf("PublicKey  = %s\n", kp.PublicKey)
			return nil
		},
	}

	wgConfigCmd := &cobra.Command{
		Use:   "config",
		Short: "Сгенерировать WireGuard mesh конфиг",
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
		Short: "Установить как системный сервис (Linux: systemd, procd, entware)",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcType, _ := cmd.Flags().GetString("service")
			return installService(svcType)
		},
	}
	cmd.Flags().String("service", "systemd", "тип сервиса: systemd|procd|entware")
	return cmd
}

var (
	globalLogFileHandle   *os.File
	globalLogFileHandleMu sync.Mutex
)

func closeLogging() {
	globalLogFileHandleMu.Lock()
	defer globalLogFileHandleMu.Unlock()
	if globalLogFileHandle != nil {
		_ = globalLogFileHandle.Sync()
		_ = globalLogFileHandle.Close()
		globalLogFileHandle = nil
	}
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
Description=NatBypass — обход NAT и P2P-доступ
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
		fmt.Println("✓ systemd unit установлен: /etc/systemd/system/natbypass.service")
		fmt.Println("Выполните: systemctl daemon-reload && systemctl enable --now natbypass")

	case "procd":
		fmt.Println("Для OpenWrt: скопируйте scripts/init/natbypass.procd в /etc/init.d/natbypass")
		fmt.Println("Затем: chmod +x /etc/init.d/natbypass && /etc/init.d/natbypass enable && /etc/init.d/natbypass start")

	case "entware":
		fmt.Println("Для Keenetic/Entware: скопируйте scripts/init/S99natbypass в /opt/etc/init.d/S99natbypass")
		fmt.Println("Затем: chmod +x /opt/etc/init.d/S99natbypass && /opt/etc/init.d/S99natbypass start")

	default:
		return fmt.Errorf("неизвестный тип сервиса: %s", svcType)
	}
	return nil
}

// в”Ђв”Ђ antigravity EASTER EGG в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newAntGravityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "antigravity",
		Short: "🚀 Easter Egg",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`
       .---.
      /     \
      \.@-@./       NatBypass v%s
      /` + "`" + `\_/` + "`" + `\      Обходим гравитацию NAT!
     //  _  \\
    | \     / |     Вдохновлено: import antigravity (Python)
   /` + "`" + `\_` + "`" + `Y` + "`" + `_/` + "`" + `\    
  /  |  |  |  \    Режим невесомости: АКТВРОВАН
  ` + "`" + `--|--|--` + "`" + `    Все пакеты теперь летят напрямую!

  "Любой достаточно продвинутый NAT
   неотличим от стены." — Артур Кларк (почти)

  double NAT? CGNAT? Не проблема!   🛸
`, Version)
		},
	}
}

// в”Ђв”Ђ konami EASTER EGG в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newKonamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "konami",
		Short: "🎮 God Mode",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(`
  ↑ ↑ ↓ ↓ ← → ← → B A  —  КОД ВВЕДЁН!
  в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
  ║       РЕЖМ БОГА АКТВРОВАН       ║
  в• в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•Ј
  ║  Скрытые настройки NatBypass:      ║
  в•‘                                    в•‘
  ║  --paranoid     Тройное шифрование ║
  ║  --ghost        Без логов вообще   ║
  ║  --turbo        нтервал 1 сек     ║
  ║  --mesh-all     Соединить всех     ║
  ║  --obfs4        Обфускация трафика ║
  ║  --chaos-mode   Случайный канал    ║
  в•‘                                    в•‘
  ║  (эти флаги существуют в мечтах)   ║
  в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ
`)
		},
	}
}

// в”Ђв”Ђ version в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Показать версию",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("NatBypass %s (commit: %s, built: %s)\n", Version, Commit, BuildDate)
		},
	}
}

// в”Ђв”Ђ diag в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
func newDiagCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diag",
		Short: "Запустить глубокую аппаратную и системную диагностику оборудования",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("================================================================")
			fmt.Println("       🩺 NatBypass — Низкоуровневая диагностика системы        ")
			fmt.Println("================================================================")
			fmt.Println()

			rep := diagnostic.RunFullDiagnostics()
			fmt.Printf("Хост: %s | ОС: %s | Архитектура: %s\n", rep.Hostname, rep.OS, rep.Arch)
			fmt.Printf("Права Администратора: %v\n\n", rep.IsAdmin)

			for i, item := range rep.Items {
				statusIcon := "🟢"
				if !item.Passed {
					statusIcon = "🔴"
				}
				fmt.Printf("[%d/8] %s %s (%d ms)\n", i+1, statusIcon, item.Name, item.Elapsed.Milliseconds())
				fmt.Printf("      %s\n", item.Message)
				if item.Details != "" {
					fmt.Printf("      Подробности: %s\n", item.Details)
				}
				fmt.Println()
			}

			fmt.Println("================================================================")
			fmt.Println("    ⚡ RFC 4787 / STUN Анализ типа NAT и шансов DirectP2P      ")
			fmt.Println("================================================================")
			fmt.Println("Тестирование трансляции портов...")

			natInfo, err := diagnostic.ClassifyNATBehavior()
			if err != nil {
				fmt.Printf("⚠️ Ошибка тестирования NAT: %v\n", err)
			} else {
				fmt.Printf("• Внешний IP адрес:      %s\n", natInfo.PublicIP)
				fmt.Printf("• Тип NAT роутера:       %s\n", natInfo.NATType)
				fmt.Printf("• Поведение портов (EIM):%s\n", natInfo.MappingType)
				fmt.Printf("• Вероятность DirectP2P: %s\n", natInfo.P2PFeasibility)
				fmt.Printf("• Рекомендация:          %s\n", natInfo.Recommendation)
			}

			fmt.Println("================================================================")
			if rep.AllPassed {
				fmt.Println("✅ Все базовые тесты пройдены! Оборудование и сеть готовы к работе.")
			} else {
				fmt.Println("⚠️ Обнаружены системные замечания. Ознакомьтесь с подсказками выше.")
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
			return [32]byte{}, [32]byte{}, fmt.Errorf("некорректный публичный ключ: %w", err)
		}
		priv, err := crypto.HexToKey(cfg.Crypto.PrivateKey)
		if err != nil {
			return [32]byte{}, [32]byte{}, fmt.Errorf("некорректный приватный ключ: %w", err)
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
# NatBypass — Конфигурационный файл
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
        token: ""      # Вставьте токен от @BotFather (например: 7123456789:AAF...)
        chat_id: ""    # ID приватной группы/канала (например: -1001234567890)
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

func respondICMPEcho(puncher *network.UDPPuncher, payload []byte, fromAddr *net.UDPAddr) {
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

	if fromAddr != nil && puncher != nil {
		_ = puncher.SendDataPacket(fromAddr.String(), reply)
	}
}
