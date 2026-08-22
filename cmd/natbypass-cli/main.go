package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
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

// Заполняется при сборке через -ldflags -X
var (
	Version   = "1.0.0"
	Commit    = "release"
	BuildDate = "unknown"

	// Вшитые умолчания (задаются через build-win.ps1 / build-linux.sh)
	DefaultTgToken    = "" // Токен Telegram-бота
	DefaultTgChatID   = "" // ID чата/канала Telegram
	DefaultMQTTBroker = "" // URL MQTT-брокера
	DefaultMQTTTopic  = "" // MQTT-топик
	DefaultWebhookURL = "" // URL HTTP Webhook
	DefaultDeviceID   = "" // Идентификатор устройства
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
			if err != nil {
				if os.IsNotExist(err) {
					cfg = buildDefaultConfig()
				} else {
					return fmt.Errorf("ошибка загрузки конфига: %w", err)
				}
			}
			applyBuiltinDefaults(cfg)

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
		newAntGravityCmd(),
		newKonamiCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── start ──────────────────────────────────────────────────────
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

// ── Основной движок ───────────────────────────────────────────
func runEngine(ctx context.Context, cfg *config.Config, enableTray bool) error {
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
	log.Info().Str("device_id", deviceID).Msg("Идентификатор устройства")

	engineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	registry := peer.NewRegistry()
	registry.StartMonitor(engineCtx, 2*time.Minute)

	channels, err := buildSignalingChannels(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("Ошибка парсинга каналов, используется публичный резервный канал")
	}
	if len(channels) == 0 {
		log.Warn().Msg("⚠️ Сигнальные каналы не настроены в конфиге. Включен резервный публичный MQTT брокер (topic: natbypass/public/peers). Вы можете настроить личный Telegram-бот в Web UI (http://localhost:8080) или файле config.yaml")
		channels = append(channels, signaling.NewMQTTChannel("tcp://mqtt.eclipseprojects.io:1883", "natbypass/public/peers", deviceID, "", ""))
	}
	sigMgr := signaling.NewFallbackManager(channels)
	log.Info().Int("channels", len(channels)).Str("current", sigMgr.CurrentChannel()).Msg("Сигнальные каналы инициализированы")

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
		uiServer.SetAppState(deviceID, "Определяется...", "Определяется...")
		uiServer.SetDeviceName(deviceID)
		uiServer.AddEvent("info", "NatBypass запущен", "version="+Version)
		go func() {
			if err := uiServer.Start(engineCtx); err != nil {
				log.Error().Err(err).Msg("Web UI остановлен")
			}
		}()
	}

	var stunAddr string
	var publicIP net.IP = net.IPv4(0, 0, 0, 0)
	ipDisc := network.NewDiscoverer(cfg.Network.IPApis, time.Duration(cfg.Network.IPTimeout)*time.Second)

	// Фоновое первоначальное определение IP и STUN
	go func() {
		if ip, err := ipDisc.GetPublicIPCached(engineCtx, 5*time.Minute); err == nil {
			publicIP = ip
			log.Info().Str("ip", publicIP.String()).Msg("Публичный IP определён")
		}

		stunClient := network.NewSTUNClient(cfg.Network.StunServers)
		if stunIP, stunPort, stunErr := stunClient.GetMappedAddress(engineCtx); stunErr == nil {
			stunAddr = fmt.Sprintf("%s:%d", stunIP.String(), stunPort)
			log.Info().Str("stun_addr", stunAddr).Msg("STUN адрес определён")
		}

		if cfg.Network.UpnpEnabled {
			upnpClient := network.NewUPnPClient()
			if upnpClient.IsAvailable() {
				log.Info().Msg("UPnP доступен")
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
		publishInterval = 60 * time.Second
	}

	// Цикл публикации
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
				payload := &signaling.Payload{
					DeviceID:  deviceID,
					PublicKey: crypto.KeyToHex(pubKey),
					PublicIP:  ip.String(),
					STUNAddr:  stunAddr,
					WGPubKey:  wgPubKey,
					WGPort:    wgPort,
					Timestamp: time.Now(),
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
						decrypted, decErr := signaling.DecryptPayload(p, pubKey, privKey)
						if decErr == nil {
							p = decrypted
						}
					}
					if p.DeviceID == deviceID {
						continue
					}
					registry.Upsert(&peer.Peer{
						DeviceID:  p.DeviceID,
						PublicKey: p.PublicKey,
						PublicIP:  p.PublicIP,
						STUNAddr:  p.STUNAddr,
						WGPubKey:  p.WGPubKey,
						WGPort:    p.WGPort,
						LastSeen:  p.Timestamp,
						Online:    true,
						AWG:       p.AWG,
					})
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

	// Если включен режим трея (на Windows)
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
					ch = "нет"
				}
				return fmt.Sprintf("💡 Статус: Онлайн (Канал: %s)", ch)
			},
		})
		log.Info().Msg("Запущен системный трей Windows")
		return trayApp.Run(engineCtx)
	}

	// Консольный режим (ожидание SIGINT/SIGTERM)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Завершение работы...")
	cancel()
	time.Sleep(300 * time.Millisecond)
	return nil
}

// ── stop ───────────────────────────────────────────────────────
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

// ── status ─────────────────────────────────────────────────────
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

// ── keygen ─────────────────────────────────────────────────────
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

// ── wg ─────────────────────────────────────────────────────────
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

// ── install ────────────────────────────────────────────────────
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

// ── antigravity EASTER EGG ─────────────────────────────────────
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
  /  |  |  |  \    Режим невесомости: АКТИВИРОВАН
  ` + "`" + `--|--|--` + "`" + `    Все пакеты теперь летят напрямую!

  "Любой достаточно продвинутый NAT
   неотличим от стены." — Артур Кларк (почти)

  double NAT? CGNAT? Не проблема!   🛸
`, Version)
		},
	}
}

// ── konami EASTER EGG ──────────────────────────────────────────
func newKonamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "konami",
		Short: "🎮 God Mode",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(`
  ↑ ↑ ↓ ↓ ← → ← → B A  —  КОД ВВЕДЁН!
  ╔════════════════════════════════════╗
  ║       РЕЖИМ БОГА АКТИВИРОВАН       ║
  ╠════════════════════════════════════╣
  ║  Скрытые настройки NatBypass:      ║
  ║                                    ║
  ║  --paranoid     Тройное шифрование ║
  ║  --ghost        Без логов вообще   ║
  ║  --turbo        Интервал 1 сек     ║
  ║  --mesh-all     Соединить всех     ║
  ║  --obfs4        Обфускация трафика ║
  ║  --chaos-mode   Случайный канал    ║
  ║                                    ║
  ║  (эти флаги существуют в мечтах)   ║
  ╚════════════════════════════════════╝
`)
		},
	}
}

// ── version ────────────────────────────────────────────────────
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Показать версию",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("NatBypass %s (commit: %s, built: %s)\n", Version, Commit, BuildDate)
		},
	}
}

// ── helpers ────────────────────────────────────────────────────

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