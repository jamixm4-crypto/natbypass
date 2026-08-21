package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
)

type StatusResponse struct {
	DeviceID       string `json:"device_id"`
	PublicIP       string `json:"public_ip"`
	STUNAddr       string `json:"stun_addr"`
	CurrentChannel string `json:"current_channel"`
	PeersCount     int    `json:"peers_count"`
	WebUIPort      int    `json:"web_ui_port"`
	Uptime         string `json:"uptime"`
	Online         bool   `json:"online"`
}

type App struct {
	ctx        context.Context
	engineCtx  context.Context
	cancel     context.CancelFunc
	configPath string
	startedAt  time.Time

	cfg        *config.Config
	registry   *peer.Registry
	sigMgr     *signaling.FallbackManager
	ipDisc     *network.Discoverer
	stunClient *network.STUNClient

	deviceID  string
	publicIP  string
	stunAddr  string
	webUIPort int

	logs      []string
	logsMutex sync.RWMutex
}

func NewApp(configPath string) *App {
	if configPath == "" {
		configPath = "config.yaml"
	}
	return &App{
		configPath: configPath,
		startedAt:  time.Now(),
		logs:       make([]string, 0, 500),
		registry:   peer.NewRegistry(),
		webUIPort:  8080,
	}
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	a.engineCtx, a.cancel = context.WithCancel(context.Background())

	a.log("🚀 NatBypass GUI инициализирован")

	// 1. Загрузка конфигурации
	cfg, err := config.Load(a.configPath)
	if err != nil {
		a.log(fmt.Sprintf("⚠️ Конфиг не найден (%v), используем значения по умолчанию", err))
		cfg = a.buildDefaultConfig()
	}
	a.cfg = cfg

	// 2. Генерация или загрузка ключей
	pubKey, privKey, err := a.loadOrGenerateKeys()
	if err != nil {
		a.log(fmt.Sprintf("❌ Ошибка ключей: %v", err))
		return
	}
	a.deviceID = "dev-" + crypto.KeyToHex(pubKey)[:12]
	a.log(fmt.Sprintf("🔑 Идентификатор устройства: %s", a.deviceID))

	// 3. Сетевые модули
	a.ipDisc = network.NewDiscoverer(cfg.Network.IPApis, 10*time.Second)
	a.stunClient = network.NewSTUNClient(cfg.Network.StunServers)

	// 4. Сигнальные каналы
	channels := a.initChannels()
	if len(channels) > 0 {
		a.sigMgr = signaling.NewFallbackManager(channels)
		a.log(fmt.Sprintf("📡 Сигнальный менеджер запущен (%d каналов, активен: %s)", len(channels), a.sigMgr.CurrentChannel()))
	}

	// 5. Реестр пиров
	a.registry.StartMonitor(a.engineCtx, 2*time.Minute)

	// 6. Запуск встроенного Web UI
	if cfg.WebUI.Enabled {
		port := cfg.WebUI.Port
		if port <= 0 {
			port = 8080
		}
		uiServer := webui.NewServer(port, cfg.WebUI.Username, cfg.WebUI.Password, a.registry, a.sigMgr)
		go func() {
			if err := uiServer.Start(a.engineCtx); err != nil {
				a.log(fmt.Sprintf("⚠️ Web UI остановлен: %v", err))
			}
		}()
		a.webUIPort = uiServer.GetPort()
	}

	// 7. Фоновый рабочий цикл (IP, STUN, публикация, приём)
	go a.runBackgroundEngine(pubKey, privKey)

	// 8. Таймер эмиссии событий во фронтенд (каждые 3 сек)
	go a.startEventBroadcaster()
}

func (a *App) BeforeClose(ctx context.Context) (prevent bool) {
	// Сворачиваем в трей вместо закрытия при нажатии крестика
	runtime.WindowHide(a.ctx)
	return true
}

func (a *App) Shutdown(ctx context.Context) {
	if a.cancel != nil {
		a.cancel()
	}
	a.log("🛑 NatBypass остановлен")
}

// ── Exported Methods (Available from JS Frontend) ───────────────

func (a *App) GetStatus() (*StatusResponse, error) {
	peers := a.registry.List()
	curChan := "нет"
	if a.sigMgr != nil {
		curChan = a.sigMgr.CurrentChannel()
	}

	uptimeDur := time.Since(a.startedAt).Round(time.Second)
	uptimeStr := uptimeDur.String()

	return &StatusResponse{
		DeviceID:       a.deviceID,
		PublicIP:       a.publicIP,
		STUNAddr:       a.stunAddr,
		CurrentChannel: curChan,
		PeersCount:     len(peers),
		WebUIPort:      a.webUIPort,
		Uptime:         uptimeStr,
		Online:         a.publicIP != "" && a.publicIP != "Определяется...",
	}, nil
}

func (a *App) GetDevices() ([]*peer.Peer, error) {
	return a.registry.List(), nil
}

func (a *App) UpdateIP() (string, error) {
	a.log("🔄 Принудительный запрос на обновление внешнего IP...")
	ip, err := a.ipDisc.GetPublicIP(a.engineCtx)
	if err != nil {
		a.log(fmt.Sprintf("❌ Ошибка определения IP: %v", err))
		return "", err
	}
	a.publicIP = ip.String()
	a.log(fmt.Sprintf("✓ Новый внешний IP: %s", a.publicIP))

	if stunIP, stunPort, err := a.stunClient.GetMappedAddress(a.engineCtx); err == nil {
		a.stunAddr = fmt.Sprintf("%s:%d", stunIP.String(), stunPort)
		a.log(fmt.Sprintf("✓ Новый STUN адрес: %s", a.stunAddr))
	}

	runtime.EventsEmit(a.ctx, "status_updated", a.publicIP)
	return a.publicIP, nil
}

func (a *App) GetConfig() (*config.Config, error) {
	return a.cfg, nil
}

func (a *App) SaveConfig(newCfg *config.Config) error {
	a.cfg = newCfg
	a.log("💾 Сохранение новой конфигурации...")
	return nil
}

func (a *App) GetLogs() ([]string, error) {
	a.logsMutex.RLock()
	defer a.logsMutex.RUnlock()
	res := make([]string, len(a.logs))
	copy(res, a.logs)
	return res, nil
}

func (a *App) SwitchChannel(name string) error {
	if a.sigMgr == nil {
		return fmt.Errorf("сигнальный менеджер не инициализирован")
	}
	err := a.sigMgr.SwitchTo(name)
	if err != nil {
		a.log(fmt.Sprintf("❌ Ошибка переключения на канал %s: %v", name, err))
		return err
	}
	a.log(fmt.Sprintf("🔀 Активный канал переключен на: %s", name))
	runtime.EventsEmit(a.ctx, "channel_changed", name)
	return nil
}

func (a *App) GetChannels() ([]signaling.ChannelStatus, error) {
	if a.sigMgr == nil {
		return nil, nil
	}
	return a.sigMgr.Status(), nil
}

func (a *App) GetWireGuardConfig() (string, error) {
	kp, err := wireguard.GenerateKeyPair()
	if err != nil {
		return "", err
	}
	wgCfg := &wireguard.WGConfig{
		InterfaceName: "wg0",
		PrivateKey:    kp.PrivateKey,
		Address:       "10.200.0.1/24",
		ListenPort:    51820,
		DNS:           "",
		MTU:           1420,
	}
	return wireguard.GenerateWGConfig(wgCfg)
}

func (a *App) OpenWebUI() {
	url := fmt.Sprintf("http://localhost:%d", a.webUIPort)
	exec.Command("cmd", "/c", "start", url).Start()
}

func (a *App) MinimizeToTray() {
	runtime.WindowHide(a.ctx)
}

func (a *App) ShowWindow() {
	runtime.WindowShow(a.ctx)
	runtime.WindowUnminimise(a.ctx)
}

func (a *App) QuitApp() {
	runtime.Quit(a.ctx)
}

// ── Private Engine Helpers ─────────────────────────────────────

func (a *App) log(msg string) {
	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s", ts, msg)
	a.logsMutex.Lock()
	if len(a.logs) > 500 {
		a.logs = a.logs[1:]
	}
	a.logs = append(a.logs, line)
	a.logsMutex.Unlock()

	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "log_entry", line)
	}
}

func (a *App) startEventBroadcaster() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.engineCtx.Done():
			return
		case <-ticker.C:
			st, err := a.GetStatus()
			if err == nil {
				runtime.EventsEmit(a.ctx, "status_tick", st)
			}
			peers, _ := a.GetDevices()
			runtime.EventsEmit(a.ctx, "peers_tick", peers)
		}
	}
}

func (a *App) runBackgroundEngine(pubKey, privKey [32]byte) {
	// 1. IP & STUN
	if ip, err := a.ipDisc.GetPublicIPCached(a.engineCtx, 5*time.Minute); err == nil {
		a.publicIP = ip.String()
		a.log(fmt.Sprintf("✓ Внешний публичный IP: %s", a.publicIP))
	}

	if stunIP, stunPort, err := a.stunClient.GetMappedAddress(a.engineCtx); err == nil {
		a.stunAddr = fmt.Sprintf("%s:%d", stunIP.String(), stunPort)
		a.log(fmt.Sprintf("✓ STUN адрес: %s", a.stunAddr))
	}

	if a.sigMgr == nil {
		return
	}

	// 2. Прием сообщений
	inCh, err := a.sigMgr.Receive(a.engineCtx)
	if err == nil {
		go func() {
			for {
				select {
				case <-a.engineCtx.Done():
					return
				case p, ok := <-inCh:
					if !ok {
						return
					}
					if len(p.Encrypted) > 0 {
						if dec, err := signaling.DecryptPayload(p, pubKey, privKey); err == nil {
							p = dec
						}
					}
					if p.DeviceID == a.deviceID {
						continue
					}
					a.registry.Upsert(&peer.Peer{
						DeviceID:  p.DeviceID,
						PublicKey: p.PublicKey,
						PublicIP:  p.PublicIP,
						STUNAddr:  p.STUNAddr,
						WGPubKey:  p.WGPubKey,
						WGPort:    p.WGPort,
						LastSeen:  p.Timestamp,
						Online:    true,
					})
					a.log(fmt.Sprintf("📡 Обнаружено устройство: %s (%s)", p.DeviceID, p.PublicIP))
					runtime.EventsEmit(a.ctx, "peer_discovered", p)
				}
			}
		}()
	}

	// 3. Публикация состояния
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.engineCtx.Done():
			return
		case <-ticker.C:
			payload := &signaling.Payload{
				DeviceID:  a.deviceID,
				PublicKey: crypto.KeyToHex(pubKey),
				PublicIP:  a.publicIP,
				STUNAddr:  a.stunAddr,
				Timestamp: time.Now(),
			}
			if enc, err := signaling.EncryptPayload(payload, pubKey, privKey); err == nil {
				a.sigMgr.Send(a.engineCtx, enc)
			}
		}
	}
}

func (a *App) loadOrGenerateKeys() ([32]byte, [32]byte, error) {
	if a.cfg.Crypto.PublicKey != "" && a.cfg.Crypto.PrivateKey != "" {
		pub, _ := crypto.HexToKey(a.cfg.Crypto.PublicKey)
		priv, _ := crypto.HexToKey(a.cfg.Crypto.PrivateKey)
		return pub, priv, nil
	}
	return crypto.GenerateKeyPair()
}

func (a *App) initChannels() []signaling.SignalingChannel {
	var channels []signaling.SignalingChannel
	for _, chCfg := range a.cfg.Signaling.Channels {
		if !chCfg.Enabled {
			continue
		}
		switch chCfg.Type {
		case "telegram":
			t := chCfg.Params["token"]
			c := chCfg.Params["chat_id"]
			if t != "" && c != "" {
				channels = append(channels, signaling.NewTelegramChannel(t, c, chCfg.Params["proxy"]))
			}
		case "mqtt":
			b := chCfg.Params["broker_url"]
			tp := chCfg.Params["topic"]
			if b != "" && tp != "" {
				channels = append(channels, signaling.NewMQTTChannel(b, tp, a.deviceID, "", ""))
			}
		case "webhook":
			p := chCfg.Params["post_url"]
			if p != "" {
				channels = append(channels, signaling.NewWebhookChannel(p, chCfg.Params["poll_url"], chCfg.Params["secret"]))
			}
		case "dns":
			token := chCfg.Params["cf_api_token"]
			zone := chCfg.Params["zone_id"]
			rec := chCfg.Params["record_name"]
			if token != "" && zone != "" && rec != "" {
				channels = append(channels, signaling.NewDNSChannel(token, zone, rec))
			}
		}
	}
	return channels
}

func (a *App) buildDefaultConfig() *config.Config {
	cfg := &config.Config{}
	cfg.App.LogLevel = "info"
	cfg.App.PublishInterval = 60
	cfg.WebUI.Enabled = true
	cfg.WebUI.Port = 8080
	cfg.Network.UpnpEnabled = true
	cfg.Network.IPTimeout = 10
	cfg.Network.StunServers = []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun.cloudflare.com:3478",
	}
	cfg.Network.IPApis = []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	return cfg
}