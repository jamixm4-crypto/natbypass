package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
)

// MobileEngine — синглтон движка для Android/iOS
type MobileEngine struct {
	ctx        context.Context
	cancel     context.CancelFunc
	registry   *peer.Registry
	sigMgr     *signaling.FallbackManager
	ipDisc     *network.Discoverer
	stunClient *network.STUNClient
	cfg        *config.Config

	deviceID  string
	publicIP  string
	stunAddr  string
	startedAt time.Time
	mu        sync.RWMutex
	running   bool
}

var (
	engineInstance *MobileEngine
	engineMu       sync.Mutex
)

// StartService запускает фоновый P2P движок на Android
func StartService(configYaml string) string {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engineInstance != nil && engineInstance.running {
		return "already running"
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := &MobileEngine{
		ctx:       ctx,
		cancel:    cancel,
		registry:  peer.NewRegistry(),
		startedAt: time.Now(),
		running:   true,
	}
	engineInstance = m

	// 1. Конфигурация
	cfg := buildDefaultConfig()
	m.cfg = cfg

	// 2. Ключи NaCl
	pubKey, privKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Sprintf("crypto error: %v", err)
	}
	m.deviceID = "dev-android-" + crypto.KeyToHex(pubKey)[:8]

	// 3. Сеть и STUN
	m.ipDisc = network.NewDiscoverer(cfg.Network.IPApis, 10*time.Second)
	m.stunClient = network.NewSTUNClient(cfg.Network.StunServers)

	// 4. Сигнальные каналы
	var channels []signaling.SignalingChannel
	for _, chCfg := range cfg.Signaling.Channels {
		if !chCfg.Enabled {
			continue
		}
		if chCfg.Type == "mqtt" {
			channels = append(channels, signaling.NewMQTTChannel(chCfg.Params["broker_url"], chCfg.Params["topic"], m.deviceID, "", ""))
		} else if chCfg.Type == "telegram" && chCfg.Params["token"] != "" {
			channels = append(channels, signaling.NewTelegramChannel(chCfg.Params["token"], chCfg.Params["chat_id"], ""))
		}
	}
	if len(channels) > 0 {
		m.sigMgr = signaling.NewFallbackManager(channels)
	}

	// 5. Монитор пиров
	m.registry.StartMonitor(ctx, 2*time.Minute)

	// 6. Локальный Web UI на Android (http://localhost:8080)
	if cfg.WebUI.Enabled {
		uiServer := webui.NewServer(cfg.WebUI.Port, cfg.WebUI.Username, cfg.WebUI.Password, m.registry, m.sigMgr)
		go uiServer.Start(ctx)
	}

	// 7. Фоновый цикл
	go m.runLoop(pubKey, privKey)

	return "started"
}

// StopService останавливает движок
func StopService() string {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engineInstance != nil && engineInstance.running {
		engineInstance.cancel()
		engineInstance.running = false
		return "stopped"
	}
	return "not running"
}

// GetStatusJSON возвращает JSON статус для Android UI (Activity / Service)
func GetStatusJSON() string {
	if engineInstance == nil || !engineInstance.running {
		return `{"online":false,"status":"stopped"}`
	}

	engineInstance.mu.RLock()
	defer engineInstance.mu.RUnlock()

	curCh := "нет"
	if engineInstance.sigMgr != nil {
		curCh = engineInstance.sigMgr.CurrentChannel()
	}

	res := map[string]interface{}{
		"online":          engineInstance.publicIP != "",
		"device_id":       engineInstance.deviceID,
		"public_ip":       engineInstance.publicIP,
		"stun_addr":       engineInstance.stunAddr,
		"current_channel": curCh,
		"peers_count":     len(engineInstance.registry.List()),
		"uptime_seconds":  int(time.Since(engineInstance.startedAt).Seconds()),
	}

	b, _ := json.Marshal(res)
	return string(b)
}

// GetPeersJSON возвращает список устройств в JSON
func GetPeersJSON() string {
	if engineInstance == nil || !engineInstance.running {
		return "[]"
	}
	peers := engineInstance.registry.List()
	b, _ := json.Marshal(peers)
	return string(b)
}

// UpdateIP обновляет внешний IP и STUN
func UpdateIP() string {
	if engineInstance == nil || !engineInstance.running {
		return "error: not running"
	}
	ip, err := engineInstance.ipDisc.GetPublicIP(engineInstance.ctx)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	engineInstance.mu.Lock()
	engineInstance.publicIP = ip.String()
	engineInstance.mu.Unlock()
	return engineInstance.publicIP
}

// GetWireGuardConfig возвращает готовую конфигурацию WireGuard
func GetWireGuardConfig() string {
	kp, err := wireguard.GenerateKeyPair()
	if err != nil {
		return "# error generating keys"
	}
	wgCfg := &wireguard.WGConfig{
		InterfaceName: "wg0",
		PrivateKey:    kp.PrivateKey,
		Address:       "10.200.0.10/24",
		ListenPort:    51820,
		MTU:           1420,
	}
	conf, _ := wireguard.GenerateWGConfig(wgCfg)
	return conf
}

func (m *MobileEngine) runLoop(pubKey, privKey [32]byte) {
	// Первичное определение IP
	if ip, err := m.ipDisc.GetPublicIPCached(m.ctx, 5*time.Minute); err == nil {
		m.mu.Lock()
		m.publicIP = ip.String()
		m.mu.Unlock()
	}

	if stunIP, stunPort, err := m.stunClient.GetMappedAddress(m.ctx); err == nil {
		m.mu.Lock()
		m.stunAddr = fmt.Sprintf("%s:%d", stunIP.String(), stunPort)
		m.mu.Unlock()
	}

	if m.sigMgr == nil {
		return
	}

	// Прием сообщений
	inCh, err := m.sigMgr.Receive(m.ctx)
	if err == nil {
		go func() {
			for {
				select {
				case <-m.ctx.Done():
					return
				case p, ok := <-inCh:
					if !ok {
						return
					}
					if p.DeviceID == m.deviceID {
						continue
					}
					m.registry.Upsert(&peer.Peer{
						DeviceID:  p.DeviceID,
						PublicKey: p.PublicKey,
						PublicIP:  p.PublicIP,
						STUNAddr:  p.STUNAddr,
						WGPubKey:  p.WGPubKey,
						WGPort:    p.WGPort,
						LastSeen:  p.Timestamp,
						Online:    true,
					})
				}
			}
		}()
	}

	// Периодическая публикация
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.RLock()
			pubIP := m.publicIP
			stAddr := m.stunAddr
			m.mu.RUnlock()

			payload := &signaling.Payload{
				DeviceID:  m.deviceID,
				PublicKey: crypto.KeyToHex(pubKey),
				PublicIP:  pubIP,
				STUNAddr:  stAddr,
				Timestamp: time.Now(),
			}
			if enc, err := signaling.EncryptPayload(payload, pubKey, privKey); err == nil {
				m.sigMgr.Send(m.ctx, enc)
			}
		}
	}
}

func buildDefaultConfig() *config.Config {
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
	cfg.Signaling.Channels = []config.ChannelConfig{
		{
			Type:     "mqtt",
			Priority: 1,
			Enabled:  true,
			Params: map[string]string{
				"broker_url": "tcp://mqtt.eclipseprojects.io:1883",
				"topic":      "natbypass/mynet/peers",
			},
		},
	}
	return cfg
}