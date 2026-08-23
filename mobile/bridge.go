package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/wireguard"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

var (
	engineMu       sync.Mutex
	engineCtx      context.Context
	engineCancel   context.CancelFunc
	engineRunning  bool
	globalRegistry *peer.Registry
	globalSigMgr   *signaling.FallbackManager
	globalConfig   *config.Config
	globalDevID    string
	globalPublicIP string
	globalSTUN     string
	globalStarted  time.Time
	logger         zerolog.Logger
)

func init() {
	logger = zerolog.New(os.Stdout).With().Timestamp().Str("module", "mobile").Logger()
}

// StartEngine запускает ядро NatBypass внутри Android VpnService
func StartEngine(configYAML string, tunFd int) string {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engineRunning {
		return "движок уже запущен"
	}

	cfg, err := parseConfigFromString(configYAML)
	if err != nil {
		return fmt.Sprintf("ошибка парсинга конфига: %v", err)
	}
	globalConfig = cfg

	ctx, cancel := context.WithCancel(context.Background())
	engineCtx = ctx
	engineCancel = cancel
	globalStarted = time.Now()

	// NaCl ключи
	pubKey, _, err := loadOrGenKeys(cfg)
	if err != nil {
		cancel()
		return fmt.Sprintf("ошибка генерации ключей: %v", err)
	}

	devID := cfg.App.DeviceID
	if devID == "" {
		devID = "Android-" + crypto.KeyToHex(pubKey)[:8]
	}
	globalDevID = devID

	// Реестр пиров
	globalRegistry = peer.NewRegistry()
	globalRegistry.StartMonitor(ctx, 2*time.Minute)

	// Сигнальные каналы
	channels, err := buildChannels(cfg, devID)
	if err != nil || len(channels) == 0 {
		channels = append(channels, signaling.NewMQTTChannel(
			"tcp://broker.emqx.io:1883",
			"natbypass/mynet/peers",
			devID, "", "",
		))
	}
	globalSigMgr = signaling.NewFallbackManager(channels)

	// Определение IP и STUN
	ipDisc := network.NewDiscoverer(cfg.Network.IPApis, 5*time.Second)
	go func() {
		if ip, err := ipDisc.GetPublicIPCached(ctx, 5*time.Minute); err == nil {
			globalPublicIP = ip.String()
		}
		stunClient := network.NewSTUNClient(cfg.Network.StunServers)
		if extIP, port, err := stunClient.GetMappedAddress(ctx); err == nil {
			globalSTUN = fmt.Sprintf("%s:%d", extIP.String(), port)
		}
	}()

	// WireGuard ключи
	wgKey, err := wireguard.GenerateKeyPair()
	if err != nil {
		wgKey = &wireguard.KeyPair{PublicKey: "", PrivateKey: ""}
	}

	// Цикл публикации в сигнальный канал
	pubInterval := time.Duration(cfg.App.PublishInterval) * time.Second
	if pubInterval <= 0 {
		pubInterval = 8 * time.Second
	}
	go func() {
		ticker := time.NewTicker(pubInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
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
					DeviceID:  devID,
					PublicKey: crypto.KeyToHex(pubKey),
					PublicIP:  globalPublicIP,
					STUNAddr:  globalSTUN,
					WGPubKey:  wgKey.PublicKey,
					WGPort:    cfg.WireGuard.ListenPort,
					Timestamp: time.Now(),
					AWG:       awgParams,
				}
				_ = globalSigMgr.Send(ctx, payload)
			}
		}
	}()

	// Цикл приёма от сигнального канала
	go func() {
		rxChan, err := globalSigMgr.Receive(ctx)
		if err != nil {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case p, ok := <-rxChan:
				if !ok {
					return
				}
				if p != nil && p.DeviceID != devID {
					globalRegistry.Upsert(&peer.Peer{
						DeviceID:  p.DeviceID,
						PublicKey: p.PublicKey,
						PublicIP:  p.PublicIP,
						STUNAddr:  p.STUNAddr,
						WGPubKey:  p.WGPubKey,
						WGPort:    p.WGPort,
						LastSeen:  time.Now(),
						Online:    true,
						AWG:       p.AWG,
					})
				}
			}
		}
	}()

	engineRunning = true
	logger.Info().Str("device_id", devID).Int("tun_fd", tunFd).Msg("NatBypass Android VpnService ядро запущено")
	return ""
}

// StopEngine останавливает фоновый движок
func StopEngine() {
	engineMu.Lock()
	defer engineMu.Unlock()

	if !engineRunning {
		return
	}
	if engineCancel != nil {
		engineCancel()
	}
	engineRunning = false
	logger.Info().Msg("NatBypass Android VpnService ядро остановлено")
}

// IsRunning возвращает true, если движок активен
func IsRunning() bool {
	engineMu.Lock()
	defer engineMu.Unlock()
	return engineRunning
}

// GetStatusJSON возвращает актуальный статус в формате JSON
func GetStatusJSON() string {
	engineMu.Lock()
	defer engineMu.Unlock()

	status := map[string]interface{}{
		"running":         engineRunning,
		"device_id":       globalDevID,
		"public_ip":       globalPublicIP,
		"stun_addr":       globalSTUN,
		"uptime":          time.Since(globalStarted).Round(time.Second).String(),
		"current_channel": "",
		"peers_count":     0,
	}

	if globalSigMgr != nil {
		status["current_channel"] = globalSigMgr.CurrentChannel()
	}
	if globalRegistry != nil {
		status["peers_count"] = len(globalRegistry.List())
	}

	data, _ := json.Marshal(status)
	return string(data)
}

// GetPeersJSON возвращает список устройств в JSON
func GetPeersJSON() string {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalRegistry == nil {
		return "[]"
	}
	peers := globalRegistry.List()
	data, _ := json.Marshal(peers)
	return string(data)
}

// GetDiagnosticsJSON возвращает результаты диагностики
func GetDiagnosticsJSON() string {
	type check struct {
		Ok     bool   `json:"ok"`
		Detail string `json:"detail"`
		Extra  string `json:"extra,omitempty"`
	}
	result := map[string]interface{}{}

	// Интернет
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 3*time.Second)
	if err == nil {
		conn.Close()
		result["internet"] = check{Ok: true, Detail: "Интернет доступен"}
	} else {
		result["internet"] = check{Ok: false, Detail: "Нет связи с интернетом"}
	}

	// Публичный IP
	if globalPublicIP != "" {
		result["public_ip"] = check{Ok: true, Detail: "Внешний IP определён", Extra: globalPublicIP}
	} else {
		result["public_ip"] = check{Ok: false, Detail: "IP определяется..."}
	}

	// STUN
	if globalSTUN != "" {
		result["stun"] = check{Ok: true, Detail: "STUN-сокет определён", Extra: globalSTUN}
	} else {
		result["stun"] = check{Ok: false, Detail: "STUN не определён"}
	}

	data, _ := json.Marshal(result)
	return string(data)
}

// ParseQRInvite парсит QR-код приглашения и возвращает JSON с параметрами
func ParseQRInvite(qrText string) string {
	// Формат: NatBypass|DeviceName|PublicIP|InviteURL
	parts := strings.Split(qrText, "|")
	res := map[string]interface{}{
		"valid": false,
	}
	if len(parts) >= 4 && parts[0] == "NatBypass" {
		res["valid"] = true
		res["peer_name"] = parts[1]
		res["peer_ip"] = parts[2]
		res["url"] = parts[3]
	}
	data, _ := json.Marshal(res)
	return string(data)
}

// GenerateKeysJSON генерирует пару ключей NaCl и WireGuard
func GenerateKeysJSON() string {
	pub, priv, _ := crypto.GenerateKeyPair()
	wg, _ := wireguard.GenerateKeyPair()

	res := map[string]string{
		"nacl_public":  crypto.KeyToHex(pub),
		"nacl_private": crypto.KeyToHex(priv),
		"wg_public":    wg.PublicKey,
		"wg_private":   wg.PrivateKey,
	}
	data, _ := json.Marshal(res)
	return string(data)
}

// Вспомогательные функции
func parseConfigFromString(data string) (*config.Config, error) {
	cfg := &config.Config{}
	cfg.App.Name = "NatBypass"
	cfg.App.LogLevel = "info"
	cfg.App.PublishInterval = 8
	cfg.Network.StunServers = []string{"stun.l.google.com:19302", "stun1.l.google.com:19302", "stun.cloudflare.com:3478"}
	cfg.Network.IPApis = []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"}
	cfg.Network.IPTimeout = 5
	cfg.WireGuard.Enabled = true
	cfg.WireGuard.ListenPort = 51820
	cfg.WireGuard.MTU = 1420

	trimmed := strings.TrimSpace(data)
	if strings.HasPrefix(trimmed, "{") {
		_ = json.Unmarshal([]byte(trimmed), cfg)
	} else if trimmed != "" {
		_ = yaml.Unmarshal([]byte(trimmed), cfg)
	}
	return cfg, nil
}

func loadOrGenKeys(cfg *config.Config) ([32]byte, [32]byte, error) {
	if cfg.Crypto.PublicKey != "" && cfg.Crypto.PrivateKey != "" {
		pub, err := crypto.HexToKey(cfg.Crypto.PublicKey)
		if err == nil {
			priv, err := crypto.HexToKey(cfg.Crypto.PrivateKey)
			if err == nil {
				return pub, priv, nil
			}
		}
	}
	return crypto.GenerateKeyPair()
}

func buildChannels(cfg *config.Config, deviceID string) ([]signaling.SignalingChannel, error) {
	var channels []signaling.SignalingChannel
	for _, ch := range cfg.Signaling.Channels {
		if !ch.Enabled {
			continue
		}
		switch ch.Type {
		case "telegram":
			token := ch.Params["token"]
			chatID := ch.Params["chat_id"]
			proxy := ch.Params["proxy"]
			if token != "" && chatID != "" {
				channels = append(channels, signaling.NewTelegramChannel(token, chatID, proxy))
			}
		case "mqtt":
			broker := ch.Params["broker_url"]
			topic := ch.Params["topic"]
			user := ch.Params["username"]
			pass := ch.Params["password"]
			if broker != "" && topic != "" {
				channels = append(channels, signaling.NewMQTTChannel(broker, topic, deviceID, user, pass))
			}
		}
	}
	return channels, nil
}
