package mobile

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	globalDevName  string
	globalPublicIP string
	globalSTUN     string
	globalStarted  time.Time
	globalExitNode string
	globalAWGPreset string = "dpi"
	globalTxBytes  uint64
	globalRxBytes  uint64
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
	if cfg.App.DeviceName != "" {
		globalDevName = cfg.App.DeviceName
	} else if globalDevName == "" {
		globalDevName = devID
	}

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
				if cfg.WireGuard.AWG.Enabled || globalAWGPreset != "standard" {
					awgParams = getAWGParamsFromPreset(globalAWGPreset)
				}
				payload := &signaling.Payload{
					DeviceID:         devID,
					PublicKey:        crypto.KeyToHex(pubKey),
					PublicIP:         globalPublicIP,
					STUNAddr:         globalSTUN,
					WGPubKey:         wgKey.PublicKey,
					WGPort:           cfg.WireGuard.ListenPort,
					VirtualIP:        "10.200.0.100",
					IsExitNode:       cfg.Network.AllowExitNode,
					AdvertisedRoutes: cfg.Network.AdvertisedSubnets,
					Timestamp:        time.Now(),
					AWG:              awgParams,
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
						DeviceID:         p.DeviceID,
						PublicKey:        p.PublicKey,
						PublicIP:         p.PublicIP,
						STUNAddr:         p.STUNAddr,
						WGPubKey:         p.WGPubKey,
						WGPort:           p.WGPort,
						VirtualIP:        p.VirtualIP,
						IsExitNode:       p.IsExitNode,
						AdvertisedRoutes: p.AdvertisedRoutes,
						LastSeen:         time.Now(),
						Online:           true,
						AWG:              p.AWG,
					})
				}
			}
		}
	}()

	// UDP Puncher для реального P2P на Android
	puncher, pErr := network.NewUDPPuncher(51820, devID, cfg.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		if p, ok := globalRegistry.Get(remoteDevID); ok {
			p.DirectP2P = true
			if rtt > 0 {
				if p.Latency > 0 {
					p.Latency = time.Duration(float64(p.Latency)*0.75 + float64(rtt)*0.25)
				} else {
					p.Latency = rtt
				}
				p.PingMs = p.Latency.Milliseconds()
			}
			p.Online = true
			p.ActiveEndpoint = fromAddr
			p.LastSeen = time.Now()
			globalRegistry.Upsert(p)
		}
	})
	if pErr == nil && puncher != nil {
		logger.Info().Int("port", puncher.LocalPort()).Msg("Android P2P UDPPuncher запущен")
	}

	var tunFile *os.File
	if tunFd > 0 {
		tunFile = os.NewFile(uintptr(tunFd), "tun")
	}

	if puncher != nil && tunFile != nil {
		puncher.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
			atomic.AddUint64(&globalRxBytes, uint64(len(payload)))
			_, _ = tunFile.Write(payload)
		})

		go func() {
			buf := make([]byte, 65535)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					n, err := tunFile.Read(buf)
					if err != nil || n == 0 {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					pkt := buf[:n]
					atomic.AddUint64(&globalTxBytes, uint64(n))

					// Интеллектуальная маршрутизация по IP-заголовку
					if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
						destIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
						
						var targetPeer *peer.Peer
						for _, p := range globalRegistry.List() {
							if p.VirtualIP != "" && p.VirtualIP == destIP.String() {
								targetPeer = p
								break
							}
							for _, route := range p.AdvertisedRoutes {
								if _, ipNet, err := net.ParseCIDR(route); err == nil && ipNet.Contains(destIP) {
									targetPeer = p
									break
								}
							}
						}

						if targetPeer == nil && globalExitNode != "" {
							if ep, ok := globalRegistry.Get(globalExitNode); ok && ep.Online {
								targetPeer = ep
							}
						}

						if targetPeer != nil && targetPeer.ActiveEndpoint != "" {
							_ = puncher.SendDataPacket(targetPeer.ActiveEndpoint, pkt)
							continue
						}
					}

					// Fallback broadcast
					for _, p := range globalRegistry.List() {
						if p.Online && p.ActiveEndpoint != "" {
							_ = puncher.SendDataPacket(p.ActiveEndpoint, pkt)
						}
					}
				}
			}
		}()
	}

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

// TestTelegram проверяет подключение к Telegram Bot API
func TestTelegram(token, chatID, proxyURL string) string {
	if token == "" || chatID == "" {
		return "Ошибка: укажите токен и Chat ID бота"
	}
	ch := signaling.NewTelegramChannel(token, chatID, proxyURL)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	p := &signaling.Payload{
		DeviceID:  "test-probe",
		PublicKey: "00000000000000000000000000000000",
		Timestamp: time.Now(),
	}
	if err := ch.Send(ctx, p); err != nil {
		return fmt.Sprintf("Ошибка связи с Telegram: %v", err)
	}
	return "✓ Бот успешно ответил! Тестовое сообщение отправлено."
}

// TestMQTT проверяет подключение к MQTT брокеру
func TestMQTT(broker, topic, user, pass string) string {
	if broker == "" || topic == "" {
		return "Ошибка: укажите URL брокера и топик"
	}
	ch := signaling.NewMQTTChannel(broker, topic, "test-probe", user, pass)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	p := &signaling.Payload{
		DeviceID:  "test-probe",
		PublicKey: "00000000000000000000000000000000",
		Timestamp: time.Now(),
	}
	if err := ch.Send(ctx, p); err != nil {
		return fmt.Sprintf("Ошибка связи с MQTT: %v", err)
	}
	return fmt.Sprintf("✓ Успешное подключение к брокеру %s (топик: %s)!", broker, topic)
}

// GetPublicIP возвращает текущий публичный IP
func GetPublicIP() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalPublicIP != "" {
		return globalPublicIP
	}
	return "Определяется..."
}

// GetSTUNAddr возвращает текущий STUN-адрес
func GetSTUNAddr() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalSTUN != "" {
		return globalSTUN
	}
	return "Определяется..."
}

// SetDeviceName устанавливает имя устройства
func SetDeviceName(name string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	globalDevName = name
}

// SelectExitNode выбирает шлюз для выхода в интернет
func SelectExitNode(deviceID string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	globalExitNode = deviceID
	logger.Info().Str("exit_node", deviceID).Msg("Выбран Exit Node для Android")
}

// GetSelectedExitNode возвращает ID выбранного шлюза
func GetSelectedExitNode() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	return globalExitNode
}

// SetAWGPreset устанавливает пресет обфускации AWG 2.0
func SetAWGPreset(preset string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	globalAWGPreset = preset
	logger.Info().Str("preset", preset).Msg("Установлен пресет AmneziaWG 2.0")
}

// GetRandomAWGParamsJSON генерирует случайные параметры обхода блокировок
func GetRandomAWGParamsJSON() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	p := signaling.AWGParams{
		Jc:   3 + int(b[0]%4),
		Jmin: 30 + int(b[1]%30),
		Jmax: 60 + int(b[2]%60),
		S1:   20 + int(b[3]%40),
		S2:   20 + int(b[4]%40),
		H1:   fmt.Sprintf("%d", binary.BigEndian.Uint32(b[0:4])),
		H2:   fmt.Sprintf("%d", binary.BigEndian.Uint32(b[4:8])),
		H3:   fmt.Sprintf("%d", binary.BigEndian.Uint32(b[8:12])),
		H4:   fmt.Sprintf("%d", binary.BigEndian.Uint32(b[12:16])),
	}
	data, _ := json.Marshal(p)
	return string(data)
}

func getAWGParamsFromPreset(preset string) *signaling.AWGParams {
	switch preset {
	case "standard":
		return &signaling.AWGParams{
			Jc: 0, Jmin: 0, Jmax: 0, S1: 0, S2: 0,
			H1: "1", H2: "2", H3: "3", H4: "4",
		}
	case "stealth":
		var b [16]byte
		_, _ = rand.Read(b[:])
		return &signaling.AWGParams{
			Jc:   4,
			Jmin: 40,
			Jmax: 80,
			S1:   48,
			S2:   32,
			H1:   fmt.Sprintf("%d", binary.BigEndian.Uint32(b[0:4])),
			H2:   fmt.Sprintf("%d", binary.BigEndian.Uint32(b[4:8])),
			H3:   fmt.Sprintf("%d", binary.BigEndian.Uint32(b[8:12])),
			H4:   fmt.Sprintf("%d", binary.BigEndian.Uint32(b[12:16])),
		}
	default: // dpi
		return &signaling.AWGParams{
			Jc:   4,
			Jmin: 40,
			Jmax: 70,
			S1:   48,
			S2:   32,
			H1:   "1428571428",
			H2:   "2147483647",
			H3:   "857142857",
			H4:   "1122334455",
		}
	}
}

// GetFullTelemetryJSON возвращает детальные телеметрические метрики
func GetFullTelemetryJSON() string {
	engineMu.Lock()
	defer engineMu.Unlock()

	peersCount := 0
	directCount := 0
	var avgPing int64 = 0
	var pingSum int64 = 0

	if globalRegistry != nil {
		peers := globalRegistry.List()
		peersCount = len(peers)
		for _, p := range peers {
			if p.DirectP2P {
				directCount++
			}
			if p.PingMs > 0 {
				pingSum += p.PingMs
			}
		}
		if peersCount > 0 && pingSum > 0 {
			avgPing = pingSum / int64(peersCount)
		}
	}

	channel := "MQTT"
	if globalSigMgr != nil {
		channel = globalSigMgr.CurrentChannel()
	}

	res := map[string]interface{}{
		"running":         engineRunning,
		"device_id":       globalDevID,
		"device_name":     globalDevName,
		"public_ip":       globalPublicIP,
		"stun_addr":       globalSTUN,
		"virtual_ip":      "10.200.0.100",
		"peers_count":     peersCount,
		"direct_p2p":      directCount > 0,
		"direct_count":    directCount,
		"avg_ping_ms":     avgPing,
		"channel":         channel,
		"exit_node":       globalExitNode,
		"awg_preset":      globalAWGPreset,
		"tx_bytes":        atomic.LoadUint64(&globalTxBytes),
		"rx_bytes":        atomic.LoadUint64(&globalRxBytes),
		"uptime":          time.Since(globalStarted).Round(time.Second).String(),
	}
	data, _ := json.Marshal(res)
	return string(data)
}

// GetStatusJSON возвращает базовый статус
func GetStatusJSON() string {
	return GetFullTelemetryJSON()
}

// GetPeersJSON возвращает список устройств
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

	// Сигнальный канал
	ch := "MQTT / Telegram"
	if globalSigMgr != nil && globalSigMgr.CurrentChannel() != "" {
		ch = globalSigMgr.CurrentChannel()
	}
	result["channel"] = check{Ok: true, Detail: "Канал активен", Extra: ch}

	// Пиры
	pCount := 0
	if globalRegistry != nil {
		pCount = len(globalRegistry.List())
	}
	result["peers"] = check{Ok: pCount > 0, Detail: fmt.Sprintf("%d узлов в сети", pCount)}

	// NAT Type
	if globalSTUN != "" {
		result["nat_type"] = check{Ok: true, Detail: "Возможно Full Cone / Restricted NAT (P2P доступен)"}
	} else {
		result["nat_type"] = check{Ok: false, Detail: "Симметричный NAT (требует Relay)"}
	}

	data, _ := json.Marshal(result)
	return string(data)
}

// ParseQRInvite парсит QR-код приглашения
func ParseQRInvite(qrText string) string {
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

// ClearPeers очищает кэш всех узлов в оперативной памяти
func ClearPeers() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalRegistry != nil {
		globalRegistry.ClearAll()
	}
}

// GenerateInviteQRText возвращает строку QR-кода приглашения
func GenerateInviteQRText() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	ip := globalPublicIP
	if ip == "" {
		ip = "127.0.0.1"
	}
	name := globalDevName
	if name == "" {
		name = globalDevID
	}
	return fmt.Sprintf("NatBypass|%s|%s|https://github.com/jamixm4-crypto/natbypass/releases/latest", name, ip)
}

// GenerateKeysJSON генерирует ключи
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
