package mobile

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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

const Version = "1.9.130"




type logRing struct {
	mu    sync.Mutex
	lines []string
	max   int
}

var globalLogs = &logRing{
	lines: make([]string, 0, 500),
	max:   500,
}

func (lr *logRing) Write(p []byte) (n int, err error) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	raw := strings.TrimSpace(string(p))
	if raw == "" {
		return len(p), nil
	}

	formatted := raw
	// If zerolog JSON payload, format cleanly: "15:04:05 [INFO] Message (key=val)"
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			lvl := "INFO"
			if l, ok := m["level"].(string); ok && l != "" {
				lvl = strings.ToUpper(l)
			}
			msg := ""
			if msgVal, ok := m["message"].(string); ok {
				msg = msgVal
			} else if msgVal, ok := m["msg"].(string); ok {
				msg = msgVal
			}

			var extraParts []string
			for k, v := range m {
				if k != "level" && k != "time" && k != "message" && k != "msg" && k != "caller" {
					extraParts = append(extraParts, fmt.Sprintf("%s=%v", k, v))
				}
			}
			extraStr := ""
			if len(extraParts) > 0 {
				extraStr = " (" + strings.Join(extraParts, ", ") + ")"
			}
			formatted = fmt.Sprintf("[%s] [%s] %s%s", time.Now().Format("15:04:05"), lvl, msg, extraStr)
		}
	} else {
		formatted = fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), raw)
	}

	if len(lr.lines) >= lr.max {
		lr.lines = lr.lines[1:]
	}
	lr.lines = append(lr.lines, formatted)
	return len(p), nil
}

func (lr *logRing) GetText() string {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if len(lr.lines) == 0 {
		return "Журнал пуст. Запустите соединение или выполните диагностику."
	}
	return strings.Join(lr.lines, "\n")
}

func (lr *logRing) Clear() {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	lr.lines = lr.lines[:0]
}

var (
	engineMu        sync.Mutex
	engineCtx       context.Context
	engineCancel    context.CancelFunc
	engineRunning   bool
	globalRegistry  *peer.Registry
	globalSigMgr    *signaling.FallbackManager
	globalConfig    *config.Config
	globalDevID     string
	globalDevName   string
	globalPublicIP  string
	globalIPv6      string
	globalSTUN      string
	globalVirtualIP string = ""
	globalStarted   time.Time
	globalExitNode         string
	globalAllowExitNode    bool
	globalAdvertisedRoutes []string
	globalAWGPreset        string = "dpi"
	globalPuncher          *network.UDPPuncher
	globalTunFile   *os.File
	globalTxBytes   uint64
	globalRxBytes   uint64
	logger          zerolog.Logger
)

func deriveInitialVirtualIP(devID string) string {
	if devID == "" {
		return "100.64.200.10"
	}
	var sum uint32
	for i := 0; i < len(devID); i++ {
		sum = (sum * 31) + uint32(devID[i])
	}
	octet := 10 + int(sum%240) // range 10..249
	return fmt.Sprintf("100.64.200.%d", octet)
}

func negotiateVirtualIP() {
	if globalRegistry == nil {
		return
	}
	usedIPs := make(map[string]string)
	for _, p := range globalRegistry.List() {
		pVIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
		if p.Online && pVIP != "" {
			usedIPs[pVIP] = p.DeviceID
		}
	}


	conflictDev, hasConflict := usedIPs[globalVirtualIP]
	if hasConflict && conflictDev != "" {
		if globalDevID > conflictDev {
			for i := 10; i <= 250; i++ {
				cand := fmt.Sprintf("100.64.200.%d", i)
				if _, used := usedIPs[cand]; !used {
					globalVirtualIP = cand
					break
				}
			}
		}
	}
}

func init() {
	multiWriter := io.MultiWriter(os.Stdout, globalLogs)
	logger = zerolog.New(multiWriter).With().Timestamp().Str("module", "mobile").Logger()
}

// StartEngine запускает ядро NatBypass внутри Android VpnService
func StartEngine(configYAML string, tunFd int) string {
	engineMu.Lock()
	defer engineMu.Unlock()

	// Если движок уже активен и передан валидный TUN fd - привязываем TUN к работающему сокету
	if engineRunning {
		if tunFd > 0 {
			attachTUN(tunFd)
			go func() {
				time.Sleep(500 * time.Millisecond)
				RefreshPublicIP()
			}()
		}
		return "OK"
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
	if globalVirtualIP == "" {
		globalVirtualIP = deriveInitialVirtualIP(devID)
	}
	if cfg.App.DeviceName != "" {
		globalDevName = cfg.App.DeviceName
	} else if globalDevName == "" {
		globalDevName = devID
	}

	// Реестр пиров
	globalRegistry = peer.NewRegistry()
	globalRegistry.StartMonitor(ctx, 2*time.Minute)

	// Сигнальные каналы
	activeProf := cfg.EnsureActiveProfile()
	if activeProf.AWGPreset != "" {
		globalAWGPreset = activeProf.AWGPreset
	}

	channels, err := buildChannels(cfg, devID)
	if err != nil || len(channels) == 0 {
		broker := activeProf.MQTTBroker
		if broker == "" {
			broker = "tcp://broker.emqx.io:1883"
		}
		channels = append(channels, signaling.NewMQTTChannel(
			broker,
			activeProf.MQTTTopic,
			devID,
			activeProf.MQTTUser,
			activeProf.MQTTPass,
		))
	}
	globalSigMgr = signaling.NewFallbackManager(channels)

	// UDP Puncher для P2P сокетов
	// UDPPort=0 (по умолчанию) → OS выделяет случайный порт (не конфликтует с AWG/WG)
	var puncher *network.UDPPuncher
	puncher, _ = network.NewUDPPuncher(cfg.Network.UDPPort, devID, cfg.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		if p, ok := globalRegistry.Get(remoteDevID); ok {
			p.DirectP2P = true
			p.ActiveEndpoint = fromAddr
			p.STUNAddr = fromAddr
			p.LastSeen = time.Now() // ВСЕГДА обновляем LastSeen!
			p.Online = true
			if rtt > 0 {
				p.PingMs = rtt.Milliseconds()
			} else {
				p.PingMs = 1
			}
			if p.PingMs <= 0 {
				p.PingMs = 1
			}
			if p.Latency > 0 {
				p.Latency = time.Duration(float64(p.Latency)*0.75 + float64(rtt)*0.25)
			} else {
				p.Latency = rtt
			}
			globalRegistry.Upsert(p)
			logger.Info().Str("peer", remoteDevID).Str("endpoint", fromAddr).Int64("ping_ms", p.PingMs).Msg("⚡ Android P2P сокет пробит!")

// periodic probeTicker maintains connection
		}
	})
	globalPuncher = puncher

	// Определение IP и STUN на постоянном UDP Puncher сокете
	ipDisc := network.NewDiscoverer(cfg.Network.IPApis, 5*time.Second)
	go func() {
		if ip, err := ipDisc.GetPublicIPCached(ctx, 5*time.Minute); err == nil {
			globalPublicIP = ip.String()
		}
		if v6 := network.GetPublicIPv6(ctx); v6 != "" {
			pPort := 51820
			if puncher != nil {
				pPort = puncher.LocalPort()
			}
			globalIPv6 = fmt.Sprintf("[%s]:%d", v6, pPort)
			logger.Info().Str("ipv6", globalIPv6).Msg("Глобальный IPv6 адрес мобильного устройства определён (P2P без CGNAT)")
		}
		if puncher != nil {
			if extIP, port, err := puncher.DiscoverMappedAddress(ctx); err == nil {
				globalSTUN = fmt.Sprintf("%s:%d", extIP.String(), port)
			}
		}
		if globalSTUN == "" {
			stunClient := network.NewSTUNClient(cfg.Network.StunServers)
			if extIP, port, err := stunClient.GetMappedAddress(ctx); err == nil {
				globalSTUN = fmt.Sprintf("%s:%d", extIP.String(), port)
			}
		}
	}()

	// WireGuard ключи
	wgKey, err := wireguard.GenerateKeyPair()
	if err != nil {
		wgKey = &wireguard.KeyPair{PublicKey: "", PrivateKey: ""}
	}

	// Цикл публикации в сигнальный канал (каждые 8 секунд)
	pubInterval := time.Duration(cfg.App.PublishInterval) * time.Second
	if pubInterval <= 0 || pubInterval > 15*time.Second {
		pubInterval = 5 * time.Second
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
				pPort := 47832
				if puncher != nil {
					pPort = puncher.LocalPort()
				}
				lanIP := network.GetLocalLANIP()
				localAddr := ""
				if lanIP != "" {
					localAddr = fmt.Sprintf("%s:%d", lanIP, pPort)
				}
				activeProf := cfg.EnsureActiveProfile()
				activeKey := ""
				activeTopic := ""
				if activeProf != nil {
					activeKey = activeProf.NetworkKey
					activeTopic = activeProf.MQTTTopic
				}
				hasDirect := false
				if globalRegistry != nil {
					for _, p := range globalRegistry.List() {
						if p.DirectP2P {
							hasDirect = true
							break
						}
					}
				}
				natTypeStr := "unknown"
				if puncher != nil {
					natTypeStr = puncher.GetNATType().String()
				}
				payload := &signaling.Payload{
					DeviceID:         devID,
					Nickname:         globalDevName,
					DeviceName:       globalDevName,
					PublicKey:        crypto.KeyToHex(pubKey),
					PublicIP:         globalPublicIP,
					LocalAddr:        localAddr,
					STUNAddr:         globalSTUN,
					IPv6Addr:         globalIPv6,
					WGPubKey:         wgKey.PublicKey,
					WGPort:           pPort,
					VirtualIP:        globalVirtualIP,
					DirectP2P:        hasDirect,
					NATType:          natTypeStr,
					IsExitNode:       globalAllowExitNode || cfg.Network.AllowExitNode,
					AdvertisedRoutes: func() []string {
						if len(globalAdvertisedRoutes) > 0 {
							return globalAdvertisedRoutes
						}
						return cfg.Network.AdvertisedSubnets
					}(),
					Timestamp:        time.Now(),
					AWG:              awgParams,
					NetworkKey:       activeKey,
					OS:               "android",
					Platform:         "Android",
					Arch:             "arm64",
					Version:          "1.9.130",
					IsKeenetic:       false,
					Topic:            activeTopic,
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
				if p != nil {
					// Расшифровка сквозного шифрования (E2E) сетевым ключом профиля
					if len(p.Encrypted) > 0 {
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
					}
				}
				if p != nil && p.DeviceID != devID {
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
					existingPeer, hasExisting := globalRegistry.Get(p.DeviceID)
					directP2P := false
					activeEP := ""
					latency := time.Duration(0)
					pingMs := p.PingMs
					if hasExisting && existingPeer != nil {
						directP2P = existingPeer.DirectP2P
						activeEP = existingPeer.ActiveEndpoint
						latency = existingPeer.Latency
						if existingPeer.PingMs > 0 {
							pingMs = existingPeer.PingMs
						}
					}
					globalRegistry.Upsert(&peer.Peer{
						DeviceID:         p.DeviceID,
						Nickname:         p.Nickname,
						PublicKey:        p.PublicKey,
						PublicIP:         p.PublicIP,
						LocalAddr:        p.LocalAddr,
						STUNAddr:         p.STUNAddr,
						IPv6Addr:         p.IPv6Addr,
						WGPubKey:         p.WGPubKey,
						WGPort:           p.WGPort,
						VirtualIP:        p.VirtualIP,
						DirectP2P:        directP2P,
						ActiveEndpoint:   activeEP,
						PingMs:           pingMs,
						Latency:          latency,
						IsExitNode:       p.IsExitNode,
						AdvertisedRoutes: p.AdvertisedRoutes,
						LastSeen:         time.Now(),
						Online:           true,
						AWG:              p.AWG,
						OS:               p.OS,
						Platform:         p.Platform,
						Arch:             p.Arch,
						Version:          p.Version,
						IsKeenetic:       p.IsKeenetic,
					})
					negotiateVirtualIP()

					// Немедленно посылаем UDP Hole Punch пробу по всем векторам (burst 5)
					if puncher != nil {
						go func(target *signaling.Payload) {
							addrs := []string{target.STUNAddr, target.LocalAddr}
							if target.IPv6Addr != "" {
								addrs = append(addrs, target.IPv6Addr)
							}
							if target.PublicIP != "" {
								addrs = append(addrs, fmt.Sprintf("%s:47832", target.PublicIP))
								addrs = append(addrs, fmt.Sprintf("%s:51820", target.PublicIP))
								if target.WGPort > 0 && target.WGPort != 47832 && target.WGPort != 51820 {
									addrs = append(addrs, fmt.Sprintf("%s:%d", target.PublicIP, target.WGPort))
								}
							}
							for b := 0; b < 5; b++ {
								for _, addr := range addrs {
									if addr != "" {
										_ = puncher.SendHolePunchProbe(addr)
									}
								}
								if b < 4 {
									time.Sleep(200 * time.Millisecond)
								}
							}
						}(p)
					}
				}
			}
		}
	}()

	// Фоновый цикл постоянного пробития NAT и удержания мобильного CGNAT (каждые 3 секунды)
	go func() {
		probeTicker := time.NewTicker(3 * time.Second)
		defer probeTicker.Stop()

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-probeTicker.C:
					if puncher != nil && globalRegistry != nil {
						for _, peerItem := range globalRegistry.List() {
							if peerItem.Online {
								if peerItem.STUNAddr != "" {
									_ = puncher.SendHolePunchProbe(peerItem.STUNAddr)
								}
								if peerItem.LocalAddr != "" && peerItem.LocalAddr != peerItem.STUNAddr {
									_ = puncher.SendHolePunchProbe(peerItem.LocalAddr)
								}
							}
						}
					}
				}
			}
		}()

		// Логируем NAT тип через 6 секунд после старта
		time.AfterFunc(6*time.Second, func() {
			if puncher != nil {
				natType := puncher.GetNATType()
				switch natType {
				case network.NATTypeSymmetric:
					logger.Warn().Str("nat_type", natType.String()).Msg("🔴 Обнаружен Symmetric NAT (CGNAT оператора)")
				case network.NATTypeFullCone:
					logger.Info().Str("nat_type", natType.String()).Msg("🟢 Обнаружен Full Cone / Restricted NAT — прямое P2P доступно")
				default:
					logger.Info().Str("nat_type", natType.String()).Msg("🔍 Тип NAT: " + natType.String())
				}
			}
		})

		for {
			select {
			case <-ctx.Done():
				return
			case <-probeTicker.C:
				if puncher != nil && globalRegistry != nil {
					for _, p := range globalRegistry.List() {
						go func(peer *peer.Peer) {
							if peer.DirectP2P && peer.ActiveEndpoint != "" {
								_ = puncher.SendKeepAlive(peer.ActiveEndpoint)
							} else {
								if peer.STUNAddr != "" {
									_ = puncher.SendHolePunchProbe(peer.STUNAddr)
								}
								if peer.LocalAddr != "" {
									_ = puncher.SendHolePunchProbe(peer.LocalAddr)
								}
								for _, cand := range peer.Candidates {
									if cand != "" && cand != peer.STUNAddr {
										_ = puncher.SendHolePunchProbe(cand)
									}
								}
							}
						}(p)
					}
				}
			}
		}
	}()



	if tunFd > 0 {
		attachTUN(tunFd)
	}

	engineRunning = true
	logger.Info().Str("device_id", devID).Int("tun_fd", tunFd).Msg("NatBypass Android ядро запущено")
	return "OK"
}

func attachTUN(tunFd int) {
	if tunFd <= 0 {
		return
	}
	globalTunFile = os.NewFile(uintptr(tunFd), "tun")

	if globalPuncher != nil && globalTunFile != nil {
		globalPuncher.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
			atomic.AddUint64(&globalRxBytes, uint64(len(payload)))

			// Write ALL packets directly to TUN fd.
			// Android OS handles ICMP Echo Reply, TCP ACK, UDP natively — no userspace interception needed.
			// Do NOT call respondICMPEcho here: it causes double-ICMP and corrupts the reply path.
			engineMu.Lock()
			tf := globalTunFile
			engineMu.Unlock()
			if tf != nil {
				_, _ = tf.Write(payload)
			}
		})

		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Warn().Msg(fmt.Sprintf("TUN read loop recovered: %v", r))
				}
			}()
			buf := make([]byte, 65535)
			for {
				engineMu.Lock()
				tf := globalTunFile
				ctx := engineCtx
				engineMu.Unlock()

				if tf == nil || ctx == nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				default:
					n, err := tf.Read(buf)
					if err != nil || n == 0 {
						// Socket closed or EOF -> exit loop cleanly
						return
					}
					pkt := buf[:n]
					atomic.AddUint64(&globalTxBytes, uint64(n))

					if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
						destIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])

						var targetPeer *peer.Peer
						if globalRegistry != nil {
							for _, p := range globalRegistry.List() {
								pVIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
								if pVIP != "" && pVIP == destIP.String() {
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
						}


						if targetPeer == nil && globalExitNode != "" && globalRegistry != nil {
							if ep, ok := globalRegistry.Get(globalExitNode); ok && ep.Online {
								targetPeer = ep
							}
						}

						if targetPeer != nil {
							if globalPuncher != nil {
								if targetPeer.ActiveEndpoint != "" {
									_ = globalPuncher.SendDataPacket(targetPeer.ActiveEndpoint, pkt)
								}
								if targetPeer.LocalAddr != "" && targetPeer.LocalAddr != targetPeer.ActiveEndpoint {
									_ = globalPuncher.SendDataPacket(targetPeer.LocalAddr, pkt)
								}
								if targetPeer.STUNAddr != "" && targetPeer.STUNAddr != targetPeer.ActiveEndpoint && targetPeer.STUNAddr != targetPeer.LocalAddr {
									_ = globalPuncher.SendDataPacket(targetPeer.STUNAddr, pkt)
								}
							}
							if globalSigMgr != nil {
								_ = globalSigMgr.PublishTunnelData(targetPeer.DeviceID, pkt)
							}
							logger.Debug().
								Str("dst", destIP.String()).
								Str("peer", targetPeer.DeviceID).
								Int("size", len(pkt)).
								Msg("📤 TUN TX: пакет отправлен узлу")
						} else {
							logger.Debug().
								Str("dst", destIP.String()).
								Msg("🚫 TUN TX: пир не найден для destination IP")
						}
					}
				}
			}
		}()
	}
}

func respondICMPEcho(payload []byte, fromAddr *net.UDPAddr) {
	if len(payload) < 20 {
		return
	}
	ihl := int(payload[0]&0x0F) * 4
	if len(payload) < ihl+8 {
		return
	}
	if payload[9] != 1 || payload[ihl] != 8 { // Not ICMP Echo Request
		return
	}

	reply := make([]byte, len(payload))
	copy(reply, payload)

	// Swap IP addresses
	srcIP := net.IPv4(payload[12], payload[13], payload[14], payload[15])
	destIP := net.IPv4(payload[16], payload[17], payload[18], payload[19])
	copy(reply[12:16], destIP.To4())
	copy(reply[16:20], srcIP.To4())

	// Reset IPv4 checksum
	reply[10] = 0
	reply[11] = 0
	ipCS := calcChecksum(reply[:ihl])
	reply[10] = byte(ipCS >> 8)
	reply[11] = byte(ipCS)

	// Change Type to 0 (Echo Reply)
	reply[ihl] = 0
	// Reset ICMP checksum
	reply[ihl+2] = 0
	reply[ihl+3] = 0
	icmpCS := calcChecksum(reply[ihl:])
	reply[ihl+2] = byte(icmpCS >> 8)
	reply[ihl+3] = byte(icmpCS)

	// Send reply back directly via UDP puncher socket
	if fromAddr != nil && globalPuncher != nil {
		_ = globalPuncher.SendDataPacket(fromAddr.String(), reply)
	} else if globalPuncher != nil && globalRegistry != nil {
		for _, p := range globalRegistry.List() {
			pVIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
			if (pVIP == srcIP.String() || p.VirtualIP == srcIP.String()) && p.ActiveEndpoint != "" {
				_ = globalPuncher.SendDataPacket(p.ActiveEndpoint, reply)
				break
			}
		}
	}

}

func calcChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// DetachTUN отключает TUN-интерфейс без остановки сигнального канала
func DetachTUN() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalTunFile == nil {
		return
	}
	tf := globalTunFile
	globalTunFile = nil
	_ = tf.Close()
	logger.Info().Msg("TUN интерфейс безопасно отключен")
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
	if globalTunFile != nil {
		_ = globalTunFile.Close()
		globalTunFile = nil
	}
	engineRunning = false
	logger.Info().Msg("NatBypass Android ядро остановлено")
}

// RestartEngine перезапускает движок с новым конфигом
func RestartEngine(configYAML string) string {
	StopEngine()
	time.Sleep(200 * time.Millisecond)
	return StartEngine(configYAML, 0)
}

// RefreshPublicIP вызывается Android NetworkCallback при смене сети (Wi-Fi → LTE и обратно)
// или по нажатию кнопки «Синхронизация»/«Обновить» в интерфейсе.
// Принудительно пересматривает публичный IP и STUN-mapped адрес, затем публикует обновлённый маяк.
func RefreshPublicIP() {
	engineMu.Lock()
	defer engineMu.Unlock()

	if !engineRunning {
		return
	}
	puncher := globalPuncher
	logger.Info().Msg("🔄 Смена сети обнаружена — принудительно пересматриваю IP и STUN-адрес...")

	// Сбрасываем текущий STUN и IP
	globalSTUN = ""
	globalPublicIP = ""
	globalIPv6 = ""

	go func() {
		time.Sleep(300 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// 1. Опрос STUN через puncher сокет (наиболее точный UDP-маппинг)
		if puncher != nil {
			if sIP, sPort, err := puncher.DiscoverMappedAddress(ctx); err == nil && sIP != nil {
				engineMu.Lock()
				globalSTUN = fmt.Sprintf("%s:%d", sIP.String(), sPort)
				globalPublicIP = sIP.String()
				engineMu.Unlock()
				logger.Info().Str("stun", globalSTUN).Str("ip", globalPublicIP).Msg("✅ STUN и внешний IP обновлены после смены сети")
			}
		}

		// 2. Если STUN не определил IP, быстрый HTTP discoverer без кэша
		if globalPublicIP == "" {
			ipDisc := network.NewDiscoverer(nil, 3*time.Second)
			if ip, err := ipDisc.GetPublicIP(ctx); err == nil && ip != nil {
				engineMu.Lock()
				globalPublicIP = ip.String()
				engineMu.Unlock()
				logger.Info().Str("public_ip", globalPublicIP).Msg("✅ Внешний IP обновлён через HTTP после смены сети")
			}
		}

		// 3. Обновление IPv6
		if v6 := network.GetPublicIPv6(ctx); v6 != "" {
			pPort := 51820
			if puncher != nil {
				pPort = puncher.LocalPort()
			}
			engineMu.Lock()
			globalIPv6 = fmt.Sprintf("[%s]:%d", v6, pPort)
			engineMu.Unlock()
			logger.Info().Str("ipv6", globalIPv6).Msg("✅ IPv6-адрес обновлён после смены сети")
		}

		// 4. Мгновенная публикация маяка в сигнальный канал и зондинг всех пиров
		if globalSigMgr != nil && globalConfig != nil {
			activeProf := globalConfig.EnsureActiveProfile()
			activeKey := ""
			activeTopic := ""
			if activeProf != nil {
				activeKey = activeProf.NetworkKey
				activeTopic = activeProf.MQTTTopic
			}
			var awgParams *signaling.AWGParams
			if globalConfig.WireGuard.AWG.Enabled || globalAWGPreset != "standard" {
				awgParams = getAWGParamsFromPreset(globalAWGPreset)
			}
			cleanVIP := strings.TrimSpace(strings.Split(globalVirtualIP, "/")[0])
			payload := &signaling.Payload{
				DeviceID:         globalDevID,
				Nickname:         globalDevName,
				DeviceName:       globalDevName,
				PublicIP:         globalPublicIP,
				STUNAddr:         globalSTUN,
				IPv6Addr:         globalIPv6,
				VirtualIP:        cleanVIP,
				NATType:          "unknown",
				Timestamp:        time.Now(),
				AWG:              awgParams,
				OS:               "android",
				Platform:         "Android",
				Arch:             "arm64",
				Version:          Version,
				IsKeenetic:       false,
				NetworkKey:       activeKey,
				Topic:            activeTopic,
			}
			_ = globalSigMgr.Send(ctx, payload)
		}

		// 5. Мгновенная отправка UDP hole punch зондов на все известные пиры
		if puncher != nil && globalRegistry != nil {
			for _, p := range globalRegistry.List() {
				if p.ActiveEndpoint != "" {
					_ = puncher.SendHolePunchProbe(p.ActiveEndpoint)
				}
				if p.STUNAddr != "" && p.STUNAddr != p.ActiveEndpoint {
					_ = puncher.SendHolePunchProbe(p.STUNAddr)
				}
				if p.IPv6Addr != "" && p.IPv6Addr != p.ActiveEndpoint {
					_ = puncher.SendHolePunchProbe(p.IPv6Addr)
				}
			}
		}
	}()
}

// GetLogsText возвращает полный лог ядра
func GetLogsText() string {
	return globalLogs.GetText()
}

// ClearLogs очищает накопленный буфер логов
func ClearLogs() {
	globalLogs.Clear()
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

// GetVirtualIP возвращает текущий виртуальный IP устройства в P2P сети
// SetVirtualIP устанавливает кастомный Virtual IP для мобильного устройства
func SetVirtualIP(vip string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	clean := strings.TrimSpace(strings.Split(vip, "/")[0])
	if clean != "" {
		globalVirtualIP = clean
		if globalConfig != nil {
			globalConfig.Network.Address = clean
			if p := globalConfig.EnsureActiveProfile(); p != nil {
				p.VirtualIP = clean
			}
		}
		logger.Info().Str("vip", clean).Msg("Virtual IP мобильного устройства обновлен")
	}
}

func GetVirtualIP() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalVirtualIP != "" {
		return globalVirtualIP
	}
	if globalDevID != "" {
		return deriveInitialVirtualIP(globalDevID)
	}
	return "100.64.200.10"
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

// SetAllowExitNode разрешает другим устройствам выходить в интернет через этот узел
func SetAllowExitNode(allow bool) {
	engineMu.Lock()
	defer engineMu.Unlock()
	globalAllowExitNode = allow
	if globalConfig != nil {
		globalConfig.Network.AllowExitNode = allow
	}
	logger.Info().Bool("allow_exit_node", allow).Msg("Статус Exit Node обновлен")
}

// GetAllowExitNode возвращает true, если узел может служить шлюзом
func GetAllowExitNode() bool {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalConfig != nil {
		return globalConfig.Network.AllowExitNode || globalAllowExitNode
	}
	return globalAllowExitNode
}

// SetAdvertisedRoutes устанавливает анонсируемые локальные подсети (например, "192.168.1.0/24")
func SetAdvertisedRoutes(routesCSV string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	var routes []string
	if routesCSV != "" {
		for _, s := range strings.Split(routesCSV, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				routes = append(routes, s)
			}
		}
	}
	globalAdvertisedRoutes = routes
	if globalConfig != nil {
		globalConfig.Network.AdvertisedSubnets = routes
	}
	logger.Info().Strs("routes", routes).Msg("Анонсируемые подсети обновлены")
}

// GetAdvertisedRoutes возвращает список анонсируемых подсетей
func GetAdvertisedRoutes() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	if len(globalAdvertisedRoutes) > 0 {
		return strings.Join(globalAdvertisedRoutes, ", ")
	}
	if globalConfig != nil && len(globalConfig.Network.AdvertisedSubnets) > 0 {
		return strings.Join(globalConfig.Network.AdvertisedSubnets, ", ")
	}
	return ""
}

// GetLocalSubnetsJSON возвращает список обнаруженных локальных подсетей устройства
func GetLocalSubnetsJSON() string {
	subnets := network.GetLocalSubnets()
	data, _ := json.Marshal(subnets)
	return string(data)
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
		"virtual_ip":      globalVirtualIP,
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
	pubIP := globalPublicIP
	if pubIP == "" && globalSTUN != "" {
		if host, _, err := net.SplitHostPort(globalSTUN); err == nil && host != "" {
			pubIP = host
			globalPublicIP = host
		}
	}
	if pubIP == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ipDisc := network.NewDiscoverer(nil, 2*time.Second)
		if ip, err := ipDisc.GetPublicIP(ctx); err == nil && ip != nil {
			pubIP = ip.String()
			globalPublicIP = pubIP
		}
		cancel()
	}

	if pubIP != "" {
		result["public_ip"] = check{Ok: true, Detail: "Внешний IP определён", Extra: pubIP}
	} else {
		result["public_ip"] = check{Ok: false, Detail: "IP определяется..."}
	}

	// STUN
	if globalSTUN != "" {
		result["stun"] = check{Ok: true, Detail: "STUN-сокет определён", Extra: globalSTUN}
	} else {
		result["stun"] = check{Ok: false, Detail: "STUN не определён"}
	}

	//                 
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
		result["nat_type"] = check{Ok: false, Detail: "             NAT (        Relay)"}
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

	activeProf := cfg.EnsureActiveProfile()
	if activeProf.MQTTTopic == "" || activeProf.MQTTTopic == "natbypass/mynet/peers" {
		activeProf.MQTTTopic = "natbypass/mesh/" + config.GenerateRandomHex(8)
		cfg.SyncSignalingWithProfile(activeProf)
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
			if broker == "" {
				broker = ch.Params["broker"]
			}
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

// GetProfilesJSON возвращает JSON список всех профилей с указанием активного
func GetProfilesJSON() string {
	engineMu.Lock()
	defer engineMu.Unlock()

	cfg := globalConfig
	if cfg == nil {
		cfg = &config.Config{}
	}
	active := cfg.EnsureActiveProfile()

	res := map[string]interface{}{
		"profiles":       cfg.Profiles,
		"active_id":      cfg.ActiveProfileID,
		"active_profile": active,
	}
	data, _ := json.Marshal(res)
	return string(data)
}

// CreateProfile создает новый профиль сети и опционально переключается на него
func CreateProfile(name, broker, topic, user, pass, tgToken string, tgChat int64, tgProxy, awgPreset string, autoSwitch bool) string {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		globalConfig = &config.Config{}
	}

	if name == "" {
		name = fmt.Sprintf("Сеть #%d", len(globalConfig.Profiles)+1)
	}
	if topic == "" {
		topic = "natbypass/mesh/" + config.GenerateRandomHex(8)
	}
	if broker == "" {
		broker = "tcp://broker.emqx.io:1883"
	}
	if awgPreset == "" {
		awgPreset = "dpi"
	}

	newProf := config.Profile{
		ID:         "p-" + config.GenerateRandomHex(4),
		Name:       name,
		NetworkKey: config.GenerateRandomHex(16),
		MQTTBroker: broker,
		MQTTTopic:  topic,
		MQTTUser:   user,
		MQTTPass:   pass,
		TGToken:    tgToken,
		TGChatID:   tgChat,
		TGProxy:    tgProxy,
		AWGPreset:  awgPreset,
		IsActive:   autoSwitch || len(globalConfig.Profiles) == 0,
		CreatedAt:  time.Now(),
	}

	saved := globalConfig.AddOrUpdateProfile(newProf)
	if autoSwitch {
		rebuildSignalingInternal(saved)
	}

	data, _ := json.Marshal(saved)
	return string(data)
}

// UpdateProfile обновляет существующий профиль (название, топик, брокер, AWG пресет, TG)
func UpdateProfile(profileID, name, broker, topic, user, pass, tgToken string, tgChat int64, tgProxy, awgPreset string) string {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		globalConfig = &config.Config{}
	}

	for i := range globalConfig.Profiles {
		if globalConfig.Profiles[i].ID == profileID {
			if name != "" {
				globalConfig.Profiles[i].Name = name
			}
			if broker != "" {
				globalConfig.Profiles[i].MQTTBroker = broker
			}
			if topic != "" {
				globalConfig.Profiles[i].MQTTTopic = topic
			}
			globalConfig.Profiles[i].MQTTUser = user
			globalConfig.Profiles[i].MQTTPass = pass
			globalConfig.Profiles[i].TGToken = tgToken
			globalConfig.Profiles[i].TGChatID = tgChat
			globalConfig.Profiles[i].TGProxy = tgProxy
			if awgPreset != "" {
				globalConfig.Profiles[i].AWGPreset = awgPreset
			}

			if globalConfig.Profiles[i].IsActive || globalConfig.ActiveProfileID == profileID {
				globalConfig.SyncSignalingWithProfile(&globalConfig.Profiles[i])
				if globalRegistry != nil {
					globalRegistry.ClearAll()
				}
				rebuildSignalingInternal(&globalConfig.Profiles[i])
			}

			data, _ := json.Marshal(globalConfig.Profiles[i])
			return string(data)
		}
	}
	return `{"error":"профиль не найден"}`
}

// GetConfigYAML возвращает текущий полный конфиг в формате YAML для сохранения
func GetConfigYAML() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalConfig == nil {
		return "{}"
	}
	data, err := yaml.Marshal(globalConfig)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// SwitchProfile переключает активный профиль по ID
func SwitchProfile(profileID string) bool {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		return false
	}

	target, err := globalConfig.SwitchProfile(profileID)
	if err != nil {
		logger.Error().Err(err).Msg("Ошибка переключения профиля")
		return false
	}

	if globalRegistry != nil {
		globalRegistry.ClearAll()
	}

	rebuildSignalingInternal(target)
	return true
}

// DeleteProfile удаляет профиль
func DeleteProfile(profileID string) bool {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		return false
	}

	wasActive := (globalConfig.ActiveProfileID == profileID)
	if err := globalConfig.DeleteProfile(profileID); err != nil {
		return false
	}

	if wasActive {
		active := globalConfig.GetActiveProfile()
		if globalRegistry != nil {
			globalRegistry.ClearAll()
		}
		rebuildSignalingInternal(active)
	}
	return true
}

// ExportProfileURI формирует natbypass://profile?... для QR или шеринга
func ExportProfileURI(profileID string) string {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		return ""
	}

	var target *config.Profile
	if profileID != "" {
		for i := range globalConfig.Profiles {
			if globalConfig.Profiles[i].ID == profileID {
				target = &globalConfig.Profiles[i]
				break
			}
		}
	}
	if target == nil {
		target = globalConfig.EnsureActiveProfile()
	}

	return config.ExportProfileURI(*target)
}

// ImportProfileURI импортирует профиль по ссылке или QR строке
func ImportProfileURI(rawURI string) string {
	parsed, err := config.ImportProfileURI(rawURI)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	engineMu.Lock()
	if globalConfig == nil {
		globalConfig = &config.Config{}
	}

	parsed.IsActive = true
	saved := globalConfig.AddOrUpdateProfile(*parsed)
	rebuildSignalingInternal(saved)
	engineMu.Unlock()

	// Мгновенная синхронизация сети и отправка маяка в новый топик
	go RefreshPublicIP()

	data, _ := json.Marshal(saved)
	return string(data)
}

// rebuildSignalingInternal пересобирает сигнальные каналы при смене профиля (вызывается под engineMu)
func rebuildSignalingInternal(p *config.Profile) {
	if p == nil {
		return
	}
	logger.Info().Str("profile", p.Name).Str("topic", p.MQTTTopic).Msg("🔄 Переключение сигнального канала на новый профиль...")

	if globalRegistry != nil {
		globalRegistry.ClearAll()
	}

	if globalSigMgr != nil {
		globalSigMgr.UpdateMQTTTopic(p.MQTTTopic)
	}

	if p.AWGPreset != "" {
		globalAWGPreset = p.AWGPreset
	}
}

// PingPeer активно отправляет UDP зонд пиру и возвращает реальный RTT в миллисекундах (-1 при отсутствии ответа)
func PingPeer(deviceID string) int64 {
	engineMu.Lock()
	p := globalPuncher
	reg := globalRegistry
	engineMu.Unlock()

	if p == nil || reg == nil {
		return -1
	}

	peerObj, ok := reg.Get(deviceID)
	if !ok || !peerObj.Online {
		return -1
	}

	initialTs := peerObj.LastSeen

	// Отправляем зонды на все известные адреса пира
	if peerObj.ActiveEndpoint != "" {
		_ = p.SendHolePunchProbe(peerObj.ActiveEndpoint)
	}
	if peerObj.STUNAddr != "" && peerObj.STUNAddr != peerObj.ActiveEndpoint {
		_ = p.SendHolePunchProbe(peerObj.STUNAddr)
	}
	if peerObj.IPv6Addr != "" && peerObj.IPv6Addr != peerObj.ActiveEndpoint {
		_ = p.SendHolePunchProbe(peerObj.IPv6Addr)
	}
	if peerObj.LocalAddr != "" {
		_ = p.SendHolePunchProbe(peerObj.LocalAddr)
	}
	if peerObj.PublicIP != "" {
		_ = p.SendHolePunchProbe(fmt.Sprintf("%s:47832", peerObj.PublicIP))
		_ = p.SendHolePunchProbe(fmt.Sprintf("%s:51820", peerObj.PublicIP))
		if peerObj.WGPort > 0 && peerObj.WGPort != 47832 && peerObj.WGPort != 51820 {
			_ = p.SendHolePunchProbe(fmt.Sprintf("%s:%d", peerObj.PublicIP, peerObj.WGPort))
		}
	}

	// Ждем до 400мс реального эхо-ответа
	for i := 0; i < 8; i++ {
		time.Sleep(50 * time.Millisecond)
		if updated, exists := reg.Get(deviceID); exists {
			if updated.LastSeen.After(initialTs) && updated.PingMs > 0 {
				return updated.PingMs
			}
		}
	}

	if updated, exists := reg.Get(deviceID); exists && updated.PingMs > 0 {
		return updated.PingMs
	}
	return -1
}



// SetProfileVirtualIP устанавливает кастомный Virtual IP для профиля
func SetProfileVirtualIP(profileID, vip string) bool {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		return false
	}
	for i := range globalConfig.Profiles {
		if globalConfig.Profiles[i].ID == profileID {
			cleanVIP := strings.TrimSpace(strings.Split(vip, "/")[0])
			globalConfig.Profiles[i].VirtualIP = cleanVIP
			if globalConfig.Profiles[i].IsActive || globalConfig.ActiveProfileID == profileID {
				globalConfig.Network.Address = cleanVIP
				globalVirtualIP = cleanVIP
			}
			return true
		}
	}
	return false
}
