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
	_ "golang.org/x/mobile/bind"
)

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
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		if len(lr.lines) >= lr.max {
			lr.lines = lr.lines[1:]
		}
		lr.lines = append(lr.lines, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	}
	return len(p), nil
}

func (lr *logRing) GetText() string {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if len(lr.lines) == 0 {
		return "Р›РѕРі РїРѕРєР° РїСѓСЃС‚. Р—Р°РїСѓСЃС‚РёС‚Рµ VPN РёР»Рё РІС‹РїРѕР»РЅРёС‚Рµ РґРёР°РіРЅРѕСЃС‚РёРєСѓ."
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
	peers := globalRegistry.List()
	usedIPs := make(map[string]string)
	for _, p := range peers {
		if p.Online && p.VirtualIP != "" {
			usedIPs[p.VirtualIP] = p.DeviceID
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

// StartEngine Р·Р°РїСѓСЃРєР°РµС‚ СЏРґСЂРѕ NatBypass РІРЅСѓС‚СЂРё Android VpnService
func StartEngine(configYAML string, tunFd int) string {
	engineMu.Lock()
	defer engineMu.Unlock()

	// Р•СЃР»Рё РґРІРёР¶РѕРє СѓР¶Рµ Р°РєС‚РёРІРµРЅ Рё РїРµСЂРµРґР°РЅ РІР°Р»РёРґРЅС‹Р№ TUN fd - РїСЂРёРІСЏР·С‹РІР°РµРј TUN Рє СЂР°Р±РѕС‚Р°СЋС‰РµРјСѓ СЃРѕРєРµС‚Сѓ
	if engineRunning {
		if tunFd > 0 {
			attachTUN(tunFd)
		}
		return "OK"
	}

	cfg, err := parseConfigFromString(configYAML)
	if err != nil {
		return fmt.Sprintf("РѕС€РёР±РєР° РїР°СЂСЃРёРЅРіР° РєРѕРЅС„РёРіР°: %v", err)
	}
	globalConfig = cfg

	ctx, cancel := context.WithCancel(context.Background())
	engineCtx = ctx
	engineCancel = cancel
	globalStarted = time.Now()

	// NaCl РєР»СЋС‡Рё
	pubKey, _, err := loadOrGenKeys(cfg)
	if err != nil {
		cancel()
		return fmt.Sprintf("РѕС€РёР±РєР° РіРµРЅРµСЂР°С†РёРё РєР»СЋС‡РµР№: %v", err)
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

	// Р РµРµСЃС‚СЂ РїРёСЂРѕРІ
	globalRegistry = peer.NewRegistry()
	globalRegistry.StartMonitor(ctx, 2*time.Minute)

	// РЎРёРіРЅР°Р»СЊРЅС‹Рµ РєР°РЅР°Р»С‹
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

	// UDP Puncher РґР»СЏ P2P СЃРѕРєРµС‚РѕРІ
	// UDPPort=0 (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ) в†’ OS РІС‹РґРµР»СЏРµС‚ СЃР»СѓС‡Р°Р№РЅС‹Р№ РїРѕСЂС‚ (РЅРµ РєРѕРЅС„Р»РёРєС‚СѓРµС‚ СЃ AWG/WG)
	var puncher *network.UDPPuncher
	puncher, _ = network.NewUDPPuncher(cfg.Network.UDPPort, devID, cfg.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		if p, ok := globalRegistry.Get(remoteDevID); ok {
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
			globalRegistry.Upsert(p)
			logger.Info().Str("peer", remoteDevID).Str("endpoint", fromAddr).Int64("ping_ms", p.PingMs).Msg("вљЎ Android P2P СЃРѕРєРµС‚ РїСЂРѕР±РёС‚!")

			// Р’СЃС‚СЂРµС‡РЅС‹Р№ Р·РѕРЅРґ РЅР° РѕР±РЅР°СЂСѓР¶РµРЅРЅС‹Р№ СЃРѕРєРµС‚ РґР»СЏ РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕРіРѕ РїРѕРґС‚РІРµСЂР¶РґРµРЅРёСЏ СЃРѕ СЃС‚РѕСЂРѕРЅС‹ РџРљ/СЂРѕСѓС‚РµСЂР°
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
	globalPuncher = puncher

	// РћРїСЂРµРґРµР»РµРЅРёРµ IP Рё STUN РЅР° РїРѕСЃС‚РѕСЏРЅРЅРѕРј UDP Puncher СЃРѕРєРµС‚Рµ
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
			logger.Info().Str("ipv6", globalIPv6).Msg("Р“Р»РѕР±Р°Р»СЊРЅС‹Р№ IPv6 Р°РґСЂРµСЃ РјРѕР±РёР»СЊРЅРѕРіРѕ СѓСЃС‚СЂРѕР№СЃС‚РІР° РѕРїСЂРµРґРµР»С‘РЅ (P2P Р±РµР· CGNAT)")
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

	// WireGuard РєР»СЋС‡Рё
	wgKey, err := wireguard.GenerateKeyPair()
	if err != nil {
		wgKey = &wireguard.KeyPair{PublicKey: "", PrivateKey: ""}
	}

	// Р¦РёРєР» РїСѓР±Р»РёРєР°С†РёРё РІ СЃРёРіРЅР°Р»СЊРЅС‹Р№ РєР°РЅР°Р» (РєР°Р¶РґС‹Рµ 8 СЃРµРєСѓРЅРґ)
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
					Topic:            activeTopic,
				}
				_ = globalSigMgr.Send(ctx, payload)
			}
		}
	}()

	// Р¦РёРєР» РїСЂРёС‘РјР° РѕС‚ СЃРёРіРЅР°Р»СЊРЅРѕРіРѕ РєР°РЅР°Р»Р°
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
						DirectP2P:        p.DirectP2P,
						ActiveEndpoint:   p.ActiveEndpoint,
						PingMs:           p.PingMs,
						IsExitNode:       p.IsExitNode,
						AdvertisedRoutes: p.AdvertisedRoutes,
						LastSeen:         time.Now(),
						Online:           true,
						AWG:              p.AWG,
					})
					negotiateVirtualIP()

					// РќРµРјРµРґР»РµРЅРЅРѕ РїРѕСЃС‹Р»Р°РµРј UDP Hole Punch РїСЂРѕР±Сѓ РїРѕ РІСЃРµРј РІРµРєС‚РѕСЂР°Рј (burst 5)
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

	// Р¤РѕРЅРѕРІС‹Р№ С†РёРєР» РїРѕСЃС‚РѕСЏРЅРЅРѕРіРѕ РїСЂРѕР±РёС‚РёСЏ NAT Рё РїРѕРґРґРµСЂР¶Р°РЅРёСЏ СЃРѕРєРµС‚РѕРІ Р¶РёРІС‹РјРё (РєР°Р¶РґС‹Рµ 3 СЃРµРєСѓРЅРґС‹)
	// РћС‚РїСЂР°РІР»СЏРµС‚ NATBYPASS:PING РЅР° РІСЃРµ РёР·РІРµСЃС‚РЅС‹Рµ Р°РґСЂРµСЃР° РїРёСЂР° РґР»СЏ СѓРґРµСЂР¶Р°РЅРёСЏ NAT-СЃРµСЃСЃРёРё
	// Рё РЅРµРїСЂРµСЂС‹РІРЅРѕРіРѕ РёР·РјРµСЂРµРЅРёСЏ RTT / РїРѕРґС‚РІРµСЂР¶РґРµРЅРёСЏ Direct P2P.
	go func() {
		probeTicker := time.NewTicker(3 * time.Second)
		defer probeTicker.Stop()

		// Р›РѕРіРёСЂСѓРµРј NAT С‚РёРї С‡РµСЂРµР· 6 СЃРµРєСѓРЅРґ РїРѕСЃР»Рµ СЃС‚Р°СЂС‚Р° (РґР°С‘Рј РґРµС‚РµРєС†РёРё Р·Р°РІРµСЂС€РёС‚СЊСЃСЏ)
		time.AfterFunc(6*time.Second, func() {
			if puncher != nil {
				natType := puncher.GetNATType()
				switch natType {
				case network.NATTypeSymmetric:
					logger.Warn().Str("nat_type", natType.String()).Msg("рџ”ґ РћР±РЅР°СЂСѓР¶РµРЅ Symmetric NAT (CGNAT РѕРїРµСЂР°С‚РѕСЂР°) вЂ” РєР»Р°СЃСЃРёС‡РµСЃРєРёР№ UDP hole punch РЅРµРЅР°РґС‘Р¶РµРЅ, РёСЃРїРѕР»СЊР·СѓСЋ СЂР°СЃС€РёСЂРµРЅРЅС‹Р№ sweep")
				case network.NATTypeFullCone:
					logger.Info().Str("nat_type", natType.String()).Msg("рџџў РћР±РЅР°СЂСѓР¶РµРЅ Full Cone / Restricted NAT вЂ” РїСЂСЏРјРѕРµ P2P СЃРѕРµРґРёРЅРµРЅРёРµ РґРѕСЃС‚СѓРїРЅРѕ")
				default:
					logger.Info().Str("nat_type", natType.String()).Msg("рџ”Ќ РўРёРї NAT: " + natType.String())
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
							if peer.ActiveEndpoint != "" {
								_ = puncher.SendHolePunchProbe(peer.ActiveEndpoint)
							}
							if peer.STUNAddr != "" && peer.STUNAddr != peer.ActiveEndpoint {
								_ = puncher.SendHolePunchProbe(peer.STUNAddr)
							}
							if peer.IPv6Addr != "" && peer.IPv6Addr != peer.ActiveEndpoint {
								_ = puncher.SendHolePunchProbe(peer.IPv6Addr)
							}
							if peer.LocalAddr != "" && peer.LocalAddr != peer.ActiveEndpoint {
								_ = puncher.SendHolePunchProbe(peer.LocalAddr)
							}
							if peer.PublicIP != "" {
								_ = puncher.SendHolePunchProbe(fmt.Sprintf("%s:47832", peer.PublicIP))
								_ = puncher.SendHolePunchProbe(fmt.Sprintf("%s:51820", peer.PublicIP))
								if peer.WGPort > 0 && peer.WGPort != 47832 && peer.WGPort != 51820 {
									_ = puncher.SendHolePunchProbe(fmt.Sprintf("%s:%d", peer.PublicIP, peer.WGPort))
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
	logger.Info().Str("device_id", devID).Int("tun_fd", tunFd).Msg("NatBypass Android СЏРґСЂРѕ Р·Р°РїСѓС‰РµРЅРѕ")
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

			// Instant ICMP echo reply for Android
			if len(payload) >= 20 && (payload[0]>>4) == 4 && payload[9] == 1 {
				ihl := int(payload[0]&0x0F) * 4
				if len(payload) >= ihl+8 && payload[ihl] == 8 {
					respondICMPEcho(payload, srcAddr)
				}
			}

			// Р—Р°РїРёСЃС‹РІР°РµРј РїР°РєРµС‚ РІ TUN вЂ” Android OS СЃР°РјР° РѕР±СЂР°Р±Р°С‚С‹РІР°РµС‚ ICMP, TCP, UDP
			// РќР• РїРµСЂРµС…РІР°С‚С‹РІР°РµРј ICMP РІСЂСѓС‡РЅСѓСЋ вЂ” РћРЎ РіРµРЅРµСЂРёСЂСѓРµС‚ Echo Reply СЃР°РјР° Рё РїРёС€РµС‚ РµРіРѕ РѕР±СЂР°С‚РЅРѕ РІ TUN
			if globalTunFile != nil {
				_, _ = globalTunFile.Write(payload)
			}
		})

		go func() {
			buf := make([]byte, 65535)
			for {
				if globalTunFile == nil || engineCtx == nil {
					return
				}
				select {
				case <-engineCtx.Done():
					return
				default:
					n, err := globalTunFile.Read(buf)
					if err != nil || n == 0 {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					pkt := buf[:n]
					atomic.AddUint64(&globalTxBytes, uint64(n))

					if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
						destIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])

						var targetPeer *peer.Peer
						if globalRegistry != nil {
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
						}

						if targetPeer == nil && globalExitNode != "" && globalRegistry != nil {
							if ep, ok := globalRegistry.Get(globalExitNode); ok && ep.Online {
								targetPeer = ep
							}
						}

						if targetPeer != nil && globalPuncher != nil {
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
						// РџР°РєРµС‚С‹ Р±РµР· С†РµР»Рё (РЅРµ mesh Рё РЅРµ exit node) РѕС‚Р±СЂР°СЃС‹РІР°СЋС‚СЃСЏ вЂ”
						// РќР• СЂР°СЃСЃС‹Р»Р°РµРј broadcast РїРѕ РІСЃРµРј РїРёСЂР°Рј (СЌС‚Рѕ РІС‹Р·С‹РІР°РµС‚ С€С‚РѕСЂРј С‚СЂР°С„РёРєР°)
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
			if p.VirtualIP == srcIP.String() && p.ActiveEndpoint != "" {
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

// DetachTUN РѕС‚РєР»СЋС‡Р°РµС‚ TUN-РёРЅС‚РµСЂС„РµР№СЃ Р±РµР· РѕСЃС‚Р°РЅРѕРІРєРё СЃРёРіРЅР°Р»СЊРЅРѕРіРѕ РєР°РЅР°Р»Р°
func DetachTUN() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalTunFile == nil {
		// Already detached вЂ” do not log again to avoid duplicate messages
		return
	}
	_ = globalTunFile.Close()
	globalTunFile = nil
	logger.Info().Msg("TUN РёРЅС‚РµСЂС„РµР№СЃ РѕС‚РєР»СЋС‡РµРЅ (СЃРёРіРЅР°Р»СЊРЅС‹Р№ РєР°РЅР°Р» РїСЂРѕРґРѕР»Р¶Р°РµС‚ СЂР°Р±РѕС‚Сѓ)")
}

// StopEngine РѕСЃС‚Р°РЅР°РІР»РёРІР°РµС‚ С„РѕРЅРѕРІС‹Р№ РґРІРёР¶РѕРє
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
	logger.Info().Msg("NatBypass Android СЏРґСЂРѕ РѕСЃС‚Р°РЅРѕРІР»РµРЅРѕ")
}

// RestartEngine РїРµСЂРµР·Р°РїСѓСЃРєР°РµС‚ РґРІРёР¶РѕРє СЃ РЅРѕРІС‹Рј РєРѕРЅС„РёРіРѕРј
func RestartEngine(configYAML string) string {
	StopEngine()
	time.Sleep(200 * time.Millisecond)
	return StartEngine(configYAML, 0)
}

// RefreshPublicIP РІС‹Р·С‹РІР°РµС‚СЃСЏ Android NetworkCallback РїСЂРё СЃРјРµРЅРµ СЃРµС‚Рё (Wi-Fi в†’ LTE Рё РѕР±СЂР°С‚РЅРѕ)
// РёР»Рё РїРѕ РЅР°Р¶Р°С‚РёСЋ РєРЅРѕРїРєРё В«РЎРёРЅС…СЂРѕРЅРёР·Р°С†РёСЏВ»/В«РћР±РЅРѕРІРёС‚СЊВ» РІ РёРЅС‚РµСЂС„РµР№СЃРµ.
// РџСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕ РїРµСЂРµСЃРјР°С‚СЂРёРІР°РµС‚ РїСѓР±Р»РёС‡РЅС‹Р№ IP Рё STUN-mapped Р°РґСЂРµСЃ, Р·Р°С‚РµРј РїСѓР±Р»РёРєСѓРµС‚ РѕР±РЅРѕРІР»С‘РЅРЅС‹Р№ РјР°СЏРє.
func RefreshPublicIP() {
	engineMu.Lock()
	defer engineMu.Unlock()

	if !engineRunning {
		return
	}
	puncher := globalPuncher
	logger.Info().Msg("рџ”„ РЎРјРµРЅР° СЃРµС‚Рё РѕР±РЅР°СЂСѓР¶РµРЅР° вЂ” РїСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕ РїРµСЂРµСЃРјР°С‚СЂРёРІР°СЋ IP Рё STUN-Р°РґСЂРµСЃ...")

	// РЎР±СЂР°СЃС‹РІР°РµРј С‚РµРєСѓС‰РёР№ STUN Рё IP
	globalSTUN = ""
	globalPublicIP = ""
	globalIPv6 = ""

	go func() {
		time.Sleep(300 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// 1. РћРїСЂРѕСЃ STUN С‡РµСЂРµР· puncher СЃРѕРєРµС‚ (РЅР°РёР±РѕР»РµРµ С‚РѕС‡РЅС‹Р№ UDP-РјР°РїРїРёРЅРі)
		if puncher != nil {
			if sIP, sPort, err := puncher.DiscoverMappedAddress(ctx); err == nil && sIP != nil {
				engineMu.Lock()
				globalSTUN = fmt.Sprintf("%s:%d", sIP.String(), sPort)
				globalPublicIP = sIP.String()
				engineMu.Unlock()
				logger.Info().Str("stun", globalSTUN).Str("ip", globalPublicIP).Msg("вњ… STUN Рё РІРЅРµС€РЅРёР№ IP РѕР±РЅРѕРІР»РµРЅС‹ РїРѕСЃР»Рµ СЃРјРµРЅС‹ СЃРµС‚Рё")
			}
		}

		// 2. Р•СЃР»Рё STUN РЅРµ РѕРїСЂРµРґРµР»РёР» IP, Р±С‹СЃС‚СЂС‹Р№ HTTP discoverer Р±РµР· РєСЌС€Р°
		if globalPublicIP == "" {
			ipDisc := network.NewDiscoverer(nil, 3*time.Second)
			if ip, err := ipDisc.GetPublicIP(ctx); err == nil && ip != nil {
				engineMu.Lock()
				globalPublicIP = ip.String()
				engineMu.Unlock()
				logger.Info().Str("public_ip", globalPublicIP).Msg("вњ… Р’РЅРµС€РЅРёР№ IP РѕР±РЅРѕРІР»С‘РЅ С‡РµСЂРµР· HTTP РїРѕСЃР»Рµ СЃРјРµРЅС‹ СЃРµС‚Рё")
			}
		}

		// 3. РћР±РЅРѕРІР»РµРЅРёРµ IPv6
		if v6 := network.GetPublicIPv6(ctx); v6 != "" {
			pPort := 51820
			if puncher != nil {
				pPort = puncher.LocalPort()
			}
			engineMu.Lock()
			globalIPv6 = fmt.Sprintf("[%s]:%d", v6, pPort)
			engineMu.Unlock()
			logger.Info().Str("ipv6", globalIPv6).Msg("вњ… IPv6-Р°РґСЂРµСЃ РѕР±РЅРѕРІР»С‘РЅ РїРѕСЃР»Рµ СЃРјРµРЅС‹ СЃРµС‚Рё")
		}

		// 4. РњРіРЅРѕРІРµРЅРЅР°СЏ РїСѓР±Р»РёРєР°С†РёСЏ РјР°СЏРєР° РІ СЃРёРіРЅР°Р»СЊРЅС‹Р№ РєР°РЅР°Р» Рё Р·РѕРЅРґРёРЅРі РІСЃРµС… РїРёСЂРѕРІ
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
			payload := &signaling.Payload{
				DeviceID:         globalDevID,
				Nickname:         globalDevName,
				DeviceName:       globalDevName,
				PublicIP:         globalPublicIP,
				STUNAddr:         globalSTUN,
				IPv6Addr:         globalIPv6,
				VirtualIP:        globalVirtualIP,
				NATType:          "unknown",
				Timestamp:        time.Now(),
				AWG:              awgParams,
				NetworkKey:       activeKey,
				Topic:            activeTopic,
			}
			_ = globalSigMgr.Send(ctx, payload)
		}

		// 5. РњРіРЅРѕРІРµРЅРЅР°СЏ РѕС‚РїСЂР°РІРєР° UDP hole punch Р·РѕРЅРґРѕРІ РЅР° РІСЃРµ РёР·РІРµСЃС‚РЅС‹Рµ РїРёСЂС‹
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

// GetLogsText РІРѕР·РІСЂР°С‰Р°РµС‚ РїРѕР»РЅС‹Р№ Р»РѕРі СЏРґСЂР°
func GetLogsText() string {
	return globalLogs.GetText()
}

// ClearLogs РѕС‡РёС‰Р°РµС‚ РЅР°РєРѕРїР»РµРЅРЅС‹Р№ Р±СѓС„РµСЂ Р»РѕРіРѕРІ
func ClearLogs() {
	globalLogs.Clear()
}

// IsRunning РІРѕР·РІСЂР°С‰Р°РµС‚ true, РµСЃР»Рё РґРІРёР¶РѕРє Р°РєС‚РёРІРµРЅ
func IsRunning() bool {
	engineMu.Lock()
	defer engineMu.Unlock()
	return engineRunning
}

// TestTelegram РїСЂРѕРІРµСЂСЏРµС‚ РїРѕРґРєР»СЋС‡РµРЅРёРµ Рє Telegram Bot API
func TestTelegram(token, chatID, proxyURL string) string {
	if token == "" || chatID == "" {
		return "РћС€РёР±РєР°: СѓРєР°Р¶РёС‚Рµ С‚РѕРєРµРЅ Рё Chat ID Р±РѕС‚Р°"
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
		return fmt.Sprintf("РћС€РёР±РєР° СЃРІСЏР·Рё СЃ Telegram: %v", err)
	}
	return "вњ“ Р‘РѕС‚ СѓСЃРїРµС€РЅРѕ РѕС‚РІРµС‚РёР»! РўРµСЃС‚РѕРІРѕРµ СЃРѕРѕР±С‰РµРЅРёРµ РѕС‚РїСЂР°РІР»РµРЅРѕ."
}

// TestMQTT РїСЂРѕРІРµСЂСЏРµС‚ РїРѕРґРєР»СЋС‡РµРЅРёРµ Рє MQTT Р±СЂРѕРєРµСЂСѓ
func TestMQTT(broker, topic, user, pass string) string {
	if broker == "" || topic == "" {
		return "РћС€РёР±РєР°: СѓРєР°Р¶РёС‚Рµ URL Р±СЂРѕРєРµСЂР° Рё С‚РѕРїРёРє"
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
		return fmt.Sprintf("РћС€РёР±РєР° СЃРІСЏР·Рё СЃ MQTT: %v", err)
	}
	return fmt.Sprintf("вњ“ РЈСЃРїРµС€РЅРѕРµ РїРѕРґРєР»СЋС‡РµРЅРёРµ Рє Р±СЂРѕРєРµСЂСѓ %s (С‚РѕРїРёРє: %s)!", broker, topic)
}

// GetVirtualIP РІРѕР·РІСЂР°С‰Р°РµС‚ С‚РµРєСѓС‰РёР№ РІРёСЂС‚СѓР°Р»СЊРЅС‹Р№ IP СѓСЃС‚СЂРѕР№СЃС‚РІР° РІ P2P СЃРµС‚Рё
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

// GetPublicIP РІРѕР·РІСЂР°С‰Р°РµС‚ С‚РµРєСѓС‰РёР№ РїСѓР±Р»РёС‡РЅС‹Р№ IP
func GetPublicIP() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalPublicIP != "" {
		return globalPublicIP
	}
	return "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ..."
}

// GetSTUNAddr РІРѕР·РІСЂР°С‰Р°РµС‚ С‚РµРєСѓС‰РёР№ STUN-Р°РґСЂРµСЃ
func GetSTUNAddr() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalSTUN != "" {
		return globalSTUN
	}
	return "РћРїСЂРµРґРµР»СЏРµС‚СЃСЏ..."
}

// SetDeviceName СѓСЃС‚Р°РЅР°РІР»РёРІР°РµС‚ РёРјСЏ СѓСЃС‚СЂРѕР№СЃС‚РІР°
func SetDeviceName(name string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	globalDevName = name
}

// SelectExitNode РІС‹Р±РёСЂР°РµС‚ С€Р»СЋР· РґР»СЏ РІС‹С…РѕРґР° РІ РёРЅС‚РµСЂРЅРµС‚
func SelectExitNode(deviceID string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	globalExitNode = deviceID
	logger.Info().Str("exit_node", deviceID).Msg("Р’С‹Р±СЂР°РЅ Exit Node РґР»СЏ Android")
}

// GetSelectedExitNode РІРѕР·РІСЂР°С‰Р°РµС‚ ID РІС‹Р±СЂР°РЅРЅРѕРіРѕ С€Р»СЋР·Р°
func GetSelectedExitNode() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	return globalExitNode
}

// SetAllowExitNode СЂР°Р·СЂРµС€Р°РµС‚ РґСЂСѓРіРёРј СѓСЃС‚СЂРѕР№СЃС‚РІР°Рј РІС‹С…РѕРґРёС‚СЊ РІ РёРЅС‚РµСЂРЅРµС‚ С‡РµСЂРµР· СЌС‚РѕС‚ СѓР·РµР»
func SetAllowExitNode(allow bool) {
	engineMu.Lock()
	defer engineMu.Unlock()
	globalAllowExitNode = allow
	if globalConfig != nil {
		globalConfig.Network.AllowExitNode = allow
	}
	logger.Info().Bool("allow_exit_node", allow).Msg("РЎС‚Р°С‚СѓСЃ Exit Node РѕР±РЅРѕРІР»РµРЅ")
}

// GetAllowExitNode РІРѕР·РІСЂР°С‰Р°РµС‚ true, РµСЃР»Рё СѓР·РµР» РјРѕР¶РµС‚ СЃР»СѓР¶РёС‚СЊ С€Р»СЋР·РѕРј
func GetAllowExitNode() bool {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalConfig != nil {
		return globalConfig.Network.AllowExitNode || globalAllowExitNode
	}
	return globalAllowExitNode
}

// SetAdvertisedRoutes СѓСЃС‚Р°РЅР°РІР»РёРІР°РµС‚ Р°РЅРѕРЅСЃРёСЂСѓРµРјС‹Рµ Р»РѕРєР°Р»СЊРЅС‹Рµ РїРѕРґСЃРµС‚Рё (РЅР°РїСЂРёРјРµСЂ, "192.168.1.0/24")
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
	logger.Info().Strs("routes", routes).Msg("РђРЅРѕРЅСЃРёСЂСѓРµРјС‹Рµ РїРѕРґСЃРµС‚Рё РѕР±РЅРѕРІР»РµРЅС‹")
}

// GetAdvertisedRoutes РІРѕР·РІСЂР°С‰Р°РµС‚ СЃРїРёСЃРѕРє Р°РЅРѕРЅСЃРёСЂСѓРµРјС‹С… РїРѕРґСЃРµС‚РµР№
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

// GetLocalSubnetsJSON РІРѕР·РІСЂР°С‰Р°РµС‚ СЃРїРёСЃРѕРє РѕР±РЅР°СЂСѓР¶РµРЅРЅС‹С… Р»РѕРєР°Р»СЊРЅС‹С… РїРѕРґСЃРµС‚РµР№ СѓСЃС‚СЂРѕР№СЃС‚РІР°
func GetLocalSubnetsJSON() string {
	subnets := network.GetLocalSubnets()
	data, _ := json.Marshal(subnets)
	return string(data)
}

// SetAWGPreset СѓСЃС‚Р°РЅР°РІР»РёРІР°РµС‚ РїСЂРµСЃРµС‚ РѕР±С„СѓСЃРєР°С†РёРё AWG 2.0
func SetAWGPreset(preset string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	globalAWGPreset = preset
	logger.Info().Str("preset", preset).Msg("РЈСЃС‚Р°РЅРѕРІР»РµРЅ РїСЂРµСЃРµС‚ AmneziaWG 2.0")
}

// GetRandomAWGParamsJSON РіРµРЅРµСЂРёСЂСѓРµС‚ СЃР»СѓС‡Р°Р№РЅС‹Рµ РїР°СЂР°РјРµС‚СЂС‹ РѕР±С…РѕРґР° Р±Р»РѕРєРёСЂРѕРІРѕРє
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

// GetFullTelemetryJSON РІРѕР·РІСЂР°С‰Р°РµС‚ РґРµС‚Р°Р»СЊРЅС‹Рµ С‚РµР»РµРјРµС‚СЂРёС‡РµСЃРєРёРµ РјРµС‚СЂРёРєРё
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

// GetStatusJSON РІРѕР·РІСЂР°С‰Р°РµС‚ Р±Р°Р·РѕРІС‹Р№ СЃС‚Р°С‚СѓСЃ
func GetStatusJSON() string {
	return GetFullTelemetryJSON()
}

// GetPeersJSON РІРѕР·РІСЂР°С‰Р°РµС‚ СЃРїРёСЃРѕРє СѓСЃС‚СЂРѕР№СЃС‚РІ
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

// GetDiagnosticsJSON РІРѕР·РІСЂР°С‰Р°РµС‚ СЂРµР·СѓР»СЊС‚Р°С‚С‹ РґРёР°РіРЅРѕСЃС‚РёРєРё
func GetDiagnosticsJSON() string {
	type check struct {
		Ok     bool   `json:"ok"`
		Detail string `json:"detail"`
		Extra  string `json:"extra,omitempty"`
	}
	result := map[string]interface{}{}

	// РРЅС‚РµСЂРЅРµС‚
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 3*time.Second)
	if err == nil {
		conn.Close()
		result["internet"] = check{Ok: true, Detail: "РРЅС‚РµСЂРЅРµС‚ РґРѕСЃС‚СѓРїРµРЅ"}
	} else {
		result["internet"] = check{Ok: false, Detail: "РќРµС‚ СЃРІСЏР·Рё СЃ РёРЅС‚РµСЂРЅРµС‚РѕРј"}
	}

	// РџСѓР±Р»РёС‡РЅС‹Р№ IP
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
		result["public_ip"] = check{Ok: true, Detail: "Р’РЅРµС€РЅРёР№ IP РѕРїСЂРµРґРµР»С‘РЅ", Extra: pubIP}
	} else {
		result["public_ip"] = check{Ok: false, Detail: "IP РѕРїСЂРµРґРµР»СЏРµС‚СЃСЏ..."}
	}

	// STUN
	if globalSTUN != "" {
		result["stun"] = check{Ok: true, Detail: "STUN-СЃРѕРєРµС‚ РѕРїСЂРµРґРµР»С‘РЅ", Extra: globalSTUN}
	} else {
		result["stun"] = check{Ok: false, Detail: "STUN РЅРµ РѕРїСЂРµРґРµР»С‘РЅ"}
	}

	// РЎРёРіРЅР°Р»СЊРЅС‹Р№ РєР°РЅР°Р»
	ch := "MQTT / Telegram"
	if globalSigMgr != nil && globalSigMgr.CurrentChannel() != "" {
		ch = globalSigMgr.CurrentChannel()
	}
	result["channel"] = check{Ok: true, Detail: "РљР°РЅР°Р» Р°РєС‚РёРІРµРЅ", Extra: ch}

	// РџРёСЂС‹
	pCount := 0
	if globalRegistry != nil {
		pCount = len(globalRegistry.List())
	}
	result["peers"] = check{Ok: pCount > 0, Detail: fmt.Sprintf("%d СѓР·Р»РѕРІ РІ СЃРµС‚Рё", pCount)}

	// NAT Type
	if globalSTUN != "" {
		result["nat_type"] = check{Ok: true, Detail: "Р’РѕР·РјРѕР¶РЅРѕ Full Cone / Restricted NAT (P2P РґРѕСЃС‚СѓРїРµРЅ)"}
	} else {
		result["nat_type"] = check{Ok: false, Detail: "РЎРёРјРјРµС‚СЂРёС‡РЅС‹Р№ NAT (С‚СЂРµР±СѓРµС‚ Relay)"}
	}

	data, _ := json.Marshal(result)
	return string(data)
}

// ParseQRInvite РїР°СЂСЃРёС‚ QR-РєРѕРґ РїСЂРёРіР»Р°С€РµРЅРёСЏ
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

// ClearPeers РѕС‡РёС‰Р°РµС‚ РєСЌС€ РІСЃРµС… СѓР·Р»РѕРІ РІ РѕРїРµСЂР°С‚РёРІРЅРѕР№ РїР°РјСЏС‚Рё
func ClearPeers() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalRegistry != nil {
		globalRegistry.ClearAll()
	}
}

// GenerateInviteQRText РІРѕР·РІСЂР°С‰Р°РµС‚ СЃС‚СЂРѕРєСѓ QR-РєРѕРґР° РїСЂРёРіР»Р°С€РµРЅРёСЏ
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

// GenerateKeysJSON РіРµРЅРµСЂРёСЂСѓРµС‚ РєР»СЋС‡Рё
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

// GetProfilesJSON РІРѕР·РІСЂР°С‰Р°РµС‚ JSON СЃРїРёСЃРѕРє РІСЃРµС… РїСЂРѕС„РёР»РµР№ СЃ СѓРєР°Р·Р°РЅРёРµРј Р°РєС‚РёРІРЅРѕРіРѕ
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

// CreateProfile СЃРѕР·РґР°РµС‚ РЅРѕРІС‹Р№ РїСЂРѕС„РёР»СЊ СЃРµС‚Рё Рё РѕРїС†РёРѕРЅР°Р»СЊРЅРѕ РїРµСЂРµРєР»СЋС‡Р°РµС‚СЃСЏ РЅР° РЅРµРіРѕ
func CreateProfile(name, broker, topic, user, pass, tgToken string, tgChat int64, tgProxy, awgPreset string, autoSwitch bool) string {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		globalConfig = &config.Config{}
	}

	if name == "" {
		name = fmt.Sprintf("РЎРµС‚СЊ #%d", len(globalConfig.Profiles)+1)
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

// UpdateProfile РѕР±РЅРѕРІР»СЏРµС‚ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ РїСЂРѕС„РёР»СЊ (РЅР°Р·РІР°РЅРёРµ, С‚РѕРїРёРє, Р±СЂРѕРєРµСЂ, AWG РїСЂРµСЃРµС‚, TG)
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
	return `{"error":"РїСЂРѕС„РёР»СЊ РЅРµ РЅР°Р№РґРµРЅ"}`
}

// GetConfigYAML РІРѕР·РІСЂР°С‰Р°РµС‚ С‚РµРєСѓС‰РёР№ РїРѕР»РЅС‹Р№ РєРѕРЅС„РёРі РІ С„РѕСЂРјР°С‚Рµ YAML РґР»СЏ СЃРѕС…СЂР°РЅРµРЅРёСЏ
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

// SwitchProfile РїРµСЂРµРєР»СЋС‡Р°РµС‚ Р°РєС‚РёРІРЅС‹Р№ РїСЂРѕС„РёР»СЊ РїРѕ ID
func SwitchProfile(profileID string) bool {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		return false
	}

	target, err := globalConfig.SwitchProfile(profileID)
	if err != nil {
		logger.Error().Err(err).Msg("РћС€РёР±РєР° РїРµСЂРµРєР»СЋС‡РµРЅРёСЏ РїСЂРѕС„РёР»СЏ")
		return false
	}

	if globalRegistry != nil {
		globalRegistry.ClearAll()
	}

	rebuildSignalingInternal(target)
	return true
}

// DeleteProfile СѓРґР°Р»СЏРµС‚ РїСЂРѕС„РёР»СЊ
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

// ExportProfileURI С„РѕСЂРјРёСЂСѓРµС‚ natbypass://profile?... РґР»СЏ QR РёР»Рё С€РµСЂРёРЅРіР°
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

// ImportProfileURI РёРјРїРѕСЂС‚РёСЂСѓРµС‚ РїСЂРѕС„РёР»СЊ РїРѕ СЃСЃС‹Р»РєРµ РёР»Рё QR СЃС‚СЂРѕРєРµ
func ImportProfileURI(rawURI string) string {
	parsed, err := config.ImportProfileURI(rawURI)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	engineMu.Lock()
	defer engineMu.Unlock()

	if globalConfig == nil {
		globalConfig = &config.Config{}
	}

	parsed.IsActive = true
	saved := globalConfig.AddOrUpdateProfile(*parsed)
	rebuildSignalingInternal(saved)

	data, _ := json.Marshal(saved)
	return string(data)
}

// rebuildSignalingInternal РїРµСЂРµСЃРѕР±РёСЂР°РµС‚ СЃРёРіРЅР°Р»СЊРЅС‹Рµ РєР°РЅР°Р»С‹ РїСЂРё СЃРјРµРЅРµ РїСЂРѕС„РёР»СЏ (РІС‹Р·С‹РІР°РµС‚СЃСЏ РїРѕРґ engineMu)
func rebuildSignalingInternal(p *config.Profile) {
	if p == nil {
		return
	}
	logger.Info().Str("profile", p.Name).Str("topic", p.MQTTTopic).Msg("рџ”„ РџРµСЂРµРєР»СЋС‡РµРЅРёРµ СЃРёРіРЅР°Р»СЊРЅРѕРіРѕ РєР°РЅР°Р»Р° РЅР° РЅРѕРІС‹Р№ РїСЂРѕС„РёР»СЊ...")

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

// PingPeer Р°РєС‚РёРІРЅРѕ РѕС‚РїСЂР°РІР»СЏРµС‚ UDP Р·РѕРЅРґ РїРёСЂСѓ Рё РІРѕР·РІСЂР°С‰Р°РµС‚ СЂРµР°Р»СЊРЅС‹Р№ RTT РІ РјРёР»Р»РёСЃРµРєСѓРЅРґР°С… (-1 РїСЂРё РѕС‚СЃСѓС‚СЃС‚РІРёРё РѕС‚РІРµС‚Р°)
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

	// РћС‚РїСЂР°РІР»СЏРµРј Р·РѕРЅРґС‹ РЅР° РІСЃРµ РёР·РІРµСЃС‚РЅС‹Рµ Р°РґСЂРµСЃР° РїРёСЂР°
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

	// Р–РґРµРј РґРѕ 400РјСЃ СЂРµР°Р»СЊРЅРѕРіРѕ СЌС…Рѕ-РѕС‚РІРµС‚Р°
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

