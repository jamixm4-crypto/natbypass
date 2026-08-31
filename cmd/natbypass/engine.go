package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"



	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/daemon"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/relay"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/tray"
	"github.com/natbypass/natbypass/internal/tunnel"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
	"github.com/rs/zerolog/log"
)


// runEngine initializes and runs the core NatBypass networking pipeline.

var (
	magicSock        *network.MagicSock
	wssClient        *relay.WSSRelayClient
	udpRelay         *relay.UDPRelayClient
	triggerPublishCh = make(chan struct{}, 10)
)

func triggerPublish() {
	select {
	case triggerPublishCh <- struct{}{}:
	default:
	}
}

func runEngine(ctx context.Context, cfg *config.Config, enableTray bool) error {
	logTarget := ""
	if cfg.App.SaveLogsToDisk {
		logTarget = cfg.App.LogFile
		if logTarget == "" {
			logTarget = "natbypass.log"
		}
	}
	setupLogging(cfg.App.LogLevel, logTarget)

	if cfg.Daemon.PidFile == "" {
		if runtime.GOOS == "linux" {
			if _, err := os.Stat("/opt/var/run"); err == nil {
				cfg.Daemon.PidFile = "/opt/var/run/natbypass.pid"
			} else if _, err := os.Stat("/run"); err == nil {
				cfg.Daemon.PidFile = "/run/natbypass.pid"
			} else {
				cfg.Daemon.PidFile = "/var/run/natbypass.pid"
			}
		} else {
			cfg.Daemon.PidFile = "natbypass.pid"
		}
	}

	if cfg.Daemon.PidFile != "" {
		_ = daemon.WritePID(cfg.Daemon.PidFile)
		defer daemon.RemovePID(cfg.Daemon.PidFile)
	}

	log.Info().
		Str("version", Version).
		Str("commit", Commit).
		Str("config", configFile).
		Msg("Starting NatBypass engine")

	pubKey, privKey, err := loadOrGenerateKeys(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize encryption keys: %w", err)
	}
	log.Info().Str("public_key", crypto.KeyToHex(pubKey)).Msg("NaCl encryption keys loaded")

	deviceID := resolveDeviceID(cfg, pubKey)
	myVirtualIP := resolveVirtualIP(cfg, deviceID)
	log.Info().Str("device_id", deviceID).Str("virtual_ip", myVirtualIP).Msg("Device identity initialized")

	engineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	registry := startPeerRegistry(engineCtx)
	sigMgr := startSignaling(engineCtx, cfg, deviceID)
	uiServer := startWebUI(engineCtx, cfg, registry, sigMgr, deviceID, myVirtualIP)
	puncher, ipDisc := startNetworkLayer(engineCtx, cfg, deviceID, registry)
	if puncher != nil {
		defer puncher.Close()
	}

	awgParams := cfg.GetAWGParams()
	if puncher != nil {
		puncher.SetAWGVersion(string(awgParams.Version))
	}
	log.Info().
		Str("version", string(awgParams.Version)).
		Str("preset", cfg.WireGuard.AWGPreset).
		Bool("header_protection", awgParams.HeaderProtectionEnabled).
		Bool("random_trailers", awgParams.RandomTrailers).
		Bool("disable_cookies", awgParams.DisableCookies).
		Msg("AmneziaWG configuration loaded")

	wgPubKey, wgPort := initWireGuard(cfg)

	// Unconditional Wintun / TUN adapter creation with VirtualIP
	adapterName := "nb0"
	if runtime.GOOS == "windows" {
		adapterName = "NatBypass"
	}
	tunDev, tunErr := tunnel.CreateAdapter(adapterName, myVirtualIP)

	if tunErr != nil {
		log.Warn().Err(tunErr).Msg("Could not create TUN adapter (ensure running with Administrator rights)")
	} else {
		log.Info().Str("adapter", adapterName).Str("vip", myVirtualIP).Msg("TUN interface created and configured")
		defer tunDev.Close()

		if runtime.GOOS == "linux" {
			if err := tunnel.EnableMSSClamping(adapterName, 1420); err != nil {
				log.Warn().Err(err).Msg("Failed to enable MSS clamping")
			}
			defer tunnel.DisableMSSClamping(adapterName)
		}

		// Self-check and self-ping of Virtual IP
		go func() {
			time.Sleep(2 * time.Second)
			foundVIP := false
			ifaces, _ := net.Interfaces()
			for _, iface := range ifaces {
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					if strings.Contains(addr.String(), myVirtualIP) {
						foundVIP = true
						break
					}
				}
			}

			var pingCmd *exec.Cmd
			if runtime.GOOS == "windows" {
				pingCmd = exec.Command("ping", "-n", "1", "-w", "1000", myVirtualIP)
			} else {
				pingCmd = exec.Command("ping", "-c", "1", "-W", "1", myVirtualIP)
			}

			pingErr := pingCmd.Run()
			if pingErr == nil {
				log.Info().Str("vip", myVirtualIP).Bool("interface_bound", foundVIP).Msg("Self-check Virtual IP OK (ping responded)")
			} else {
				log.Warn().Str("vip", myVirtualIP).Bool("interface_bound", foundVIP).Err(pingErr).Msg("Self-check Virtual IP ping returned non-zero (interface still settling)")
			}
		}()

		// L3 Data-plane: Inbound packets from UDP Puncher & MQTT Relay -> Write directly to kernel TUN
		onInboundPacket := func(payload []byte, directAddr *net.UDPAddr) {
			if len(payload) < 20 {
				return
			}
			if payload[0]>>4 != 4 {
				return // Must be IPv4
			}
			srcIP := net.IPv4(payload[12], payload[13], payload[14], payload[15]).String()
			cleanVIP := strings.TrimSpace(strings.Split(myVirtualIP, "/")[0])
			if srcIP == cleanVIP && cleanVIP != "" {
				return // Protect against loopback reflection
			}
			// Verify IPv4 Total Length to ensure exact packet boundary
			totalLen := int(binary.BigEndian.Uint16(payload[2:4]))
			if totalLen >= 20 && totalLen <= len(payload) {
				payload = payload[:totalLen]
			}

			// If direct UDP data packet arrived, immediately lock and promote direct P2P path with Dynamic IP Auto-Learning
			if directAddr != nil && registry != nil {
				fromAddrStr := directAddr.String()
				var targetPeer *peer.Peer
				// 1. Match by Virtual IP
				if p, ok := registry.GetByVirtualIP(srcIP); ok && p != nil {
					targetPeer = p
				} else {
					// 2. Dynamic Auto-learning: Match peer by sender socket address (STUNAddr, ActiveEndpoint, Candidates, LocalAddr)
					for _, item := range registry.List() {
						if item.ActiveEndpoint == fromAddrStr || item.STUNAddr == fromAddrStr || item.LocalAddr == fromAddrStr {
							targetPeer = item
							targetPeer.VirtualIP = srcIP
							break
						}
						for _, c := range item.Candidates {
							if c == fromAddrStr {
								targetPeer = item
								targetPeer.VirtualIP = srcIP
								break
							}
						}
						if targetPeer != nil {
							break
						}
					}
					// 3. Fallback: if only 1 peer is connected in mesh, map srcIP directly
					if targetPeer == nil {
						pList := registry.List()
						if len(pList) == 1 {
							targetPeer = pList[0]
							targetPeer.VirtualIP = srcIP
						}
					}
				}

				if targetPeer != nil {
					oldEP := targetPeer.ActiveEndpoint
					targetPeer.DirectP2P = true
					targetPeer.ActiveEndpoint = fromAddrStr
					targetPeer.Online = true
					targetPeer.LastSeen = time.Now()
					registry.Upsert(targetPeer)
					if magicSock != nil {
						magicSock.RecordProbeSuccess(targetPeer.DeviceID, fromAddrStr, 0)
					}
					if puncher != nil {
						if oldEP != "" && oldEP != fromAddrStr {
							puncher.RemoveKeepAliveTarget(oldEP)
						}
						puncher.AddKeepAliveTarget(fromAddrStr)
					}
				}
			}

			if tunDev != nil {
				// Recalculate IPv4 header checksum to guarantee Windows kernel Wintun accepts packet unconditionally
				if len(payload) >= 20 && payload[0]>>4 == 4 {
					ihl := int(payload[0]&0x0F) * 4
					if ihl >= 20 && ihl <= len(payload) {
						payload[10] = 0
						payload[11] = 0
						var sum uint32
						for i := 0; i < ihl; i += 2 {
							sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
						}
						for sum > 0xFFFF {
							sum = (sum & 0xFFFF) + (sum >> 16)
						}
						binary.BigEndian.PutUint16(payload[10:12], ^uint16(sum))
					}
				}
				inSrcIP := net.IPv4(payload[12], payload[13], payload[14], payload[15]).String()
				inDstIP := net.IPv4(payload[16], payload[17], payload[18], payload[19]).String()
				log.Info().Str("src", inSrcIP).Str("dst", inDstIP).Int("len", len(payload)).Msg("📥 UDP→TUN inbound write")
				_ = tunDev.WritePacket(payload)
			}
		}

		if puncher != nil {
			puncher.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
				onInboundPacket(payload, srcAddr)
			})
		}

		// Signaling is strictly for control plane / peer discovery.
		// All data plane traffic flows strictly peer-to-peer over direct UDP.


		// L3 Data-plane: Outbound packets from TUN -> Dispatch to peer over UDP Direct or MQTT Relay
		pktCh := make(chan []byte, 256)
		go func() {
			for {
				select {
				case <-engineCtx.Done():
					return
				default:
				}
				pkt, err := tunDev.ReadPacket()
				if err != nil {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				if len(pkt) < 20 {
					continue
				}
				pktCopy := make([]byte, len(pkt))
				copy(pktCopy, pkt)
				select {
				case pktCh <- pktCopy:
				default:
				}
			}
		}()
		go func() {
			for {
				select {
				case <-engineCtx.Done():
					return
				case pkt, ok := <-pktCh:
					if !ok {
						return
					}
					if len(pkt) < 20 || pkt[0]>>4 != 4 {
						continue
					}
					dstNetIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
					dstIP := dstNetIP.String()
					cleanVIP := strings.TrimSpace(strings.Split(myVirtualIP, "/")[0])

					// Self-loopback: reflect local virtual IP packets directly back to TUN
					if dstIP == cleanVIP {
						if tunDev != nil {
							_ = tunDev.WritePacket(pkt)
						}
						continue
					}

					// Ignore multicast, broadcast
					if dstNetIP.IsMulticast() || dstNetIP.IsUnspecified() || dstIP == "255.255.255.255" || strings.HasSuffix(dstIP, ".255") {
						continue
					}

					var p *peer.Peer
					var found bool

					// 1. Direct match on Virtual IP
					p, found = registry.GetByVirtualIP(dstIP)
					if !found || p == nil {
						for _, item := range registry.List() {
							pVIP := strings.TrimSpace(strings.Split(item.VirtualIP, "/")[0])
							if pVIP == dstIP && pVIP != "" {
								p = item
								found = true
								break
							}
						}
					}

					// 2. Longest Prefix Match (LPM) on AdvertisedRoutes
					if !found || p == nil {
						bestPrefixLen := -1
						for _, item := range registry.List() {
							for _, route := range item.AdvertisedRoutes {
								if _, ipNet, err2 := net.ParseCIDR(strings.TrimSpace(route)); err2 == nil && ipNet.Contains(dstNetIP) {
									ones, _ := ipNet.Mask.Size()
									if ones > bestPrefixLen {
										bestPrefixLen = ones
										p = item
										found = true
									}
								}
							}
						}
					}

					if found && p != nil {
						targetEP := p.ActiveEndpoint
						if magicSock != nil {
							if bestEP, _, _ := magicSock.GetActiveRoute(p.DeviceID); bestEP != "" {
								targetEP = bestEP
							}
						}
						if targetEP == "" {
							targetEP = p.STUNAddr
						}
						if targetEP == "" {
							targetEP = p.LocalAddr
						}
						if targetEP == "" && p.PublicIP != "" && p.WGPort > 0 {
							targetEP = fmt.Sprintf("%s:%d", p.PublicIP, p.WGPort)
						}

						pmin := 0
						pmax := 0
						if p.AWG != nil {
							pmin = p.AWG.Pmin
							pmax = p.AWG.Pmax
						}

						// 1. Pure P2P Direct UDP packet transmission
						if targetEP != "" && puncher != nil {
							srcIP := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]).String()
							log.Info().Str("src", srcIP).Str("dst", dstIP).Str("peer", p.DeviceID).Str("ep", targetEP).Int("len", len(pkt)).Msg("📤 TUN→UDP outbound")
							err := puncher.SendDataPacketWithPadding(targetEP, pkt, pmin, pmax)
							if err != nil {
								log.Warn().Err(err).Str("dst", dstIP).Str("ep", targetEP).Msg("📤 TUN→UDP send error")
							}
						} else {
							log.Warn().Str("dst", dstIP).Str("peer", p.DeviceID).Str("ep", targetEP).Bool("puncher_nil", puncher == nil).Msg("📤 TUN→UDP no endpoint or puncher")
						}

						// 1b. Reactive instant hole punching if direct P2P is not yet confirmed
						if !p.DirectP2P && puncher != nil {
							if p.STUNAddr != "" && p.STUNAddr != targetEP {
								_ = puncher.SendHolePunchProbe(p.STUNAddr)
							}
							for _, cand := range p.Candidates {
								if cand != "" && cand != targetEP && cand != p.STUNAddr {
									_ = puncher.SendHolePunchProbe(cand)
								}
							}
						}
					}
				}
			}
		}()
	}

	// Dedicated rapid 2.5s keepalive & probe loop for maintaining carrier CGNAT mappings
	if puncher != nil {
		go func() {
			kaTicker := time.NewTicker(2 * time.Second)
			defer kaTicker.Stop()
			for {
				select {
				case <-engineCtx.Done():
					return
				case <-kaTicker.C:
					for _, p := range registry.List() {
						if p.DirectP2P && p.ActiveEndpoint != "" {
							_ = puncher.SendKeepAlive(p.ActiveEndpoint)
						} else {
							if p.ActiveEndpoint != "" {
								_ = puncher.SendHolePunchProbe(p.ActiveEndpoint)
							}
							if p.STUNAddr != "" {
								_ = puncher.SendHolePunchProbe(p.STUNAddr)
							}
							if p.LocalAddr != "" {
								_ = puncher.SendHolePunchProbe(p.LocalAddr)
							}
							if p.IPv6Addr != "" {
								_ = puncher.SendHolePunchProbe(p.IPv6Addr)
							}
							for _, cand := range p.Candidates {
								if cand != "" && cand != p.STUNAddr && cand != p.LocalAddr {
									_ = puncher.SendHolePunchProbe(cand)
								}
							}
							if p.PublicIP != "" && p.WGPort > 0 {
								_ = puncher.SendHolePunchProbe(fmt.Sprintf("%s:%d", p.PublicIP, p.WGPort))
							}
						}
					}
				}
			}
		}()
	}

	if cfg.Relay.Server != "" {
		wssClient = relay.NewWSSRelayClient(cfg.Relay.Server, deviceID, func(srcID string, payload []byte) {
			if len(payload) > 0 && tunDev != nil {
				_ = tunDev.WritePacket(payload)
			}
		})
		wssClient.Start()
		log.Info().Str("server", cfg.Relay.Server).Msg("🔒 WSS/HTTPS Fallback Relay (порт 443) подключен")
	}

	go initialDiscovery(engineCtx, puncher, ipDisc, uiServer, deviceID)

	go publishLoop(engineCtx, cfg, deviceID, myVirtualIP, pubKey, privKey, uiServer, registry, puncher, ipDisc, wgPubKey, wgPort, sigMgr, tunDev)
	go receiveLoop(engineCtx, cfg, deviceID, pubKey, privKey, registry, puncher, sigMgr, tunDev)
	go handleSIGHUP(engineCtx, cfg)


	return waitForTermination(engineCtx, enableTray, cancel, cfg, uiServer, sigMgr, ipDisc)
}

func resolveDeviceID(cfg *config.Config, pubKey [32]byte) string {
	if cfg.App.DeviceID != "" {
		return cfg.App.DeviceID
	}
	if hn, err := os.Hostname(); err == nil && hn != "" {
		return hn
	}
	return generateDeviceID(pubKey)
}

func resolveVirtualIP(cfg *config.Config, deviceID string) string {
	return config.ResolveVirtualIP(cfg, deviceID)
}

func startPeerRegistry(ctx context.Context) *peer.Registry {
	registry := peer.NewRegistry()
	registry.StartMonitor(ctx, constants.PeerMonitorInterval)
	return registry
}

func startSignaling(ctx context.Context, cfg *config.Config, deviceID string) *signaling.FallbackManager {
	activeProf := cfg.EnsureActiveProfile()
	if activeProf != nil {
		cfg.SyncSignalingWithProfile(activeProf)
	}

	channels, err := buildSignalingChannels(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse signaling channels from configuration")
	}
	if len(channels) == 0 {
		topic := "natbypass/mesh/default"
		if activeProf != nil && activeProf.MQTTTopic != "" {
			topic = activeProf.MQTTTopic
		}
		channels = append(channels, signaling.NewMQTTChannel("tcp://broker.emqx.io:1883", topic, deviceID, "", ""))
	}

	sigMgr := signaling.NewFallbackManager(channels)
	log.Info().Int("channels", len(channels)).Str("current", sigMgr.CurrentChannel()).Msg("Signaling channels initialized")
	return sigMgr
}

func startWebUI(ctx context.Context, cfg *config.Config, registry *peer.Registry, sigMgr *signaling.FallbackManager, deviceID, virtualIP string) *webui.Server {
	if noWebUI || !cfg.WebUI.Enabled {
		return nil
	}

	port := cfg.WebUI.Port
	if webUIPort > 0 {
		port = webUIPort
	}
	if port <= 0 {
		port = constants.DefaultWebUIPort
	}

	username := cfg.WebUI.Username
	password := cfg.WebUI.Password

	var customAuth func(user, pass string) bool

	if webui.IsKeeneticOS() {
		log.Info().Msg("🛡️ Обнаружена KeeneticOS: активирована системная авторизация роутера")
		customAuth = webui.VerifyKeeneticAuth
	} else if runtime.GOOS != "windows" && username == "" && password == "" {
		username = "admin"
		password = "admin"
		log.Info().Str("user", username).Msg("🔐 Web UI защищен авторизацией по умолчанию (admin/admin)")
	}

	uiServer := webui.NewServer(port, username, password, registry, sigMgr)
	if customAuth != nil {
		uiServer.SetCustomAuth(customAuth)
	}
	uiServer.SetOnConfigChange(triggerPublish)
	uiServer.SetConfigPath(configFile)
	uiServer.SetAppState(deviceID, "Определяется...", "Определяется...")
	uiServer.SetDeviceName(deviceID)
	uiServer.SetVersion(Version)
	uiServer.SetVirtualIP(virtualIP)
	uiServer.AddEvent("info", "NatBypass запущен", "version="+Version)


	go func() {
		if err := uiServer.Start(ctx); err != nil {
			log.Error().Err(err).Msg("Web UI stopped")
		}
	}()

	// Windows: open native WebView2 window after readiness gate confirms listening (TCP + HTTP healthz)
	if runtime.GOOS == "windows" {
		go func() {
			actualPort := uiServer.GetPort()
			if err := tray.EnsureFirewallRule(actualPort); err != nil {
				log.Debug().Err(err).Msg("Windows Firewall rule notice")
			}
			if uiServer.WaitForReady(10 * time.Second) {
				actualPort = uiServer.GetPort()
				url := fmt.Sprintf("http://127.0.0.1:%d", actualPort)
				log.Info().Int("port", actualPort).Str("url", url).Msg("WebUI readiness confirmed (TCP + HTTP healthz OK), opening window")
				openAppWindow(actualPort)
			} else {
				log.Warn().Int("port", actualPort).Msg("WebUI readiness gate timed out; window launch skipped")
			}
		}()
	}

	return uiServer
}

func startNetworkLayer(ctx context.Context, cfg *config.Config, deviceID string, registry *peer.Registry) (*network.UDPPuncher, *network.Discoverer) {
	ipDisc := network.NewDiscoverer(cfg.Network.IPApis, time.Duration(cfg.Network.IPTimeout)*time.Second)

	udpListenPort := cfg.Network.UDPPort
	if udpListenPort <= 0 {
		udpListenPort = constants.DefaultUDPPort
	}

	var puncher *network.UDPPuncher
	var punchErr error
	puncher, punchErr = network.NewUDPPuncher(udpListenPort, deviceID, cfg.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		log.Info().Str("peer", remoteDevID).Float64("rtt_ms", float64(rtt.Microseconds())/1000.0).Str("from", fromAddr).Msg("⚡ [P2P Direct UDP] Connection confirmed via UDP ping")
		if magicSock != nil {
			magicSock.RecordProbeSuccess(remoteDevID, fromAddr, rtt)
		}
		if p, ok := registry.Get(remoteDevID); ok && p != nil {
			oldEP := p.ActiveEndpoint
			p.DirectP2P = true
			if rtt > 0 {
				p.Latency = rtt
				p.PingMs = rtt.Milliseconds()
			}
			if magicSock != nil {
				if bestEP, _, _ := magicSock.GetActiveRoute(remoteDevID); bestEP != "" {
					p.ActiveEndpoint = bestEP
				} else {
					p.ActiveEndpoint = fromAddr
				}
			} else {
				p.ActiveEndpoint = fromAddr
			}
			p.NATBlocked = false
			registry.Upsert(p)
			if oldEP != "" && oldEP != p.ActiveEndpoint && puncher != nil {
				puncher.RemoveKeepAliveTarget(oldEP)
			}
			if puncher != nil && p.ActiveEndpoint != "" {
				puncher.AddKeepAliveTarget(p.ActiveEndpoint)
			}
		}
	})

	if punchErr != nil {
		log.Warn().Err(punchErr).Msg("Failed to initialize UDP puncher socket")
	} else if puncher != nil {
		puncher.StartKeepAliveLoop()
		magicSock = network.NewMagicSock(puncher, func(devID, oldPath, newPath string, pType network.PathType) {
			log.Info().Str("peer", devID).Str("old", oldPath).Str("new", newPath).Str("type", string(pType)).Msg("🔀 MagicSock: Path switched")
			if p, ok := registry.Get(devID); ok && p != nil {
				p.ActiveEndpoint = newPath
				p.DirectP2P = true
				registry.Upsert(p)
				if oldPath != "" && oldPath != newPath && puncher != nil {
					puncher.RemoveKeepAliveTarget(oldPath)
				}
				if puncher != nil && newPath != "" {
					puncher.AddKeepAliveTarget(newPath)
				}
			}
		})
		log.Info().Int("port", puncher.LocalPort()).Msg("UDP puncher active on persistent socket with MagicSock and KeepAlive")
	}

	return puncher, ipDisc
}

func initWireGuard(cfg *config.Config) (string, int) {
	if !cfg.WireGuard.Enabled {
		return "", 0
	}
	wgKP, wgErr := wireguard.GenerateKeyPair()
	if wgErr != nil {
		log.Warn().Err(wgErr).Msg("Failed to generate WireGuard keypair")
		return "", 0
	}
	return wgKP.PublicKey, cfg.WireGuard.ListenPort
}

func initialDiscovery(ctx context.Context, puncher *network.UDPPuncher, ipDisc *network.Discoverer, uiServer *webui.Server, deviceID string) {
	var publicIP net.IP = net.IPv4(0, 0, 0, 0)
	var stunAddr string

	if ip, err := ipDisc.GetPublicIPCached(ctx, 5*time.Minute); err == nil {
		publicIP = ip
		log.Info().Str("ip", publicIP.String()).Msg("Public IP discovered")
	}

	if puncher != nil {
		if extIP, port, err := puncher.DiscoverMappedAddress(ctx); err == nil && extIP != nil {
			stunAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
			log.Info().Str("stun_addr", stunAddr).Msg("STUN endpoint mapped via UDPPuncher")
		}
	}

	if uiServer != nil {
		uiServer.SetAppState(deviceID, publicIP.String(), stunAddr)
	}
}

var (
	mdarMu            sync.Mutex
	currentMTU        int    = 1420
	currentAdaptEpoch uint64 = 1
	currentDPIPreset  string = "dpi"
	relayStreakCount  int    = 0
)

func publishLoop(
	ctx context.Context,
	cfg *config.Config,
	deviceID, virtualIP string,
	pubKey, privKey [32]byte,
	uiServer *webui.Server,
	registry *peer.Registry,
	puncher *network.UDPPuncher,
	ipDisc *network.Discoverer,
	wgPubKey string,
	wgPort int,
	sigMgr *signaling.FallbackManager,
	tunDev *tunnel.Device,
) {
	publishInterval := time.Duration(cfg.App.PublishInterval) * time.Second
	if publishInterval <= 0 {
		publishInterval = constants.DefaultPublishInterval
	}

	ticker := time.NewTicker(publishInterval)
	defer ticker.Stop()

	var stunAddr string
	lastVIP := virtualIP

	publishOnce := func() {
		// Dynamic reload of current config & Virtual IP
		currentVIP := virtualIP
		if configFile != "" {
			if reloaded, rErr := config.Load(configFile); rErr == nil && reloaded != nil {
				*cfg = *reloaded
			}
		}
		currentVIP = resolveVirtualIP(cfg, deviceID)
		if currentVIP != "" && currentVIP != lastVIP {
			lastVIP = currentVIP
			if tunDev != nil {
				_ = tunDev.SetVirtualIP(currentVIP)
			}
			log.Info().Str("old_vip", virtualIP).Str("new_vip", currentVIP).Msg("Virtual IP dynamically updated on interface")
		}

		ip, _ := ipDisc.GetPublicIPCached(ctx, publishInterval/2)

		var awgParams *signaling.AWGParams
		if cfg.WireGuard.AWG.Enabled || cfg.WireGuard.Enabled {
			awgP := cfg.GetAWGParams()
			awgParams = &signaling.AWGParams{
				Jc:                      awgP.Jc,
				Jmin:                    awgP.Jmin,
				Jmax:                    awgP.Jmax,
				S1:                      awgP.S1,
				S2:                      awgP.S2,
				S3:                      awgP.S3,
				S4:                      awgP.S4,
				H1:                      fmt.Sprintf("%d", awgP.H1),
				H2:                      fmt.Sprintf("%d", awgP.H2),
				H3:                      fmt.Sprintf("%d", awgP.H3),
				H4:                      fmt.Sprintf("%d", awgP.H4),
				Pmin:                    awgP.ContentPaddingAdditionMin,
				Pmax:                    awgP.ContentPaddingAdditionMax,
				Version:                 string(awgP.Version),
				Preset:                  cfg.WireGuard.AWGPreset,
				HeaderProtectionEnabled: awgP.HeaderProtectionEnabled,
				RandomTrailers:          awgP.RandomTrailers,
				DisableCookies:          awgP.DisableCookies,
			}
		}

		var candidates []string
		if puncher != nil {
			if extIP, port, err := puncher.DiscoverMappedAddress(ctx); err == nil && extIP != nil {
				stunAddr = fmt.Sprintf("%s:%d", extIP.String(), port)
			} else {
				log.Debug().Err(err).Msg("STUN mapping refresh failed, retaining previous mapped address")
			}

			// Harvest full list of ICE-like candidate endpoints
			candidates = puncher.DiscoverCandidates(ctx, ip.String())

			myNAT := puncher.GetNATType()
			peers := registry.List()
			hasDirect := false

			for _, p := range peers {
				if p.DirectP2P {
					hasDirect = true
				}

				// 1. Maintain NAT keep-alive to active direct endpoint or STUN address
				targetKA := p.STUNAddr
				if p.DirectP2P && p.ActiveEndpoint != "" {
					targetKA = p.ActiveEndpoint
				}
				if targetKA != "" {
					_ = puncher.SendKeepAlive(targetKA)
				}

				// 2. Periodic hole punch probe burst for non-direct peers
				if !p.DirectP2P {
					if p.STUNAddr != "" {
						_ = puncher.SendHolePunchProbe(p.STUNAddr)
						p.ProbeCount++
					}
					// Probe all extra candidates
					for _, cand := range p.Candidates {
						if cand != p.STUNAddr && cand != "" {
							_ = puncher.SendHolePunchProbe(cand)
							p.ProbeCount++
						}
					}

					// Honest Double Symmetric NAT diagnostics
					if !p.FirstSeen.IsZero() && time.Since(p.FirstSeen) > 60*time.Second {
						if p.NATType == "symmetric" && myNAT == network.NATTypeSymmetric {
							p.NATBlocked = true
							log.Debug().
								Str("peer", p.DeviceID).
								Int("probes", p.ProbeCount).
								Msg("Double Symmetric NAT detected — direct P2P unavailable, running in Relay mode")
						}
					}
				}
			}

			// MDAR: Network Quality Monitoring and Adaptive MTU Scaling
			if len(peers) > 0 && !hasDirect {
				relayStreakCount++
				if relayStreakCount >= 6 && currentMTU > 1360 { // after ~30s of relay
					mdarMu.Lock()
					currentMTU = 1360
					currentAdaptEpoch++
					mdarMu.Unlock()
					if tunDev != nil {
						_ = tunDev.SetMTU(currentMTU)
					}
					log.Info().Int("adapted_mtu", currentMTU).Uint64("epoch", currentAdaptEpoch).Msg("MDAR: Адаптивное согласование MTU=1360 для обхода фрагментации")
				} else if relayStreakCount >= 12 && currentMTU > 1280 { // after ~60s of relay
					mdarMu.Lock()
					currentMTU = 1280
					currentAdaptEpoch++
					mdarMu.Unlock()
					if tunDev != nil {
						_ = tunDev.SetMTU(currentMTU)
					}
					log.Info().Int("adapted_mtu", currentMTU).Uint64("epoch", currentAdaptEpoch).Msg("MDAR: Адаптивное согласование MTU=1280 (максимальная проходимость)")
				}
			} else if hasDirect {
				relayStreakCount = 0
			}
		}

		if uiServer != nil {
			uiServer.SetAppState(deviceID, ip.String(), stunAddr)
			uiServer.SetVirtualIP(virtualIP)
		}

		natLabel := "unknown"
		if puncher != nil {
			natLabel = puncher.GetNATType().String()
		}

		mdarMu.Lock()
		activeMTU := currentMTU
		activeEpoch := currentAdaptEpoch
		activeDPI := currentDPIPreset
		mdarMu.Unlock()

		localIP := network.GetLocalLANIP()
		localAddr := ""
		if puncher != nil && localIP != "" {
			localAddr = fmt.Sprintf("%s:%d", localIP, puncher.LocalPort())
		}

		activeProf := cfg.EnsureActiveProfile()
		activeKey := ""
		activeTopic := ""
		if activeProf != nil {
			activeKey = activeProf.NetworkKey
			activeTopic = activeProf.MQTTTopic
		}

		payload := &signaling.Payload{
			DeviceID:        deviceID,
			NetworkKey:      activeKey,
			Topic:           activeTopic,
			LocalAddr:       localAddr,
			Nickname:        cfg.App.DeviceName,
			DeviceName:      cfg.App.DeviceName,
			PublicKey:       crypto.KeyToHex(pubKey),
			PublicIP:        ip.String(),
			STUNAddr:        stunAddr,
			Candidates:      candidates,
			NATType:         natLabel,
			WGPubKey:        wgPubKey,
			WGPort:          wgPort,
			Timestamp:       time.Now(),
			VirtualIP:       strings.TrimSpace(strings.Split(currentVIP, "/")[0]),
			OS:              runtime.GOOS,
			Platform: func() string {
				if webui.IsKeeneticOS() {
					return "KeeneticOS"
				}
				switch runtime.GOOS {
				case "windows":
					return "Windows"
				case "linux":
					return "Linux"
				case "darwin":
					return "macOS"
				default:
					return runtime.GOOS
				}
			}(),
			Arch:            runtime.GOARCH,
			Version:         Version,
			IsKeenetic:      webui.IsKeeneticOS(),
			AWG:             awgParams,
			MTU:             activeMTU,
			AdaptationEpoch: activeEpoch,
			DPIPreset:       activeDPI,
		}

		_ = sigMgr.Send(ctx, payload)
	}

	// Rapid initial discovery burst (3 beacons within 1.5s for instant mesh convergence)
	go func() {
		publishOnce()
		time.Sleep(350 * time.Millisecond)
		publishOnce()
		time.Sleep(900 * time.Millisecond)
		publishOnce()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publishOnce()
		case <-triggerPublishCh:
			publishOnce()
		}
	}
}

func receiveLoop(
	ctx context.Context,
	cfg *config.Config,
	deviceID string,
	pubKey, privKey [32]byte,
	registry *peer.Registry,
	puncher *network.UDPPuncher,
	sigMgr *signaling.FallbackManager,
	tunDev *tunnel.Device,
) {
	inCh, err := sigMgr.Receive(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to open signaling receiver channel")
		return
	}

	for {
		select {
		case <-ctx.Done():
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

			// Маяки внутри одной сигнальной комнаты принимаются безусловно

			// MDAR: Синхронизация эпохи адаптации сети от удаленного узла
			if p.AdaptationEpoch > currentAdaptEpoch {
				mdarMu.Lock()
				currentAdaptEpoch = p.AdaptationEpoch
				if p.MTU >= 1280 && p.MTU <= 1500 && p.MTU != currentMTU {
					currentMTU = p.MTU
					if tunDev != nil {
						_ = tunDev.SetMTU(currentMTU)
					}
					log.Info().Int("peer_mtu", p.MTU).Str("from", p.DeviceID).Msg("MDAR: Синхронизирован адаптированный MTU от удаленного узла")
				}
				mdarMu.Unlock()
			}

			existingPeer, peerFound := registry.Get(p.DeviceID)
			needsFastReply := !peerFound || existingPeer == nil || existingPeer.STUNAddr != p.STUNAddr || time.Since(existingPeer.LastSeen) > 6*time.Second

			// При наличии стабильного прямого P2P сокета — не сбиваем его зондированием чужих локальных подсетей
			if puncher != nil {
				if p.ActiveEndpoint != "" {
					_ = puncher.SendHolePunchProbe(p.ActiveEndpoint)
				}
				if p.STUNAddr != "" && p.STUNAddr != p.ActiveEndpoint {
					_ = puncher.SendHolePunchProbe(p.STUNAddr)
				}
				if p.LocalAddr != "" && p.LocalAddr != p.ActiveEndpoint {
					_ = puncher.SendHolePunchProbe(p.LocalAddr)
				}
				if p.IPv6Addr != "" {
					_ = puncher.SendHolePunchProbe(p.IPv6Addr)
				}
				for _, cand := range p.Candidates {
					if cand != "" && cand != p.STUNAddr && cand != p.LocalAddr && cand != p.ActiveEndpoint {
						_ = puncher.SendHolePunchProbe(cand)
					}
				}
				if p.PublicIP != "" && p.WGPort > 0 {
					_ = puncher.SendHolePunchProbe(fmt.Sprintf("%s:%d", p.PublicIP, p.WGPort))
				}
			}
			if magicSock != nil {
				magicSock.RegisterPeerEndpoints(p.DeviceID, p.STUNAddr, p.LocalAddr, p.IPv6Addr, p.Candidates...)
			}

			preservedEP := ""
			preservedDirect := false
			preservedLat := int64(0)
			if existingPeer != nil {
				preservedEP = existingPeer.ActiveEndpoint
				preservedDirect = existingPeer.DirectP2P
				preservedLat = existingPeer.PingMs
			}

			registry.Upsert(&peer.Peer{
				DeviceID:         p.DeviceID,
				Nickname:         p.Nickname,
				DeviceName:       p.DeviceName,
				PublicKey:        p.PublicKey,
				PublicIP:         p.PublicIP,
				STUNAddr:         p.STUNAddr,
				Candidates:       p.Candidates,
				NATType:          p.NATType,
				WGPubKey:         p.WGPubKey,
				WGPort:           p.WGPort,
				VirtualIP:        p.VirtualIP,
				IsExitNode:       p.IsExitNode,
				AdvertisedRoutes: p.AdvertisedRoutes,
				LastSeen:         time.Now(),
				Online:           true,
				DirectP2P:        preservedDirect,
				ActiveEndpoint:   preservedEP,
				PingMs:           preservedLat,
				AWG:              p.AWG,
				OS:               p.OS,
				Platform:         p.Platform,
				Arch:             p.Arch,
				Version:          p.Version,
				IsKeenetic:       p.IsKeenetic,
			})

			// Мгновенный ответный маяк при обнаружении нового узла, смене сокета или перезапуске клиента
			if needsFastReply {
				go func() {
					jitter := time.Duration(10+rand.Intn(70)) * time.Millisecond
					time.Sleep(jitter)
					triggerPublish()
				}()
			}
		}
	}
}


func handleSIGHUP(ctx context.Context, cfg *config.Config) {
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighupCh:
			log.Info().Msg("SIGHUP received: reloading configuration")
			config.Reload(cfg, configFile)
		}
	}
}

func waitForTermination(
	ctx context.Context,
	enableTray bool,
	cancel context.CancelFunc,
	cfg *config.Config,
	uiServer *webui.Server,
	sigMgr *signaling.FallbackManager,
	ipDisc *network.Discoverer,
) error {
	port := cfg.WebUI.Port
	if webUIPort > 0 {
		port = webUIPort
	}
	if port <= 0 {
		port = constants.DefaultWebUIPort
	}

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
				ipDisc.GetPublicIP(ctx)
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
		return trayApp.Run(ctx)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ctx.Done():
	case <-sigChan:
		log.Info().Msg("Shutdown signal received")
		cancel()
	}

	time.Sleep(300 * time.Millisecond)
	return nil
}

func createICMPEchoReply(pkt []byte) []byte {
	if len(pkt) < 28 {
		return nil
	}
	// Protocol must be ICMP (1) and Type must be Echo Request (8)
	if pkt[9] != 1 || pkt[20] != 8 {
		return nil
	}
	reply := make([]byte, len(pkt))
	copy(reply, pkt)

	// Swap Source IP (bytes 12..15) and Destination IP (bytes 16..19)
	copy(reply[12:16], pkt[16:20])
	copy(reply[16:20], pkt[12:16])

	// Set TTL = 64
	reply[8] = 64

	// Reset and recalculate IPv4 header checksum (bytes 10..11)
	reply[10] = 0
	reply[11] = 0
	ipChecksum := calculateChecksum(reply[:20])
	binary.BigEndian.PutUint16(reply[10:12], ipChecksum)

	// Change ICMP Type to 0 (Echo Reply)
	reply[20] = 0

	// Reset and recalculate ICMP checksum (bytes 22..23)
	reply[22] = 0
	reply[23] = 0
	icmpChecksum := calculateChecksum(reply[20:])
	binary.BigEndian.PutUint16(reply[22:24], icmpChecksum)

	return reply
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
