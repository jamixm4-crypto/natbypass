package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/tray"
	"github.com/natbypass/natbypass/internal/tunnel"
	"github.com/natbypass/natbypass/internal/webui"
	"github.com/natbypass/natbypass/internal/wireguard"
	"github.com/rs/zerolog/log"
)


// runEngine initializes and runs the core NatBypass networking pipeline.
func runEngine(ctx context.Context, cfg *config.Config, enableTray bool) error {
	setupLogging(cfg.App.LogLevel, cfg.App.LogFile)
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
	wgPubKey, wgPort := initWireGuard(cfg)

	// Unconditional Wintun / TUN adapter creation with VirtualIP
	adapterName := "NatBypass"
	tunDev, tunErr := tunnel.CreateAdapter(adapterName, myVirtualIP)

	if tunErr != nil {
		log.Warn().Err(tunErr).Msg("Could not create TUN adapter (ensure running with Administrator rights)")
	} else {
		log.Info().Str("adapter", adapterName).Str("vip", myVirtualIP).Msg("TUN interface created and configured")
		defer tunDev.Close()

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

		// L3 Data-plane: Inbound packets from UDP Puncher -> Write to TUN
		if puncher != nil {
			puncher.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
				if len(payload) >= 20 {
					_ = tunDev.WritePacket(payload)
				}
			})
		}

		// L3 Data-plane: Inbound packets from MQTT Relay -> Write to TUN
		if sigMgr != nil {
			sigMgr.SubscribeTunnelData(deviceID, func(pkt []byte) {
				if len(pkt) >= 20 {
					_ = tunDev.WritePacket(pkt)
				}
			})
		}

		// L3 Data-plane: Outbound packets from TUN -> Dispatch to peer over UDP Direct or MQTT Relay
		go func() {
			for {
				select {
				case <-engineCtx.Done():
					return
				default:
				}

				pkt, err := tunDev.ReadPacket()
				if err != nil || len(pkt) < 20 {
					time.Sleep(20 * time.Millisecond)
					continue
				}

				dstIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]).String()

				p, found := registry.GetByVirtualIP(dstIP)
				if !found || p == nil {
					peers := registry.List()
					if len(peers) == 1 {
						p = peers[0]
						found = true
					}
				}

				if found && p != nil {
					sentUDP := false
					if p.DirectP2P && p.ActiveEndpoint != "" && puncher != nil {
						if err := puncher.SendDataPacket(p.ActiveEndpoint, pkt); err == nil {
							sentUDP = true
						}
						if p.STUNAddr != "" && p.STUNAddr != p.ActiveEndpoint {
							_ = puncher.SendDataPacket(p.STUNAddr, pkt)
						}
					}
					if (!sentUDP || !p.DirectP2P) && sigMgr != nil {
						_ = sigMgr.PublishTunnelData(p.DeviceID, pkt)
					}
				}

			}
		}()
	}

	// Dedicated rapid 2.5s keepalive & probe loop for maintaining carrier CGNAT mappings
	if puncher != nil {
		go func() {
			kaTicker := time.NewTicker(2500 * time.Millisecond)
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
							if p.STUNAddr != "" {
								_ = puncher.SendHolePunchProbe(p.STUNAddr)
							}
							for _, cand := range p.Candidates {
								if cand != "" && cand != p.STUNAddr {
									_ = puncher.SendHolePunchProbe(cand)
								}
							}
						}
					}
				}
			}
		}()
	}

	go initialDiscovery(engineCtx, puncher, ipDisc, uiServer, deviceID)

	go publishLoop(engineCtx, cfg, deviceID, myVirtualIP, pubKey, privKey, uiServer, registry, puncher, ipDisc, wgPubKey, wgPort, sigMgr)
	go receiveLoop(engineCtx, deviceID, pubKey, privKey, registry, puncher, sigMgr)
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
	if cfg.Network.Address != "" {
		return strings.Split(cfg.Network.Address, "/")[0]
	}
	if activeProf := cfg.EnsureActiveProfile(); activeProf != nil && activeProf.VirtualIP != "" {
		return strings.Split(activeProf.VirtualIP, "/")[0]
	}
	h := sha256.Sum256([]byte(deviceID))
	octet := int(h[0]%250) + 2
	return fmt.Sprintf("100.64.200.%d", octet)
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

	uiServer := webui.NewServer(port, cfg.WebUI.Username, cfg.WebUI.Password, registry, sigMgr)
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

	puncher, punchErr := network.NewUDPPuncher(udpListenPort, deviceID, cfg.Network.StunServers, func(remoteDevID string, rtt time.Duration, fromAddr string) {
		log.Info().Str("peer", remoteDevID).Float64("rtt_ms", float64(rtt.Microseconds())/1000.0).Str("from", fromAddr).Msg("⚡ [P2P Direct UDP] Connection confirmed via UDP ping")
		if p, ok := registry.Get(remoteDevID); ok && p != nil {
			p.DirectP2P = true
			p.Latency = rtt
			p.PingMs = rtt.Milliseconds()
			p.ActiveEndpoint = fromAddr
			p.NATBlocked = false
			registry.Upsert(p)
		}
	})

	if punchErr != nil {
		log.Warn().Err(punchErr).Msg("Failed to initialize UDP puncher socket")
	} else if puncher != nil {
		log.Info().Int("port", puncher.LocalPort()).Msg("UDP puncher active on persistent socket")
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
) {
	publishInterval := time.Duration(cfg.App.PublishInterval) * time.Second
	if publishInterval <= 0 {
		publishInterval = constants.DefaultPublishInterval
	}

	ticker := time.NewTicker(publishInterval)
	defer ticker.Stop()

	var stunAddr string

	publishOnce := func() {
		ip, _ := ipDisc.GetPublicIPCached(ctx, publishInterval/2)

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

			for _, p := range registry.List() {
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
		}

		if uiServer != nil {
			uiServer.SetAppState(deviceID, ip.String(), stunAddr)
			uiServer.SetVirtualIP(virtualIP)
		}

		natLabel := "unknown"
		if puncher != nil {
			natLabel = puncher.GetNATType().String()
		}

		payload := &signaling.Payload{
			DeviceID:   deviceID,
			PublicKey:  crypto.KeyToHex(pubKey),
			PublicIP:   ip.String(),
			STUNAddr:   stunAddr,
			Candidates: candidates,
			NATType:    natLabel,
			WGPubKey:   wgPubKey,
			WGPort:     wgPort,
			Timestamp:  time.Now(),
			VirtualIP:  virtualIP,
			AWG:        awgParams,
		}

		encrypted, encErr := signaling.EncryptPayload(payload, pubKey, privKey)
		if encErr == nil {
			sigMgr.Send(ctx, encrypted)
		}
	}

	// Immediate initial beacon
	publishOnce()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publishOnce()
		}
	}
}

func receiveLoop(
	ctx context.Context,
	deviceID string,
	pubKey, privKey [32]byte,
	registry *peer.Registry,
	puncher *network.UDPPuncher,
	sigMgr *signaling.FallbackManager,
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
			if puncher != nil {
				go func(targetSTUN string, extraCandidates []string) {
					for burst := 0; burst < 6; burst++ {
						if targetSTUN != "" {
							_ = puncher.SendHolePunchProbe(targetSTUN)
						}
						for _, cand := range extraCandidates {
							if cand != "" && cand != targetSTUN {
								_ = puncher.SendHolePunchProbe(cand)
							}
						}
						time.Sleep(2 * time.Second)
					}
				}(p.STUNAddr, p.Candidates)
			}
			registry.Upsert(&peer.Peer{
				DeviceID:         p.DeviceID,
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
				LastSeen:         p.Timestamp,
				Online:           true,
				AWG:              p.AWG,
			})
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