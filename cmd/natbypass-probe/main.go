package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

const version = "1.0.0-beta.1"

func main() {
	var (
		configPath = flag.String("config", "probe.json", "Path to probe config JSON")
		nodeID     = flag.String("node", "", "Node ID (auto-detected from hostname if empty)")
		timeoutSec = flag.Int("timeout", 0, "Test timeout in seconds (0 = use config value)")
		outputPath = flag.String("out", "", "Save JSON report to file")
		initFlag   = flag.Bool("init", false, "Initialize a new probe.json config")
		label      = flag.String("label", "", "Human-readable label for this node (e.g. 'BY / Beltelecom')")
		country    = flag.String("country", "", "Country code (BY, RU, US, etc.)")
		listenPort = flag.Int("port", 19876, "UDP listen port for incoming probe packets (advertised via STUN/MQTT)")
	)
	flag.Parse()

	logf("NatBypass Probe v%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
	logf("=======================================")

	// Init mode: create a new probe.json
	if *initFlag {
		hostname, _ := os.Hostname()
		probeID := "probe-" + strings.ToLower(hostname) + "-" + fmt.Sprintf("%d", time.Now().Unix()%10000)
		cfg := DefaultConfig(probeID)
		if err := SaveConfig(cfg, *configPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
		logf("[INIT] Created %s with probe_id=%s", *configPath, probeID)
		logf("[INIT] Share this file with other participants.")
		logf("[INIT] Each participant runs: natbypass-probe --config probe.json --label 'Country/ISP'")
		return
	}

	// Load config
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v\nRun with --init to create a new config.", err)
	}
	logf("[CFG] Loaded probe config: %s", cfg.ProbeID)

	if *timeoutSec > 0 {
		cfg.TestDurationSec = *timeoutSec
	}

	// Determine node ID
	hostname, _ := os.Hostname()
	myNodeID := *nodeID
	if myNodeID == "" {
		// Try to find by hostname in config
		if n := cfg.FindNodeByHostname(hostname); n != nil {
			myNodeID = n.ID
		} else {
			// Auto-generate stable node ID from hostname hash
			h := sha256.Sum256([]byte(hostname))
			myNodeID = fmt.Sprintf("node-%s", hex.EncodeToString(h[:4]))
		}
	}
	logf("[SELF] Node ID: %s (hostname: %s)", myNodeID, hostname)

	// Load or generate WG keypair
	myKP, err := LoadOrGenerateKeyPair(hostname)
	if err != nil {
		log.Fatalf("Keypair error: %v", err)
	}

	// Setup context with timeout
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(cfg.TestDurationSec)*time.Second,
	)
	defer cancel()

	startTime := time.Now()
	report := &ProbeReport{
		ProbeID:   cfg.ProbeID,
		Timestamp: startTime,
		MyNodeID:  myNodeID,
		Pairs:     make(map[string]*PairResult),
	}

	// ─── PHASE 1: SELF-TEST ───────────────────────────────────
	logf("\n[>] PHASE 1: Self-test")
	selfResult, err := RunSelfTest(ctx, cfg, *listenPort)
	if err != nil {
		logf("[SELF] Warning: %v", err)
	}
	report.SelfTest = selfResult

	// Start UDP probe listener (echo server) — needed for bidirectional UDP punch tests
	probeListenAddr := startUDPProbeListener(ctx, *listenPort, myNodeID)
	logf("[UDP-SRV] Probe listener on %s", probeListenAddr)

	// ─── PHASE 2: DISCOVERY ──────────────────────────────────
	logf("\n[>] PHASE 2: Peer discovery (60s)")

	nodeLabel := *label
	if nodeLabel == "" {
		nodeLabel = hostname
	}
	myVIP := NodeVIP(myNodeID)

	var discoveredPeers []*PeerInfo

	disc, err := NewDiscovery(cfg, myNodeID, func(peer *PeerInfo) {
		discoveredPeers = append(discoveredPeers, peer)
	})
	if err != nil {
		log.Fatalf("Discovery init error: %v", err)
	}

	// Start receiving
	if err := disc.StartReceiving(ctx); err != nil {
		logf("[SIG] Warning: %v", err)
	}

	stunAddr := ""
	if selfResult != nil {
		stunAddr = selfResult.STUNAddr
	}
	natType := ""
	if selfResult != nil {
		natType = selfResult.NATType
	}

	// Start beacon loop (publish every 10s)
	beaconListenPort := *listenPort
	if selfResult != nil && selfResult.ListenPort > 0 {
		beaconListenPort = selfResult.ListenPort
	}
	beacon := &ProbeBeacon{
		NodeID:     myNodeID,
		Label:      nodeLabel,
		Country:    *country,
		PubKey:     myKP.PublicKey,
		STUNAddr:   stunAddr,
		NATType:    natType,
		VIP:        myVIP,
		ProbeID:    cfg.ProbeID,
		ListenPort: beaconListenPort,
	}
	disc.StartBeaconLoop(ctx, beacon, 10)


	// Wait for discovery (up to 60s or until we have at least 1 peer)
	discoveryDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(discoveryDeadline) {
		if len(disc.GetPeers()) >= 1 {
			time.Sleep(5 * time.Second) // small extra wait for more peers
			break
		}
		time.Sleep(2 * time.Second)
		select {
		case <-ctx.Done():
			goto printReport
		default:
		}
	}

	discoveredPeers = disc.GetPeers()
	if len(discoveredPeers) == 0 {
		logf("[SIG] No peers discovered after 60s. Check MQTT connectivity.")
		goto printReport
	}
	logf("[SIG] Discovered %d peer(s)", len(discoveredPeers))
	report.Nodes = discoveredPeers

	// ─── PHASE 3: TESTS ──────────────────────────────────────
	logf("\n[>] PHASE 3: Connectivity tests")

	for _, peer := range discoveredPeers {
		pairKey := myNodeID + ">" + peer.NodeID
		pair := &PairResult{From: myNodeID, To: peer.NodeID}

		logf("\n--- Testing %s ---", pairKey)

		// 3a. Raw UDP punch
		if peer.STUNAddr != "" {
			pair.UDPPunch = TestRawUDPPunch(ctx, myNodeID, peer)
		}

		// 3b. AWG Handshake
		pair.AWGHandshake = TestAWGHandshake(ctx, cfg, myNodeID, myKP, peer)

		// 3c. AWG Ping (if handshake OK)
		// if pair.AWGHandshake != nil && pair.AWGHandshake.Success {
		//     pair.AWGPing = TestAWGPing(ctx, peer, 10)
		// }

		// 3d. TCP tests
		if peer.STUNAddr != "" {
			host := strings.Split(peer.STUNAddr, ":")[0]
			pair.TCPTests = TestTCPConnectivity(ctx, myNodeID, peer.NodeID, host)
		}

		// 3e. DPI probe (if AWG failed but UDP ok)
		if pair.UDPPunch != nil && pair.UDPPunch.Success &&
			pair.AWGHandshake != nil && !pair.AWGHandshake.Success && !pair.AWGHandshake.Skipped {
			pair.DPIProbe = TestDPIProbe(ctx, cfg, myNodeID, myKP, peer)
		}

		// Determine verdict
		verdict, notes := DetermineVerdict(pair)
		pair.Verdict = verdict
		pair.Notes = notes

		report.Pairs[pairKey] = pair
	}

printReport:
	report.DurationSec = int(time.Since(startTime).Seconds())

	// Print to console
	PrintReport(report)

	// Save JSON
	outPath := *outputPath
	if outPath == "" {
		outPath = fmt.Sprintf("probe-report-%s-%s.json",
			myNodeID, time.Now().Format("20060102-150405"))
	}
	if err := SaveJSONReport(report, outPath); err != nil {
		logf("[OUT] Failed to save report: %v", err)
	} else {
		logf("[OUT] Report saved: %s", outPath)
	}
}

// logf prints a timestamped log message
func logf(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s %s\n", timestamp, fmt.Sprintf(format, args...))
}
