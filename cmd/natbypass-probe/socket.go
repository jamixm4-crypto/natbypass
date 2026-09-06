package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v2"
)

type stunResultEvent struct {
	server   string
	mappedIP net.IP
	port     int
	rtt      int64
	err      error
}

type udpReplyEvent struct {
	fromNodeID string
	remoteAddr *net.UDPAddr
	receivedAt time.Time
}

type awgReplyEvent struct {
	fromNodeID string
	remoteAddr *net.UDPAddr
	receivedAt time.Time
}

// ProbeSocket инкапсулирует единый UDP-сокет, используемый одновременно для:
// 1. STUN-запросов (определение реального внешнего сопоставленного порта роутера).
// 2. Входящих и исходящих P2P UDP-проб пробива NAT (Same Socket Hole Punching).
// 3. Отправки и приёма AWG-рукопожатий и мусорных пакетов (Jc/H1/H2).
type ProbeSocket struct {
	conn       *net.UDPConn
	localPort  int
	mappedIP   net.IP
	mappedPort int
	myNodeID   string
	cfg        *ProbeConfig

	mu         sync.Mutex
	stunEvents chan stunResultEvent
	udpReplies chan udpReplyEvent
	awgReplies chan awgReplyEvent

	ctx    context.Context
	cancel context.CancelFunc
}

// NewProbeSocket открывает локальный UDP-сокет и запускает единый readLoop
func NewProbeSocket(preferredPort int, myNodeID string, cfg *ProbeConfig) (*ProbeSocket, error) {
	var conn *net.UDPConn
	var err error

	if preferredPort > 0 {
		lAddr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", preferredPort))
		conn, err = net.ListenUDP("udp4", lAddr)
	}

	if err != nil || conn == nil {
		lAddr, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		conn, err = net.ListenUDP("udp4", lAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to bind UDP socket: %w", err)
		}
	}

	localPort := conn.LocalAddr().(*net.UDPAddr).Port

	_ = conn.SetReadBuffer(2 * 1024 * 1024)
	_ = conn.SetWriteBuffer(2 * 1024 * 1024)

	ctx, cancel := context.WithCancel(context.Background())

	ps := &ProbeSocket{
		conn:       conn,
		localPort:  localPort,
		myNodeID:   myNodeID,
		cfg:        cfg,
		stunEvents: make(chan stunResultEvent, 64),
		udpReplies: make(chan udpReplyEvent, 64),
		awgReplies: make(chan awgReplyEvent, 64),
		ctx:        ctx,
		cancel:     cancel,
	}

	go ps.readLoop()
	return ps, nil
}

func (ps *ProbeSocket) Close() {
	ps.cancel()
	if ps.conn != nil {
		_ = ps.conn.Close()
	}
}

func (ps *ProbeSocket) GetLocalPort() int {
	return ps.localPort
}

func (ps *ProbeSocket) GetMappedAddr() string {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.mappedIP != nil && ps.mappedPort > 0 {
		return fmt.Sprintf("%s:%d", ps.mappedIP.String(), ps.mappedPort)
	}
	return ""
}

func (ps *ProbeSocket) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ps.ctx.Done():
			return
		default:
		}

		_ = ps.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := ps.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ps.ctx.Err() != nil {
				return
			}
			continue
		}

		if n <= 0 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		// 1. Проверяем, является ли пакет STUN-ответом
		if stun.IsMessage(packet) {
			var msg stun.Message
			msg.Raw = packet
			if err := msg.Decode(); err == nil {
				var xorAddr stun.XORMappedAddress
				if err := xorAddr.GetFrom(&msg); err == nil {
					ps.stunEvents <- stunResultEvent{
						mappedIP: xorAddr.IP,
						port:     xorAddr.Port,
					}
					continue
				}
				var mappedAddr stun.MappedAddress
				if err := mappedAddr.GetFrom(&msg); err == nil {
					ps.stunEvents <- stunResultEvent{
						mappedIP: mappedAddr.IP,
						port:     mappedAddr.Port,
					}
					continue
				}
			}
		}

		// 2. Проверяем текстовые маркеры NATPROBE / NATREPLY
		payloadStr := string(packet)
		if strings.HasPrefix(payloadStr, "NATPROBE:") {
			body := strings.TrimPrefix(payloadStr, "NATPROBE:")
			parts := strings.Split(body, ">")
			fromID := parts[0]

			reply := []byte("NATREPLY:" + ps.myNodeID)
			_, _ = ps.conn.WriteToUDP(reply, remoteAddr)
			logf("[UDP-SRV] Received NATPROBE from %s (%s) -> sent NATREPLY", remoteAddr, fromID)
			continue
		}

		if strings.HasPrefix(payloadStr, "NATREPLY:") {
			fromID := strings.TrimPrefix(payloadStr, "NATREPLY:")
			select {
			case ps.udpReplies <- udpReplyEvent{
				fromNodeID: fromID,
				remoteAddr: remoteAddr,
				receivedAt: time.Now(),
			}:
			default:
			}
			continue
		}

		// 3. Проверяем AWG Handshake
		h1 := ps.cfg.AWG.H1
		h2 := ps.cfg.AWG.H2

		isAWGInit := false
		if n >= 4 && binary.LittleEndian.Uint32(packet[:4]) == h1 {
			isAWGInit = true
		} else if n >= 4 && binary.BigEndian.Uint32(packet[:4]) == h1 {
			isAWGInit = true
		} else if strings.Contains(payloadStr, "AWGPROBE:") {
			isAWGInit = true
		}

		if isAWGInit {
			fromID := "peer"
			if idx := strings.Index(payloadStr, "AWGPROBE:"); idx >= 0 {
				body := payloadStr[idx+len("AWGPROBE:"):]
				if p := strings.Split(body, ">"); len(p) > 0 {
					fromID = p[0]
				}
			}

			reply := make([]byte, 92+ps.cfg.AWG.S2)
			binary.LittleEndian.PutUint32(reply[:4], h2)
			copy(reply[4:], []byte("AWGREPLY:"+ps.myNodeID))
			if len(reply) > 20 {
				_, _ = rand.Read(reply[20:])
			}
			_, _ = ps.conn.WriteToUDP(reply, remoteAddr)
			logf("[AWG-SRV] Received AWG Handshake Initiation from %s (%s) -> sent AWG H2 Response", remoteAddr, fromID)
			continue
		}

		isAWGResp := false
		if n >= 4 && binary.LittleEndian.Uint32(packet[:4]) == h2 {
			isAWGResp = true
		} else if n >= 4 && binary.BigEndian.Uint32(packet[:4]) == h2 {
			isAWGResp = true
		} else if strings.Contains(payloadStr, "AWGREPLY:") {
			isAWGResp = true
		}

		if isAWGResp {
			fromID := "peer"
			if idx := strings.Index(payloadStr, "AWGREPLY:"); idx >= 0 {
				fromID = strings.TrimSpace(payloadStr[idx+len("AWGREPLY:"):])
				if len(fromID) > 32 {
					fromID = fromID[:32]
				}
			}
			select {
			case ps.awgReplies <- awgReplyEvent{
				fromNodeID: fromID,
				remoteAddr: remoteAddr,
				receivedAt: time.Now(),
			}:
			default:
			}
			continue
		}
	}
}

func (ps *ProbeSocket) RunSTUNSelfTest(ctx context.Context) (*SelfTestResult, error) {
	hostname, _ := getHostname()
	localIPs := getLocalIPs()

	res := &SelfTestResult{
		Hostname:   hostname,
		LocalIPs:   localIPs,
		ListenPort: ps.localPort,
	}

	logf("[STUN] Running multi-server STUN query on socket port %d...", ps.localPort)

	var ports []int
	for _, server := range ps.cfg.STUNServers {
		sr := STUNResult{Server: server}
		rAddr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			sr.Error = err.Error()
			res.STUNResults = append(res.STUNResults, sr)
			continue
		}

		start := time.Now()
		reqMsg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		if _, err := ps.conn.WriteToUDP(reqMsg.Raw, rAddr); err != nil {
			sr.Error = err.Error()
			res.STUNResults = append(res.STUNResults, sr)
			continue
		}

		timer := time.NewTimer(2 * time.Second)
		got := false
		for !got {
			select {
			case <-ctx.Done():
				timer.Stop()
				return res, ctx.Err()
			case <-timer.C:
				sr.Error = "timeout (no response)"
				got = true
			case ev := <-ps.stunEvents:
				sr.LatencyMs = time.Since(start).Milliseconds()
				sr.MappedIP = ev.mappedIP
				sr.MappedPort = ev.port
				ports = append(ports, ev.port)
				got = true
				timer.Stop()

				if ps.mappedIP == nil {
					ps.mu.Lock()
					ps.mappedIP = ev.mappedIP
					ps.mappedPort = ev.port
					ps.mu.Unlock()
					res.STUNAddr = fmt.Sprintf("%s:%d", ev.mappedIP.String(), ev.port)
				}
				logf("[STUN] %s -> %s:%d (%dms)", server, ev.mappedIP, ev.port, sr.LatencyMs)
			}
		}
		res.STUNResults = append(res.STUNResults, sr)
	}

	if len(ports) == 0 {
		res.NATType = "blocked"
		logf("[STUN] All STUN servers timed out. UDP traffic is blocked!")
		return res, nil
	}

	firstPort := ports[0]
	isSymmetric := false
	maxDelta := 0
	for i := 1; i < len(ports); i++ {
		d := ports[i] - ports[i-1]
		if d < 0 {
			d = -d
		}
		if d > maxDelta {
			maxDelta = d
		}
		if ports[i] != firstPort {
			isSymmetric = true
		}
	}

	res.NATDelta = maxDelta
	if isSymmetric {
		res.NATType = "symmetric"
		logf("[STUN] NAT Type: SYMMETRIC (ports differ: delta ~%d)", maxDelta)
	} else {
		res.NATType = "full_cone"
		logf("[STUN] NAT Type: CONE / FULL_CONE (mapped port: %d)", firstPort)
	}

	return res, nil
}

func (ps *ProbeSocket) TestUDPPunch(ctx context.Context, peer *PeerInfo) *UDPPunchResult {
	result := &UDPPunchResult{}

	targetAddr := peer.STUNAddr
	if targetAddr == "" {
		result.Error = "no STUN address for peer"
		return result
	}

	rAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		result.Error = fmt.Sprintf("invalid address %s: %v", targetAddr, err)
		return result
	}

	logf("[UDP] %s -> %s: Punching to %s (via socket port %d)", ps.myNodeID, peer.NodeID, targetAddr, ps.localPort)

	probePayload := []byte(fmt.Sprintf("NATPROBE:%s>%s", ps.myNodeID, peer.NodeID))

	delta := peer.NATDelta
	if delta <= 0 {
		delta = 1
	}

	start := time.Now()
	for attempt := 0; attempt < 6; attempt++ {
		_, _ = ps.conn.WriteToUDP(probePayload, rAddr)

		if peer.NATType == "symmetric" || peer.NATDelta > 0 {
			for step := 1; step <= 3; step++ {
				pHigh := rAddr.Port + step*delta
				pLow := rAddr.Port - step*delta
				if pHigh > 1024 && pHigh < 65535 {
					_, _ = ps.conn.WriteToUDP(probePayload, &net.UDPAddr{IP: rAddr.IP, Port: pHigh})
				}
				if pLow > 1024 && pLow < 65535 {
					_, _ = ps.conn.WriteToUDP(probePayload, &net.UDPAddr{IP: rAddr.IP, Port: pLow})
				}
			}
		}

		waitTimer := time.NewTimer(400 * time.Millisecond)
		select {
		case <-ctx.Done():
			waitTimer.Stop()
			result.Error = ctx.Err().Error()
			return result
		case reply := <-ps.udpReplies:
			waitTimer.Stop()
			if reply.fromNodeID == peer.NodeID || strings.Contains(reply.fromNodeID, peer.NodeID) || peer.NodeID == "" {
				result.Success = true
				result.Bidirectional = true
				result.LatencyMs = time.Since(start).Milliseconds()
				logf("[UDP] %s -> %s: SUCCESS (%dms, from %s)", ps.myNodeID, peer.NodeID, result.LatencyMs, reply.remoteAddr)
				return result
			}
		case <-waitTimer.C:
		}
	}

	result.Success = false
	result.Error = "no response after 6 punch attempts"
	logf("[UDP] %s -> %s: FAIL (no response from %s)", ps.myNodeID, peer.NodeID, targetAddr)
	return result
}

func (ps *ProbeSocket) TestAWGHandshake(ctx context.Context, peer *PeerInfo, plainMode bool) *AWGHandshakeResult {
	result := &AWGHandshakeResult{Attempts: 3}

	targetAddr := peer.STUNAddr
	if targetAddr == "" {
		result.Error = "no target STUN address"
		return result
	}

	rAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	logf("[AWG-HS] %s -> %s: Testing AWG Handshake (plain=%v, H1=%d, Jc=%d)",
		ps.myNodeID, peer.NodeID, plainMode, ps.cfg.AWG.H1, ps.cfg.AWG.Jc)

	start := time.Now()

	for attempt := 0; attempt < 3; attempt++ {
		if !plainMode && ps.cfg.AWG.Jc > 0 {
			jMin := ps.cfg.AWG.Jmin
			jMax := ps.cfg.AWG.Jmax
			if jMin <= 0 {
				jMin = 36
			}
			if jMax <= jMin {
				jMax = jMin + 40
			}
			for j := 0; j < ps.cfg.AWG.Jc; j++ {
				jLen := jMin + (j*7)%(jMax-jMin+1)
				junkBuf := make([]byte, jLen)
				_, _ = rand.Read(junkBuf)
				_, _ = ps.conn.WriteToUDP(junkBuf, rAddr)
			}
		}

		packetLen := 148
		if !plainMode {
			packetLen += ps.cfg.AWG.S1
		}
		initPacket := make([]byte, packetLen)

		if plainMode {
			initPacket[0] = 0x01
		} else {
			binary.LittleEndian.PutUint32(initPacket[:4], ps.cfg.AWG.H1)
		}

		marker := fmt.Sprintf("AWGPROBE:%s>%s", ps.myNodeID, peer.NodeID)
		copy(initPacket[4:], []byte(marker))
		if len(initPacket) > 4+len(marker) {
			_, _ = rand.Read(initPacket[4+len(marker):])
		}

		_, _ = ps.conn.WriteToUDP(initPacket, rAddr)

		waitTimer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			waitTimer.Stop()
			result.Error = ctx.Err().Error()
			return result
		case reply := <-ps.awgReplies:
			waitTimer.Stop()
			result.Success = true
			result.TimeMs = time.Since(start).Milliseconds()
			logf("[AWG-HS] %s -> %s: SUCCESS (%dms, received H2 response from %s)",
				ps.myNodeID, peer.NodeID, result.TimeMs, reply.remoteAddr)
			return result
		case <-waitTimer.C:
		}
	}

	result.Success = false
	result.Error = "no H2 response received"
	logf("[AWG-HS] %s -> %s: FAIL (no response to Initiation)", ps.myNodeID, peer.NodeID)
	return result
}

func (ps *ProbeSocket) TestDPIProbe(ctx context.Context, peer *PeerInfo) *DPIProbeResult {
	result := &DPIProbeResult{}
	logf("[DPI] %s -> %s: Testing DPI evasion (Plain WG vs AWG)", ps.myNodeID, peer.NodeID)

	// Test 1: Plain WG (type 0x01)
	plainRes := ps.TestAWGHandshake(ctx, peer, true)
	result.PlainWGSuccess = plainRes.Success

	// Test 2: AWG with configured H1/H2 and Jc
	awgRes := ps.TestAWGHandshake(ctx, peer, false)
	result.AWGSuccess = awgRes.Success

	if !result.PlainWGSuccess && !result.AWGSuccess {
		result.BlockedByDPI = true
		result.Notes = "WireGuard handshake blocked completely by DPI/TSPU."
	} else if !result.PlainWGSuccess && result.AWGSuccess {
		result.Notes = "Plain WG blocked by DPI, but AWG obfuscation bypassed it successfully!"
	} else if result.PlainWGSuccess && !result.AWGSuccess {
		result.Notes = "Plain WG passed, but AWG parameters failed."
	} else {
		result.Notes = "Both plain WG and AWG passed."
	}
	return result
}
