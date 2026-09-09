// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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

// PeerPunchState хранит текущий статус активного пробива пира в реальном времени
type PeerPunchState struct {
	mu           sync.RWMutex
	Peer         *PeerInfo
	TargetAddr   *net.UDPAddr
	PunchSent    int
	PunchSuccess bool
	PunchRTT     int64
	PunchRemote  string
	AWGSent      int
	AWGSuccess   bool
	AWGRTT       int64
	LastSent     time.Time
}

// ProbeSocket инкапсулирует единый UDP-сокет, используемый одновременно для:
// 1. STUN-запросов (определение реального внешнего сопоставленного порта роутера).
// 2. Непрерывного параллельного фонового пробива NAT (Continuous Mesh Hole Punching).
// 3. Автоматического ответа на входящие пробы и AWG-пакеты.
// 4. Тестирования обфускации AmneziaWG и DPI.
type ProbeSocket struct {
	conn       *net.UDPConn
	localPort  int
	mappedIP   net.IP
	mappedPort int
	myNodeID   string
	cfg        *ProbeConfig

	mu         sync.Mutex
	peerStates sync.Map // string (NodeID) -> *PeerPunchState

	stunEvents chan stunResultEvent
	udpReplies chan udpReplyEvent
	awgReplies chan awgReplyEvent

	ctx        context.Context
	cancel     context.CancelFunc
	punchOnce  sync.Once
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

	DisableUDPConnReset(conn)

	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(4 * 1024 * 1024)

	ctx, cancel := context.WithCancel(context.Background())

	ps := &ProbeSocket{
		conn:       conn,
		localPort:  localPort,
		myNodeID:   myNodeID,
		cfg:        cfg,
		stunEvents: make(chan stunResultEvent, 128),
		udpReplies: make(chan udpReplyEvent, 128),
		awgReplies: make(chan awgReplyEvent, 128),
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

// TrackPeer добавляет обнаруженного пира в активный фоновый цикл пробива
func (ps *ProbeSocket) TrackPeer(peer *PeerInfo) {
	if peer == nil || peer.NodeID == "" || peer.NodeID == ps.myNodeID {
		return
	}

	rAddr, err := net.ResolveUDPAddr("udp4", peer.STUNAddr)
	if err != nil {
		return
	}

	val, loaded := ps.peerStates.LoadOrStore(peer.NodeID, &PeerPunchState{
		Peer:       peer,
		TargetAddr: rAddr,
	})

	if loaded {
		state := val.(*PeerPunchState)
		state.mu.Lock()
		state.Peer = peer
		state.TargetAddr = rAddr
		state.mu.Unlock()
	} else {
		logf("[PUNCH-TRACK] Started continuous P2P punching worker to %s (%s)", peer.NodeID, peer.STUNAddr)
	}

	ps.punchOnce.Do(func() {
		go ps.continuousPunchLoop()
	})
}

// continuousPunchLoop непрерывно отсылает пробы ко всем обнаруженным узлам параллельно
func (ps *ProbeSocket) continuousPunchLoop() {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ps.ctx.Done():
			return
		case <-ticker.C:
			ps.peerStates.Range(func(key, value interface{}) bool {
				state := value.(*PeerPunchState)
				ps.sendPunchStep(state)
				return true
			})
		}
	}
}

func (ps *ProbeSocket) sendPunchStep(state *PeerPunchState) {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.TargetAddr == nil {
		return
	}

	now := time.Now()
	state.LastSent = now

	// 1. Если пробив UDP ещё не подтверждён, шлём NATPROBE
	if !state.PunchSuccess || state.PunchSent < 20 {
		probePayload := []byte(fmt.Sprintf("NATPROBE:%s>%s", ps.myNodeID, state.Peer.NodeID))
		// Основной целевой порт
		_, _ = ps.conn.WriteToUDP(probePayload, state.TargetAddr)
		state.PunchSent++

		// ВСЕГДА опрашиваем последовательных соседей (±1, ±2, ±3, ±4, ±8) вокруг basePort!
		// Это критично для роутеров Белтелеком / Ростелеком, которые смещают порт при открытии новой сессии.
		neighborSteps := []int{1, -1, 2, -2, 3, -3, 4, -4, 8, -8}
		for _, offset := range neighborSteps {
			cPort := state.TargetAddr.Port + offset
			if cPort > 1024 && cPort < 65535 {
				_, _ = ps.conn.WriteToUDP(probePayload, &net.UDPAddr{IP: state.TargetAddr.IP, Port: cPort})
			}
		}

		// Если известен delta — дополнительный веерный опрос
		delta := state.Peer.NATDelta
		if delta > 0 {
			for step := 1; step <= 6; step++ {
				pHigh := state.TargetAddr.Port + step*delta
				pLow := state.TargetAddr.Port - step*delta
				if pHigh > 1024 && pHigh < 65535 {
					_, _ = ps.conn.WriteToUDP(probePayload, &net.UDPAddr{IP: state.TargetAddr.IP, Port: pHigh})
				}
				if pLow > 1024 && pLow < 65535 {
					_, _ = ps.conn.WriteToUDP(probePayload, &net.UDPAddr{IP: state.TargetAddr.IP, Port: pLow})
				}
			}
		}
	}

	// 2. Если UDP подтверждён, но AWG ещё нет — шлём AWG Handshake Initiation
	if state.PunchSuccess && !state.AWGSuccess && state.AWGSent < 15 {
		// Junk packets
		if ps.cfg.AWG.Jc > 0 {
			jMin := ps.cfg.AWG.Jmin
			if jMin <= 0 {
				jMin = 36
			}
			jMax := ps.cfg.AWG.Jmax
			if jMax <= jMin {
				jMax = jMin + 40
			}
			for j := 0; j < ps.cfg.AWG.Jc; j++ {
				jLen := jMin + (j*7)%(jMax-jMin+1)
				junk := make([]byte, jLen)
				if _, err := io.ReadFull(rand.Reader, junk); err != nil {
					panic(fmt.Sprintf("probe: csprng failure: %v", err))
				}
				_, _ = ps.conn.WriteToUDP(junk, state.TargetAddr)
			}
		}

		// AWG Initiation packet
		packetLen := 148 + ps.cfg.AWG.S1
		initPacket := make([]byte, packetLen)
		binary.LittleEndian.PutUint32(initPacket[:4], ps.cfg.AWG.H1)
		marker := fmt.Sprintf("AWGPROBE:%s>%s", ps.myNodeID, state.Peer.NodeID)
		copy(initPacket[4:], []byte(marker))
		if len(initPacket) > 4+len(marker) {
			if _, err := io.ReadFull(rand.Reader, initPacket[4+len(marker):]); err != nil {
				panic(fmt.Sprintf("probe: csprng failure: %v", err))
			}
		}

		_, _ = ps.conn.WriteToUDP(initPacket, state.TargetAddr)
		state.AWGSent++
	}
}

// AllPeersSuccess возвращает true, если для всех пиров подтверждён пробив и AWG
func (ps *ProbeSocket) AllPeersSuccess(peers []*PeerInfo) bool {
	if len(peers) == 0 {
		return false
	}
	for _, p := range peers {
		val, ok := ps.peerStates.Load(p.NodeID)
		if !ok {
			return false
		}
		st := val.(*PeerPunchState)
		st.mu.RLock()
		okPunch := st.PunchSuccess
		okAWG := st.AWGSuccess
		st.mu.RUnlock()
		if !okPunch || !okAWG {
			return false
		}
	}
	return true
}

func (ps *ProbeSocket) GetUDPPunchResult(peer *PeerInfo) *UDPPunchResult {
	res := &UDPPunchResult{}
	val, ok := ps.peerStates.Load(peer.NodeID)
	if !ok {
		res.Error = "peer was not probed"
		return res
	}
	st := val.(*PeerPunchState)
	st.mu.RLock()
	defer st.mu.RUnlock()

	res.Success = st.PunchSuccess
	res.Bidirectional = st.PunchSuccess
	res.LatencyMs = st.PunchRTT
	if !st.PunchSuccess {
		res.Error = fmt.Sprintf("no UDP response after %d continuous probes to %s", st.PunchSent, peer.STUNAddr)
	}
	return res
}

func (ps *ProbeSocket) GetAWGHandshakeResult(peer *PeerInfo) *AWGHandshakeResult {
	res := &AWGHandshakeResult{Attempts: 3}
	val, ok := ps.peerStates.Load(peer.NodeID)
	if !ok {
		res.Error = "peer was not probed"
		return res
	}
	st := val.(*PeerPunchState)
	st.mu.RLock()
	defer st.mu.RUnlock()

	res.Success = st.AWGSuccess
	res.TimeMs = st.AWGRTT
	res.Attempts = st.AWGSent
	if !st.AWGSuccess {
		if !st.PunchSuccess {
			res.Error = "UDP hole punch failed, AWG handshake unreachable"
		} else {
			res.Error = fmt.Sprintf("no AWG H2 response after %d attempts", st.AWGSent)
		}
	}
	return res
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
		if strings.Contains(payloadStr, "NATPROBE:") {
			idx := strings.Index(payloadStr, "NATPROBE:")
			body := payloadStr[idx+len("NATPROBE:"):]
			parts := strings.Split(body, ">")
			fromID := parts[0]

			reply := []byte("NATREPLY:" + ps.myNodeID)
			_, _ = ps.conn.WriteToUDP(reply, remoteAddr)
			logf("[UDP-SRV] Received NATPROBE from %s (%s) -> sent NATREPLY", remoteAddr, fromID)

			if val, ok := ps.peerStates.Load(fromID); ok {
				st := val.(*PeerPunchState)
				st.mu.Lock()
				st.PunchRemote = remoteAddr.String()
				st.TargetAddr = remoteAddr // обновляем точный сопоставленный адрес!
				st.mu.Unlock()
			}
			continue
		}

		if strings.Contains(payloadStr, "NATREPLY:") {
			idx := strings.Index(payloadStr, "NATREPLY:")
			fromID := strings.TrimSpace(payloadStr[idx+len("NATREPLY:"):])
			if len(fromID) > 32 {
				fromID = fromID[:32]
			}

			if val, ok := ps.peerStates.Load(fromID); ok {
				st := val.(*PeerPunchState)
				st.mu.Lock()
				if !st.PunchSuccess {
					st.PunchSuccess = true
					st.PunchRTT = time.Since(st.LastSent).Milliseconds()
					st.PunchRemote = remoteAddr.String()
					st.TargetAddr = remoteAddr // фиксируем рабочий адрес
					logf("[PUNCH-OK] %s <-> %s: Direct UDP hole punched! RTT=%dms (remote: %s)",
						ps.myNodeID, fromID, st.PunchRTT, remoteAddr)
				}
				st.mu.Unlock()
			}

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
				if _, err := io.ReadFull(rand.Reader, reply[20:]); err != nil {
					panic(fmt.Sprintf("probe: csprng failure: %v", err))
				}
			}
			_, _ = ps.conn.WriteToUDP(reply, remoteAddr)
			logf("[AWG-SRV] Received AWG Handshake Initiation from %s (%s) -> sent H2 response", remoteAddr, fromID)
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

			if val, ok := ps.peerStates.Load(fromID); ok {
				st := val.(*PeerPunchState)
				st.mu.Lock()
				if !st.AWGSuccess {
					st.AWGSuccess = true
					st.AWGRTT = time.Since(st.LastSent).Milliseconds()
					logf("[AWG-OK] %s <-> %s: AWG Handshake confirmed! RTT=%dms (remote: %s)",
						ps.myNodeID, fromID, st.AWGRTT, remoteAddr)
				}
				st.mu.Unlock()
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

func (ps *ProbeSocket) TestDPIProbe(ctx context.Context, peer *PeerInfo) *DPIProbeResult {
	result := &DPIProbeResult{}
	logf("[DPI] %s -> %s: Testing DPI evasion (Plain WG vs AWG)", ps.myNodeID, peer.NodeID)

	targetAddr := peer.STUNAddr
	if targetAddr == "" {
		result.Notes = "no STUN address"
		return result
	}
	rAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		result.Notes = err.Error()
		return result
	}

	// 1. Test Plain WG (0x01)
	plainInit := make([]byte, 148)
	plainInit[0] = 0x01
	copy(plainInit[4:], []byte("AWGPROBE:"+ps.myNodeID+">"+peer.NodeID))
	_, _ = ps.conn.WriteToUDP(plainInit, rAddr)

	timer := time.NewTimer(1 * time.Second)
	select {
	case <-ctx.Done():
		timer.Stop()
	case <-timer.C:
		result.PlainWGSuccess = false
	case <-ps.awgReplies:
		timer.Stop()
		result.PlainWGSuccess = true
	}

	// 2. Check AWG result
	if val, ok := ps.peerStates.Load(peer.NodeID); ok {
		st := val.(*PeerPunchState)
		st.mu.RLock()
		result.AWGSuccess = st.AWGSuccess
		st.mu.RUnlock()
	}

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
