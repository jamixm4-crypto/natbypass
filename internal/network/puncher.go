package network

import (
	"crypto/rand"
	"encoding/binary"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/pion/stun/v2"
)

// IPRateLimiter implements a per-IP Token Bucket rate limiter to protect against PING/PONG flood attacks.
type IPRateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*tokenBucket
	capacity    float64
	refillRate  float64
	lastCleanup time.Time
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

func NewIPRateLimiter(capacity, refillRate float64) *IPRateLimiter {
	return &IPRateLimiter{
		buckets:     make(map[string]*tokenBucket),
		capacity:    capacity,
		refillRate:  refillRate,
		lastCleanup: time.Now(),
	}
}

func (rl *IPRateLimiter) Allow(ip string) bool {
	if ip == "" {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.lastCleanup) > 60*time.Second {
		for k, b := range rl.buckets {
			if now.Sub(b.lastRefill) > 60*time.Second {
				delete(rl.buckets, k)
			}
		}
		rl.lastCleanup = now
	}

	b, exists := rl.buckets[ip]
	if !exists {
		rl.buckets[ip] = &tokenBucket{
			tokens:     rl.capacity - 1,
			lastRefill: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * rl.refillRate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.lastRefill = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

type DirectPingCallback func(deviceID string, rtt time.Duration, fromAddr string)
type DirectDataCallback func(srcAddr *net.UDPAddr, payload []byte)
type DirectMTUCallback func(deviceID string, mtu int, fromAddr string)

type AWGPacketHandler interface {
	HandlePacket(payload []byte, remoteAddr *net.UDPAddr)
}

type UDPPuncher struct {
	awgVersion     string
	awgHandler     AWGPacketHandler
	trafficShaper   *TrafficShaper
	conn         *net.UDPConn
	localPort    int
	mappedIP     net.IP
	mappedPort   int
	myDevID      string
	stunServers  []string
	onPingResult DirectPingCallback
	onDataPacket DirectDataCallback
	onMTUResult  DirectMTUCallback
	mappedEndpoints map[string]struct{}
	stunRespCh   chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	connID       uint64

	// NATType is detected asynchronously after construction.
	NATType   NATType
	natTypeMu sync.RWMutex

	// portDelta tracks the observed consecutive port increment for Symmetric NAT prediction.
	lastMappedPort int
	portDelta      int

	// stunMappedPortSamples and cgnatProfile track multi-STUN triangulation & PBA blocks
	stunMappedPortSamples []int
	cgnatProfile          CGNATProfile

	probeMu          sync.Mutex
	lastProbeMap     map[string]time.Time
	lastCleanupTime  time.Time
	pingRateLimiter  *IPRateLimiter

	keepAliveTargets map[string]time.Time
	keepAliveMu      sync.Mutex
	addrCache        sync.Map
	lastReversePing  sync.Map

	cipherKey    [32]byte
	hasCipherKey bool
	cipherMu     sync.RWMutex
}

// SetCipherKey конфигурирует ключ симметричного шифрования (ChaCha20-Poly1305) для L3 Data-plane пакетов.
func (p *UDPPuncher) SetCipherKey(key string) {
	p.cipherMu.Lock()
	defer p.cipherMu.Unlock()
	p.addrCache.Range(func(k, v any) bool { p.addrCache.Delete(k); return true })
	if key == "" {
		p.hasCipherKey = false
		p.cipherKey = [32]byte{}
		return
	}
	p.cipherKey = crypto.DeriveKey(key)
	p.hasCipherKey = true
}

// resolveAddr resolves a UDP address string with caching to avoid per-packet overhead.
// Tries IPv4 "udp4" first to avoid IPv6 AAAA DNS resolution delays on Linux, falls back to "udp".
func (p *UDPPuncher) resolveAddr(targetAddr string) (*net.UDPAddr, error) {
	if cached, ok := p.addrCache.Load(targetAddr); ok {
		return cached.(*net.UDPAddr), nil
	}
	rAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		rAddr, err = net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			return nil, err
		}
	}
	p.addrCache.Store(targetAddr, rAddr)
	return rAddr, nil
}


// NewUDPPuncher creates a new persistent UDP socket for STUN, hole punching, and data transfer.
func NewUDPPuncher(preferredPort int, myDevID string, stunServers []string, onPing DirectPingCallback) (*UDPPuncher, error) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	var conn *net.UDPConn
	var err error
	var lAddr *net.UDPAddr

	// Bind IPv4 socket (udp4) first for maximum compatibility with Linux/router NAT stacks
	if preferredPort > 0 {
		lAddr, _ = net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", preferredPort))
		conn, err = net.ListenUDP("udp4", lAddr)
		if err != nil {
			lAddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", preferredPort))
			conn, err = net.ListenUDP("udp", lAddr)
		}
	}

	if err != nil || conn == nil {
		lAddr4, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		conn, err = net.ListenUDP("udp4", lAddr4)
		if err != nil {
			lAddr, _ = net.ResolveUDPAddr("udp", ":0")
			conn, err = net.ListenUDP("udp", lAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to bind UDP socket: %w", err)
			}
		}
	}

	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())

	p := &UDPPuncher{
		conn:            conn,
		localPort:       localPort,
		myDevID:         myDevID,
		stunServers:     stunServers,
		onPingResult:    onPing,
		mappedEndpoints: make(map[string]struct{}),
		stunRespCh:      make(chan struct{}, 8),
		ctx:             ctx,
		cancel:          cancel,
		NATType:         NATTypeUnknown,
		lastProbeMap:    make(map[string]time.Time),
		lastCleanupTime: time.Now(),
		pingRateLimiter:  NewIPRateLimiter(60.0, 15.0),
	}

	// Start packet processing loop
	go p.readLoop()

	// Detect NAT type in background with retry up to 3 times
	go func() {
		for attempt := 1; attempt <= 3; attempt++ {
			dCtx, dCancel := context.WithTimeout(ctx, 6*time.Second)
			natType, err := DetectNATType(dCtx, conn, stunServers)
			dCancel()

			p.natTypeMu.Lock()
			if err == nil && natType != NATTypeUnknown {
				p.NATType = natType
				p.natTypeMu.Unlock()
				return
			}
			p.natTypeMu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()

	// Try UPnP automatic port mapping on gateway router in background
	go func() {
		upnpClient := NewUPnPClient()
		_ = upnpClient.AddPortMapping(ctx, localPort, localPort, "UDP", "NatBypass P2P", 3600)
	}()

	return p, nil
}


// LocalPort returns the local bound UDP port.
func (p *UDPPuncher) LocalPort() int {
	return p.localPort
}

// GetNATType returns the detected NAT type (may be Unknown if detection is still running).
func (p *UDPPuncher) GetNATType() NATType {
	p.natTypeMu.RLock()
	defer p.natTypeMu.RUnlock()
	return p.NATType
}

// DiscoverCandidates harvests all possible ICE-like candidate endpoints for direct connectivity.
func (p *UDPPuncher) DiscoverCandidates(ctx context.Context, publicIP string) []string {
	candidateSet := make(map[string]struct{})
	localPort := p.LocalPort()

	// 1. Mapped STUN endpoints
	p.mu.Lock()
	if p.mappedIP != nil && p.mappedPort > 0 {
		candidateSet[fmt.Sprintf("%s:%d", p.mappedIP.String(), p.mappedPort)] = struct{}{}
	}
	p.mu.Unlock()

	// Query first 3 STUN servers to harvest possible multi-NAT mapped endpoints
	// and detect Symmetric NAT on the active socket!
	serversToQuery := p.stunServers
	if len(serversToQuery) > 3 {
		serversToQuery = serversToQuery[:3]
	}
	var observedMappedPorts []int
	for _, srv := range serversToQuery {
		srvAddr, err := net.ResolveUDPAddr("udp4", srv)
		if err != nil {
			srvAddr, err = net.ResolveUDPAddr("udp", srv)
			if err != nil {
				continue
			}
		}
		msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		if _, err := p.conn.WriteToUDP(msg.Raw, srvAddr); err == nil {
			select {
			case <-p.stunRespCh:
				p.mu.Lock()
				if p.mappedIP != nil && p.mappedPort > 0 {
					candidateSet[fmt.Sprintf("%s:%d", p.mappedIP.String(), p.mappedPort)] = struct{}{}
					observedMappedPorts = append(observedMappedPorts, p.mappedPort)
				}
				p.mu.Unlock()
			case <-time.After(350 * time.Millisecond):
			case <-ctx.Done():
				break
			}
		}
	}

	// Точный детект Symmetric NAT на боевом сокете:
	// Если разные STUN-серверы вернули разные внешние порты для одного и того же сокета p.conn,
	// это 100% подтвержденный Symmetric NAT (провайдерский CGNAT).
	if len(observedMappedPorts) >= 2 {
		firstPort := observedMappedPorts[0]
		isSymmetric := false
		for _, port := range observedMappedPorts[1:] {
			if port != firstPort {
				isSymmetric = true
				break
			}
		}
		p.natTypeMu.Lock()
		p.stunMappedPortSamples = make([]int, len(observedMappedPorts))
		copy(p.stunMappedPortSamples, observedMappedPorts)
		p.cgnatProfile = FingerprintCGNAT(observedMappedPorts)
		if isSymmetric {
			p.NATType = NATTypeSymmetric
		} else if p.NATType == NATTypeUnknown {
			p.NATType = NATTypeFullCone
		}
		p.natTypeMu.Unlock()
	}

	// 2. Public IP + localPort (only if mappedPort matches localPort or mappedPort is not yet discovered)
	p.mu.Lock()
	curMappedPort := p.mappedPort
	p.mu.Unlock()
	if publicIP != "" && publicIP != "0.0.0.0" && publicIP != "<nil>" {
		if curMappedPort == 0 || curMappedPort == localPort {
			candidateSet[fmt.Sprintf("%s:%d", publicIP, localPort)] = struct{}{}
		}
	}

	// 3. Основной физический LAN-адрес шлюза по умолчанию (Default Gateway)
	// Добавляем ТОЛЬКО реальный локальный IP адаптера, выходящего в интернет,
	// исключая виртуальные адаптеры Hyper-V, WSL, VMware, VirtualBox.
	if primaryLAN := GetLocalLANIP(); primaryLAN != "" {
		candidateSet[fmt.Sprintf("%s:%d", primaryLAN, localPort)] = struct{}{}
	}

	var res []string
	for c := range candidateSet {
		res = append(res, c)
	}
	return res
}


// DiscoverMappedAddress sends a STUN Binding Request from the persistent socket.
func (p *UDPPuncher) DiscoverMappedAddress(ctx context.Context) (net.IP, int, error) {
	// 1. Быстрая проверка: возможно, адрес уже обнаружен
	p.mu.Lock()
	if p.mappedIP != nil && p.mappedPort > 0 {
		ip, port := p.mappedIP, p.mappedPort
		p.mu.Unlock()
		return ip, port, nil
	}
	conn := p.conn
	servers := make([]string, len(p.stunServers))
	copy(servers, p.stunServers)
	p.mu.Unlock()

	if conn == nil {
		return nil, 0, fmt.Errorf("UDP socket closed")
	}

	if len(servers) > 6 {
		servers = servers[:6]
	}

	// 2. Отправляем Binding Request параллельно на все топ STUN сервера
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	for _, srv := range servers {
		if rAddr, err := p.resolveAddr(srv); err == nil && rAddr != nil {
			_, _ = conn.WriteToUDP(msg.Raw, rAddr)
		}
	}

	// 3. Ждём ответа из stunRespCh с таймаутом до 1200 мс
	select {
	case <-p.stunRespCh:
		p.mu.Lock()
		ip, port := p.mappedIP, p.mappedPort
		p.mu.Unlock()
		if ip != nil && port > 0 {
			return ip, port, nil
		}
	case <-time.After(1200 * time.Millisecond):
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}

	p.mu.Lock()
	ip, port := p.mappedIP, p.mappedPort
	p.mu.Unlock()
	if ip != nil && port > 0 {
		return ip, port, nil
	}
	return nil, 0, fmt.Errorf("STUN discovery timeout")
}

// InvalidateMappedAddress clears cached STUN mapping (e.g. after network roaming).
func (p *UDPPuncher) InvalidateMappedAddress() {
	p.mu.Lock()
	p.mappedIP = nil
	p.mappedPort = 0
	p.mu.Unlock()
}

// ForceDiscoverMappedAddress bypasses cache and performs a fresh STUN query.
func (p *UDPPuncher) ForceDiscoverMappedAddress(ctx context.Context) (net.IP, int, error) {
	p.InvalidateMappedAddress()
	return p.DiscoverMappedAddress(ctx)
}

// GetSocketFd returns the raw OS file descriptor of the UDP socket (used for Android VpnService.protect).
func (p *UDPPuncher) GetSocketFd() int {
	p.mu.Lock()
	conn := p.conn
	p.mu.Unlock()
	if conn == nil {
		return -1
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return -1
	}
	sockFd := -1
	_ = rawConn.Control(func(fd uintptr) {
		sockFd = int(fd)
	})
	return sockFd
}

// ResetSocket re-binds the UDP socket to a new socket, useful for network roaming (Wi-Fi <-> Cellular).
// It returns the new raw socket file descriptor so it can be protected by VpnService.protect().
func (p *UDPPuncher) ResetSocket() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.mappedIP = nil
	p.mappedPort = 0
	p.lastProbeMap = make(map[string]time.Time)
	p.mappedEndpoints = make(map[string]struct{})

	preferredPort := p.localPort
	var newConn *net.UDPConn
	var err error

	if preferredPort > 0 {
		lAddr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", preferredPort))
		newConn, err = net.ListenUDP("udp4", lAddr)
		if err != nil {
			lAddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", preferredPort))
			newConn, err = net.ListenUDP("udp", lAddr)
		}
	}
	if err != nil || newConn == nil {
		lAddr4, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		newConn, err = net.ListenUDP("udp4", lAddr4)
		if err != nil {
			lAddrGen, _ := net.ResolveUDPAddr("udp", ":0")
			newConn, err = net.ListenUDP("udp", lAddrGen)
			if err != nil {
				return -1, fmt.Errorf("failed to re-bind UDP socket: %w", err)
			}
		}
	}

	oldConn := p.conn
	p.conn = newConn
	p.localPort = newConn.LocalAddr().(*net.UDPAddr).Port
	p.connID++

	if oldConn != nil {
		_ = oldConn.Close()
	}

	// Start reading on the new socket
	go p.readLoop()

	rawConn, err := newConn.SyscallConn()
	if err != nil {
		return -1, nil
	}
	sockFd := -1
	_ = rawConn.Control(func(fd uintptr) {
		sockFd = int(fd)
	})
	return sockFd, nil
}

// CGNATProfile describes port allocation behavior of the Carrier-Grade NAT (RFC 4787 / RFC 6888).
type CGNATProfile struct {
	IsSequential    bool
	ParityPreserved bool
	Parity          int // 0 (even) or 1 (odd)
	BlockSize       int // 0 if not blocked, else 64, 128, 256, 512
	BlockBase       int
	Delta           int
}

// FingerprintCGNAT analyzes consecutive port samples from different STUN servers.
func FingerprintCGNAT(samples []int) CGNATProfile {
	prof := CGNATProfile{Delta: 1}
	if len(samples) < 2 {
		return prof
	}

	p1 := samples[0]
	p2 := samples[1]

	if len(samples) >= 3 {
		p3 := samples[2]
		// 1. Parity preservation (RFC 4787 Section 4.2.2)
		if (p1%2 == p2%2) && (p2%2 == p3%2) {
			prof.ParityPreserved = true
			prof.Parity = p1 % 2
			prof.Delta = 2
		}

		// 2. Port Block Allocation detection (RFC 6888 Section 5)
		blockSizes := []int{64, 128, 256, 512}
		for _, size := range blockSizes {
			mask := ^(size - 1)
			if (p1&mask) == (p2&mask) && (p2&mask) == (p3&mask) {
				prof.BlockSize = size
				prof.BlockBase = p1 & mask
				break
			}
		}

		// 3. Linear sequence analysis
		d1 := p2 - p1
		d2 := p3 - p2
		if d1 > 0 && d1 == d2 {
			prof.IsSequential = true
			prof.Delta = d1
		}
	} else {
		if p1%2 == p2%2 {
			prof.ParityPreserved = true
			prof.Parity = p1 % 2
			prof.Delta = 2
		}
		d := p2 - p1
		if d > 0 && d < 512 {
			prof.Delta = d
		}
	}

	return prof
}

// candidatePorts calculates predicted port numbers for Symmetric NAT traversal using CGNAT profile.
func (p *UDPPuncher) candidatePorts(base int) []int {
	p.natTypeMu.RLock()
	prof := p.cgnatProfile
	samples := make([]int, len(p.stunMappedPortSamples))
	copy(samples, p.stunMappedPortSamples)
	d := p.portDelta
	p.natTypeMu.RUnlock()

	if len(samples) >= 2 && (prof.BlockSize == 0 && !prof.ParityPreserved && !prof.IsSequential) {
		prof = FingerprintCGNAT(samples)
	}

	return p.CandidatePortsAdvanced(base, samples, prof, d)
}

// CandidatePortsAdvanced calculates predicted port numbers with full support for PBA blocks and parity.
func (p *UDPPuncher) CandidatePortsAdvanced(base int, samples []int, prof CGNATProfile, fallbackDelta int) []int {
	seen := make(map[int]bool)
	var ports []int

	add := func(pt int) {
		if pt > 1024 && pt < 65535 && !seen[pt] {
			seen[pt] = true
			ports = append(ports, pt)
		}
	}

	add(base)

	// Strategy A: Port Block Allocation (PBA) spray inside operator's assigned block
	if prof.BlockSize > 0 {
		for port := prof.BlockBase; port < prof.BlockBase+prof.BlockSize; port++ {
			if prof.ParityPreserved && (port%2 != prof.Parity) {
				continue
			}
			add(port)
		}
		if len(ports) > 1 {
			return ports
		}
	}

	// Strategy B: Parity-aware and delta-based prediction
	delta := prof.Delta
	if delta <= 0 {
		delta = fallbackDelta
	}
	if delta <= 0 {
		delta = 1
	}
	if prof.ParityPreserved && delta%2 != 0 {
		delta *= 2
	}

	// 1. Delta series prediction (+/- 1*delta .. 16*delta)
	for i := 1; i <= 16; i++ {
		add(base + i*delta)
		add(base - i*delta)
	}

	// 2. Sequential neighbor spray
	step := 1
	if prof.ParityPreserved {
		step = 2
	}
	for i := 1; i <= 8; i++ {
		add(base + i*step)
		add(base - i*step)
	}

	return ports
}

const (
	QUICVersion1   = uint32(0x00000001)
	QUICHeaderLong = byte(0xC0) // Header Form=1, Fixed Bit=1, Type=0 (Initial)
)

func putQUICVarint(val int) []byte {
	if val < 64 {
		return []byte{byte(val)}
	}
	b0 := byte(0x40 | ((val >> 8) & 0x3f))
	b1 := byte(val & 0xff)
	return []byte{b0, b1}
}

func readQUICVarint(data []byte) (int, int, error) {
	if len(data) < 1 {
		return 0, 0, errors.New("short varint")
	}
	first := data[0]
	switch first >> 6 {
	case 0:
		return int(first & 0x3f), 1, nil
	case 1:
		if len(data) < 2 {
			return 0, 0, errors.New("short varint 2-byte")
		}
		val := (int(first&0x3f) << 8) | int(data[1])
		return val, 2, nil
	default:
		return int(first & 0x3f), 1, nil
	}
}

// BuildQUICChameleonProbe formats a hole punching probe as a valid QUIC v1 Initial Packet (RFC 9000).
func BuildQUICChameleonProbe(myDevID string, cKey [32]byte) ([]byte, error) {
	nowNano := time.Now().UnixNano()
	probeData := []byte(fmt.Sprintf("%s%s:%d", constants.PingPrefix, myDevID, nowNano))
	encPayload, err := crypto.EncryptSelf(probeData, cKey)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 256)
	buf = append(buf, QUICHeaderLong)

	// Version 1 (4 bytes)
	var verBuf [4]byte
	binary.BigEndian.PutUint32(verBuf[:], QUICVersion1)
	buf = append(buf, verBuf[:]...)

	// DCID: 8 random bytes
	dcid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	buf = append(buf, byte(len(dcid)))
	buf = append(buf, dcid...)

	// SCID: 8 random bytes
	scid := make([]byte, 8)
	_, _ = rand.Read(scid)
	buf = append(buf, byte(len(scid)))
	buf = append(buf, scid...)

	// Token: our encrypted payload
	buf = append(buf, putQUICVarint(len(encPayload))...)
	buf = append(buf, encPayload...)

	// Length varint + dummy packet payload
	buf = append(buf, putQUICVarint(16)...)
	buf = append(buf, 0x00, 0x01)
	pad := make([]byte, 14)
	_, _ = rand.Read(pad)
	buf = append(buf, pad...)

	return buf, nil
}

// BuildQUICPongChameleonProbe formats a PONG response as a valid QUIC v1 Initial Packet.
func BuildQUICPongChameleonProbe(myDevID, sentTs string, cKey [32]byte) ([]byte, error) {
	pongData := []byte(fmt.Sprintf("%s%s:%s", constants.PongPrefix, myDevID, sentTs))
	encPayload, err := crypto.EncryptSelf(pongData, cKey)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 256)
	buf = append(buf, QUICHeaderLong)

	var verBuf [4]byte
	binary.BigEndian.PutUint32(verBuf[:], QUICVersion1)
	buf = append(buf, verBuf[:]...)

	dcid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	buf = append(buf, byte(len(dcid)))
	buf = append(buf, dcid...)

	scid := make([]byte, 8)
	_, _ = rand.Read(scid)
	buf = append(buf, byte(len(scid)))
	buf = append(buf, scid...)

	buf = append(buf, putQUICVarint(len(encPayload))...)
	buf = append(buf, encPayload...)

	buf = append(buf, putQUICVarint(16)...)
	buf = append(buf, 0x00, 0x01)
	pad := make([]byte, 14)
	_, _ = rand.Read(pad)
	buf = append(buf, pad...)

	return buf, nil
}

// ParseQUICChameleonProbe parses a QUIC v1 Initial Packet probe and extracts decrypted payload.
func ParseQUICChameleonProbe(packet []byte, cKey [32]byte) ([]byte, error) {
	if len(packet) < 25 {
		return nil, errors.New("packet too short")
	}
	if packet[0]&0xC0 != 0xC0 {
		return nil, errors.New("not a long header")
	}
	if binary.BigEndian.Uint32(packet[1:5]) != QUICVersion1 {
		return nil, errors.New("not quic v1")
	}

	idx := 5
	if idx >= len(packet) {
		return nil, errors.New("truncated dcid len")
	}
	dcidLen := int(packet[idx])
	idx += 1 + dcidLen
	if idx >= len(packet) {
		return nil, errors.New("truncated dcid")
	}

	scidLen := int(packet[idx])
	idx += 1 + scidLen
	if idx >= len(packet) {
		return nil, errors.New("truncated scid")
	}

	tokenLen, vLen, err := readQUICVarint(packet[idx:])
	if err != nil {
		return nil, err
	}
	idx += vLen
	if idx+tokenLen > len(packet) {
		return nil, errors.New("truncated token")
	}

	encToken := packet[idx : idx+tokenLen]
	return crypto.DecryptSelf(encToken, cKey)
}

// ProbeFeedback represents feedback signals received during hole punching.
type ProbeFeedback int

const (
	FeedbackNone ProbeFeedback = iota
	FeedbackPortUnreachable // ICMP Type 3 Code 3 received
	FeedbackSuccess         // Echo response received
	FeedbackTimeout         // Silent drop
)

// AdaptiveProbeEngine manages reinforcement probing state with dynamic search tree.
type AdaptiveProbeEngine struct {
	basePort    int
	targetIP    string
	cKey        [32]byte
	hasCKey     bool
	feedbacks   chan ProbeFeedback
	activeDelta int
	mu          sync.Mutex
}

func NewAdaptiveProbeEngine(targetIP string, basePort int, cKey [32]byte, hasCKey bool) *AdaptiveProbeEngine {
	return &AdaptiveProbeEngine{
		basePort:    basePort,
		targetIP:    targetIP,
		cKey:        cKey,
		hasCKey:     hasCKey,
		feedbacks:   make(chan ProbeFeedback, 16),
		activeDelta: 1,
	}
}

func (e *AdaptiveProbeEngine) NotifyFeedback(fb ProbeFeedback) {
	select {
	case e.feedbacks <- fb:
	default:
	}
}

// ExecuteAdaptiveProbing runs multi-phase probing: rapid scout -> bracket zoom on ICMP -> block jump on drop.
func (p *UDPPuncher) ExecuteAdaptiveProbing(ctx context.Context, engine *AdaptiveProbeEngine) bool {
	if engine == nil || engine.targetIP == "" || engine.basePort <= 0 {
		return false
	}

	// Phase 1: Rapid 3-probe scout
	initialPorts := []int{engine.basePort, engine.basePort + 1, engine.basePort + 2}
	for _, port := range initialPorts {
		target := fmt.Sprintf("%s:%d", engine.targetIP, port)
		_ = p.SendHolePunchProbe(target)
	}

	// Wait 250ms for feedback or echo
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case fb := <-engine.feedbacks:
		if fb == FeedbackSuccess {
			return true
		}
		if fb == FeedbackPortUnreachable {
			// Port unreachable proves NAT mapping is open! Zoom immediately in basePort +/- 4
			return p.probePortRange(ctx, engine.targetIP, engine.basePort-4, engine.basePort+4, 1)
		}
	case <-timer.C:
		// Silent drop timeout: switch to Phase 3 (Block boundary jumping)
	}

	// Phase 3: Block boundary jumping (+/- 8, 16, 32, 64)
	blockJumps := []int{8, -8, 16, -16, 32, -32, 64, -64}
	for _, jump := range blockJumps {
		select {
		case <-ctx.Done():
			return false
		case fb := <-engine.feedbacks:
			if fb == FeedbackSuccess {
				return true
			}
		default:
		}
		target := fmt.Sprintf("%s:%d", engine.targetIP, engine.basePort+jump)
		_ = p.SendHolePunchProbe(target)
		time.Sleep(20 * time.Millisecond)
	}

	return false
}

func (p *UDPPuncher) probePortRange(ctx context.Context, ip string, start, end, step int) bool {
	for port := start; port <= end; port += step {
		if port <= 1024 || port >= 65535 {
			continue
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
		target := fmt.Sprintf("%s:%d", ip, port)
		_ = p.SendHolePunchProbe(target)
		time.Sleep(15 * time.Millisecond)
	}
	return true
}

// SendHolePunchProbe отправляет probe пакеты с маскировкой QUIC Initial (RFC 9000) для обхода ТСПУ/DPI
func (p *UDPPuncher) SendHolePunchProbe(targetAddr string) error {
	if targetAddr == "" || p.conn == nil {
		return nil
	}
	rAddr, err := p.resolveAddr(targetAddr)
	if err != nil {
		return err
	}

	nowNano := time.Now().UnixNano()
	probeData := []byte(fmt.Sprintf("%s%s:%d", constants.PingPrefix, p.myDevID, nowNano))

	p.cipherMu.RLock()
	cKey := p.cipherKey
	hasCKey := p.hasCipherKey
	p.cipherMu.RUnlock()

	var chameleonProbe []byte
	var stealthProbe []byte
	if hasCKey {
		if qProbe, err := BuildQUICChameleonProbe(p.myDevID, cKey); err == nil && len(qProbe) > 0 {
			chameleonProbe = qProbe
		} else if enc, err := crypto.EncryptSelf(probeData, cKey); err == nil && len(enc) > 0 {
			stealthProbe = enc
		}
	}

	// 1. Отправляем пробу: приоритет отдается QUIC Chameleon probe (неотличим от HTTP/3 трафика для ТСПУ)
	if len(chameleonProbe) > 0 {
		_, _ = p.conn.WriteToUDP(chameleonProbe, rAddr)
	} else if len(stealthProbe) > 0 {
		_, _ = p.conn.WriteToUDP(stealthProbe, rAddr)
	} else {
		_, _ = p.conn.WriteToUDP(probeData, rAddr)
	}

	// Targeted probing for Symmetric NAT using advanced CGNAT heuristics (Parity, PBA, Delta)
	if p.GetNATType().IsSymmetric() {
		targetIP := rAddr.IP
		candidates := p.candidatePorts(rAddr.Port)
		for _, port := range candidates {
			if port != rAddr.Port {
				cAddr := &net.UDPAddr{IP: targetIP, Port: port}
				if len(chameleonProbe) > 0 {
					_, _ = p.conn.WriteToUDP(chameleonProbe, cAddr)
				} else if len(stealthProbe) > 0 {
					_, _ = p.conn.WriteToUDP(stealthProbe, cAddr)
				} else {
					_, _ = p.conn.WriteToUDP(probeData, cAddr)
				}
			}
		}
	}

	return nil
}


// StartKeepAliveLoop запускает автоматическую отправку keepalive для активных пиров
func (p *UDPPuncher) StartKeepAliveLoop() {
	go func() {
		ticker := time.NewTicker(constants.KeepAliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				p.keepAliveMu.Lock()
				targets := make([]string, 0, len(p.keepAliveTargets))
				for addr := range p.keepAliveTargets {
					targets = append(targets, addr)
				}
				p.keepAliveMu.Unlock()

				for _, addr := range targets {
					_ = p.SendKeepAlive(addr)
				}
			}
		}
	}()
}

// AddKeepAliveTarget добавляет адрес для автоматической отправки keepalive
func (p *UDPPuncher) AddKeepAliveTarget(addr string) {
	if addr == "" {
		return
	}
	p.keepAliveMu.Lock()
	defer p.keepAliveMu.Unlock()
	if p.keepAliveTargets == nil {
		p.keepAliveTargets = make(map[string]time.Time)
	}
	p.keepAliveTargets[addr] = time.Now()
}

// RemoveKeepAliveTarget удаляет адрес из списка keepalive
func (p *UDPPuncher) RemoveKeepAliveTarget(addr string) {
	if addr == "" {
		return
	}
	p.keepAliveMu.Lock()
	defer p.keepAliveMu.Unlock()
	delete(p.keepAliveTargets, addr)
}

// SendKeepAlive sends a periodic active ping packet to maintain bidirectional CGNAT port mappings.
func (p *UDPPuncher) SendKeepAlive(targetAddr string) error {
	if targetAddr == "" || p.conn == nil {
		return nil
	}
	rAddr, err := p.resolveAddr(targetAddr)
	if err != nil {
		return err
	}
	nowNano := time.Now().UnixNano()
	probeData := []byte(fmt.Sprintf("%s%s:%d", constants.PingPrefix, p.myDevID, nowNano))

	p.cipherMu.RLock()
	cKey := p.cipherKey
	hasCKey := p.hasCipherKey
	p.cipherMu.RUnlock()

	if hasCKey {
		if enc, encErr := crypto.EncryptSelf(probeData, cKey); encErr == nil && len(enc) > 0 {
			_, _ = p.conn.WriteToUDP(enc, rAddr)
		}
	}

	_, err = p.conn.WriteToUDP(probeData, rAddr)
	return err
}

// SetDataCallback registers the callback handler for incoming tunnel data packets.
func (p *UDPPuncher) SetDataCallback(cb DirectDataCallback) {
	p.mu.Lock()
	p.onDataPacket = cb
	p.mu.Unlock()
}

// SendDataPacket sends a raw tunnel IP packet directly to the peer with optional Amnezia 3.x dynamic padding.
func (p *UDPPuncher) SendDataPacket(targetAddr string, payload []byte) error {
	return p.SendDataPacketWithPadding(targetAddr, payload, 0, 0)
}

// SendDataPacketWithPadding applies Amnezia 3.x random trailer padding (pmin-pmax bytes) to disguise packet length.
func (p *UDPPuncher) SendDataPacketWithPadding(targetAddr string, payload []byte, pmin, pmax int) error {
	if targetAddr == "" || p.conn == nil || len(payload) == 0 {
		return nil
	}
	rAddr, err := p.resolveAddr(targetAddr)
	if err != nil {
		return err
	}

	p.cipherMu.RLock()
	cKey := p.cipherKey
	hasCKey := p.hasCipherKey
	p.cipherMu.RUnlock()

	if hasCKey {
		payloadToEncrypt := payload
		if pmax > 0 && pmax >= pmin {
			padLen := pmin
			if diff := pmax - pmin; diff > 0 {
				var b [1]byte
				_, _ = rand.Read(b[:])
				padLen += int(b[0]) % (diff + 1)
			}
			if padLen > 0 {
				pLen := uint16(len(payload))
				padded := make([]byte, 2+len(payload)+padLen)
				binary.BigEndian.PutUint16(padded[:2], pLen)
				copy(padded[2:], payload)
				_, _ = rand.Read(padded[2+len(payload):])
				payloadToEncrypt = padded
			}
		}

		if enc, encErr := crypto.EncryptSelf(payloadToEncrypt, cKey); encErr == nil && len(enc) > 0 {
			p.mu.Lock()
			shaper := p.trafficShaper
			p.mu.Unlock()

			if shaper != nil && shaper.IsEnabled() {
				return shaper.SendPacket(p.conn, rAddr, enc)
			}

			_, err = p.conn.WriteToUDP(enc, rAddr)
			return err
		}
	}

	header := []byte(constants.TunHeader)
	fullPkt := make([]byte, len(header)+len(payload))
	copy(fullPkt, header)
	copy(fullPkt[len(header):], payload)

	p.mu.Lock()
	shaper := p.trafficShaper
	p.mu.Unlock()

	if shaper != nil && shaper.IsEnabled() {
		return shaper.SendPacket(p.conn, rAddr, fullPkt)
	}

	_, err = p.conn.WriteToUDP(fullPkt, rAddr)
	return err
}

// handleSTUNMessage decodes incoming STUN responses and extracts mapped public IP/port.
func (p *UDPPuncher) handleSTUNMessage(data []byte) {
	var stunResp stun.Message
	stunResp.Raw = make([]byte, len(data))
	copy(stunResp.Raw, data)
	if err := stunResp.Decode(); err != nil {
		return
	}

	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(&stunResp); err == nil {
		p.mu.Lock()
		p.mappedIP = xorAddr.IP
		p.mappedPort = xorAddr.Port
		p.mu.Unlock()
		select {
		case p.stunRespCh <- struct{}{}:
		default:
		}
		return
	}

	var mappedAddr stun.MappedAddress
	if err := mappedAddr.GetFrom(&stunResp); err == nil {
		p.mu.Lock()
		p.mappedIP = mappedAddr.IP
		p.mappedPort = mappedAddr.Port
		p.mu.Unlock()
		select {
		case p.stunRespCh <- struct{}{}:
		default:
		}
	}
}

// handlePing processes incoming NAT hole punch PING probes.
func (p *UDPPuncher) handlePing(data string, remoteAddr *net.UDPAddr) {
	parts := strings.Split(data, ":")
	if len(parts) < 4 {
		return
	}
	senderID := strings.Join(parts[2:len(parts)-1], ":")
	if senderID == p.myDevID {
		return
	}
	sentTs := parts[len(parts)-1]
	pongMsg := []byte(fmt.Sprintf("%s%s:%s", constants.PongPrefix, p.myDevID, sentTs))

	p.cipherMu.RLock()
	cKey := p.cipherKey
	hasCKey := p.hasCipherKey
	p.cipherMu.RUnlock()

	if hasCKey {
		if qPong, qErr := BuildQUICPongChameleonProbe(p.myDevID, sentTs, cKey); qErr == nil && len(qPong) > 0 {
			_, _ = p.conn.WriteToUDP(qPong, remoteAddr)
		} else if enc, encErr := crypto.EncryptSelf(pongMsg, cKey); encErr == nil && len(enc) > 0 {
			_, _ = p.conn.WriteToUDP(enc, remoteAddr)
		}
	} else {
		_, _ = p.conn.WriteToUDP(pongMsg, remoteAddr)
	}

	// Отправляем встречный PING (ограничен 1 разом в 2 секунды на пир) для взаимного сквозного пробития NAT сокет-в-сокет
	now := time.Now()
	if last, ok := p.lastReversePing.Load(senderID); !ok || now.Sub(last.(time.Time)) > 2*time.Second {
		p.lastReversePing.Store(senderID, now)
		reversePing := []byte(fmt.Sprintf("%s%s:%d", constants.PingPrefix, p.myDevID, now.UnixNano()))
		if hasCKey {
			if qPing, qErr := BuildQUICChameleonProbe(p.myDevID, cKey); qErr == nil && len(qPing) > 0 {
				_, _ = p.conn.WriteToUDP(qPing, remoteAddr)
			} else if enc, encErr := crypto.EncryptSelf(reversePing, cKey); encErr == nil && len(enc) > 0 {
				_, _ = p.conn.WriteToUDP(enc, remoteAddr)
			}
		} else {
			_, _ = p.conn.WriteToUDP(reversePing, remoteAddr)
		}
	}

	// Inbound PING confirms that the remote peer reached us directly over UDP
	if p.onPingResult != nil && remoteAddr != nil {
		p.onPingResult(senderID, 0, remoteAddr.String())
	}
}

// handlePong processes incoming PONG responses and measures latency.
func (p *UDPPuncher) handlePong(data string, remoteAddr *net.UDPAddr) {
	parts := strings.Split(data, ":")
	if len(parts) < 4 {
		return
	}
	senderID := strings.Join(parts[2:len(parts)-1], ":")
	if senderID == p.myDevID {
		return
	}
	sentNano, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		return
	}
	rtt := time.Since(time.Unix(0, sentNano))
	if rtt <= 0 {
		rtt = 1 * time.Millisecond
	}

	// Track port delta for Symmetric NAT port prediction
	if remoteAddr != nil && rtt > 0 {
		p.natTypeMu.Lock()
		if p.lastMappedPort > 0 && remoteAddr.Port > 0 {
			observed := remoteAddr.Port - p.lastMappedPort
			if observed > 0 && observed < 512 {
				p.portDelta = observed
			}
		}
		p.lastMappedPort = remoteAddr.Port
		p.natTypeMu.Unlock()
	}

	if p.onPingResult != nil && remoteAddr != nil {
		p.onPingResult(senderID, rtt, remoteAddr.String())
	}
}

// handleTunnelPacket dispatches incoming tunnel data packets to the data callback.
func (p *UDPPuncher) handleTunnelPacket(payload []byte, remoteAddr *net.UDPAddr) {
	p.mu.Lock()
	cb := p.onDataPacket
	p.mu.Unlock()
	if cb != nil {
		pktCopy := make([]byte, len(payload))
		copy(pktCopy, payload)
		cb(remoteAddr, pktCopy)
	}
}

func (p *UDPPuncher) getConn() (*net.UDPConn, context.Context, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn, p.ctx, p.connID
}

var packetBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

func (p *UDPPuncher) readLoop() {
	bufPtr := packetBufferPool.Get().(*[]byte)
	defer packetBufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		conn, ctx, currentID := p.getConn()
		if conn == nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		// Проверка поколения: если HopPort вызван, старый readLoop должен немедленно выйти
		_, _, latestID := p.getConn()
		if latestID != currentID {
			return
		}

		// Гарантированный выход при закрытии контекста
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "use of closed") || strings.Contains(err.Error(), "bad file descriptor") {
				return
			}
			continue
		}

		if n <= 0 {
			continue
		}

		switch {
		case stun.IsMessage(buf[:n]):
			p.handleSTUNMessage(buf[:n])
		case n >= 4 && string(buf[:4]) == constants.KeepAlivePayload:
			// Двусторонний ответ KeepAlive для поддержания исходящей трансляции NAT
			if remoteAddr != nil && conn != nil {
				_, _ = conn.WriteToUDP([]byte(constants.KeepAlivePayload), remoteAddr)
			}
		case n >= 25 && (buf[0]&0xC0 == 0xC0) && binary.BigEndian.Uint32(buf[1:5]) == QUICVersion1:
			p.cipherMu.RLock()
			cKey := p.cipherKey
			hasCKey := p.hasCipherKey
			p.cipherMu.RUnlock()
			if hasCKey {
				if dec, err := ParseQUICChameleonProbe(buf[:n], cKey); err == nil && len(dec) > 0 {
					decStr := string(dec)
					if strings.HasPrefix(decStr, constants.PingPrefix) {
						p.handlePing(decStr, remoteAddr)
						continue
					} else if strings.HasPrefix(decStr, constants.PongPrefix) {
						p.handlePong(decStr, remoteAddr)
						continue
					}
				}
			}
		case strings.HasPrefix(string(buf[:n]), constants.PingPrefix):
			p.handlePing(string(buf[:n]), remoteAddr)
		case strings.HasPrefix(string(buf[:n]), constants.PongPrefix):
			p.handlePong(string(buf[:n]), remoteAddr)
		case n > constants.TunPaddedHeaderSize+2 && string(buf[:constants.TunPaddedHeaderSize]) == constants.TunPaddedHeader:
			realLen := int(binary.BigEndian.Uint16(buf[constants.TunPaddedHeaderSize : constants.TunPaddedHeaderSize+2]))
			if realLen > 0 && constants.TunPaddedHeaderSize+2+realLen <= n {
				rawPayload := buf[constants.TunPaddedHeaderSize+2 : constants.TunPaddedHeaderSize+2+realLen]
				p.cipherMu.RLock()
				cKey := p.cipherKey
				hasCKey := p.hasCipherKey
				p.cipherMu.RUnlock()
				if hasCKey {
					if dec, err := crypto.DecryptSelf(rawPayload, cKey); err == nil && len(dec) > 0 {
						p.handleTunnelPacket(dec, remoteAddr)
					}
					// If cipherKey is set, drop packets that fail decryption
					continue
				}
				p.handleTunnelPacket(rawPayload, remoteAddr)
			}
		case n > constants.TunEncryptedHeaderSize && string(buf[:constants.TunEncryptedHeaderSize]) == constants.TunEncryptedHeader:
			rawPayload := buf[constants.TunEncryptedHeaderSize:n]
			p.cipherMu.RLock()
			cKey := p.cipherKey
			hasCKey := p.hasCipherKey
			p.cipherMu.RUnlock()
			if hasCKey {
				if dec, err := crypto.DecryptSelf(rawPayload, cKey); err == nil && len(dec) > 0 {
					p.handleTunnelPacket(dec, remoteAddr)
				}
				// If cipherKey is set, drop packets that fail decryption
				continue
			}
			// TunEncryptedHeader received but no cipherKey configured: drop
			continue
		case n > constants.TunHeaderSize && string(buf[:constants.TunHeaderSize]) == constants.TunHeader:
			rawPayload := buf[constants.TunHeaderSize:n]
			p.cipherMu.RLock()
			cKey := p.cipherKey
			hasCKey := p.hasCipherKey
			p.cipherMu.RUnlock()
			if hasCKey {
				if dec, err := crypto.DecryptSelf(rawPayload, cKey); err == nil && len(dec) > 0 {
					p.handleTunnelPacket(dec, remoteAddr)
				}
				// If cipherKey is set, drop packets that fail decryption or plaintext leak
				continue
			}
			p.handleTunnelPacket(rawPayload, remoteAddr)
		default:
			p.cipherMu.RLock()
			cKey := p.cipherKey
			hasCKey := p.hasCipherKey
			p.cipherMu.RUnlock()

			if hasCKey && n >= 40 {
				if dec, err := crypto.DecryptSelf(buf[:n], cKey); err == nil && len(dec) > 0 {
					decStr := string(dec)
					if strings.HasPrefix(decStr, constants.PingPrefix) {
						p.handlePing(decStr, remoteAddr)
						continue
					} else if strings.HasPrefix(decStr, constants.PongPrefix) {
						p.handlePong(decStr, remoteAddr)
						continue
					} else if len(dec) >= 3 && (dec[2]>>4 == 4 || dec[2]>>4 == 6) {
						// Stealth tunnel IP packet with 2-byte length prefix from dynamic padding
						realLen := int(binary.BigEndian.Uint16(dec[:2]))
						if realLen > 0 && 2+realLen <= len(dec) {
							p.handleTunnelPacket(dec[2:2+realLen], remoteAddr)
							continue
						}
					} else if (dec[0]>>4) == 4 || (dec[0]>>4) == 6 {
						// Direct unpadded stealth tunnel IP packet
						payloadToSend := dec
						if (dec[0]>>4) == 4 && len(dec) >= 20 {
							totLen := int(binary.BigEndian.Uint16(dec[2:4]))
							if totLen >= 20 && totLen <= len(dec) {
								payloadToSend = dec[:totLen]
							}
						} else if (dec[0]>>4) == 6 && len(dec) >= 40 {
							totLen := 40 + int(binary.BigEndian.Uint16(dec[4:6]))
							if totLen >= 40 && totLen <= len(dec) {
								payloadToSend = dec[:totLen]
							}
						}
						p.handleTunnelPacket(payloadToSend, remoteAddr)
						continue
					}
				}
			}

			p.mu.Lock()
			handler := p.awgHandler
			p.mu.Unlock()
			if handler != nil {
				// ✅ КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Копируем буфер перед передачей
				pktCopy := make([]byte, n)
				copy(pktCopy, buf[:n])
				handler.HandlePacket(pktCopy, remoteAddr)
			}
		}
	}
}

// HopPort закрывает текущий сокет и переоткрывает UDP-порт на случайном значении без race condition.
// SetTrafficShaper подключает шейпер для маскировки UDP-пакетов под видеопотоки.
// SetAWGHandler registers a handler for unencapsulated WireGuard / AWG 3.1 packets.
func (p *UDPPuncher) SetAWGHandler(handler AWGPacketHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.awgHandler = handler
}

// SetAWGVersion sets the active AmneziaWG protocol version string.
func (p *UDPPuncher) SetAWGVersion(version string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.awgVersion = version
}

func (p *UDPPuncher) SetTrafficShaper(shaper *TrafficShaper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trafficShaper = shaper
}

func (p *UDPPuncher) HopPort() (int, error) {
	p.mu.Lock()

	// 1. Инкремент поколения сокета для завершения старого readLoop
	p.connID++

	// 2. Останавливаем старый readLoop через cancel
	if p.cancel != nil {
		p.cancel()
	}

	// 3. Закрываем старый сокет
	if p.conn != nil {
		_ = p.conn.Close()
	}

	// 4. Создаём новый контекст
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// 5. Открываем новый сокет (предпочтительно udp4)
	lAddr4, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	conn, err := net.ListenUDP("udp4", lAddr4)
	if err != nil {
		lAddr, _ := net.ResolveUDPAddr("udp", ":0")
		conn, err = net.ListenUDP("udp", lAddr)
		if err != nil {
			p.mu.Unlock()
			return 0, fmt.Errorf("failed to re-bind port during hop: %w", err)
		}
	}

	p.conn = conn
	p.addrCache.Range(func(k, v any) bool { p.addrCache.Delete(k); return true })
	p.localPort = conn.LocalAddr().(*net.UDPAddr).Port
	// BUG-13 FIX: capture localPort before releasing lock to avoid stale read
	newPort := p.localPort
	p.mu.Unlock()

	// 6. Перезапуск цикла чтения
	go p.readLoop()

	// BUG-03 FIX: HopPort() creates a new ctx; old keepalive goroutine is already dead
	// (it listened on the old cancelled ctx). Restart keepalive explicitly.
	p.StartKeepAliveLoop()

	// 7. Обновляем STUN mapping
	go func() {
		ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
		defer cancel()
		_, _, _ = p.DiscoverMappedAddress(ctx)
	}()

	return newPort, nil
}

func (p *UDPPuncher) Close() error {
	p.cancel()
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

// SocketFd returns the underlying socket file descriptor for Android VpnService.protect()
func (p *UDPPuncher) SocketFd() int {
	p.mu.Lock()
	conn := p.conn
	p.mu.Unlock()
	if conn == nil {
		return -1
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1
	}
	var fdVal int = -1
	_ = raw.Control(func(fd uintptr) {
		fdVal = int(fd)
	})
	return fdVal
}
// SendDualPathProbe sends hole punch probes to both STUN public endpoint and LAN IP.
func (p *UDPPuncher) SendDualPathProbe(stunAddr, localAddr string) error {
	var err1, err2 error
	if stunAddr != "" {
		err1 = p.SendHolePunchProbe(stunAddr)
	}
	if localAddr != "" && localAddr != stunAddr {
		err2 = p.SendHolePunchProbe(localAddr)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

// SendMTUProbe transmits an exact-sized UDP probe packet to test path MTU.
func (p *UDPPuncher) SendMTUProbe(targetAddr string, targetMTU int) error {
	if targetAddr == "" || p.conn == nil || targetMTU < 1280 || targetMTU > 1500 {
		return nil
	}
	rAddr, err := p.resolveAddr(targetAddr)
	if err != nil {
		return err
	}

	header := fmt.Sprintf("%s%d:%s:", constants.MTUProbePrefix, targetMTU, p.myDevID)
	pkt := make([]byte, targetMTU)
	copy(pkt, []byte(header))
	for i := len(header); i < targetMTU; i++ {
		pkt[i] = byte(i % 256)
	}

	_, err = p.conn.WriteToUDP(pkt, rAddr)
	return err
}

func (p *UDPPuncher) SetMTUCallback(cb DirectMTUCallback) {
	p.mu.Lock()
	p.onMTUResult = cb
	p.mu.Unlock()
}
