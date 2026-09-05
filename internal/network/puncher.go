package network

import (
	"crypto/rand"
	"encoding/binary"
	"context"
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
	serversToQuery := p.stunServers
	if len(serversToQuery) > 3 {
		serversToQuery = serversToQuery[:3]
	}
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
				}
				p.mu.Unlock()
			case <-time.After(250 * time.Millisecond):
			case <-ctx.Done():
				break
			}
		}
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

	// 3. Local LAN addresses (only physical Ethernet/Wi-Fi interfaces, skip TUN/TAP/Mesh/Docker/VPN)
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagPointToPoint != 0 {
				continue
			}
			nameLower := strings.ToLower(iface.Name)
			if strings.HasPrefix(nameLower, "nb") || strings.Contains(nameLower, "natbypass") || strings.Contains(nameLower, "wintun") ||
				strings.HasPrefix(nameLower, "tun") || strings.HasPrefix(nameLower, "tap") || strings.HasPrefix(nameLower, "nwg") ||
				strings.HasPrefix(nameLower, "wg") || strings.HasPrefix(nameLower, "docker") || strings.HasPrefix(nameLower, "veth") ||
				strings.Contains(nameLower, "virtual") || strings.Contains(nameLower, "tailscale") || strings.Contains(nameLower, "zerotier") {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					// Exclude default CGNAT mesh range 100.64.0.0/10 from candidate discovery
					if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
						continue
					}
					if ip4.IsPrivate() {
						candidateSet[fmt.Sprintf("%s:%d", ip4.String(), localPort)] = struct{}{}
					}
				}
			}

		}
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

// candidatePorts calculates predicted port numbers for Symmetric NAT traversal.
func (p *UDPPuncher) candidatePorts(base int) []int {
	ports := []int{base}
	p.natTypeMu.RLock()
	d := p.portDelta
	p.natTypeMu.RUnlock()
	if d <= 0 {
		d = 1
	}

	// 1. Delta series prediction (+/- 1*d .. 16*d)
	for i := 1; i <= 16; i++ {
		p1 := base + i*d
		p2 := base - i*d
		if p1 > 1024 && p1 < 65535 {
			ports = append(ports, p1)
		}
		if p2 > 1024 && p2 < 65535 {
			ports = append(ports, p2)
		}
	}

	// 2. Sequential neighbor spray (+/- 1 .. 8)
	for i := 1; i <= 8; i++ {
		p1 := base + i
		p2 := base - i
		if p1 > 1024 && p1 < 65535 {
			ports = append(ports, p1)
		}
		if p2 > 1024 && p2 < 65535 {
			ports = append(ports, p2)
		}
	}

	return ports
}


// SendHolePunchProbe отправляет probe пакеты без rate limiter для максимальной отзывчивости пинга
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

	// Send dual burst probes for high resilience against packet loss
	_, _ = p.conn.WriteToUDP(probeData, rAddr)
	_, _ = p.conn.WriteToUDP(probeData, rAddr)

	// Targeted probing for Symmetric NAT
	if p.GetNATType().IsSymmetric() {
		targetIP := rAddr.IP
		candidates := []int{rAddr.Port + 1, rAddr.Port + 2, rAddr.Port - 1, rAddr.Port - 2}
		if p.portDelta != 0 {
			candidates = append(candidates, rAddr.Port+p.portDelta, rAddr.Port+2*p.portDelta)
		}
		for _, port := range candidates {
			if port > 1024 && port < 65535 && port != rAddr.Port {
				cAddr := &net.UDPAddr{IP: targetIP, Port: port}
				_, _ = p.conn.WriteToUDP(probeData, cAddr)
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

	dataToSend := payload
	header := []byte(constants.TunHeader)
	if hasCKey {
		if enc, encErr := crypto.EncryptSelf(payload, cKey); encErr == nil && len(enc) > 0 {
			dataToSend = enc
			header = []byte(constants.TunEncryptedHeader)
		}
	}

	if pmax > 0 && pmax >= pmin {
		padLen := pmin
		if diff := pmax - pmin; diff > 0 {
			var b [1]byte
			_, _ = rand.Read(b[:])
			padLen += int(b[0]) % (diff + 1)
		}
		if padLen > 0 {
			pHeader := []byte(constants.TunPaddedHeader)
			pLen := uint16(len(dataToSend))
			fullPkt := make([]byte, len(pHeader)+2+len(dataToSend)+padLen)
			copy(fullPkt, pHeader)
			binary.BigEndian.PutUint16(fullPkt[len(pHeader):len(pHeader)+2], pLen)
			copy(fullPkt[len(pHeader)+2:], dataToSend)
			_, _ = rand.Read(fullPkt[len(pHeader)+2+len(dataToSend):])
			_, err = p.conn.WriteToUDP(fullPkt, rAddr)
			return err
		}
	}

	fullPkt := make([]byte, len(header)+len(dataToSend))
	copy(fullPkt, header)
	copy(fullPkt[len(header):], dataToSend)

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
	pongMsg := fmt.Sprintf("%s%s:%s", constants.PongPrefix, p.myDevID, sentTs)
	_, _ = p.conn.WriteToUDP([]byte(pongMsg), remoteAddr)

	// Отправляем встречный PING (ограничен 1 разом в 2 секунды на пир) для взаимного сквозного пробития NAT сокет-в-сокет
	now := time.Now()
	if last, ok := p.lastReversePing.Load(senderID); !ok || now.Sub(last.(time.Time)) > 2*time.Second {
		p.lastReversePing.Store(senderID, now)
		reversePing := fmt.Sprintf("%s%s:%d", constants.PingPrefix, p.myDevID, now.UnixNano())
		_, _ = p.conn.WriteToUDP([]byte(reversePing), remoteAddr)
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
	p.mu.Unlock()

	// 6. Перезапуск цикла чтения
	go p.readLoop()

	// 6. Обновляем STUN mapping
	go func() {
		ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
		defer cancel()
		_, _, _ = p.DiscoverMappedAddress(ctx)
	}()

	return p.localPort, nil
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
