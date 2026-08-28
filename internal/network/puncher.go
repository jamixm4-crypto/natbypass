package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/pion/stun/v2"
)

type DirectPingCallback func(deviceID string, rtt time.Duration, fromAddr string)
type DirectDataCallback func(srcAddr *net.UDPAddr, payload []byte)

type UDPPuncher struct {
	conn         *net.UDPConn
	localPort    int
	mappedIP     net.IP
	mappedPort   int
	myDevID      string
	stunServers  []string
	onPingResult DirectPingCallback
	onDataPacket DirectDataCallback
	stunRespCh   chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex

	// NATType is detected asynchronously after construction.
	NATType   NATType
	natTypeMu sync.RWMutex

	// portDelta tracks the observed consecutive port increment for Symmetric NAT prediction.
	lastMappedPort int
	portDelta      int

	probeMu          sync.Mutex
	lastProbeMap     map[string]time.Time
	lastCleanupTime  time.Time
}

// NewUDPPuncher creates a new persistent UDP socket for STUN, hole punching, and data transfer.
func NewUDPPuncher(preferredPort int, myDevID string, stunServers []string, onPing DirectPingCallback) (*UDPPuncher, error) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	var conn *net.UDPConn
	var err error
	var lAddr *net.UDPAddr

	// Use "udp" (dual-stack: IPv4 + IPv6) for full mobile and desktop support
	if preferredPort > 0 {
		lAddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", preferredPort))
		conn, err = net.ListenUDP("udp", lAddr)
	}

	if err != nil || conn == nil {
		lAddr, _ = net.ResolveUDPAddr("udp", ":0")
		conn, err = net.ListenUDP("udp", lAddr)
		if err != nil {
			// Fallback to udp4 if dual-stack is not supported by kernel
			lAddr4, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
			conn, err = net.ListenUDP("udp4", lAddr4)
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
		stunRespCh:      make(chan struct{}, 8),
		ctx:             ctx,
		cancel:          cancel,
		NATType:         NATTypeUnknown,
		lastProbeMap:    make(map[string]time.Time),
		lastCleanupTime: time.Now(),
	}

	// Start packet processing loop
	go p.readLoop()

	// Detect NAT type in background — non-blocking
	go func() {
		dCtx, dCancel := context.WithTimeout(ctx, 6*time.Second)
		defer dCancel()
		natType, err := DetectNATType(dCtx, conn, stunServers)
		p.natTypeMu.Lock()
		if err == nil {
			p.NATType = natType
		} else {
			p.NATType = NATTypeUnknown
		}
		p.natTypeMu.Unlock()
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

// DiscoverMappedAddress sends a STUN Binding Request from the persistent socket.
func (p *UDPPuncher) DiscoverMappedAddress(ctx context.Context) (net.IP, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, srv := range p.stunServers {
		srvAddr, err := net.ResolveUDPAddr("udp", srv)
		if err != nil {
			srvAddr, err = net.ResolveUDPAddr("udp4", srv)
			if err != nil {
				continue
			}
		}

		msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		if _, err := p.conn.WriteToUDP(msg.Raw, srvAddr); err != nil {
			continue
		}

		select {
		case <-p.stunRespCh:
			if p.mappedIP != nil && p.mappedPort > 0 {
				return p.mappedIP, p.mappedPort, nil
			}
		case <-time.After(800 * time.Millisecond):
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}

	if p.mappedIP != nil && p.mappedPort > 0 {
		return p.mappedIP, p.mappedPort, nil
	}
	return nil, 0, fmt.Errorf("STUN discovery timeout")
}

// candidatePorts calculates predicted port numbers for Symmetric NAT traversal.
func (p *UDPPuncher) candidatePorts(base int) []int {
	ports := []int{base}
	switch p.GetNATType() {
	case NATTypeSymmetric:
		p.natTypeMu.RLock()
		d := p.portDelta
		p.natTypeMu.RUnlock()
		if d <= 0 {
			d = 1
		}
		for i := 1; i <= 8; i++ {
			p1 := base + i*d
			p2 := base - i*d
			if p1 > 1024 && p1 < 65535 {
				ports = append(ports, p1)
			}
			if p2 > 1024 && p2 < 65535 {
				ports = append(ports, p2)
			}
		}
	case NATTypeUnknown:
		for i := 1; i <= 4; i++ {
			p1 := base + i
			p2 := base - i
			if p1 > 1024 && p1 < 65535 {
				ports = append(ports, p1)
			}
			if p2 > 1024 && p2 < 65535 {
				ports = append(ports, p2)
			}
		}
	}
	return ports
}

// SendHolePunchProbe sends direct UDP probe packets to the target peer endpoint and candidate ports.
func (p *UDPPuncher) SendHolePunchProbe(targetAddr string) error {
	if targetAddr == "" || p.conn == nil {
		return nil
	}
	rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		rAddr, err = net.ResolveUDPAddr("udp4", targetAddr)
		if err != nil {
			return err
		}
	}

	p.probeMu.Lock()
	now := time.Now()

	// Periodic cleanup of lastProbeMap entries older than 60s
	if now.Sub(p.lastCleanupTime) > 60*time.Second {
		for k, t := range p.lastProbeMap {
			if now.Sub(t) > 60*time.Second {
				delete(p.lastProbeMap, k)
			}
		}
		p.lastCleanupTime = now
	}

	if now.Sub(p.lastProbeMap[targetAddr]) < constants.MinProbeInterval {
		p.probeMu.Unlock()
		return nil // Rate limit: maximum 2 probes/second per address
	}
	p.lastProbeMap[targetAddr] = now
	p.probeMu.Unlock()

	nowNano := now.UnixNano()
	probeData := []byte(fmt.Sprintf("%s%s:%d", constants.PingPrefix, p.myDevID, nowNano))

	// 1. Send 2 fast probe packets directly to target address
	_, err = p.conn.WriteToUDP(probeData, rAddr)
	_, _ = p.conn.WriteToUDP(probeData, rAddr)

	// 2. Adaptive sweep across candidate ports for Symmetric NAT / CGNAT
	targetIP := rAddr.IP
	candidates := p.candidatePorts(rAddr.Port)
	for _, port := range candidates {
		if port == rAddr.Port {
			continue
		}
		cAddr := &net.UDPAddr{IP: targetIP, Port: port}
		_, _ = p.conn.WriteToUDP(probeData, cAddr)
	}

	return err
}

// SendKeepAlive sends a tiny keep-alive packet to maintain CGNAT port mappings.
func (p *UDPPuncher) SendKeepAlive(targetAddr string) error {
	if targetAddr == "" || p.conn == nil {
		return nil
	}
	rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		rAddr, err = net.ResolveUDPAddr("udp4", targetAddr)
		if err != nil {
			return err
		}
	}
	_, err = p.conn.WriteToUDP([]byte(constants.KeepAlivePayload), rAddr)
	return err
}

// SetDataCallback registers the callback handler for incoming tunnel data packets.
func (p *UDPPuncher) SetDataCallback(cb DirectDataCallback) {
	p.mu.Lock()
	p.onDataPacket = cb
	p.mu.Unlock()
}

// SendDataPacket sends a raw tunnel IP packet directly to the peer.
func (p *UDPPuncher) SendDataPacket(targetAddr string, payload []byte) error {
	if targetAddr == "" || p.conn == nil {
		return nil
	}
	rAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		return err
	}

	header := []byte(constants.TunHeader)
	fullPkt := make([]byte, len(header)+len(payload))
	copy(fullPkt, header)
	copy(fullPkt[len(header):], payload)

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
		p.mappedIP = xorAddr.IP
		p.mappedPort = xorAddr.Port
		select {
		case p.stunRespCh <- struct{}{}:
		default:
		}
		return
	}

	var mappedAddr stun.MappedAddress
	if err := mappedAddr.GetFrom(&stunResp); err == nil {
		p.mappedIP = mappedAddr.IP
		p.mappedPort = mappedAddr.Port
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

	// Calculate real RTT from embedded sender timestamp
	rtt := 35 * time.Millisecond
	if sentNano, err := strconv.ParseInt(sentTs, 10, 64); err == nil && sentNano > 0 {
		measured := time.Since(time.Unix(0, sentNano))
		if measured > 0 && measured < 10*time.Second {
			rtt = measured
		}
	}

	// Inbound PING confirms that the remote peer reached us directly over UDP
	if p.onPingResult != nil && remoteAddr != nil {
		p.onPingResult(senderID, rtt, remoteAddr.String())
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

func (p *UDPPuncher) readLoop() {
	buf := make([]byte, 65535) // MTU-safe buffer for IP packets up to 65535 bytes
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "use of closed") {
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
			// Silent keep-alive, no-op
		case strings.HasPrefix(string(buf[:n]), constants.PingPrefix):
			p.handlePing(string(buf[:n]), remoteAddr)
		case strings.HasPrefix(string(buf[:n]), constants.PongPrefix):
			p.handlePong(string(buf[:n]), remoteAddr)
		case n > constants.TunHeaderSize && string(buf[:constants.TunHeaderSize]) == constants.TunHeader:
			p.handleTunnelPacket(buf[constants.TunHeaderSize:n], remoteAddr)
		}
	}
}

func (p *UDPPuncher) Close() error {
	p.cancel()
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}