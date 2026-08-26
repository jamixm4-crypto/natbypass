package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

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
	NATType    NATType
	natTypeMu  sync.RWMutex

	// portDelta tracks the observed consecutive port increment for Symmetric NAT prediction.
	lastMappedPort int
	portDelta      int
}

func NewUDPPuncher(preferredPort int, myDevID string, stunServers []string, onPing DirectPingCallback) (*UDPPuncher, error) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	var conn *net.UDPConn
	var err error
	var lAddr *net.UDPAddr

	// Используем сеть "udp" (dual-stack: IPv4 + IPv6) для полноценной работы на мобильных сетях
	if preferredPort > 0 {
		lAddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", preferredPort))
		conn, err = net.ListenUDP("udp", lAddr)
	}

	if err != nil || conn == nil {
		lAddr, _ = net.ResolveUDPAddr("udp", ":0")
		conn, err = net.ListenUDP("udp", lAddr)
		if err != nil {
			// Fallback на udp4 если dual-stack сокет не поддерживается ядром
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
		conn:         conn,
		localPort:    localPort,
		myDevID:      myDevID,
		stunServers:  stunServers,
		onPingResult: onPing,
		stunRespCh:   make(chan struct{}, 8),
		ctx:          ctx,
		cancel:       cancel,
		NATType:      NATTypeUnknown,
	}

	// Единый цикл чтения пакетов (STUN + PING/PONG)
	go p.readLoop()

	// Detect NAT type in background — doesn't block startup
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

func (p *UDPPuncher) LocalPort() int {
	return p.localPort
}

// GetNATType returns the detected NAT type (may be Unknown if detection is still running).
func (p *UDPPuncher) GetNATType() NATType {
	p.natTypeMu.RLock()
	defer p.natTypeMu.RUnlock()
	return p.NATType
}


// DiscoverMappedAddress отправляет STUN Binding Request с постоянного сокета
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

// SendHolePunchProbe отправляет прямой UDP пакет второму устройству.
// Точное попадание отправляется всегда (3 пакета).
// Для неизвестных / CGNAT сокетов также выполняется умеренный sweep соседних портов.
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

	nowNano := time.Now().UnixNano()
	probeData := []byte(fmt.Sprintf("NATBYPASS:PING:%s:%d", p.myDevID, nowNano))

	// 1. Точное попадание — 3 пакета для надёжности
	for i := 0; i < 3; i++ {
		_, _ = p.conn.WriteToUDP(probeData, rAddr)
	}

	// 2. Умеренный sweep по диапазону портов для компенсации CGNAT port allocation
	if rAddr.IP.To4() != nil {
		p.natTypeMu.RLock()
		natT := p.NATType
		p.natTypeMu.RUnlock()

		basePort := rAddr.Port
		ip := rAddr.IP

		// Sweep диапазон: ±16 для Cone, ±32 для Symmetric
		sweep := 16
		if natT == NATTypeSymmetric {
			sweep = 32
		}

		for d := 1; d <= sweep; d++ {
			if basePort+d <= 65535 {
				_, _ = p.conn.WriteToUDP(probeData, &net.UDPAddr{IP: ip, Port: basePort + d})
			}
			if basePort-d > 1024 {
				_, _ = p.conn.WriteToUDP(probeData, &net.UDPAddr{IP: ip, Port: basePort - d})
			}
		}
	}

	return nil
}


// SendKeepAlive отправляет минимальный 4-байтный пакет для поддержания CGNAT маппинга.
// Использует отдельный tiny payload вместо полноценного PING/PONG, чтобы не триггерить лишние callback-и.
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
	_, err = p.conn.WriteToUDP([]byte("KAEP"), rAddr)
	return err
}

func (p *UDPPuncher) SetDataCallback(cb DirectDataCallback) {
	p.mu.Lock()
	p.onDataPacket = cb
	p.mu.Unlock()
}


// SendDataPacket отправляет сырой IP пакет туннеля пиру
func (p *UDPPuncher) SendDataPacket(targetAddr string, payload []byte) error {
	if targetAddr == "" || p.conn == nil {
		return nil
	}
	rAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		return err
	}

	header := []byte("NATBYPASS:TUN:")
	fullPkt := make([]byte, len(header)+len(payload))
	copy(fullPkt, header)
	copy(fullPkt[len(header):], payload)

	_, err = p.conn.WriteToUDP(fullPkt, rAddr)
	return err
}

func (p *UDPPuncher) readLoop() {
	buf := make([]byte, 2048)
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

		// 1. STUN Ответ (поддерживаем как XOR-MAPPED-ADDRESS так и MAPPED-ADDRESS)
		if stun.IsMessage(buf[:n]) {
			var stunResp stun.Message
			stunResp.Raw = make([]byte, n)
			copy(stunResp.Raw, buf[:n])
			if err := stunResp.Decode(); err == nil {
				var xorAddr stun.XORMappedAddress
				if err := xorAddr.GetFrom(&stunResp); err == nil {
					p.mappedIP = xorAddr.IP
					p.mappedPort = xorAddr.Port
					select {
					case p.stunRespCh <- struct{}{}:
					default:
					}
				} else {
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
			}
			continue
		}

		data := string(buf[:n])

		// Тихий keep-alive пакет — просто игнорируем без callback
		if data == "KAEP" {
			continue
		}

		// 2. Входящий PING от пира -> отвечаем PONG и подтверждаем сокет
		if strings.HasPrefix(data, "NATBYPASS:PING:") {
			parts := strings.Split(data, ":")
			if len(parts) >= 4 {
				senderID := strings.Join(parts[2:len(parts)-1], ":")
				if senderID == p.myDevID {
					continue
				}
				sentTs := parts[len(parts)-1]
				pongMsg := fmt.Sprintf("NATBYPASS:PONG:%s:%s", p.myDevID, sentTs)
				// Отправляем 3 PONG пакета с исходной меткой времени отправителя
				_, _ = p.conn.WriteToUDP([]byte(pongMsg), remoteAddr)
				_, _ = p.conn.WriteToUDP([]byte(pongMsg), remoteAddr)
				_, _ = p.conn.WriteToUDP([]byte(pongMsg), remoteAddr)

				// Подтверждаем активность сокета с rtt=0 (настоящий RTT вычисляется только на стороне отправителя при получении PONG)
				if p.onPingResult != nil {
					p.onPingResult(senderID, 0, remoteAddr.String())
				}
			}
			continue
		}

		// 3. Ответ PONG от пира
		if strings.HasPrefix(data, "NATBYPASS:PONG:") {
			parts := strings.Split(data, ":")
			if len(parts) >= 4 {
				senderID := strings.Join(parts[2:len(parts)-1], ":")
				if senderID == p.myDevID {
					continue
				}
				sentNano, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
				if err == nil {
					rtt := time.Since(time.Unix(0, sentNano))
					// Обновляем portDelta для Symmetric NAT предсказания (разница между mapped портами)
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
					if p.onPingResult != nil {
						p.onPingResult(senderID, rtt, remoteAddr.String())
					}
				}
			}
			continue
		}

		// 4. Входящий пакет данных виртуального сетевого интерфейса (TUN)
		if n > 14 && string(buf[:14]) == "NATBYPASS:TUN:" {
			p.mu.Lock()
			cb := p.onDataPacket
			p.mu.Unlock()
			if cb != nil {
				pktCopy := make([]byte, n-14)
				copy(pktCopy, buf[14:n])
				cb(remoteAddr, pktCopy)
			}
			continue
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
