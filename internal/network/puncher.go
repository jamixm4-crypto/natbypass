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
}

func NewUDPPuncher(preferredPort int, myDevID string, stunServers []string, onPing DirectPingCallback) (*UDPPuncher, error) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	var conn *net.UDPConn
	var err error
	var lAddr *net.UDPAddr

	if preferredPort > 0 {
		lAddr, _ = net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", preferredPort))
		conn, err = net.ListenUDP("udp4", lAddr)
	}

	if err != nil || conn == nil {
		lAddr, _ = net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		conn, err = net.ListenUDP("udp4", lAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to bind UDP socket: %w", err)
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
		stunRespCh:   make(chan struct{}, 4),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Единый цикл чтения пакетов (STUN + PING/PONG)
	go p.readLoop()

	return p, nil
}

func (p *UDPPuncher) LocalPort() int {
	return p.localPort
}

// DiscoverMappedAddress отправляет STUN Binding Request с постоянного сокета
func (p *UDPPuncher) DiscoverMappedAddress(ctx context.Context) (net.IP, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, srv := range p.stunServers {
		srvAddr, err := net.ResolveUDPAddr("udp4", srv)
		if err != nil {
			continue
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
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}

	if p.mappedIP != nil && p.mappedPort > 0 {
		return p.mappedIP, p.mappedPort, nil
	}
	return nil, 0, fmt.Errorf("STUN discovery timeout")
}

// SendHolePunchProbe отправляет прямой UDP пакет второму компьютеру
// Включает Symmetric NAT Multi-Port Prediction (пробивку диапазона портов для обхода мобильного интернета и CGNAT)
func (p *UDPPuncher) SendHolePunchProbe(targetAddr string) error {
	if targetAddr == "" || p.conn == nil {
		return nil
	}
	rAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		return err
	}

	nowNano := time.Now().UnixNano()
	probeData := fmt.Sprintf("NATBYPASS:PING:%s:%d", p.myDevID, nowNano)

	// 1. Отправка на точный STUN порт
	_, err = p.conn.WriteToUDP([]byte(probeData), rAddr)

	// 2. Multi-Port Symmetric NAT Port Prediction (±5 портов вокруг STUN адреса)
	basePort := rAddr.Port
	ip := rAddr.IP
	for delta := 1; delta <= 5; delta++ {
		if basePort+delta <= 65535 {
			_, _ = p.conn.WriteToUDP([]byte(probeData), &net.UDPAddr{IP: ip, Port: basePort + delta})
		}
		if basePort-delta > 1024 {
			_, _ = p.conn.WriteToUDP([]byte(probeData), &net.UDPAddr{IP: ip, Port: basePort - delta})
		}
	}

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

		// 1. STUN Ответ
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
				}
			}
			continue
		}

		data := string(buf[:n])

		// 2. Входящий PING от пира -> отвечаем PONG и подтверждаем сокет без сброса задержки
		if strings.HasPrefix(data, "NATBYPASS:PING:") {
			parts := strings.Split(data, ":")
			if len(parts) >= 4 {
				senderID := parts[2]
				sentTs := parts[3]
				pongMsg := fmt.Sprintf("NATBYPASS:PONG:%s:%s", p.myDevID, sentTs)
				_, _ = p.conn.WriteToUDP([]byte(pongMsg), remoteAddr)
			}
			continue
		}

		// 3. Ответ PONG от пира
		if strings.HasPrefix(data, "NATBYPASS:PONG:") {
			parts := strings.Split(data, ":")
			if len(parts) >= 4 {
				senderID := parts[2]
				sentNano, err := strconv.ParseInt(parts[3], 10, 64)
				if err == nil {
					rtt := time.Since(time.Unix(0, sentNano))
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
