package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	udpRelayHeader    = "NATBYPASS:URELAY:"
	udpRelayKeepAlive = "NATBYPASS:UKEEPALIVE"
)

// UDPRelayClient обеспечивает быструю ретрансляцию IP-пакетов через UDP
type UDPRelayClient struct {
	serverAddr *net.UDPAddr
	conn       *net.UDPConn
	sessionKey []byte // 32 bytes для ChaCha20-Poly1305
	myDeviceID string
	mu         sync.RWMutex
	connected  bool
	onPacket   func(srcDeviceID string, payload []byte)
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewUDPRelayClient создаёт клиента с шифрованием пакетов
func NewUDPRelayClient(serverAddr string, deviceID string, sessionKey []byte,
	onPacket func(srcDeviceID string, payload []byte)) (*UDPRelayClient, error) {

	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("session key must be exactly 32 bytes")
	}

	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid relay server address: %w", err)
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to bind UDP socket: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := &UDPRelayClient{
		serverAddr: addr,
		conn:       conn,
		sessionKey: sessionKey,
		myDeviceID: deviceID,
		onPacket:   onPacket,
		connected:  true,
		ctx:        ctx,
		cancel:     cancel,
	}

	go c.readLoop()
	go c.keepAliveLoop()

	return c, nil
}

// SendPacket шифрует и отправляет IP-пакет через relay
// Формат: NATBYPASS:URELAY:<srcDevID>:<dstDevID>:<nonce_b64>:<encrypted>
func (c *UDPRelayClient) SendPacket(targetDeviceID string, payload []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.conn == nil {
		return fmt.Errorf("relay not connected")
	}

	aead, err := chacha20poly1305.New(c.sessionKey)
	if err != nil {
		return err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	encrypted := aead.Seal(nil, nonce, payload, []byte(targetDeviceID))
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)

	header := fmt.Sprintf("%s%s:%s:%s:", udpRelayHeader, c.myDeviceID, targetDeviceID, nonceB64)
	packet := append([]byte(header), encrypted...)

	_, err = c.conn.WriteToUDP(packet, c.serverAddr)
	return err
}

// IsConnected возвращает статус соединения
func (c *UDPRelayClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Close закрывает соединение
func (c *UDPRelayClient) Close() error {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *UDPRelayClient) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		if n <= 0 {
			continue
		}

		data := string(buf[:n])

		// KeepAlive ответ
		if strings.HasPrefix(data, udpRelayKeepAlive) {
			c.mu.Lock()
			c.connected = true
			c.mu.Unlock()
			continue
		}

		// Данные: NATBYPASS:URELAY:<src>:<dst>:<nonce_b64>:<encrypted>
		if strings.HasPrefix(data, udpRelayHeader) {
			c.handleRelayPacket(buf[:n])
		}
	}
}

func (c *UDPRelayClient) handleRelayPacket(data []byte) {
	// Format: NATBYPASS:URELAY:<srcDevID>:<dstDevID>:<nonce_b64>:<encrypted>
	parts := strings.SplitN(string(data), ":", 6)
	if len(parts) < 6 {
		return
	}

	srcDevID := parts[2]
	dstDevID := parts[3]
	nonceB64 := parts[4]

	// Decode nonce
	nonce, err := base64.RawStdEncoding.DecodeString(nonceB64)
	if err != nil {
		nonce, err = base64.StdEncoding.DecodeString(nonceB64)
		if err != nil {
			return
		}
	}

	headerPrefix := fmt.Sprintf("%s%s:%s:%s:", udpRelayHeader, srcDevID, dstDevID, nonceB64)
	if len(data) <= len(headerPrefix) {
		return
	}
	encrypted := data[len(headerPrefix):]

	aead, err := chacha20poly1305.New(c.sessionKey)
	if err != nil {
		return
	}

	plaintext, err := aead.Open(nil, nonce, encrypted, []byte(dstDevID))
	if err != nil {
		return
	}

	if c.onPacket != nil {
		c.onPacket(srcDevID, plaintext)
	}
}

func (c *UDPRelayClient) keepAliveLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			if c.conn != nil {
				_, _ = c.conn.WriteToUDP([]byte(udpRelayKeepAlive), c.serverAddr)
			}
			c.mu.RUnlock()
		}
	}
}
