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

// UDPRelayClient provides a low-latency (30-80ms) encrypted UDP fallback relay.
type UDPRelayClient struct {
	serverAddr string
	myDeviceID string
	conn       *net.UDPConn
	sessionKey [32]byte
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	onPacket   func(srcDeviceID string, payload []byte)
	connected  bool
}

// NewUDPRelayClient creates a new high-performance ChaCha20-Poly1305 UDP relay client.
func NewUDPRelayClient(serverAddr, myDeviceID string, key [32]byte, onPacket func(srcDeviceID string, payload []byte)) (*UDPRelayClient, error) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &UDPRelayClient{
		serverAddr: serverAddr,
		myDeviceID: myDeviceID,
		sessionKey: key,
		ctx:        ctx,
		cancel:     cancel,
		onPacket:   onPacket,
	}

	if serverAddr != "" {
		if err := c.initConn(); err != nil {
			cancel()
			return nil, err
		}
	}
	return c, nil
}

func (c *UDPRelayClient) initConn() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	rAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return err
	}
	c.conn = conn
	c.connected = true

	go c.readLoop()
	return nil
}

// SendPacket encrypts the tunnel payload with ChaCha20-Poly1305 and transmits via UDP relay.
func (c *UDPRelayClient) SendPacket(targetDeviceID string, payload []byte) error {
	c.mu.Lock()
	conn := c.conn
	connected := c.connected
	c.mu.Unlock()

	if conn == nil || !connected {
		return fmt.Errorf("udp relay not connected")
	}

	aead, err := chacha20poly1305.New(c.sessionKey[:])
	if err != nil {
		return fmt.Errorf("cipher init error: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := aead.Seal(nil, nonce, payload, []byte(targetDeviceID))
	header := fmt.Sprintf("NATBYPASS:UDPRELAY:%s:%s:%s:", c.myDeviceID, targetDeviceID, base64.RawStdEncoding.EncodeToString(nonce))
	fullPkt := append([]byte(header), ciphertext...)

	_, err = conn.Write(fullPkt)
	return err
}

func (c *UDPRelayClient) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n, err := conn.Read(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if n < 30 {
			continue
		}

		msg := string(buf[:n])
		if !strings.HasPrefix(msg, "NATBYPASS:UDPRELAY:") {
			continue
		}

		parts := strings.SplitN(msg, ":", 6)
		if len(parts) < 6 {
			continue
		}

		srcDevID := parts[2]
		dstDevID := parts[3]
		nonceB64 := parts[4]
		cipherStart := len(parts[0]) + len(parts[1]) + len(parts[2]) + len(parts[3]) + len(parts[4]) + 5
		if cipherStart >= n {
			continue
		}
		ciphertext := buf[cipherStart:n]

		if dstDevID != c.myDeviceID && dstDevID != "broadcast" {
			continue
		}

		nonce, err := base64.RawStdEncoding.DecodeString(nonceB64)
		if err != nil {
			continue
		}

		aead, err := chacha20poly1305.New(c.sessionKey[:])
		if err != nil {
			continue
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(dstDevID))
		if err != nil {
			continue
		}

		if c.onPacket != nil {
			c.onPacket(srcDevID, plaintext)
		}
	}
}

// Close terminates the UDP relay client.
func (c *UDPRelayClient) Close() {
	c.cancel()
	c.mu.Lock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.connected = false
	c.mu.Unlock()
}
