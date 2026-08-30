package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSSRelayClient provides an encrypted HTTPS/WSS fallback tunnel over port 443.
type WSSRelayClient struct {
	serverURL string
	deviceID  string
	conn      *websocket.Conn
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	onPacket  func(srcDeviceID string, payload []byte)
	connected bool
}

// NewWSSRelayClient creates a new HTTPS/WSS relay client.
func NewWSSRelayClient(serverURL, deviceID string, onPacket func(srcDeviceID string, payload []byte)) *WSSRelayClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &WSSRelayClient{
		serverURL: serverURL,
		deviceID:  deviceID,
		ctx:       ctx,
		cancel:    cancel,
		onPacket:  onPacket,
	}
}

// Start begins the auto-reconnecting WSS stream.
func (c *WSSRelayClient) Start() {
	go c.connectionLoop()
}

// SendPacket transmits a TUN packet over the WSS relay.
func (c *WSSRelayClient) SendPacket(targetDeviceID string, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil || !c.connected {
		return fmt.Errorf("relay not connected")
	}

	header := fmt.Sprintf("NATBYPASS:RELAY:%s:%s:", c.deviceID, targetDeviceID)
	fullMsg := append([]byte(header), payload...)
	return c.conn.WriteMessage(websocket.BinaryMessage, fullMsg)
}

// IsConnected returns true if the WSS relay is currently active.
func (c *WSSRelayClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *WSSRelayClient) connectionLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if c.serverURL == "" {
			time.Sleep(5 * time.Second)
			continue
		}

		u, err := url.Parse(c.serverURL)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		sysCerts, _ := x509.SystemCertPool()
		tlsConfig := &tls.Config{
			RootCAs:    sysCerts,
			ServerName: u.Hostname(),
		}
		if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" {
			tlsConfig.InsecureSkipVerify = true
		}

		dialer := websocket.Dialer{
			TLSClientConfig:  tlsConfig,
			HandshakeTimeout: 10 * time.Second,
			NetDial: func(network, addr string) (net.Conn, error) {
				return net.DialTimeout(network, addr, 5*time.Second)
			},
		}

		headers := http.Header{}
		headers.Set("X-Device-ID", c.deviceID)
		headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		conn, _, err := dialer.DialContext(c.ctx, u.String(), headers)
		if err != nil {
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			time.Sleep(5 * time.Second)
			continue
		}

		c.mu.Lock()
		c.conn = conn
		c.connected = true
		c.mu.Unlock()

		// Read pump
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			if len(msg) > 30 && c.onPacket != nil {
				// Format: NATBYPASS:RELAY:<src>:<dest>:<payload>
				c.onPacket("relay", msg)
			}
		}

		c.mu.Lock()
		c.connected = false
		if c.conn != nil {
			_ = c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()

		time.Sleep(2 * time.Second)
	}
}

// Close disconnects the relay client.
func (c *WSSRelayClient) Close() error {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}