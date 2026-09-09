// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package wss

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// WSSClient manages a stealth WebSocket over TLS connection to a mesh relay node.
type WSSClient struct {
	serverURL  string
	myDevID    string
	networkKey [32]byte
	sni        string

	conn     *websocket.Conn
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	onPacket func(srcDevID string, payload []byte)
	isUp     bool
}

// NewWSSClient creates a new WSS relay client.
func NewWSSClient(ctx context.Context, serverURL, myDevID string, networkKey [32]byte, sni string, onPacket func(srcDevID string, payload []byte)) *WSSClient {
	cCtx, cancel := context.WithCancel(ctx)
	return &WSSClient{
		serverURL:  serverURL,
		myDevID:    myDevID,
		networkKey: networkKey,
		sni:        sni,
		ctx:        cCtx,
		cancel:     cancel,
		onPacket:   onPacket,
	}
}

// Start connects to the WSS relay and maintains connection with exponential backoff.
func (c *WSSClient) Start() {
	go c.lifecycleLoop()
}

func (c *WSSClient) lifecycleLoop() {
	backoff := 1 * time.Second
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if err := c.connect(); err != nil {
			log.Debug().Err(err).Str("url", c.serverURL).Msg("🔒 WSS: connect failed, retrying")
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}

		backoff = 1 * time.Second
		c.readLoop()
	}
}

func (c *WSSClient) connect() error {
	u, err := url.Parse(c.serverURL)
	if err != nil {
		return err
	}

	// Generate HMAC authentication token based on timestamp and networkKey
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, c.networkKey[:])
	mac.Write([]byte(c.myDevID + ":" + ts))
	token := hex.EncodeToString(mac.Sum(nil))

	headers := make(http.Header)
	headers.Set("X-Device-ID", c.myDevID)
	headers.Set("X-Auth-Timestamp", ts)
	headers.Set("X-Auth-Token", token)

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if c.sni != "" {
		tlsConf.ServerName = c.sni
	} else if u.Hostname() != "" {
		tlsConf.ServerName = u.Hostname()
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConf,
		HandshakeTimeout: 5 * time.Second,
	}

	conn, resp, err := dialer.DialContext(c.ctx, u.String(), headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("wss dial error: %w (status %d)", err, resp.StatusCode)
		}
		return fmt.Errorf("wss dial error: %w", err)
	}

	c.mu.Lock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = conn
	c.isUp = true
	c.mu.Unlock()

	log.Info().Str("relay", u.Host).Msg("🔒 WSS: connected to stealth relay")
	return nil
}

func (c *WSSClient) readLoop() {
	defer func() {
		c.mu.Lock()
		c.isUp = false
		if c.conn != nil {
			_ = c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		msgType, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		if msgType != websocket.BinaryMessage || len(data) < 2 {
			continue
		}

		// Frame format: [srcDevIDLen 1 byte][srcDevID string][raw IP packet]
		idLen := int(data[0])
		if idLen == 0 || 1+idLen > len(data) {
			continue
		}
		srcDevID := string(data[1 : 1+idLen])
		payload := data[1+idLen:]

		if c.onPacket != nil {
			c.onPacket(srcDevID, payload)
		}
	}
}

// SendPacket frames an IP tunnel packet to target device ID over the WSS relay.
func (c *WSSClient) SendPacket(targetDevID string, payload []byte) error {
	c.mu.Lock()
	conn := c.conn
	isUp := c.isUp
	c.mu.Unlock()

	if !isUp || conn == nil || targetDevID == "" || len(payload) == 0 {
		return fmt.Errorf("wss relay not connected or invalid target")
	}

	idLen := len(targetDevID)
	if idLen > 255 {
		return fmt.Errorf("target device ID too long")
	}

	// Traffic shaping: inject micro-jitter (1..15ms) for interactive packets (<512 bytes)
	// to disrupt uniform Inter-Arrival Time (IAT) analysis by TSPU/DPI classifiers.
	if len(payload) < 512 {
		var jitterByte [1]byte
		if _, err := io.ReadFull(rand.Reader, jitterByte[:]); err == nil {
			jitterMs := 1 + int(jitterByte[0]%15) // 1..15 ms
			time.Sleep(time.Duration(jitterMs) * time.Millisecond)
		}
	}

	frame := make([]byte, 1+idLen+len(payload))
	frame[0] = byte(idLen)
	copy(frame[1:1+idLen], []byte(targetDevID))
	copy(frame[1+idLen:], payload)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("wss connection closed")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	return c.conn.WriteMessage(websocket.BinaryMessage, frame)
}

// IsConnected returns true if the WSS tunnel is established.
func (c *WSSClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isUp
}

// Close disconnects and releases resources.
func (c *WSSClient) Close() {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isUp = false
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}
