// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	TCPRelayMagic              = "NATBYPASS:PRELAY"
	TCPRegMagic                = "NATBYPASS:PREG"
	TCPKeepAlive               = "NATBYPASS:PKEEPALIVE"
	TCPKeepAliveAck            = "NATBYPASS:PKEEPALIVE_ACK"
	TCPErrMeteredOrLowBattery  = "NATBYPASS:PERR metered_or_low_battery"
	TCPErrQuotaExceeded        = "NATBYPASS:PERR quota_exceeded"
	MaxTCPRelayPayload         = 65535
)

// TCPRelayServerConfig configures the Peer-as-Relay TCP service running on port 443 (or configured port).
type TCPRelayServerConfig struct {
	ListenAddr      string // e.g. ":443" or ":0"
	DeviceID        string
	RelayQuotaGBDay int // Daily relay quota in GB (0 = unlimited)
	IsMetered       func() bool
	BatteryLow      func() bool
	OnPacket        func(srcDevID, dstDevID string, payload []byte)
	OnRelayTraffic  func(bytes int64)
}

// TCPRelayServer accepts TCP connections from peers and proxies traffic between them,
// strictly enforcing mobile battery, metered network, and daily quota constraints.
type TCPRelayServer struct {
	cfg        TCPRelayServerConfig
	listener   net.Listener
	conns      map[string]net.Conn
	connsMu    sync.RWMutex
	dailyBytes atomic.Int64
	activeDate string
	dateMu     sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	closed     atomic.Bool
}

// NewTCPRelayServer creates and starts a TCPRelayServer.
func NewTCPRelayServer(cfg TCPRelayServerConfig) (*TCPRelayServer, error) {
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":443"
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind TCP relay listener on %s: %w", listenAddr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &TCPRelayServer{
		cfg:        cfg,
		listener:   ln,
		conns:      make(map[string]net.Conn),
		activeDate: time.Now().Format("2006-01-02"),
		ctx:        ctx,
		cancel:     cancel,
	}

	go s.acceptLoop()
	return s, nil
}

// Addr returns the listener network address.
func (s *TCPRelayServer) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Port returns the TCP port bound by this server.
func (s *TCPRelayServer) Port() int {
	if s.listener != nil {
		if tcpAddr, ok := s.listener.Addr().(*net.TCPAddr); ok {
			return tcpAddr.Port
		}
	}
	return 0
}

// RelayedBytes returns the total bytes forwarded during the active calendar day.
func (s *TCPRelayServer) RelayedBytes() int64 {
	return s.dailyBytes.Load()
}

// Close gracefully terminates the TCP relay listener and all active peer connections.
func (s *TCPRelayServer) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.cancel()

	var firstErr error
	if s.listener != nil {
		firstErr = s.listener.Close()
	}

	s.connsMu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[string]net.Conn)
	s.connsMu.Unlock()

	return firstErr
}

func (s *TCPRelayServer) checkResourceConstraints() error {
	if s.cfg.IsMetered != nil && s.cfg.IsMetered() {
		return errors.New("relay rejected: metered network active")
	}
	if s.cfg.BatteryLow != nil && s.cfg.BatteryLow() {
		return errors.New("relay rejected: low battery active")
	}

	if s.cfg.RelayQuotaGBDay > 0 {
		today := time.Now().Format("2006-01-02")
		s.dateMu.Lock()
		if s.activeDate != today {
			s.activeDate = today
			s.dailyBytes.Store(0)
		}
		s.dateMu.Unlock()

		usedGB := s.dailyBytes.Load() / (1024 * 1024 * 1024)
		if int(usedGB) >= s.cfg.RelayQuotaGBDay {
			return errors.New("relay rejected: daily quota exceeded")
		}
	}
	return nil
}

func (s *TCPRelayServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		go s.handleClient(conn)
	}
}

func (s *TCPRelayServer) handleClient(conn net.Conn) {
	defer conn.Close()

	if err := s.checkResourceConstraints(); err != nil {
		if strings.Contains(err.Error(), "quota") {
			_, _ = fmt.Fprintf(conn, "%s\n", TCPErrQuotaExceeded)
		} else {
			_, _ = fmt.Fprintf(conn, "%s\n", TCPErrMeteredOrLowBattery)
		}
		return
	}

	// 5-second deadline for peer registration handshake
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)

	// Expected: NATBYPASS:PREG <deviceID>
	parts := strings.Split(line, " ")
	if len(parts) != 2 || parts[0] != TCPRegMagic || parts[1] == "" {
		return
	}
	clientDevID := parts[1]

	// Reset deadline for persistent connection
	_ = conn.SetDeadline(time.Time{})

	s.connsMu.Lock()
	if old, exists := s.conns[clientDevID]; exists && old != nil {
		_ = old.Close()
	}
	s.conns[clientDevID] = conn
	s.connsMu.Unlock()

	defer func() {
		s.connsMu.Lock()
		if cur, ok := s.conns[clientDevID]; ok && cur == conn {
			delete(s.conns, clientDevID)
		}
		s.connsMu.Unlock()
	}()

	// Send registration ACK
	_, _ = fmt.Fprintf(conn, "NATBYPASS:PREG_OK %s\n", s.cfg.DeviceID)

	for {
		if s.closed.Load() {
			return
		}
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Read next frame line
		headerLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		headerLine = strings.TrimSpace(headerLine)
		if headerLine == "" {
			continue
		}

		// KeepAlive
		if strings.HasPrefix(headerLine, TCPKeepAlive) {
			_, _ = fmt.Fprintf(conn, "%s\n", TCPKeepAliveAck)
			continue
		}

		// Relay Packet: NATBYPASS:PRELAY <srcDevID> <dstDevID> <len>
		if strings.HasPrefix(headerLine, TCPRelayMagic) {
			hParts := strings.Split(headerLine, " ")
			if len(hParts) != 4 {
				return
			}
			srcDevID := hParts[1]
			dstDevID := hParts[2]
			payloadLen, err := strconv.Atoi(hParts[3])
			if err != nil || payloadLen <= 0 || payloadLen > MaxTCPRelayPayload {
				return
			}

			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}

			// Validate ongoing resource conditions
			if err := s.checkResourceConstraints(); err != nil {
				return
			}

			s.dailyBytes.Add(int64(payloadLen))
			if s.cfg.OnRelayTraffic != nil {
				s.cfg.OnRelayTraffic(int64(payloadLen))
			}

			// Target is this relay server itself
			if dstDevID == s.cfg.DeviceID {
				if s.cfg.OnPacket != nil {
					s.cfg.OnPacket(srcDevID, dstDevID, payload)
				}
				continue
			}

			// Forward to destination peer
			s.connsMu.RLock()
			dstConn := s.conns[dstDevID]
			s.connsMu.RUnlock()

			if dstConn != nil {
				fwdHeader := fmt.Sprintf("%s %s %s %d\n", TCPRelayMagic, srcDevID, dstDevID, payloadLen)
				fwdPacket := append([]byte(fwdHeader), payload...)
				_ = dstConn.SetWriteDeadline(time.Now().Add(3 * time.Second))
				_, _ = dstConn.Write(fwdPacket)
				_ = dstConn.SetWriteDeadline(time.Time{})
			}
		}
	}
}

// TCPRelayClient connects to a Peer-as-Relay node and forwards encrypted L3 packets.
type TCPRelayClient struct {
	serverAddr string
	myDevID    string
	conn       net.Conn
	rawFd      atomic.Int32
	mu         sync.Mutex
	connected  atomic.Bool
	onPacket   func(srcDevID string, payload []byte)
	ctx        context.Context
	cancel     context.CancelFunc
	protectFn  func(fd int) error
}

// NewTCPRelayClient creates a TCPRelayClient for communicating via a peer relay.
func NewTCPRelayClient(serverAddr, myDevID string, onPacket func(srcDevID string, payload []byte), protectFn func(fd int) error) *TCPRelayClient {
	ctx, cancel := context.WithCancel(context.Background())
	c := &TCPRelayClient{
		serverAddr: serverAddr,
		myDevID:    myDevID,
		onPacket:   onPacket,
		ctx:        ctx,
		cancel:     cancel,
		protectFn:  protectFn,
	}
	c.rawFd.Store(-1)
	return c
}

// Connect establishes a TCP connection to the relay server and performs peer registration.
func (c *TCPRelayClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected.Load() {
		return nil
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.serverAddr)
	if err != nil {
		return fmt.Errorf("TCP relay dial failed to %s: %w", c.serverAddr, err)
	}

	// Extract raw socket fd for Android VpnService.protect()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if rawConn, err := tcpConn.SyscallConn(); err == nil {
			_ = rawConn.Control(func(fd uintptr) {
				c.rawFd.Store(int32(fd))
				if c.protectFn != nil {
					_ = c.protectFn(int(fd))
				}
			})
		}
	}

	// Handshake registration: NATBYPASS:PREG <myDevID>\n
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "%s %s\n", TCPRegMagic, c.myDevID); err != nil {
		_ = conn.Close()
		return err
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to read relay handshake response: %w", err)
	}
	resp = strings.TrimSpace(resp)
	if strings.HasPrefix(resp, "NATBYPASS:PERR") {
		_ = conn.Close()
		return fmt.Errorf("relay server rejected connection: %s", resp)
	}
	if !strings.HasPrefix(resp, "NATBYPASS:PREG_OK") {
		_ = conn.Close()
		return fmt.Errorf("unexpected handshake response: %s", resp)
	}

	_ = conn.SetDeadline(time.Time{})
	c.conn = conn
	c.connected.Store(true)

	go c.readLoop(reader)
	go c.keepAliveLoop()

	return nil
}

// SendPacket transmits an IP datagram through the TCP relay to targetDeviceID.
func (c *TCPRelayClient) SendPacket(targetDeviceID string, payload []byte) error {
	if !c.connected.Load() {
		return errors.New("TCP relay not connected")
	}
	if len(payload) == 0 || len(payload) > MaxTCPRelayPayload {
		return errors.New("invalid payload size")
	}

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return errors.New("TCP relay socket is nil")
	}

	header := fmt.Sprintf("%s %s %s %d\n", TCPRelayMagic, c.myDevID, targetDeviceID, len(payload))
	fullMsg := append([]byte(header), payload...)

	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := conn.Write(fullMsg)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// IsConnected returns whether the client has an active TCP connection to the relay server.
func (c *TCPRelayClient) IsConnected() bool {
	return c.connected.Load()
}

// GetSocketFd returns the raw socket file descriptor for Android protect().
func (c *TCPRelayClient) GetSocketFd() int {
	return int(c.rawFd.Load())
}

// Close closes the TCP relay client connection and stops worker routines.
func (c *TCPRelayClient) Close() error {
	c.cancel()
	c.connected.Store(false)
	c.rawFd.Store(-1)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *TCPRelayClient) readLoop(reader *bufio.Reader) {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			c.connected.Store(false)
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == TCPKeepAliveAck {
			continue
		}

		if strings.HasPrefix(line, TCPRelayMagic) {
			parts := strings.Split(line, " ")
			if len(parts) != 4 {
				continue
			}
			srcDevID := parts[1]
			payloadLen, err := strconv.Atoi(parts[3])
			if err != nil || payloadLen <= 0 || payloadLen > MaxTCPRelayPayload {
				continue
			}

			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(reader, payload); err != nil {
				c.connected.Store(false)
				return
			}

			if c.onPacket != nil {
				c.onPacket(srcDevID, payload)
			}
		}
	}
}

func (c *TCPRelayClient) keepAliveLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if !c.connected.Load() {
				continue
			}
			c.mu.Lock()
			conn := c.conn
			c.mu.Unlock()

			if conn != nil {
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = fmt.Fprintf(conn, "%s\n", TCPKeepAlive)
				_ = conn.SetWriteDeadline(time.Time{})
			}
		}
	}
}
