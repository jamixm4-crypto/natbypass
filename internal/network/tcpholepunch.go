// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/transport/shadowtls"
)

// AttemptTCPSimultaneousOpen attempts TCP Simultaneous Open (RFC 9293 Section 3.5 / RFC 5382).
// It simultaneously listens and dials from the exact same local port using SO_REUSEADDR / SO_REUSEPORT,
// allowing two peers behind NAT to transition from SYN-SENT to SYN-RECEIVED to ESTABLISHED.
func AttemptTCPSimultaneousOpen(ctx context.Context, localPort int, targetAddr string) (net.Conn, error) {
	if targetAddr == "" {
		return nil, fmt.Errorf("empty target address")
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketReusePort(c)
		},
	}

	localAddrStr := fmt.Sprintf("0.0.0.0:%d", localPort)

	// 1. Open Listener on the same local port to accept incoming SYN-ACK
	listener, err := lc.Listen(ctx, "tcp4", localAddrStr)
	if err != nil {
		// If port is already listened on by manager's main listener or another socket,
		// don't abort — proceed with simultaneous dial from the same local port
		listener = nil
	} else {
		defer listener.Close()
	}

	connChan := make(chan net.Conn, 2)
	errChan := make(chan error, 2)

	// Accept worker only if listener successfully bound
	if listener != nil {
		go func() {
			conn, err := listener.Accept()
			if err == nil {
				connChan <- conn
			} else {
				errChan <- err
			}
		}()
	}

	// 2. Simultaneously dial the target address from the same local port
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP("0.0.0.0"),
			Port: localPort,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketReusePort(c)
		},
		Timeout: 3500 * time.Millisecond,
	}

	go func() {
		conn, err := dialer.DialContext(ctx, "tcp4", targetAddr)
		if err == nil {
			connChan <- conn
		} else {
			errChan <- err
		}
	}()

	// Wait for whichever connects first: incoming Accept or outgoing Dial
	select {
	case conn := <-connChan:
		return conn, nil
	case <-time.After(3600 * time.Millisecond):
		return nil, fmt.Errorf("tcp simultaneous open timed out to %s", targetAddr)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TCPDirectManager manages direct P2P TCP streams established via TCP Simultaneous Open or direct TCP dial.
type TCPDirectManager struct {
	conns      map[string]net.Conn
	connecting map[string]time.Time
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	listener   net.Listener
	listenPort int
	myDeviceID string
	networkKey [32]byte
	hasKey     bool
	sni        string
	onPacket   func(remoteAddr *net.UDPAddr, payload []byte)
	onPeerUp   func(peerID string, remoteAddr string)
}

// NewTCPDirectManager creates a new manager for P2P TCP streams.
func NewTCPDirectManager(ctx context.Context) *TCPDirectManager {
	cCtx, cancel := context.WithCancel(ctx)
	return &TCPDirectManager{
		conns:      make(map[string]net.Conn),
		connecting: make(map[string]time.Time),
		ctx:        cCtx,
		cancel:     cancel,
		sni:        shadowtls.DefaultSNI,
	}
}

// SetNetworkKey sets the secret network key used for ShadowTLS TLS 1.3 obfuscation.
func (m *TCPDirectManager) SetNetworkKey(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key == "" {
		m.hasKey = false
		m.networkKey = [32]byte{}
		return
	}
	m.networkKey = crypto.DeriveKey(key)
	m.hasKey = true
}

// SetSNI sets the target server name indication domain for TLS 1.3 masquerade.
func (m *TCPDirectManager) SetSNI(sni string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sni != "" {
		m.sni = sni
	}
}

// SetDeviceID sets the local device ID used for TCP handshakes.
func (m *TCPDirectManager) SetDeviceID(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.myDeviceID = id
}

// SetOnPacket sets the default incoming packet callback.
func (m *TCPDirectManager) SetOnPacket(fn func(remoteAddr *net.UDPAddr, payload []byte)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPacket = fn
}

// SetOnPeerUp sets the callback invoked when a direct TCP connection is established.
func (m *TCPDirectManager) SetOnPeerUp(fn func(peerID string, remoteAddr string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPeerUp = fn
}

// Port returns the listening TCP port, or 0 if not listening.
func (m *TCPDirectManager) Port() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listenPort
}

// StartListener starts an inbound TCP listener on preferredPort (or dynamic port if taken).
func (m *TCPDirectManager) StartListener(preferredPort int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener != nil {
		return m.listenPort, nil
	}

	var ln net.Listener
	var err error

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketReusePort(c)
		},
	}

	if preferredPort > 0 {
		ln, err = lc.Listen(m.ctx, "tcp4", fmt.Sprintf("0.0.0.0:%d", preferredPort))
	}
	if err != nil || preferredPort <= 0 {
		ln, err = lc.Listen(m.ctx, "tcp4", "0.0.0.0:0")
		if err != nil {
			return 0, fmt.Errorf("failed to start TCP listener: %w", err)
		}
	}

	m.listener = ln
	m.listenPort = ln.Addr().(*net.TCPAddr).Port

	// Attempt UPnP TCP port mapping for gateway router traversal
	go func(port int) {
		up := NewUPnPClient()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = up.AddPortMapping(ctx, port, port, "TCP", "NatBypass ShadowTLS TCP", 3600)
	}(m.listenPort)

	go m.acceptLoop(ln)
	return m.listenPort, nil
}

func (m *TCPDirectManager) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-m.ctx.Done():
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		go func(c net.Conn) {
			m.mu.RLock()
			hasKey := m.hasKey
			netKey := m.networkKey
			myID := m.myDeviceID
			onPkt := m.onPacket
			onUp := m.onPeerUp
			m.mu.RUnlock()

			if hasKey {
				// 1. Stealth TLS 1.3 Server Handshake (DPI bypass)
				if err := shadowtls.ServerHandshake(c, netKey, 5*time.Second); err != nil {
					_ = c.Close()
					return
				}
				tlsConn := shadowtls.NewShadowTLSConn(c, netKey)
				_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

				// 2. Read remote peer ID inside encrypted TLS 1.3 Application Data frame
				peerIDPkt, err := tlsConn.ReadPacket()
				if err != nil || len(peerIDPkt) == 0 {
					_ = tlsConn.Close()
					return
				}
				remotePeerID := string(peerIDPkt)

				// 3. Send our peer ID inside encrypted TLS 1.3 Application Data frame
				if err := tlsConn.WritePacket([]byte(myID)); err != nil {
					_ = tlsConn.Close()
					return
				}
				_ = tlsConn.SetDeadline(time.Time{})

				m.RegisterConn(remotePeerID, tlsConn, onPkt)
				if onUp != nil {
					onUp(remotePeerID, c.RemoteAddr().String())
				}
				return
			}

			// Fallback: plaintext NBTCP handshake
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			magic := make([]byte, 5)
			if _, err := io.ReadFull(c, magic); err != nil || string(magic) != "NBTCP" {
				_ = c.Close()
				return
			}
			idLen := make([]byte, 1)
			if _, err := io.ReadFull(c, idLen); err != nil || idLen[0] == 0 {
				_ = c.Close()
				return
			}
			peerIDBuf := make([]byte, idLen[0])
			if _, err := io.ReadFull(c, peerIDBuf); err != nil {
				_ = c.Close()
				return
			}
			remotePeerID := string(peerIDBuf)

			resp := []byte("NBTCP")
			resp = append(resp, byte(len(myID)))
			resp = append(resp, []byte(myID)...)
			if _, err := c.Write(resp); err != nil {
				_ = c.Close()
				return
			}
			_ = c.SetDeadline(time.Time{})

			m.RegisterConn(remotePeerID, c, onPkt)
			if onUp != nil {
				onUp(remotePeerID, c.RemoteAddr().String())
			}
		}(conn)
	}
}

// ConnectPeer initiates a direct TCP connection or TCP Simultaneous Open to the remote peer.
func (m *TCPDirectManager) ConnectPeer(peerID, targetAddr string, localPort int) error {
	if targetAddr == "" {
		return fmt.Errorf("empty target address")
	}

	m.mu.Lock()
	if _, ok := m.conns[peerID]; ok {
		m.mu.Unlock()
		return nil
	}
	if lastAttempt, inProgress := m.connecting[peerID]; inProgress && time.Since(lastAttempt) < 6*time.Second {
		m.mu.Unlock()
		return nil // Dial already in-flight
	}
	m.connecting[peerID] = time.Now()
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.connecting, peerID)
		m.mu.Unlock()
	}()

	if localPort <= 0 {
		localPort = m.Port()
	}

	var conn net.Conn
	var err error

	// 1. Dial with local port binding + SO_REUSEADDR for simultaneous open NAT hole punching
	if localPort > 0 {
		dialer := net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP:   net.ParseIP("0.0.0.0"),
				Port: localPort,
			},
			Control: func(network, address string, c syscall.RawConn) error {
				return setSocketReusePort(c)
			},
			Timeout: 4 * time.Second,
		}
		conn, err = dialer.DialContext(m.ctx, "tcp4", targetAddr)
	}

	// 2. Fallback to standard dialer
	if err != nil || conn == nil {
		if m.HasConn(peerID) {
			return nil
		}
		stdDialer := net.Dialer{Timeout: 3500 * time.Millisecond}
		conn, err = stdDialer.DialContext(m.ctx, "tcp", targetAddr)
	}

	// 3. Fallback to full simultaneous open
	if err != nil && localPort > 0 {
		if m.HasConn(peerID) {
			return nil
		}
		sCtx, sCancel := context.WithTimeout(m.ctx, 3600*time.Millisecond)
		defer sCancel()
		conn, err = AttemptTCPSimultaneousOpen(sCtx, localPort, targetAddr)
	}

	if err != nil || conn == nil {
		if m.HasConn(peerID) {
			return nil
		}
		return fmt.Errorf("tcp connect to %s failed: %w", targetAddr, err)
	}

	if m.HasConn(peerID) {
		_ = conn.Close()
		return nil
	}

	m.mu.RLock()
	hasKey := m.hasKey
	netKey := m.networkKey
	sni := m.sni
	myID := m.myDeviceID
	onPkt := m.onPacket
	onUp := m.onPeerUp
	m.mu.RUnlock()

	if hasKey {
		// 1. Stealth TLS 1.3 Client Handshake (DPI bypass)
		if err := shadowtls.ClientHandshake(conn, sni, netKey, 5*time.Second); err != nil {
			_ = conn.Close()
			return fmt.Errorf("shadowtls handshake failed: %w", err)
		}
		tlsConn := shadowtls.NewShadowTLSConn(conn, netKey)
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

		// 2. Send our peer ID inside encrypted TLS 1.3 Application Data frame
		if err := tlsConn.WritePacket([]byte(myID)); err != nil {
			_ = tlsConn.Close()
			return err
		}

		// 3. Receive remote peer ID inside encrypted TLS 1.3 Application Data frame
		respPkt, err := tlsConn.ReadPacket()
		if err != nil || len(respPkt) == 0 {
			_ = tlsConn.Close()
			return fmt.Errorf("failed to read remote peer id: %w", err)
		}
		_ = tlsConn.SetDeadline(time.Time{})

		m.RegisterConn(peerID, tlsConn, onPkt)
		if onUp != nil {
			onUp(peerID, targetAddr)
		}
		return nil
	}

	// Fallback: plaintext NBTCP handshake
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	req := []byte("NBTCP")
	req = append(req, byte(len(myID)))
	req = append(req, []byte(myID)...)
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return err
	}

	magic := make([]byte, 5)
	if _, err := io.ReadFull(conn, magic); err != nil || string(magic) != "NBTCP" {
		_ = conn.Close()
		return fmt.Errorf("invalid tcp handshake from %s", targetAddr)
	}
	idLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, idLen); err != nil || idLen[0] == 0 {
		_ = conn.Close()
		return fmt.Errorf("invalid handshake id length from %s", targetAddr)
	}
	peerIDBuf := make([]byte, idLen[0])
	if _, err := io.ReadFull(conn, peerIDBuf); err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to read remote peer id from %s", targetAddr)
	}
	_ = conn.SetDeadline(time.Time{})

	m.RegisterConn(peerID, conn, onPkt)
	if onUp != nil {
		onUp(peerID, targetAddr)
	}
	return nil
}

// HasConn returns true if an active TCP stream exists for the peer.
func (m *TCPDirectManager) HasConn(deviceID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.conns[deviceID]
	return ok
}

// RegisterConn registers a newly established TCP connection and starts reading packets.
func (m *TCPDirectManager) RegisterConn(deviceID string, conn net.Conn, onPacket func(remoteAddr *net.UDPAddr, payload []byte)) {
	if onPacket == nil {
		m.mu.RLock()
		onPacket = m.onPacket
		m.mu.RUnlock()
	}

	m.mu.Lock()
	if old, exists := m.conns[deviceID]; exists && old != nil {
		_ = old.Close()
	}
	m.conns[deviceID] = conn
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			if current, exists := m.conns[deviceID]; exists && current == conn {
				delete(m.conns, deviceID)
			}
			m.mu.Unlock()
			_ = conn.Close()
		}()

		var remoteUDP *net.UDPAddr
		if rTCP, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			remoteUDP = &net.UDPAddr{IP: rTCP.IP, Port: rTCP.Port}
		}

		// If wrapped in ShadowTLSConn, read via ReadPacket (decrypts and removes padding)
		if sConn, ok := conn.(*shadowtls.ShadowTLSConn); ok {
			for {
				select {
				case <-m.ctx.Done():
					return
				default:
				}
				_ = sConn.SetReadDeadline(time.Now().Add(25 * time.Second))
				pkt, err := sConn.ReadPacket()
				if err != nil {
					return
				}
				if onPacket != nil && len(pkt) > 0 {
					onPacket(remoteUDP, pkt)
				}
			}
		}

		// Fallback for standard length-prefixed raw TCP frames
		lenBuf := make([]byte, 2)
		for {
			select {
			case <-m.ctx.Done():
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			pLen := binary.BigEndian.Uint16(lenBuf)
			if pLen == 0 || pLen > 65535 {
				return
			}
			pktBuf := make([]byte, pLen)
			if _, err := io.ReadFull(conn, pktBuf); err != nil {
				return
			}
			if onPacket != nil {
				onPacket(remoteUDP, pktBuf)
			}
		}
	}()
}

// SendPacket writes a packet to the peer's TCP connection (encapsulated in TLS Application Data).
func (m *TCPDirectManager) SendPacket(deviceID string, payload []byte) error {
	m.mu.RLock()
	conn, exists := m.conns[deviceID]
	m.mu.RUnlock()
	if !exists || conn == nil {
		return fmt.Errorf("no active tcp stream for peer %s", deviceID)
	}

	if sConn, ok := conn.(*shadowtls.ShadowTLSConn); ok {
		_ = sConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		return sConn.WritePacket(payload)
	}

	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Write(frame)
	return err
}

// Close closes all managed TCP streams.
func (m *TCPDirectManager) Close() {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener != nil {
		_ = m.listener.Close()
		m.listener = nil
	}
	for _, c := range m.conns {
		_ = c.Close()
	}
	m.conns = make(map[string]net.Conn)
}

