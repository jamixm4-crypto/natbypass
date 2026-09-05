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
		return nil, fmt.Errorf("tcp simultaneous listen error: %w", err)
	}
	defer listener.Close()

	connChan := make(chan net.Conn, 2)
	errChan := make(chan error, 2)

	// Accept worker
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			connChan <- conn
		} else {
			errChan <- err
		}
	}()

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

// TCPDirectManager manages direct P2P TCP streams established via TCP Simultaneous Open.
type TCPDirectManager struct {
	conns  map[string]net.Conn
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

// NewTCPDirectManager creates a new manager for P2P TCP streams.
func NewTCPDirectManager(ctx context.Context) *TCPDirectManager {
	cCtx, cancel := context.WithCancel(ctx)
	return &TCPDirectManager{
		conns:  make(map[string]net.Conn),
		ctx:    cCtx,
		cancel: cancel,
	}
}

// HasConn returns true if an active TCP stream exists for the peer.
func (m *TCPDirectManager) HasConn(deviceID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.conns[deviceID]
	return ok
}

// RegisterConn registers a newly established TCP connection and starts reading length-prefixed frames.
func (m *TCPDirectManager) RegisterConn(deviceID string, conn net.Conn, onPacket func(remoteAddr *net.UDPAddr, payload []byte)) {
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

// SendPacket writes a length-prefixed frame to the peer's TCP connection.
func (m *TCPDirectManager) SendPacket(deviceID string, payload []byte) error {
	m.mu.RLock()
	conn, exists := m.conns[deviceID]
	m.mu.RUnlock()
	if !exists || conn == nil {
		return fmt.Errorf("no active tcp stream for peer %s", deviceID)
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
	for _, c := range m.conns {
		_ = c.Close()
	}
	m.conns = make(map[string]net.Conn)
}

