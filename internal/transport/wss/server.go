// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package wss

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	// maxWSSAuthClockSkew is the maximum allowed skew between client and server clocks (in seconds).
	// 45 seconds provides ample tolerance for NTP time drift while preventing replay attacks.
	maxWSSAuthClockSkew = 45
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32768,
	WriteBufferSize: 32768,
	// CheckOrigin returns true because NatBypass WSS relay is strictly an internal daemon-to-daemon
	// transport (not accessed by browser WebApps/cross-origin pages). Authentication is enforced
	// cryptographically via HMAC-SHA256 signature in X-Auth-Token and timestamp validation.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// WSSRelayServer is an HTTP handler that terminates and multiplexes mesh tunnels over WebSockets.
type WSSRelayServer struct {
	networkKey [32]byte
	clients    map[string]*clientSession
	mu         sync.RWMutex
}

type clientSession struct {
	conn    *websocket.Conn
	devID   string
	writeMu sync.Mutex
	closed  bool
}

func (cs *clientSession) Close() error {
	cs.writeMu.Lock()
	defer cs.writeMu.Unlock()
	if cs.closed {
		return nil
	}
	cs.closed = true
	if cs.conn != nil {
		return cs.conn.Close()
	}
	return nil
}

func (cs *clientSession) Send(msgType int, data []byte, timeout time.Duration) error {
	cs.writeMu.Lock()
	defer cs.writeMu.Unlock()
	if cs.closed || cs.conn == nil {
		return errors.New("client session closed")
	}
	_ = cs.conn.SetWriteDeadline(time.Now().Add(timeout))
	return cs.conn.WriteMessage(msgType, data)
}

// NewWSSRelayServer creates a new WebSocket relay handler.
func NewWSSRelayServer(networkKey [32]byte) *WSSRelayServer {
	return &WSSRelayServer{
		networkKey: networkKey,
		clients:    make(map[string]*clientSession),
	}
}

// ServeHTTP implements http.Handler for WebSocket upgrades.
func (s *WSSRelayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	devID := r.Header.Get("X-Device-ID")
	tsStr := r.Header.Get("X-Auth-Timestamp")
	token := r.Header.Get("X-Auth-Token")

	if devID == "" || tsStr == "" || token == "" {
		http.Error(w, "Unauthorized: missing mesh authentication headers", http.StatusUnauthorized)
		return
	}

	// Validate timestamp within 45 seconds to strictly prevent replay attacks
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	now := time.Now().Unix()
	if err != nil || now-ts > maxWSSAuthClockSkew || ts-now > maxWSSAuthClockSkew {
		http.Error(w, "Unauthorized: invalid or expired timestamp", http.StatusUnauthorized)
		return
	}

	// Validate HMAC
	mac := hmac.New(sha256.New, s.networkKey[:])
	mac.Write([]byte(devID + ":" + tsStr))
	expectedToken := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(token), []byte(expectedToken)) {
		http.Error(w, "Unauthorized: invalid auth token", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Debug().Err(err).Msg("🔒 WSS Server: upgrade failed")
		return
	}

	sess := &clientSession{
		conn:  conn,
		devID: devID,
	}

	s.mu.Lock()
	if old, exists := s.clients[devID]; exists && old != nil {
		_ = old.Close()
	}
	s.clients[devID] = sess
	s.mu.Unlock()

	log.Info().Str("devID", devID).Str("remote", conn.RemoteAddr().String()).Msg("🔒 WSS Server: client connected")

	defer func() {
		s.mu.Lock()
		if current, exists := s.clients[devID]; exists && current == sess {
			delete(s.clients, devID)
		}
		s.mu.Unlock()
		_ = sess.Close()
		log.Info().Str("devID", devID).Msg("🔒 WSS Server: client disconnected")
	}()

	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if msgType != websocket.BinaryMessage || len(data) < 2 {
			continue
		}

		// Inbound format: [dstDevIDLen 1 byte][dstDevID string][raw IP packet]
		dstLen := int(data[0])
		if dstLen == 0 || 1+dstLen > len(data) {
			continue
		}
		dstDevID := string(data[1 : 1+dstLen])
		payload := data[1+dstLen:]

		// Forwarding to target client
		s.mu.RLock()
		targetSess := s.clients[dstDevID]
		s.mu.RUnlock()

		if targetSess == nil {
			continue
		}

		// Outbound format: [srcDevIDLen 1 byte][srcDevID string][raw IP packet]
		srcLen := len(devID)
		fwdFrame := make([]byte, 1+srcLen+len(payload))
		fwdFrame[0] = byte(srcLen)
		copy(fwdFrame[1:1+srcLen], []byte(devID))
		copy(fwdFrame[1+srcLen:], payload)

		if err := targetSess.Send(websocket.BinaryMessage, fwdFrame, 2*time.Second); err != nil {
			// Session is dead: clean it up to prevent resource leaks and TOCTOU writes
			s.mu.Lock()
			if current, exists := s.clients[dstDevID]; exists && current == targetSess {
				delete(s.clients, dstDevID)
			}
			s.mu.Unlock()
			_ = targetSess.Close()
		}
	}
}

// ClientCount returns the number of currently active WSS clients.
func (s *WSSRelayServer) ClientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}
