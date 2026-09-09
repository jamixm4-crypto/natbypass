// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package quic

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrSessionNotFound = errors.New("quic: session not found")
)

// SessionManager manages active peer QUIC sessions, DCID routing, and connection migrations.
type SessionManager struct {
	mu             sync.RWMutex
	sessionsByPeer map[string]*Session
	sessionsByDCID map[[DCIDLen]byte]*Session
}

// NewSessionManager creates a new QUIC session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessionsByPeer: make(map[string]*Session),
		sessionsByDCID: make(map[[DCIDLen]byte]*Session),
	}
}

// GetOrCreateSession gets or creates a QUIC session for peerID.
func (m *SessionManager) GetOrCreateSession(peerID string, remoteAddr string, cKey [32]byte) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	if sess, ok := m.sessionsByPeer[peerID]; ok {
		if remoteAddr != "" {
			sess.HandleMigration(remoteAddr)
		}
		return sess
	}

	sess := NewSession(peerID, remoteAddr, cKey)
	m.sessionsByPeer[peerID] = sess
	m.sessionsByDCID[sess.dcid] = sess
	return sess
}

// GetSession returns an existing session for peerID, if any.
func (m *SessionManager) GetSession(peerID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessionsByPeer[peerID]
	return sess, ok
}

// GetSessionByDCID returns a session matching the 8-byte DCID.
func (m *SessionManager) GetSessionByDCID(dcid []byte) (*Session, bool) {
	if len(dcid) < DCIDLen {
		return nil, false
	}
	var key [DCIDLen]byte
	copy(key[:], dcid[:DCIDLen])

	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessionsByDCID[key]
	return sess, ok
}

// RouteInbound parses an inbound QUIC 1-RTT short header packet, verifies decryption,
// detects connection migration, and returns the unpacked payload.
func (m *SessionManager) RouteInbound(packet []byte, fromAddr string, cKey [32]byte) (payload []byte, peerID string, migrated bool, err error) {
	decPayload, _, dcid, err := ParseQUICDataPacket(packet, cKey)
	if err != nil {
		return nil, "", false, err
	}

	sess, found := m.GetSessionByDCID(dcid)
	if found && sess != nil {
		migrated = sess.HandleMigration(fromAddr)
		peerID = sess.peerID
	}

	return decPayload, peerID, migrated, nil
}

// Prune removes stale sessions that have not received packets within maxAge.
func (m *SessionManager) Prune(maxAge time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	pruned := 0
	for peerID, sess := range m.sessionsByPeer {
		sess.mu.RLock()
		lastSeen := sess.lastSeen
		dcid := sess.dcid
		sess.mu.RUnlock()

		if now.Sub(lastSeen) > maxAge {
			delete(m.sessionsByPeer, peerID)
			delete(m.sessionsByDCID, dcid)
			pruned++
		}
	}
	return pruned
}
