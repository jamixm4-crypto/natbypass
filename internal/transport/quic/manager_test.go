// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package quic

import (
	"bytes"
	"testing"
	"time"
)

func TestSessionManager_LifecycleAndMigration(t *testing.T) {
	mgr := NewSessionManager()
	var testKey [32]byte
	copy(testKey[:], []byte("quic-test-secret-key-32-bytes!"))

	peerID := "peer-alpha"
	remoteAddr := "192.168.1.50:41234"

	sess := mgr.GetOrCreateSession(peerID, remoteAddr, testKey)
	if sess == nil {
		t.Fatal("expected non-nil session")
	}

	// Lookup by peer ID
	foundSess, ok := mgr.GetSession(peerID)
	if !ok || foundSess != sess {
		t.Errorf("failed to retrieve session by peer ID")
	}

	// Lookup by DCID
	foundByDCID, ok := mgr.GetSessionByDCID(sess.dcid[:])
	if !ok || foundByDCID != sess {
		t.Errorf("failed to retrieve session by DCID")
	}

	// Encapsulate data packet
	payload := []byte("hello-mesh-quic-packet")
	encPkt, err := sess.Encapsulate(payload)
	if err != nil {
		t.Fatalf("encapsulate error: %v", err)
	}

	// Route inbound from new IP (simulating connection migration Wi-Fi -> LTE)
	newRemoteAddr := "95.21.50.80:55000"
	decPayload, routedPeer, migrated, err := mgr.RouteInbound(encPkt, newRemoteAddr, testKey)
	if err != nil {
		t.Fatalf("route inbound error: %v", err)
	}
	if !bytes.Equal(decPayload, payload) {
		t.Errorf("payload mismatch: got %s, want %s", string(decPayload), string(payload))
	}
	if routedPeer != peerID {
		t.Errorf("peer mismatch: got %s, want %s", routedPeer, peerID)
	}
	if !migrated {
		t.Errorf("expected connection migration to be true")
	}
}

func TestSessionManager_Prune(t *testing.T) {
	mgr := NewSessionManager()
	var testKey [32]byte
	copy(testKey[:], []byte("quic-test-secret-key-32-bytes!"))

	sess := mgr.GetOrCreateSession("stale-peer", "1.1.1.1:1234", testKey)
	sess.mu.Lock()
	sess.lastSeen = time.Now().Add(-1 * time.Hour)
	sess.mu.Unlock()

	pruned := mgr.Prune(10 * time.Minute)
	if pruned != 1 {
		t.Errorf("expected 1 session pruned, got %d", pruned)
	}

	if _, ok := mgr.GetSession("stale-peer"); ok {
		t.Errorf("stale session still found after prune")
	}
}
