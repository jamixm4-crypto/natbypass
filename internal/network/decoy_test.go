// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"context"
	"testing"
	"time"
)

func TestDecoy_BuildDecoyFrame(t *testing.T) {
	frame := BuildDecoyFrame()
	if len(frame) != 17 {
		t.Fatalf("expected decoy frame length 17, got %d", len(frame))
	}
	// Check HTTP/2 PING frame header
	if frame[0] != 0 || frame[1] != 0 || frame[2] != 8 {
		t.Fatalf("invalid payload length prefix: %v", frame[:3])
	}
	if frame[3] != 6 {
		t.Fatalf("expected PING type 0x06, got %d", frame[3])
	}
	// Verify it does NOT look like IPv4 (IPv4 must have version 4 in top nibble of byte 0)
	if frame[0]>>4 == 4 {
		t.Fatalf("decoy frame must not masquerade as IPv4 to avoid TUN leakage")
	}
}

func TestDecoyManager_Lifecycle(t *testing.T) {
	cfg := DecoyConfig{
		Enabled:       true,
		IdleThreshold: 10 * time.Millisecond,
		DecoyInterval: 20 * time.Millisecond,
		DecoyURLs:     nil, // no network probes in unit tests
	}
	mgr := NewDecoyManager(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	mgr.RecordActivity()
	mgr.Stop()
}
