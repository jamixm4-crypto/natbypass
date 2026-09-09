// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// DefaultDecoyEndpoints are high-reputation CDN endpoints used to generate natural background HTTPS activity.
var DefaultDecoyEndpoints = []string{
	"https://gateway.icloud.com",
	"https://connectivity-check.ubuntu.com",
	"https://cloudflare-dns.com",
	"https://swx.cdn.skype.com",
}

// DecoyConfig holds configuration for the covert decoy traffic generator.
type DecoyConfig struct {
	Enabled       bool
	IdleThreshold time.Duration
	DecoyInterval time.Duration
	DecoyURLs     []string
}

// DefaultDecoyConfig returns recommended defaults for anti-DPI decoy operation.
func DefaultDecoyConfig() DecoyConfig {
	return DecoyConfig{
		Enabled:       true,
		IdleThreshold: 45 * time.Second,
		DecoyInterval: 60 * time.Second,
		DecoyURLs:     DefaultDecoyEndpoints,
	}
}

// DecoyManager orchestrates background HTTPS camouflage traffic and tunnel dummy frames
// during idle periods to prevent TCP RST and behavioral flagging on port 443 by DPI/TSPU.
type DecoyManager struct {
	cfg        DecoyConfig
	tcpMgr     *TCPDirectManager
	httpClient *http.Client
	mu         sync.RWMutex
	lastActive time.Time
	running    bool
	cancel     context.CancelFunc
}

// NewDecoyManager creates a new decoy traffic generator.
func NewDecoyManager(cfg DecoyConfig, tcpMgr *TCPDirectManager) *DecoyManager {
	return &DecoyManager{
		cfg:    cfg,
		tcpMgr: tcpMgr,
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
		},
		lastActive: time.Now(),
	}
}

// RecordActivity notes that genuine tunnel data was transmitted, resetting the idle counter.
func (d *DecoyManager) RecordActivity() {
	d.mu.Lock()
	d.lastActive = time.Now()
	d.mu.Unlock()
}

// BuildDecoyFrame constructs a synthetic HTTP/2 PING frame with random payload.
// When parsed by onInboundPacket, its non-IPv4 header (0x00 != 0x45) ensures it is discarded safely.
func BuildDecoyFrame() []byte {
	// HTTP/2 PING frame: 3 bytes length (8), 1 byte type (0x06 PING), 1 byte flags (0), 4 bytes stream ID (0)
	frame := make([]byte, 9+8)
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = 0x08 // Length: 8 bytes payload
	frame[3] = 0x06 // Type: PING
	frame[4] = 0x00 // Flags
	// 4 bytes Stream ID = 0 (Connection control)

	// 8 bytes random opaque data
	if _, err := io.ReadFull(rand.Reader, frame[9:]); err != nil {
		panic(fmt.Sprintf("decoy: csprng failure in BuildDecoyFrame: %v", err))
	}
	return frame
}

// Start runs the background decoy generation loop.
func (d *DecoyManager) Start(ctx context.Context) {
	d.mu.Lock()
	if d.running || !d.cfg.Enabled {
		d.mu.Unlock()
		return
	}
	d.running = true
	loopCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	d.mu.Unlock()

	go func() {
		ticker := time.NewTicker(d.cfg.DecoyInterval)
		defer ticker.Stop()

		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				d.mu.RLock()
				lastAct := d.lastActive
				idleLimit := d.cfg.IdleThreshold
				urls := d.cfg.DecoyURLs
				tcpMgr := d.tcpMgr
				d.mu.RUnlock()

				if time.Since(lastAct) < idleLimit {
					continue // Tunnel is actively carrying real traffic
				}

				// 1. Send covert dummy frame across idle ShadowTLS sessions
				if tcpMgr != nil {
					peers := tcpMgr.ListConns()
					if len(peers) > 0 {
						decoyPkt := BuildDecoyFrame()
						for _, peerID := range peers {
							_ = tcpMgr.SendPacket(peerID, decoyPkt)
						}
						log.Debug().Int("peers", len(peers)).Msg("🛡️ [Decoy] Sent covert TLS keepalive frame to idle peers")
					}
				}

				// 2. Perform lightweight background CDN probe to populate local ISP flow cache with benign HTTPS
				if len(urls) > 0 {
					go func() {
						idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(urls))))
						if err != nil {
							return
						}
						targetURL := urls[idx.Int64()]
						req, err := http.NewRequestWithContext(loopCtx, http.MethodHead, targetURL, nil)
						if err == nil {
							req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
							resp, reqErr := d.httpClient.Do(req)
							if reqErr == nil && resp != nil {
								_ = resp.Body.Close()
							}
						}
					}()
				}
			}
		}
	}()
}

// Stop terminates the decoy loop.
func (d *DecoyManager) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	d.running = false
}
