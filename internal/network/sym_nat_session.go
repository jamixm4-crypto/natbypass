// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// SymmetricNATSession manages a multi-hop hole punching session for Symmetric NAT peers.
// Each hop calls HopPort() to force the local NAT to allocate a fresh external port,
// then immediately sprays probe packets to the predicted remote port range.
// The session terminates early upon receiving the first successful PONG from the peer.
type SymmetricNATSession struct {
	puncher   *UDPPuncher
	targetIP  string
	basePort  int
	winner    string
	winnerMu  sync.RWMutex
	successCh chan string // delivers winning address on success
	stopOnce  sync.Once
	cancel    context.CancelFunc
}

// newSymmetricNATSession creates a session. Call Run() to start it.
func newSymmetricNATSession(p *UDPPuncher, targetIP string, basePort int) *SymmetricNATSession {
	return &SymmetricNATSession{
		puncher:   p,
		targetIP:  targetIP,
		basePort:  basePort,
		successCh: make(chan string, 1),
	}
}

func (s *SymmetricNATSession) getWinner() string {
	s.winnerMu.RLock()
	defer s.winnerMu.RUnlock()
	return s.winner
}

// NotifySuccess is called by the outer code when a PONG arrives from any address.
// It signals the session to stop immediately.
func (s *SymmetricNATSession) NotifySuccess(fromAddr string) {
	s.stopOnce.Do(func() {
		s.winnerMu.Lock()
		s.winner = fromAddr
		s.winnerMu.Unlock()
		select {
		case s.successCh <- fromAddr:
		default:
		}
		if s.cancel != nil {
			s.cancel()
		}
	})
}

// Run executes the Symmetric NAT session: up to SymmetricNATMaxHops HopPort cycles.
// Each cycle:
//  1. Calls HopPort() to get a fresh external port (forces NAT to create new mapping)
//  2. Queries STUN to discover new mapped address
//  3. Generates candidate remote ports and sprays probes
//
// Returns the winning address (empty string on timeout/context cancel).
func (s *SymmetricNATSession) Run(ctx context.Context) string {
	sessionCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	defer cancel()

	for hop := 0; hop < SymmetricNATMaxHops; hop++ {
		if w := s.getWinner(); w != "" {
			return w
		}
		select {
		case <-sessionCtx.Done():
			return s.getWinner()
		case winner := <-s.successCh:
			return winner
		default:
		}

		// Step 1: HopPort -- create fresh NAT mapping
		_, err := s.puncher.HopPort()
		if err != nil {
			continue
		}

		// Step 2: Discover our new mapped address (tells us our new external port)
		discCtx, discCancel := context.WithTimeout(sessionCtx, 3*time.Second)
		myIP, myPort, err := s.puncher.DiscoverMappedAddress(discCtx)
		discCancel()
		if err != nil || myPort == 0 {
			// No STUN response -- still spray with base port
			myIP = nil
			myPort = s.basePort
		}
		_ = myIP

		// Step 3: Build candidate remote port list from the fingerprinted CGNAT profile
		candidates := s.puncher.candidatePorts(s.basePort)

		// Step 4: Spray probes to all candidates
	hopDone:
		for _, port := range candidates {
			select {
			case <-sessionCtx.Done():
				break hopDone
			default:
			}
			addr := fmt.Sprintf("%s:%d", s.targetIP, port)
			_ = s.puncher.SendHolePunchProbe(addr)
		}

		// Also probe using our own new mapped port as a hint
		// (symmetric NAT often assigns symmetric port on both sides)
		if myPort > 0 && myPort != s.basePort {
			addr := fmt.Sprintf("%s:%d", s.targetIP, myPort)
			_ = s.puncher.SendHolePunchProbe(addr)
		}

		// Wait between hops or for early success
		if w := s.getWinner(); w != "" {
			return w
		}
		select {
		case <-sessionCtx.Done():
			return s.getWinner()
		case winner := <-s.successCh:
			return winner
		case <-time.After(SymmetricNATHopDelay):
		}
	}

	// Check if winner was recorded
	if w := s.getWinner(); w != "" {
		return w
	}
	select {
	case winner := <-s.successCh:
		return winner
	default:
		return s.getWinner()
	}
}

// LaunchSymmetricNATSession starts a background Symmetric NAT punch session for a peer.
// It is designed to be called when the standard hole punching fails after many probes.
//
// Parameters:
//   - ctx: parent context (cancel to abort)
//   - targetIP: remote peer's public IP
//   - basePort: last known remote external port from signaling/STUN
//   - onSuccess: called with winning endpoint address when P2P is established
//
// Returns the session handle so the caller can call NotifySuccess() when a PONG arrives.
func (p *UDPPuncher) LaunchSymmetricNATSession(
	ctx context.Context,
	targetIP string,
	basePort int,
	onSuccess func(addr string),
) *SymmetricNATSession {
	session := newSymmetricNATSession(p, targetIP, basePort)
	go func() {
		winner := session.Run(ctx)
		if winner != "" && onSuccess != nil {
			onSuccess(winner)
		}
	}()
	return session
}

// GetMappedPort returns the last known mapped external port (0 if unknown).
func (p *UDPPuncher) GetMappedPort() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mappedPort
}

// GetMappedIPPort returns the last known mapped external IP and port.
func (p *UDPPuncher) GetMappedIPPort() (net.IP, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mappedIP, p.mappedPort
}
