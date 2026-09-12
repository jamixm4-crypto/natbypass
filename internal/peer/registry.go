// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package peer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/bits"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/rs/zerolog/log"
)

// Peer represents a discovered mesh network device.
type Peer struct {
	// OutboundSeq tracks monotonically increasing packet sequence numbers.
	// 32-bit atomic is always 4-byte aligned on 32-bit MIPS/ARM and contains no mutex.
	OutboundSeq      uint32               `json:"-"`
	DeviceID         string               `json:"device_id"`
	Nickname         string               `json:"nickname,omitempty"`
	DeviceName       string               `json:"device_name,omitempty"`
	PublicKey        string               `json:"public_key"`
	PublicIP         string               `json:"public_ip"`
	LocalAddr        string               `json:"local_addr,omitempty"`
	STUNAddr         string               `json:"stun_addr,omitempty"`
	TCPAddr          string               `json:"tcp_addr,omitempty"`
	IPv6Addr         string               `json:"ipv6_addr,omitempty"`
	WGPubKey         string               `json:"wg_pubkey,omitempty"`
	WGPort           int                  `json:"wg_port,omitempty"`
	VirtualIP        string               `json:"virtual_ip,omitempty"`
	DirectP2P        bool                 `json:"direct_p2p"`
	DirectTCP        bool                 `json:"direct_tcp,omitempty"`
	Transport        string               `json:"transport,omitempty"` // "tcp_tls", "udp_direct", "relay_mqtt"
	ActiveEndpoint   string               `json:"active_endpoint,omitempty"`
	PingMs           int64                `json:"ping_ms"`
	NATType          string               `json:"nat_type,omitempty"`
	NATDelta         int                  `json:"nat_delta,omitempty"`
	OS               string               `json:"os,omitempty"`
	Platform         string               `json:"platform,omitempty"`
	Arch             string               `json:"arch,omitempty"`
	Version          string               `json:"version,omitempty"`
	IsKeenetic       bool                 `json:"is_keenetic,omitempty"`
	IsExitNode       bool                 `json:"is_exit_node,omitempty"`
	ExitRevoked      bool                 `json:"exit_revoked,omitempty"`
	AdvertisedRoutes []string             `json:"advertised_routes,omitempty"`
	LastSeen         time.Time            `json:"last_seen"`
	LastDirectSeen   time.Time            `json:"last_direct_seen,omitempty"`
	Online           bool                 `json:"online"`
	Latency          time.Duration        `json:"latency"`
	Channel          string               `json:"channel,omitempty"`
	HasMQTT          bool                 `json:"has_mqtt,omitempty"`
	HasTelegram      bool                 `json:"has_telegram,omitempty"`
	LastMQTTSeen     time.Time            `json:"last_mqtt_seen,omitempty"`
	LastTelegramSeen time.Time            `json:"last_telegram_seen,omitempty"`
	AWG              *signaling.AWGParams `json:"awg,omitempty"`
	AWGMismatch      bool                 `json:"awg_mismatch,omitempty"`
	IPConflict       bool                 `json:"ip_conflict,omitempty"`
	CountryFlag              string                  `json:"country_flag,omitempty"`
	Candidates               []string                `json:"candidates,omitempty"`
	Endpoints                []signaling.EndpointDesc `json:"endpoints,omitempty"`
	NATBlocked               bool                    `json:"nat_blocked,omitempty"`
	FirstSeen                time.Time               `json:"first_seen,omitempty"`
	ProbeCount               int                     `json:"probe_count,omitempty"`
	DeliveryMask             uint32                  `json:"delivery_mask,omitempty"`       // 32-bit sliding bitmap of recent packet deliveries
	LossPercent              int                     `json:"loss_percent,omitempty"`        // Integer loss percentage (0-100%)
	ConsecutiveDrops         int                     `json:"consec_drops,omitempty"`        // Consecutive failed probes
	ConsecutiveDirectSuccess int                     `json:"consec_direct_success,omitempty"`// Consecutive successful direct probes (hysteresis)
	StandbyRelayReady        bool                    `json:"standby_relay_ready,omitempty"`  // True if Hot-Standby Relay path is verified
	LastRelayPing            time.Time               `json:"last_relay_ping,omitempty"`      // Timestamp of last Hot-Standby heartbeat
	ReplayFilter             *crypto.ReplayFilter    `json:"-"`                              // Anti-Replay sliding window (RFC 6479)
}

// NextOutboundSeq returns the next monotonically increasing sequence number for this peer.
// Uses atomic 32-bit increment which is always 4-byte aligned on 32-bit MIPS/ARM architectures
// and avoids copylocks issues when copying Peer structs.
func (p *Peer) NextOutboundSeq() uint64 {
	return uint64(atomic.AddUint32(&p.OutboundSeq, 1))
}

// GetReplayFilter returns the initialized Anti-Replay filter for this peer.
func (p *Peer) GetReplayFilter() *crypto.ReplayFilter {
	if p.ReplayFilter == nil {
		p.ReplayFilter = crypto.NewReplayFilter()
	}
	return p.ReplayFilter
}

// RecordProbeResult updates the 32-bit delivery bitmap and recalculates LossPercent using pure integer arithmetic (MIPS safe).
func (p *Peer) RecordProbeResult(success bool) {
	if success {
		p.DeliveryMask = (p.DeliveryMask << 1) | 1
		p.ConsecutiveDrops = 0
		p.ConsecutiveDirectSuccess++
	} else {
		p.DeliveryMask = (p.DeliveryMask << 1)
		p.ConsecutiveDrops++
		p.ConsecutiveDirectSuccess = 0
	}

	popcount := bits.OnesCount32(p.DeliveryMask)
	p.LossPercent = 100 - (popcount * 100 / 32)
}

// MergeFrom merges discovery details into an existing peer while preserving established connections.
func (existing *Peer) MergeFrom(newer *Peer) {
	now := time.Now()

	if newer.Channel == "mqtt" {
		newer.HasMQTT = true
		if newer.LastMQTTSeen.IsZero() {
			newer.LastMQTTSeen = now
		}
	} else if newer.Channel == "telegram" {
		newer.HasTelegram = true
		if newer.LastTelegramSeen.IsZero() {
			newer.LastTelegramSeen = now
		}
	}

	if newer.LastDirectSeen.IsZero() {
		newer.LastDirectSeen = existing.LastDirectSeen
	}

	if newer.Transport == "" {
		newer.Transport = existing.Transport
	}

	// Dynamic P2P health check:
	// If transport is TCP ShadowTLS, DirectP2P is backed by an active TCP stream, not UDP hole-punch probes.
	// For UDP, demote to relay only if no direct inbound packets seen for 30 seconds.
	// ProbeCount is an outbound metric (probes sent), NOT an indicator of P2P health —
	// it must NOT trigger demotion, or it creates a feedback loop where probing itself kills P2P.
	directP2PExpired := false
	if existing.DirectP2P {
		if existing.Transport == "tcp_tls" || existing.Transport == "tcp_shadowtls" {
			if existing.LastDirectSeen.IsZero() || time.Since(existing.LastDirectSeen) > 25*time.Second {
				directP2PExpired = true
			}
		} else {
			if existing.LastDirectSeen.IsZero() || time.Since(existing.LastDirectSeen) > 15*time.Second {
				directP2PExpired = true
			}
		}
	}

	// Unconditional preservation of measured latency and ping across periodic signaling beacons
	stunChanged := newer.STUNAddr != "" && existing.STUNAddr != "" && newer.STUNAddr != existing.STUNAddr
	if stunChanged || directP2PExpired {
		if stunChanged {
			newer.ActiveEndpoint = newer.STUNAddr
		} else if newer.ActiveEndpoint == "" {
			newer.ActiveEndpoint = existing.ActiveEndpoint
		}
		newer.DirectP2P = false
		newer.Transport = "relay_mqtt"
		if stunChanged {
			newer.Latency = 0
			newer.PingMs = 0
		}
	} else {
		if newer.ActiveEndpoint == "" {
			newer.ActiveEndpoint = existing.ActiveEndpoint
		}
		if !newer.DirectP2P {
			newer.DirectP2P = existing.DirectP2P
		}
		if !newer.DirectTCP {
			newer.DirectTCP = existing.DirectTCP
		}
	}

	// Absolute safety guarantee: A peer CANNOT have DirectP2P = true if ActiveEndpoint is empty, never seen direct, or failing UDP probes
	if newer.Transport != "tcp_tls" && newer.Transport != "tcp_shadowtls" {
		if newer.ActiveEndpoint == "" || newer.LastDirectSeen.IsZero() || (existing.ProbeCount >= 2 && time.Since(newer.LastDirectSeen) > 10*time.Second) {
			newer.DirectP2P = false
			newer.Transport = "relay_mqtt"
		}
	}

	if newer.Transport == "" {
		if newer.DirectP2P {
			newer.Transport = "udp_direct"
		} else {
			newer.Transport = "relay_mqtt"
		}
	}

	// Prune stale/dead endpoints if peer is persistently failing probes and unconfirmed
	if existing.ProbeCount >= 4 && !newer.DirectP2P && newer.STUNAddr != "" {
		newer.ActiveEndpoint = newer.STUNAddr
	}

	if newer.Latency == 0 && existing.Latency > 0 && (existing.DirectP2P || existing.DirectTCP || existing.Transport == "tcp_tls" || existing.Transport == "tcp_shadowtls") && (newer.DirectP2P || newer.DirectTCP || newer.Transport == "tcp_tls" || newer.Transport == "tcp_shadowtls") {
		newer.Latency = existing.Latency
		newer.PingMs = existing.PingMs
	} else if !newer.DirectP2P && !newer.DirectTCP && newer.Transport != "tcp_tls" && newer.Transport != "tcp_shadowtls" {
		newer.Latency = 0
		newer.PingMs = 0
	}

	if newer.TCPAddr == "" && existing.TCPAddr != "" {
		newer.TCPAddr = existing.TCPAddr
	}

	if newer.NATDelta == 0 && existing.NATDelta > 0 {
		newer.NATDelta = existing.NATDelta
	}

	if newer.Arch == "" && existing.Arch != "" {
		newer.Arch = existing.Arch
	}
	if newer.Version == "" && existing.Version != "" {
		newer.Version = existing.Version
	}
	if !newer.IsKeenetic && existing.IsKeenetic {
		newer.IsKeenetic = existing.IsKeenetic
	}
	if newer.OS == "" && existing.OS != "" {
		newer.OS = existing.OS
	}
	if newer.Platform == "" && existing.Platform != "" {
		newer.Platform = existing.Platform
	}
	if newer.Nickname == "" && existing.Nickname != "" {
		newer.Nickname = existing.Nickname
	}
	if newer.DeviceName == "" && existing.DeviceName != "" {
		newer.DeviceName = existing.DeviceName
	}
	if newer.DeviceName != "" && newer.Nickname == "" {
		newer.Nickname = newer.DeviceName
	} else if newer.Nickname != "" && newer.DeviceName == "" {
		newer.DeviceName = newer.Nickname
	}
	// Preserve existing valid VirtualIP if newer is empty or carries legacy 100.64.200.x fallback
	if existing.VirtualIP != "" {
		if newer.VirtualIP == "" || (strings.HasPrefix(newer.VirtualIP, "100.64.200.") && !strings.HasPrefix(existing.VirtualIP, "100.64.200.")) {
			newer.VirtualIP = existing.VirtualIP
		}
	}

	if newer.Transport == "" && existing.Transport != "" {
		newer.Transport = existing.Transport
	}
	if !newer.DirectTCP && existing.DirectTCP {
		newer.DirectTCP = true
	}

	if newer.STUNAddr == "" && existing.STUNAddr != "" {
		newer.STUNAddr = existing.STUNAddr
	}
	if newer.PublicIP == "" && existing.PublicIP != "" {
		newer.PublicIP = existing.PublicIP
	}
	if newer.WGPubKey == "" && existing.WGPubKey != "" {
		newer.WGPubKey = existing.WGPubKey
	}
	if newer.ActiveEndpoint == "" && existing.ActiveEndpoint != "" {
		newer.ActiveEndpoint = existing.ActiveEndpoint
	}
	if newer.ActiveEndpoint == "" {
		if newer.STUNAddr != "" {
			newer.ActiveEndpoint = newer.STUNAddr
		} else if newer.LocalAddr != "" {
			newer.ActiveEndpoint = newer.LocalAddr
		}
	}
	if newer.AWG == nil && existing.AWG != nil {
		newer.AWG = existing.AWG
	}
	if len(newer.Endpoints) > 0 {
		existing.Endpoints = newer.Endpoints
	} else if len(existing.Endpoints) > 0 {
		newer.Endpoints = existing.Endpoints
	}
	if newer.DeliveryMask == 0 && existing.DeliveryMask != 0 {
		newer.DeliveryMask = existing.DeliveryMask
		newer.LossPercent = existing.LossPercent
		newer.ConsecutiveDrops = existing.ConsecutiveDrops
		newer.ConsecutiveDirectSuccess = existing.ConsecutiveDirectSuccess
	}
	if !newer.StandbyRelayReady && existing.StandbyRelayReady {
		newer.StandbyRelayReady = existing.StandbyRelayReady
	}
	if newer.LastRelayPing.IsZero() && !existing.LastRelayPing.IsZero() {
		newer.LastRelayPing = existing.LastRelayPing
	}
	if newer.ReplayFilter == nil && existing.ReplayFilter != nil {
		newer.ReplayFilter = existing.ReplayFilter
	}
	if newer.OutboundSeq == 0 && existing.OutboundSeq != 0 {
		newer.OutboundSeq = existing.OutboundSeq
	}


	if existing.HasMQTT && now.Sub(existing.LastMQTTSeen) < constants.PeerOfflineThreshold {
		newer.HasMQTT = true
		if newer.LastMQTTSeen.IsZero() {
			newer.LastMQTTSeen = existing.LastMQTTSeen
		}
	}
	if existing.HasTelegram && now.Sub(existing.LastTelegramSeen) < constants.PeerOfflineThreshold {
		newer.HasTelegram = true
		if newer.LastTelegramSeen.IsZero() {
			newer.LastTelegramSeen = existing.LastTelegramSeen
		}
	}

	if newer.HasMQTT && newer.HasTelegram {
		newer.Channel = "parallel"
	} else if newer.HasTelegram && !newer.HasMQTT {
		newer.Channel = "telegram"
	} else if newer.HasMQTT && !newer.HasTelegram {
		newer.Channel = "mqtt"
	}

	if !newer.DirectP2P && !newer.DirectTCP && newer.Transport != "tcp_tls" && newer.Transport != "tcp_shadowtls" {
		newer.Latency = 0
		newer.PingMs = 0
	} else if newer.Latency > 0 {
		newer.PingMs = newer.Latency.Milliseconds()
	}

	if !existing.FirstSeen.IsZero() {
		newer.FirstSeen = existing.FirstSeen
	} else {
		newer.FirstSeen = now
	}
	if len(newer.Candidates) == 0 && len(existing.Candidates) > 0 {
		newer.Candidates = existing.Candidates
	}
	if existing.NATBlocked && !newer.DirectP2P {
		newer.NATBlocked = true
	}
	// Reset backoff if peer changed its STUN address or returned from offline/restart
	endpointChanged := newer.STUNAddr != "" && existing.STUNAddr != "" && newer.STUNAddr != existing.STUNAddr
	peerRecovered := now.Sub(existing.LastSeen) > 15*time.Second
	if endpointChanged || peerRecovered {
		newer.ProbeCount = 0
	} else if existing.ProbeCount > 0 && newer.ProbeCount == 0 {
		newer.ProbeCount = existing.ProbeCount
	}

	newer.Online = true
	newer.LastSeen = now
}


// PeerUpdateCallback is called whenever a peer is discovered, registered or updated in the registry.
type PeerUpdateCallback func(p *Peer)

// Registry manages thread-safe tracking of discovered mesh peers.
type Registry struct {
	mu           sync.RWMutex
	peers        map[string]*Peer
	maxPeers     int
	onPeerUpdate PeerUpdateCallback
}

// SetOnPeerUpdate registers a callback called asynchronously when any peer is added or updated.
func (r *Registry) SetOnPeerUpdate(cb PeerUpdateCallback) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onPeerUpdate = cb
}

// NewRegistry creates a new peer registry.
func NewRegistry() *Registry {
	return &Registry{
		peers: make(map[string]*Peer),
	}
}

// NewRegistryWithLimit creates a new peer registry with a maximum limit.
func NewRegistryWithLimit(maxPeers int) *Registry {
	return &Registry{
		peers:    make(map[string]*Peer),
		maxPeers: maxPeers,
	}
}

// ClearAll removes all peers from the registry.
func (r *Registry) ClearAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers = make(map[string]*Peer)
}

// Delete removes a peer immediately by deviceID.
func (r *Registry) Delete(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, deviceID)
}

// MarkDeviceOffline marks a specific device offline immediately.
func (r *Registry) MarkDeviceOffline(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.peers[deviceID]; ok {
		p.Online = false
		p.DirectP2P = false
		p.Transport = "relay_mqtt"
	}
}

// Upsert adds or updates a peer in the registry while preserving active connection state.
func (r *Registry) Upsert(p *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	if p.Channel == "mqtt" {
		p.HasMQTT = true
		p.LastMQTTSeen = now
	} else if p.Channel == "telegram" {
		p.HasTelegram = true
		p.LastTelegramSeen = now
	}

	if p.Nickname == "" && p.DeviceName != "" {
		p.Nickname = p.DeviceName
	} else if p.DeviceName == "" && p.Nickname != "" {
		p.DeviceName = p.Nickname
	}

	// 🛡️ Автоматическое вытеснение зависших пиров (Ghost Peers) с одинаковым Virtual IP или Public Key.
	// В меш-сети один виртуальный IP (например 10.11.12.225) может принадлежать только одному активному узлу.
	// BUG-10 FIX: Evict only truly stale peers — check freshness before evicting to avoid
	// a delayed MQTT beacon destroying an actively-connected peer.
	cleanPVIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
	var staleConflictingIDs []string
	for id, existing := range r.peers {
		if id == p.DeviceID || existing == nil {
			continue
		}
		cleanExistingVIP := strings.TrimSpace(strings.Split(existing.VirtualIP, "/")[0])

		// 1. Конфликт одного и того же Virtual IP:
		if cleanPVIP != "" && cleanExistingVIP != "" && cleanPVIP == cleanExistingVIP {
			existingIsActive := existing.Online && now.Sub(existing.LastSeen) < constants.PeerOfflineThreshold

			if existingIsActive {
				// Если конфликт вызван дефолтным адресом подсети (например, 100.64.200.1 или .0):
				if strings.HasSuffix(cleanPVIP, ".1") || strings.HasSuffix(cleanPVIP, ".0") {
					prefix := "100.64.200"
					parts := strings.Split(cleanPVIP, ".")
					if len(parts) >= 3 {
						prefix = strings.Join(parts[:3], ".")
					}
					h := sha256.Sum256([]byte(p.DeviceID))
					octet := int(h[0]%250) + 2
					if octet == 1 {
						octet = 2
					}
					p.VirtualIP = fmt.Sprintf("%s.%d", prefix, octet)
					cleanPVIP = p.VirtualIP
					p.IPConflict = false
					log.Info().
						Str("existing_id", id).
						Str("peer_id", p.DeviceID).
						Str("reassigned_vip", p.VirtualIP).
						Msg("🛡️ Default Virtual IP collision resolved: assigned unique deterministic IP")
					continue
				}

				// 🛡️ Защита от Peer Displacement: активный узел НЕЛЬЗЯ вытеснить, даже при совпадении ключа или времени!
				p.IPConflict = true
				existing.IPConflict = true
				p.VirtualIP = ""
				log.Warn().
					Str("victim_id", id).
					Str("victim_key", existing.PublicKey).
					Str("attacker_id", p.DeviceID).
					Str("attacker_key", p.PublicKey).
					Str("conflicting_vip", cleanPVIP).
					Msg("🛡️ Security alert: Peer displacement rejected! Active peer protected against Virtual IP hijack")
				continue
			}

			// Существующий узел действительно офлайн / устарел (!Online или LastSeen > PeerOfflineThreshold)
			existingIsStale := existing.LastSeen.IsZero() || !existing.Online || now.Sub(existing.LastSeen) > constants.PeerOfflineThreshold
			if existingIsStale {
				staleConflictingIDs = append(staleConflictingIDs, id)
			}
			continue
		}

		// 2. Совпадение Public Key (перезапуск узла с новым DeviceID или попытка подделки):
		if p.PublicKey != "" && existing.PublicKey != "" && p.PublicKey == existing.PublicKey {
			existingIsActive := existing.Online && now.Sub(existing.LastSeen) < constants.PeerOfflineThreshold
			if existingIsActive {
				log.Warn().
					Str("existing_id", id).
					Str("conflicting_id", p.DeviceID).
					Str("public_key", p.PublicKey).
					Msg("🛡️ Security alert: Eviction rejected — active peer is online with the same PublicKey")
				continue
			}

			existingIsStale := existing.LastSeen.IsZero() || !existing.Online || now.Sub(existing.LastSeen) > constants.PeerOfflineThreshold
			if existingIsStale {
				staleConflictingIDs = append(staleConflictingIDs, id)
			}
			continue
		}

		// 3. Переподключающийся Android с меняющимся DeviceID:
		if strings.HasPrefix(p.DeviceID, "Android-") && strings.HasPrefix(id, "Android-") {
			if cleanPVIP != "" && cleanExistingVIP == cleanPVIP {
				existingIsStale := existing.LastSeen.IsZero() || !existing.Online || now.Sub(existing.LastSeen) > constants.PeerOfflineThreshold
				if existingIsStale {
					staleConflictingIDs = append(staleConflictingIDs, id)
				}
				continue
			}
		}
	}
	for _, staleID := range staleConflictingIDs {
		delete(r.peers, staleID)
	}

	if existing, ok := r.peers[p.DeviceID]; ok {
		existing.MergeFrom(p)
		r.peers[p.DeviceID] = p // ✅ Сохраняем обогащенный объект
	} else {
		if !p.DirectP2P && !p.DirectTCP && p.Transport != "tcp_tls" && p.Transport != "tcp_shadowtls" {
			p.Latency = 0
			p.PingMs = 0
		} else if p.Latency > 0 {
			p.PingMs = p.Latency.Milliseconds()
		}
		if p.ActiveEndpoint == "" {
			if p.STUNAddr != "" {
				p.ActiveEndpoint = p.STUNAddr
			} else if p.LocalAddr != "" {
				p.ActiveEndpoint = p.LocalAddr
			}
		}
		if p.Transport == "" {
			if p.DirectP2P {
				p.Transport = "udp_direct"
			} else {
				p.Transport = "relay_mqtt"
			}
		}
		// Only force Online=true and reset LastSeen when the peer has no explicit timestamp.
		// Peers arriving from signaling have their own LastSeen from the beacon timestamp.
		if p.LastSeen.IsZero() {
			p.Online = true
			p.LastSeen = now
		}
		r.peers[p.DeviceID] = p
	}

	if r.maxPeers > 0 && len(r.peers) > r.maxPeers {
		var oldestID string
		var oldestTime time.Time
		first := true
		for id, peer := range r.peers {
			if first || peer.LastSeen.Before(oldestTime) {
				oldestID = id
				oldestTime = peer.LastSeen
				first = false
			}
		}
		if !first {
			delete(r.peers, oldestID)
		}
	}

	cb := r.onPeerUpdate
	if cb != nil {
		cp := *p
		go cb(&cp)
	}
}

// List returns a list of all peers, sorted by DeviceID.
func (r *Registry) List() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []*Peer
	for _, p := range r.peers {
		list = append(list, p)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].DeviceID < list[j].DeviceID
	})

	return list
}

// Get retrieves a peer by its DeviceID.
func (r *Registry) Get(deviceID string) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.peers[deviceID]
	return p, ok
}

// GetByVirtualIP retrieves the best active peer by its VirtualIP (ignoring /CIDR mask).
// Гарантированно выбирает живой узел (Online + DirectP2P + свежий LastSeen), исключая зависшие фантомные сессии.
func (r *Registry) GetByVirtualIP(vip string) (*Peer, bool) {
	if vip == "" {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	targetIP := strings.TrimSpace(strings.Split(vip, "/")[0])
	var bestPeer *Peer
	for _, p := range r.peers {
		if p == nil {
			continue
		}
		pIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
		if pIP == targetIP && pIP != "" {
			if bestPeer == nil {
				bestPeer = p
				continue
			}
			// Приоритет 1: Узел в сети (Online)
			if p.Online && !bestPeer.Online {
				bestPeer = p
				continue
			} else if !p.Online && bestPeer.Online {
				continue
			}
			// Приоритет 2: Прямое подтвержденное P2P-соединение (DirectP2P)
			if p.DirectP2P && !bestPeer.DirectP2P {
				bestPeer = p
				continue
			} else if !p.DirectP2P && bestPeer.DirectP2P {
				continue
			}
			// Приоритет 3: Более свежий маяк активности (LastSeen)
			if p.LastSeen.After(bestPeer.LastSeen) {
				bestPeer = p
			}
		}
	}
	if bestPeer != nil {
		return bestPeer, true
	}
	return nil, false
}



// MarkOffline sets the Online flag to false for peers not seen within maxAge.
func (r *Registry) MarkOffline(maxAge time.Duration) {
	if maxAge <= 0 {
		maxAge = constants.PeerOfflineThreshold
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	threshold := time.Now().Add(-maxAge)
	for _, p := range r.peers {
		if p.Online && p.LastSeen.Before(threshold) {
			p.Online = false
			p.DirectP2P = false
		}
	}
}

// Cleanup removes stale peers not seen within maxAge.
func (r *Registry) Cleanup(maxAge time.Duration) {
	if maxAge <= 0 {
		maxAge = constants.PeerCleanupInterval
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	threshold := time.Now().Add(-maxAge)
	for id, p := range r.peers {
		// BUG-12 FIX: Guard against zero LastSeen — newly created peers should not be evicted
		if !p.LastSeen.IsZero() && p.LastSeen.Before(threshold) {
			delete(r.peers, id)
		}
	}
}

// StartMonitor runs a background goroutine to periodically mark stale peers offline.
func (r *Registry) StartMonitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = constants.PeerMonitorInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.MarkOffline(constants.PeerOfflineThreshold)
				r.Cleanup(constants.PeerCleanupInterval)
			}
		}
	}()
}
// Exists returns true if peer deviceID is currently known in the registry
func (r *Registry) Exists(deviceID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.peers[deviceID]
	return ok
}

// IsValidEndpointForPeer checks if a socket endpoint is valid to be set as ActiveEndpoint for a peer.
// Prevents CGNAT / gateway IP poisoning (e.g. 10.100.1.210) from overwriting a valid public STUN address
// when communicating with remote peers across WAN.
func IsValidEndpointForPeer(endpoint string, p *Peer, myPublicIP string) bool {
	if endpoint == "" || p == nil {
		return false
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// Private / Loopback / LinkLocal addresses are only valid if both peers share the same Public IP
	// (meaning they are genuinely on the same local LAN behind the same NAT router) or if public IPs are unknown.
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		if p.PublicIP != "" && myPublicIP != "" && p.PublicIP != myPublicIP {
			return false
		}
	}
	return true
}
