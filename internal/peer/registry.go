package peer

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/signaling"
)

// Peer represents a discovered mesh network device.
type Peer struct {
	DeviceID         string               `json:"device_id"`
	Nickname         string               `json:"nickname,omitempty"`
	PublicKey        string               `json:"public_key"`
	PublicIP         string               `json:"public_ip"`
	LocalAddr        string               `json:"local_addr,omitempty"`
	STUNAddr         string               `json:"stun_addr,omitempty"`
	IPv6Addr         string               `json:"ipv6_addr,omitempty"`
	WGPubKey         string               `json:"wg_pubkey,omitempty"`
	WGPort           int                  `json:"wg_port,omitempty"`
	VirtualIP        string               `json:"virtual_ip,omitempty"`
	DirectP2P        bool                 `json:"direct_p2p"`
	ActiveEndpoint   string               `json:"active_endpoint,omitempty"`
	PingMs           int64                `json:"ping_ms"`
	NATType          string               `json:"nat_type,omitempty"`
	IsExitNode       bool                 `json:"is_exit_node,omitempty"`
	AdvertisedRoutes []string             `json:"advertised_routes,omitempty"`
	LastSeen         time.Time            `json:"last_seen"`
	Online           bool                 `json:"online"`
	Latency          time.Duration        `json:"latency"`
	Channel          string               `json:"channel,omitempty"`
	HasMQTT          bool                 `json:"has_mqtt,omitempty"`
	HasTelegram      bool                 `json:"has_telegram,omitempty"`
	LastMQTTSeen     time.Time            `json:"last_mqtt_seen,omitempty"`
	LastTelegramSeen time.Time            `json:"last_telegram_seen,omitempty"`
	AWG              *signaling.AWGParams `json:"awg,omitempty"`
	OS               string               `json:"os,omitempty"`
	Platform         string               `json:"platform,omitempty"`
	CountryFlag      string               `json:"country_flag,omitempty"`
	Candidates       []string             `json:"candidates,omitempty"`
	NATBlocked       bool                 `json:"nat_blocked,omitempty"`
	FirstSeen        time.Time            `json:"first_seen,omitempty"`
	ProbeCount       int                  `json:"probe_count,omitempty"`
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

	if existing.DirectP2P {
		newer.DirectP2P = true
	}
	if existing.ActiveEndpoint != "" && newer.ActiveEndpoint == "" {
		newer.ActiveEndpoint = existing.ActiveEndpoint
	}
	if existing.Latency > 0 && newer.Latency == 0 {
		newer.Latency = existing.Latency
		newer.PingMs = existing.PingMs
	}
	if newer.Nickname == "" && existing.Nickname != "" {
		newer.Nickname = existing.Nickname
	}
	if newer.AWG == nil && existing.AWG != nil {
		newer.AWG = existing.AWG
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

	if newer.Latency > 0 {
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
	if existing.ProbeCount > 0 && newer.ProbeCount == 0 {
		newer.ProbeCount = existing.ProbeCount
	}

	newer.Online = true
	newer.LastSeen = now
}


// Registry manages thread-safe tracking of discovered mesh peers.
type Registry struct {
	mu    sync.RWMutex
	peers map[string]*Peer
}

// NewRegistry creates a new peer registry.
func NewRegistry() *Registry {
	return &Registry{
		peers: make(map[string]*Peer),
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

	if existing, ok := r.peers[p.DeviceID]; ok {
		existing.MergeFrom(p)
	} else {
		if p.Latency > 0 {
			p.PingMs = p.Latency.Milliseconds()
		}
		p.Online = true
		p.LastSeen = now
	}

	r.peers[p.DeviceID] = p
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

// GetByVirtualIP retrieves a peer by its VirtualIP.
func (r *Registry) GetByVirtualIP(vip string) (*Peer, bool) {
	if vip == "" {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.peers {
		if p.VirtualIP == vip {
			return p, true
		}
	}
	return nil, false
}


// MarkOffline sets the Online flag to false for peers not seen within maxAge.
func (r *Registry) MarkOffline(maxAge time.Duration) {
	if maxAge < 60*time.Second {
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
		if p.LastSeen.Before(threshold) {
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