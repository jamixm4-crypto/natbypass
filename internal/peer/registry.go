package peer

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/signaling"
)

// Peer represents a discovered mesh network device.
type Peer struct {
	DeviceID         string                `json:"device_id"`
	Nickname         string                `json:"nickname,omitempty"`
	PublicKey        string                `json:"public_key"`
	PublicIP         string                `json:"public_ip"`
	LocalAddr        string                `json:"local_addr,omitempty"`
	STUNAddr         string                `json:"stun_addr,omitempty"`
	IPv6Addr         string                `json:"ipv6_addr,omitempty"`
	WGPubKey         string                `json:"wg_pubkey,omitempty"`
	WGPort           int                   `json:"wg_port,omitempty"`
	VirtualIP        string                `json:"virtual_ip,omitempty"`
	DirectP2P        bool                  `json:"direct_p2p"`
	ActiveEndpoint   string                `json:"active_endpoint,omitempty"`
	PingMs           int64                 `json:"ping_ms"`
	NATType          string                `json:"nat_type,omitempty"`
	IsExitNode       bool                  `json:"is_exit_node,omitempty"`
	AdvertisedRoutes []string              `json:"advertised_routes,omitempty"`
	LastSeen         time.Time             `json:"last_seen"`
	Online           bool                  `json:"online"`
	Latency          time.Duration         `json:"latency"`
	Channel          string                `json:"channel,omitempty"`
	HasMQTT          bool                  `json:"has_mqtt,omitempty"`
	HasTelegram      bool                  `json:"has_telegram,omitempty"`
	LastMQTTSeen     time.Time             `json:"last_mqtt_seen,omitempty"`
	LastTelegramSeen time.Time             `json:"last_telegram_seen,omitempty"`
	AWG              *signaling.AWGParams  `json:"awg,omitempty"`
	OS               string                `json:"os,omitempty"`
	Platform         string                `json:"platform,omitempty"`
	CountryFlag      string                `json:"country_flag,omitempty"`
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
		if existing.DirectP2P {
			p.DirectP2P = true
		}
		if existing.ActiveEndpoint != "" && p.ActiveEndpoint == "" {
			p.ActiveEndpoint = existing.ActiveEndpoint
		}
		if existing.Latency > 0 && p.Latency == 0 {
			p.Latency = existing.Latency
			p.PingMs = existing.PingMs
		}
		if p.Nickname == "" && existing.Nickname != "" {
			p.Nickname = existing.Nickname
		}
		if p.AWG == nil && existing.AWG != nil {
			p.AWG = existing.AWG
		}

		if existing.HasMQTT && now.Sub(existing.LastMQTTSeen) < 120*time.Second {
			p.HasMQTT = true
			if p.LastMQTTSeen.IsZero() {
				p.LastMQTTSeen = existing.LastMQTTSeen
			}
		}
		if existing.HasTelegram && now.Sub(existing.LastTelegramSeen) < 120*time.Second {
			p.HasTelegram = true
			if p.LastTelegramSeen.IsZero() {
				p.LastTelegramSeen = existing.LastTelegramSeen
			}
		}

		if p.HasMQTT && p.HasTelegram {
			p.Channel = "parallel"
		} else if p.HasTelegram && !p.HasMQTT {
			p.Channel = "telegram"
		} else if p.HasMQTT && !p.HasTelegram {
			p.Channel = "mqtt"
		}
	}

	if p.Latency > 0 {
		p.PingMs = p.Latency.Milliseconds()
	}

	p.Online = true
	p.LastSeen = now

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

// MarkOffline sets the Online flag to false for peers not seen within maxAge.
func (r *Registry) MarkOffline(maxAge time.Duration) {
	if maxAge < 60*time.Second {
		maxAge = 120 * time.Second
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

// Cleanup removes stale peers not seen within maxAge (default: 24 hours).
func (r *Registry) Cleanup(maxAge time.Duration) {
	if maxAge <= 0 {
		maxAge = 3 * time.Minute
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
		interval = 10 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.MarkOffline(120 * time.Second)
				r.Cleanup(3 * time.Minute)
			}
		}
	}()
}
