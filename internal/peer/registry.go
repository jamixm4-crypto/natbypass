package peer

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/signaling"
)

// Peer represents a discovered device in the network.
type Peer struct {
	DeviceID         string               `json:"device_id"`
	Nickname         string               `json:"nickname,omitempty"`
	VirtualIP        string               `json:"virtual_ip"`
	PublicKey        string               `json:"public_key"`
	PublicIP         string               `json:"public_ip"`
	LocalAddr        string               `json:"local_addr"`
	STUNAddr         string               `json:"stun_addr"`
	WGPubKey         string               `json:"wg_pub_key"`
	WGPort           int                  `json:"wg_port"`
	ActiveEndpoint   string               `json:"active_endpoint"`
	LastSeen         time.Time            `json:"last_seen"`
	Online           bool                 `json:"online"`
	DirectP2P        bool                 `json:"direct_p2p"`
	Latency          time.Duration        `json:"latency"`
	IsExitNode       bool                 `json:"is_exit_node"`
	AdvertisedRoutes []string             `json:"advertised_routes"`
	AWG              *signaling.AWGParams `json:"awg,omitempty"`
	OS               string               `json:"os,omitempty"`
	Platform         string               `json:"platform,omitempty"`
	Country          string               `json:"country,omitempty"`
	CountryFlag      string               `json:"country_flag,omitempty"`
}

// Registry manages discovered peers in a thread-safe manner.
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

// ClearAll removes all peers from the registry (used when changing signaling topics).
func (r *Registry) ClearAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers = make(map[string]*Peer)
}

// Delete removes a peer immediately by deviceID (e.g. when peer sends goodbye/leave).
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

	if existing, ok := r.peers[p.DeviceID]; ok {
		if existing.DirectP2P {
			p.DirectP2P = true
		}
		if existing.ActiveEndpoint != "" && p.ActiveEndpoint == "" {
			p.ActiveEndpoint = existing.ActiveEndpoint
		}
		if existing.Latency > 0 && p.Latency == 0 {
			p.Latency = existing.Latency
		}
		if p.Nickname == "" && existing.Nickname != "" {
			p.Nickname = existing.Nickname
		}
		if p.AWG == nil && existing.AWG != nil {
			p.AWG = existing.AWG
		}
	}

	p.Online = true
	p.LastSeen = time.Now()

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
	r.mu.Lock()
	defer r.mu.Unlock()

	threshold := time.Now().Add(-maxAge)
	for _, p := range r.peers {
		if p.Online && p.LastSeen.Before(threshold) {
			p.Online = false
		}
	}
}

// Cleanup removes peers not seen within maxAge.
func (r *Registry) Cleanup(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	threshold := time.Now().Add(-maxAge)
	for id, p := range r.peers {
		if p.LastSeen.Before(threshold) {
			delete(r.peers, id)
		}
	}
}

// StartMonitor runs a background goroutine to periodically mark stale peers offline and cleanup.
func (r *Registry) StartMonitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 || interval > 15*time.Second {
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
				r.MarkOffline(25 * time.Second)
				r.Cleanup(90 * time.Second)
			}
		}
	}()
}
