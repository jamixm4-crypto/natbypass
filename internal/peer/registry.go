package peer

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Peer represents a discovered device in the network.
type Peer struct {
	DeviceID   string        `json:"device_id"`
	PublicKey  string        `json:"public_key"`
	PublicIP   string        `json:"public_ip"`
	STUNAddr   string        `json:"stun_addr"`
	WGPubKey   string        `json:"wg_pub_key"`
	WGPort     int           `json:"wg_port"`
	LastSeen   time.Time     `json:"last_seen"`
	Online     bool          `json:"online"`
	Latency    time.Duration `json:"latency"`
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

// Upsert adds or updates a peer in the registry.
func (r *Registry) Upsert(p *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()

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

// StartMonitor runs a background goroutine to periodically mark stale peers offline.
func (r *Registry) StartMonitor(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.MarkOffline(interval * 2) // Default heuristic for maxAge
			}
		}
	}()
}
