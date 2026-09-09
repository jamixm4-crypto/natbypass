// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package transport

import (
	"sort"
	"sync"
)

const (
	TransportAWG       = "awg"
	TransportQUIC      = "quic"
	TransportShadowTLS = "shadowtls"
	TransportWSS       = "wss"
)

// TransportFeatures describes capabilities and security parameters of a transport channel.
type TransportFeatures struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"` // "udp", "tcp", "tls", "quic"
	Encrypted    bool   `json:"encrypted"`
	Obfuscated   bool   `json:"obfuscated"`
	Multiplexing bool   `json:"multiplexing"`
	Priority     int    `json:"priority"` // Lower value = higher preference (1=highest)
}

// Transport is the pluggable abstraction interface for all NatBypass network transports.
type Transport interface {
	Name() string
	Features() TransportFeatures
}

// BaseTransport is a generic container implementing Transport.
type BaseTransport struct {
	name     string
	features TransportFeatures
}

func NewBaseTransport(name string, features TransportFeatures) *BaseTransport {
	return &BaseTransport{
		name:     name,
		features: features,
	}
}

func (b *BaseTransport) Name() string {
	return b.name
}

func (b *BaseTransport) Features() TransportFeatures {
	return b.features
}

// Registry manages registered pluggable transports.
type Registry struct {
	mu         sync.RWMutex
	transports map[string]Transport
}

var (
	defaultRegistry     *Registry
	defaultRegistryOnce sync.Once
)

// NewRegistry creates a new Transport registry.
func NewRegistry() *Registry {
	return &Registry{
		transports: make(map[string]Transport),
	}
}

// DefaultRegistry returns the singleton transport registry populated with standard transports.
func DefaultRegistry() *Registry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = NewRegistry()
		defaultRegistry.Register(NewBaseTransport("awg", TransportFeatures{
			Name:         "AmneziaWG UDP",
			Protocol:     "udp",
			Encrypted:    true,
			Obfuscated:   true,
			Multiplexing: false,
			Priority:     1,
		}))
		defaultRegistry.Register(NewBaseTransport("quic", TransportFeatures{
			Name:         "RFC 9000 QUIC",
			Protocol:     "quic",
			Encrypted:    true,
			Obfuscated:   true,
			Multiplexing: true,
			Priority:     2,
		}))
		defaultRegistry.Register(NewBaseTransport("shadowtls", TransportFeatures{
			Name:         "ShadowTLS v3",
			Protocol:     "tcp",
			Encrypted:    true,
			Obfuscated:   true,
			Multiplexing: false,
			Priority:     3,
		}))
		defaultRegistry.Register(NewBaseTransport("wss", TransportFeatures{
			Name:         "WebSocket over TLS",
			Protocol:     "tls",
			Encrypted:    true,
			Obfuscated:   true,
			Multiplexing: true,
			Priority:     4,
		}))
	})
	return defaultRegistry
}

// Register registers a transport.
func (r *Registry) Register(t Transport) {
	if t == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transports[t.Name()] = t
}

// Get retrieves a transport by its internal name.
func (r *Registry) Get(name string) (Transport, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.transports[name]
	return t, ok
}

// List returns all registered transports sorted by Priority.
func (r *Registry) List() []Transport {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Transport, 0, len(r.transports))
	for _, t := range r.transports {
		result = append(result, t)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Features().Priority < result[j].Features().Priority
	})
	return result
}
