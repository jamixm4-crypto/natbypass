// Package constants defines shared system, protocol, and network constants for NatBypass.
package constants

import "time"

const (
	// Network and service defaults
	DefaultWebUIPort       = 8080
	DefaultUDPPort         = 47832
	DefaultPublishInterval = 8 * time.Second
	DefaultIPTimeout       = 10 * time.Second
	DefaultWGListenPort    = 51820
	DefaultWGMTU           = 1420
	DefaultVirtualIPSubnet = "100.64.200.0/24"

	// Peer registry lifecycle and timeouts
	PeerOfflineThreshold = 120 * time.Second
	PeerCleanupInterval  = 3 * time.Minute
	PeerMonitorInterval  = 10 * time.Second

	// Circuit breaker & signaling channel reliability
	ChannelFailureThreshold = 3
	ChannelCooldown         = 20 * time.Second
	ChannelRetryDelay       = 300 * time.Millisecond

	// UDP Wire protocol headers and payloads
	TunHeaderSize    = 14
	TunHeader        = "NATBYPASS:TUN:"
	PingPrefix       = "NATBYPASS:PING:"
	PongPrefix       = "NATBYPASS:PONG:"
	KeepAlivePayload = "KAEP"

	// UDP Hole punching rate limits
	ProbeBurstCount    = 2
	MaxProbesPerSecond = 2
	MinProbeInterval   = 500 * time.Millisecond
)