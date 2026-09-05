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
	MTUMedium              = 1360
	MTUMinimum             = 1280
	DefaultVirtualIPSubnet = "100.64.200.0/24"

	// Peer registry lifecycle and timeouts
	PeerOfflineThreshold = 35 * time.Second
	PeerCleanupInterval  = 75 * time.Second
	PeerMonitorInterval  = 5 * time.Second

	// Circuit breaker & signaling channel reliability
	ChannelFailureThreshold = 3
	ChannelCooldown         = 20 * time.Second
	ChannelRetryDelay       = 300 * time.Millisecond

	// UDP Wire protocol headers and payloads
	TunHeaderSize          = 14
	TunHeader              = "NATBYPASS:TUN:"
	TunEncryptedHeaderSize = 14
	TunEncryptedHeader     = "NATBYPASS:ENC:" // E2E Encrypted L3 Data Packet
	TunPaddedHeaderSize    = 14
	TunPaddedHeader        = "NATBYPASS:TUP:" // Amnezia 3.x Dynamic Padding Header
	PingPrefix             = "NATBYPASS:PING:"
	PongPrefix       = "NATBYPASS:PONG:"
	MTUProbePrefix   = "NATBYPASS:MTU:REQ:"
	MTUAckPrefix     = "NATBYPASS:MTU:ACK:"
	KeepAlivePayload = "KAEP"

	// UDP Hole punching & keepalive intervals
	ProbeBurstCount    = 3
	MaxProbesPerSecond = 10
	MinProbeInterval   = 100 * time.Millisecond
	KeepAliveInterval  = 4 * time.Second

	// Low-power embedded router constants for MIPS/MIPSLE/ARM (Keenetic, OpenWrt)
	// These significantly reduce CPU load and syscall frequency on weak single-core devices.
	LowPowerPublishInterval     = 30 * time.Second
	LowPowerKeepAliveInterval   = 10 * time.Second
	LowPowerPeerMonitorInterval = 30 * time.Second
	LowPowerSTUNCacheInterval   = 60 * time.Second
	MaxPeersRouter              = 64 // Maximum peers in registry for embedded router builds
)
