//go:build !windows && !linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"errors"

	"github.com/natbypass/natbypass/internal/network"
)

var ErrRoutingNotSupported = errors.New("routing is only supported on Windows and Linux")

// EnableHostIPForwarding stub.
func EnableHostIPForwarding() error {
	return ErrRoutingNotSupported
}

// DisableHostIPForwarding stub.
func DisableHostIPForwarding() error {
	return ErrRoutingNotSupported
}

// EnableExitNodeRouting stub.
func EnableExitNodeRouting(gatewayVIP string, remoteEndpoints ...string) error {
	return ErrRoutingNotSupported
}

// DisableExitNodeRouting stub.
func DisableExitNodeRouting(gatewayVIP string) error {
	return ErrRoutingNotSupported
}

// AddSubnetRoute stub.
func AddSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	return ErrRoutingNotSupported
}

// RemoveSubnetRoute stub.
func RemoveSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	return ErrRoutingNotSupported
}

// FlushAllRouting stub.
func FlushAllRouting(gatewayVIP string, subnets []string) {}

// BypassEndpoint is a stub on non-supported platforms.
func BypassEndpoint(endpoint string) error {
	return nil
}

// EnsurePeerHostRoute is a no-op on non-Linux platforms.
func EnsurePeerHostRoute(peerVIP string) {}


// GetLocalSubnets returns a unique list of local IPv4 subnet CIDRs.
func GetLocalSubnets() []string {
	return network.GetLocalSubnets()
}

// EnableMSSClamping is a cross-platform stub for non-Linux platforms.
func EnableMSSClamping(tunInterface string, mtu int) error {
	return nil
}

// DisableMSSClamping is a cross-platform stub for non-Linux platforms.
func DisableMSSClamping(tunInterface string) error {
	return nil
}
