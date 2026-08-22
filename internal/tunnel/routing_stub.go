//go:build !windows

package tunnel

import (
	"errors"

	"github.com/natbypass/natbypass/internal/network"
)

var ErrRoutingNotSupported = errors.New("routing is only supported on Windows")

// EnableHostIPForwarding stub for non-windows platforms.
func EnableHostIPForwarding() error {
	return ErrRoutingNotSupported
}

// EnableExitNodeRouting stub for non-windows platforms.
func EnableExitNodeRouting(gatewayVIP string) error {
	return ErrRoutingNotSupported
}

// DisableExitNodeRouting stub for non-windows platforms.
func DisableExitNodeRouting(gatewayVIP string) error {
	return ErrRoutingNotSupported
}

// AddSubnetRoute stub for non-windows platforms.
func AddSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	return ErrRoutingNotSupported
}

// RemoveSubnetRoute stub for non-windows platforms.
func RemoveSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	return ErrRoutingNotSupported
}

// GetLocalSubnets returns a unique list of local IPv4 subnet CIDRs.
func GetLocalSubnets() []string {
	return network.GetLocalSubnets()
}
