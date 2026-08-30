//go:build !windows && !linux

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
func EnableExitNodeRouting(gatewayVIP string) error {
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
