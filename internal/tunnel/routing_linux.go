//go:build linux

package tunnel

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/natbypass/natbypass/internal/network"
)

func runLinuxCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// EnableHostIPForwarding enables kernel IPv4 forwarding and adds iptables NAT masquerading for mesh subnet.
func EnableHostIPForwarding() error {
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	_ = runLinuxCmd("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "100.64.200.0/24", "-j", "MASQUERADE")
	_ = runLinuxCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "100.64.200.0/24", "-j", "MASQUERADE")
	return nil
}

// DisableHostIPForwarding removes iptables NAT masquerading rule.
func DisableHostIPForwarding() error {
	_ = runLinuxCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "100.64.200.0/24", "-j", "MASQUERADE")
	return nil
}

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1).
func EnableExitNodeRouting(gatewayVIP string) error {
	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	_ = runLinuxCmd("ip", "route", "add", "0.0.0.0/1", "via", gatewayVIP)
	_ = runLinuxCmd("ip", "route", "add", "128.0.0.0/1", "via", gatewayVIP)
	return nil
}

// DisableExitNodeRouting removes def1 routes.
func DisableExitNodeRouting(gatewayVIP string) error {
	if gatewayVIP != "" {
		_ = runLinuxCmd("ip", "route", "del", "0.0.0.0/1", "via", gatewayVIP)
		_ = runLinuxCmd("ip", "route", "del", "128.0.0.0/1", "via", gatewayVIP)
	} else {
		_ = runLinuxCmd("ip", "route", "del", "0.0.0.0/1")
		_ = runLinuxCmd("ip", "route", "del", "128.0.0.0/1")
	}
	return nil
}

// AddSubnetRoute adds a route for a subnet CIDR via gatewayVIP.
func AddSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	return runLinuxCmd("ip", "route", "add", subnetCIDR, "via", gatewayVIP)
}

// RemoveSubnetRoute removes a route for a subnet CIDR via gatewayVIP.
func RemoveSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	return runLinuxCmd("ip", "route", "del", subnetCIDR, "via", gatewayVIP)
}

// FlushAllRouting cleans up any active routes.
func FlushAllRouting(gatewayVIP string, subnets []string) {
	_ = DisableExitNodeRouting(gatewayVIP)
	for _, s := range subnets {
		_ = RemoveSubnetRoute(s, gatewayVIP)
	}
}

// GetLocalSubnets returns a unique list of local IPv4 subnet CIDRs.
func GetLocalSubnets() []string {
	return network.GetLocalSubnets()
}
