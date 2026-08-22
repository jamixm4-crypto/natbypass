//go:build windows

package tunnel

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"

	"github.com/natbypass/natbypass/internal/network"
)

// runRouteCmd executes a Windows command without opening a console window.
func runRouteCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// parseSubnetCIDR parses a CIDR string (e.g. 192.168.1.0/24) and returns the IPv4 network address and subnet mask.
func parseSubnetCIDR(subnetCIDR string) (string, string, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(subnetCIDR))
	if err != nil {
		return "", "", fmt.Errorf("invalid subnet CIDR %q: %w", subnetCIDR, err)
	}
	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		return "", "", fmt.Errorf("subnet CIDR %q is not an IPv4 network", subnetCIDR)
	}
	mask := ipNet.Mask
	if len(mask) == 16 {
		mask = mask[12:16]
	}
	if len(mask) != 4 {
		return "", "", fmt.Errorf("invalid IPv4 subnet mask for %q", subnetCIDR)
	}
	maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	return networkIP.String(), maskStr, nil
}

// EnableHostIPForwarding sets IP forwarding on interface "NatBypass" and enables IP routing in Windows.
func EnableHostIPForwarding() error {
	if err := runRouteCmd("netsh", "interface", "ipv4", "set", "interface", "NatBypass", "forwarding=enabled"); err != nil {
		return fmt.Errorf("failed to enable IP forwarding on NatBypass interface: %w", err)
	}
	return nil
}

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1) via gatewayVIP.
func EnableExitNodeRouting(gatewayVIP string) error {
	if err := runRouteCmd("route", "add", "0.0.0.0", "mask", "128.0.0.0", gatewayVIP, "metric", "5"); err != nil {
		return fmt.Errorf("failed to add default route 0.0.0.0/1 via %s: %w", gatewayVIP, err)
	}
	if err := runRouteCmd("route", "add", "128.0.0.0", "mask", "128.0.0.0", gatewayVIP, "metric", "5"); err != nil {
		_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0", gatewayVIP)
		return fmt.Errorf("failed to add default route 128.0.0.0/1 via %s: %w", gatewayVIP, err)
	}
	return nil
}

// DisableExitNodeRouting removes the default gateway /1 routes via gatewayVIP.
func DisableExitNodeRouting(gatewayVIP string) error {
	var errs []string
	if err := runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0", gatewayVIP); err != nil {
		errs = append(errs, err.Error())
	}
	if err := runRouteCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0", gatewayVIP); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors disabling exit node routing: %s", strings.Join(errs, "; "))
	}
	return nil
}

// AddSubnetRoute adds a routing entry for a subnet CIDR via gatewayVIP.
func AddSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	ipStr, maskStr, err := parseSubnetCIDR(subnetCIDR)
	if err != nil {
		return err
	}
	if err := runRouteCmd("route", "add", ipStr, "mask", maskStr, gatewayVIP, "metric", "10"); err != nil {
		return fmt.Errorf("failed to add subnet route %s via %s: %w", subnetCIDR, gatewayVIP, err)
	}
	return nil
}

// RemoveSubnetRoute removes a routing entry for a subnet CIDR via gatewayVIP.
func RemoveSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	ipStr, maskStr, err := parseSubnetCIDR(subnetCIDR)
	if err != nil {
		return err
	}
	if err := runRouteCmd("route", "delete", ipStr, "mask", maskStr, gatewayVIP); err != nil {
		return fmt.Errorf("failed to remove subnet route %s via %s: %w", subnetCIDR, gatewayVIP, err)
	}
	return nil
}

// GetLocalSubnets returns a unique list of local IPv4 subnet CIDRs.
func GetLocalSubnets() []string {
	return network.GetLocalSubnets()
}
