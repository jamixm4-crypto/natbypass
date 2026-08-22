package tunnel

import (
	"fmt"
	"net"
	"strings"
)

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
