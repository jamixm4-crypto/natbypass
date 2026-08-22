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

// GetDestIP extracts Destination IPv4 address from packet header.
func GetDestIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	version := packet[0] >> 4
	if version != 4 {
		return nil
	}
	return net.IPv4(packet[16], packet[17], packet[18], packet[19])
}

// GetSrcIP extracts Source IPv4 address from packet header.
func GetSrcIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	version := packet[0] >> 4
	if version != 4 {
		return nil
	}
	return net.IPv4(packet[12], packet[13], packet[14], packet[15])
}

// CalculateChecksum computes 16-bit internet checksum (RFC 1071).
func CalculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
