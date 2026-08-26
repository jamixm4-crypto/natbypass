package network

import (
	"net"
	"testing"
)

func TestExtractIPv4Subnet(t *testing.T) {
	tests := []struct {
		name     string
		addr     net.Addr
		expected string
	}{
		{
			name: "Standard /24 LAN",
			addr: &net.IPNet{
				IP:   net.ParseIP("192.168.1.100").To4(),
				Mask: net.CIDRMask(24, 32),
			},
			expected: "192.168.1.0/24",
		},
		{
			name: "Standard /16 LAN",
			addr: &net.IPNet{
				IP:   net.ParseIP("172.16.5.50").To4(),
				Mask: net.CIDRMask(16, 32),
			},
			expected: "172.16.0.0/16",
		},
		{
			name: "Standard /8 LAN",
			addr: &net.IPNet{
				IP:   net.ParseIP("10.50.2.1").To4(),
				Mask: net.CIDRMask(8, 32),
			},
			expected: "10.0.0.0/8",
		},
		{
			name: "Ignore Mesh IP 100.64.x.x",
			addr: &net.IPNet{
				IP:   net.ParseIP("100.64.200.5").To4(),
				Mask: net.CIDRMask(24, 32),
			},
			expected: "",
		},
		{
			name: "Ignore Loopback 127.0.0.1",
			addr: &net.IPNet{
				IP:   net.ParseIP("127.0.0.1").To4(),
				Mask: net.CIDRMask(8, 32),
			},
			expected: "",
		},
		{
			name: "Ignore IPv6",
			addr: &net.IPNet{
				IP:   net.ParseIP("fe80::1"),
				Mask: net.CIDRMask(64, 128),
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPv4Subnet(tt.addr)
			if got != tt.expected {
				t.Errorf("extractIPv4Subnet() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetLocalSubnets(t *testing.T) {
	subnets := GetLocalSubnets()
	// Should not crash and return valid CIDRs if any are present
	seen := make(map[string]bool)
	for _, s := range subnets {
		if seen[s] {
			t.Errorf("Duplicate subnet found: %s", s)
		}
		seen[s] = true

		_, _, err := net.ParseCIDR(s)
		if err != nil {
			t.Errorf("GetLocalSubnets returned invalid CIDR %q: %v", s, err)
		}
	}
}
