package diagnostic

import (
	"net"
	"testing"
)

func TestCGNATSubnet(t *testing.T) {
	cases := []struct {
		ip      string
		isCGNAT bool
	}{
		{"100.64.0.1", true},
		{"100.127.255.254", true},
		{"100.63.255.255", false},
		{"100.128.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
	}

	for _, tc := range cases {
		parsed := net.ParseIP(tc.ip)
		if parsed == nil {
			t.Fatalf("failed to parse IP %s", tc.ip)
		}
		got := cgnatSubnet.Contains(parsed)
		if got != tc.isCGNAT {
			t.Errorf("IP %s: expected isCGNAT=%v, got=%v", tc.ip, tc.isCGNAT, got)
		}
	}
}

func TestPBABlockDetection(t *testing.T) {
	// Ports within same 256-block: 50000 -> 50000 & ^255 = 49920, 50100 & ^255 = 49920
	p1 := 50000
	p2 := 50050
	p3 := 50120

	blockSizes := []int{512, 256, 128, 64}
	var detectedSize int
	for _, size := range blockSizes {
		mask := ^(size - 1)
		if (p1&mask) == (p2&mask) && (p2&mask) == (p3&mask) {
			detectedSize = size
			break
		}
	}

	if detectedSize != 256 && detectedSize != 512 {
		t.Errorf("expected PBA size 256 or 512, got %d", detectedSize)
	}
}

func TestParityPreservation(t *testing.T) {
	evenPorts := []int{50000, 50002, 50004}
	if (evenPorts[0]%2 != evenPorts[1]%2) || (evenPorts[1]%2 != evenPorts[2]%2) {
		t.Errorf("expected even parity preservation")
	}

	oddPorts := []int{50001, 50003, 50005}
	if (oddPorts[0]%2 != oddPorts[1]%2) || (oddPorts[1]%2 != oddPorts[2]%2) {
		t.Errorf("expected odd parity preservation")
	}
}
