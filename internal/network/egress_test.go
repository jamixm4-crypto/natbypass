package network

import (
	"context"
	"testing"
	"time"
)

func TestDetectEgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, err := DetectEgress(ctx)
	if err != nil {
		t.Fatalf("DetectEgress failed: %v", err)
	}

	if info == nil {
		t.Fatalf("expected non-nil EgressInfo")
	}

	// At least LocalIP should be detected on any connected machine
	if info.LocalIP == nil {
		t.Logf("Notice: LocalIP is nil (machine might be offline during test)")
	} else {
		t.Logf("Egress Interface: %s (%s, type=%s, ifIndex=%d, MTU=%d)", info.InterfaceName, info.LocalIP.String(), info.HardwareType, info.InterfaceIndex, info.MTU)
		if info.GatewayIP != nil {
			t.Logf("Default Gateway: %s", info.GatewayIP.String())
		}
		t.Logf("Internet Live: %v (Canary RTT: %v)", info.InternetLive, info.CanaryLatency)
	}

	if info.Signature == "" {
		t.Errorf("expected non-empty Signature")
	}
}

func TestClassifyHardwareType(t *testing.T) {
	cases := []struct {
		name     string
		expected string
	}{
		{"Wi-Fi", "Wi-Fi"},
		{"wlan0", "Wi-Fi"},
		{"wireless1", "Wi-Fi"},
		{"eth0", "Ethernet"},
		{"Ethernet 2", "Ethernet"},
		{"enp3s0", "Ethernet"},
		{"rmnet_data0", "Cellular"},
		{"cellular0", "Cellular"},
		{"ccmni0", "Cellular"},
		{"pdp0", "Cellular"},
		{"unknown_device", "Network Adapter"},
	}

	for _, c := range cases {
		got := classifyHardwareType(c.name)
		if got != c.expected {
			t.Errorf("classifyHardwareType(%q) = %q, expected %q", c.name, got, c.expected)
		}
	}
}

func TestNetworkWatchdog_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changed := false
	wd := NewNetworkWatchdog(ctx, 500*time.Millisecond, func(oldInfo, newInfo *EgressInfo) {
		changed = true
	})
	if wd == nil {
		t.Fatalf("expected non-nil watchdog")
	}

	cur := wd.GetCurrent()
	if cur == nil {
		t.Fatalf("expected non-nil current EgressInfo")
	}

	time.Sleep(700 * time.Millisecond)
	wd.Stop()
	_ = changed
}
