package wireguard

import (
	"testing"
)

func TestAWGCarrierMobileParams(t *testing.T) {
	p := GenerateAWGCarrierMobileParams()
	if !p.Enabled {
		t.Fatalf("carrier_mobile should be enabled")
	}
	if p.Jc != 3 {
		t.Errorf("expected Jc=3 for carrier_mobile, got %d", p.Jc)
	}
	if p.Jmax > 80 {
		t.Errorf("expected Jmax<=80 for mobile to prevent fragmentation, got %d", p.Jmax)
	}
	if p.S1+56 == p.S2 {
		t.Errorf("invariant violated: S1+56 == S2 (%d + 56 == %d)", p.S1, p.S2)
	}
	if p.S1 == p.S2 {
		t.Errorf("invariant violated: S1 == S2 (%d)", p.S1)
	}
	if p.S1-p.S2 == 56 || p.S2-p.S1 == 56 {
		t.Errorf("invariant violated: |S1 - S2| == 56 (%d, %d)", p.S1, p.S2)
	}
	if !p.HeaderProtectionEnabled {
		t.Errorf("carrier_mobile must have HeaderProtectionEnabled")
	}
	if !p.RandomTrailers {
		t.Errorf("carrier_mobile must have RandomTrailers")
	}
	if !p.DisableCookies {
		t.Errorf("carrier_mobile must have DisableCookies")
	}
	if p.I1 == "" {
		t.Errorf("carrier_mobile must have QUIC mimic I1 CPS")
	}
	mtu := GetRecommendedMTU("carrier_mobile")
	if mtu != 1280 {
		t.Errorf("expected MTU 1280 for carrier_mobile, got %d", mtu)
	}
}

func TestAWGCarrierFixedParams(t *testing.T) {
	p := GenerateAWGCarrierFixedParams()
	if !p.Enabled {
		t.Fatalf("carrier_fixed should be enabled")
	}
	if p.Jc != 5 {
		t.Errorf("expected Jc=5 for carrier_fixed, got %d", p.Jc)
	}
	if p.S1+56 == p.S2 || p.S1-p.S2 == 56 || p.S2-p.S1 == 56 {
		t.Errorf("invariant violated: S1/S2 difference matches 56 (%d, %d)", p.S1, p.S2)
	}
	if p.I1 == "" || p.I2 == "" {
		t.Errorf("carrier_fixed must have I1 and I2 CPS packets")
	}
	mtu := GetRecommendedMTU("carrier_fixed")
	if mtu != 1280 {
		t.Errorf("expected MTU 1280 for carrier_fixed, got %d", mtu)
	}
}

func TestAWGDeriveWithEpochRotation(t *testing.T) {
	key := "test-secret-network-key-12345"
	p0 := DeriveAWGParamsFromKeyAndEpoch(key, 0)
	p1 := DeriveAWGParamsFromKeyAndEpoch(key, 1)

	// Invariant check on derived parameters
	if p0.S1+56 == p0.S2 || p0.S1 == p0.S2 || p0.S1-p0.S2 == 56 || p0.S2-p0.S1 == 56 {
		t.Errorf("p0 invariant violated: S1=%d, S2=%d", p0.S1, p0.S2)
	}
	if p1.S1+56 == p1.S2 || p1.S1 == p1.S2 || p1.S1-p1.S2 == 56 || p1.S2-p1.S1 == 56 {
		t.Errorf("p1 invariant violated: S1=%d, S2=%d", p1.S1, p1.S2)
	}

	// Determinism check: same key and same epoch must give identical params
	p0Repeat := DeriveAWGParamsFromKeyAndEpoch(key, 0)
	if p0.H1 != p0Repeat.H1 || p0.HeaderProtectionKey != p0Repeat.HeaderProtectionKey || p0.S1 != p0Repeat.S1 {
		t.Errorf("DeriveAWGParamsFromKeyAndEpoch is not deterministic for same epoch")
	}

	// Epoch change must rotate headers and keys
	if p0.HeaderProtectionKey == p1.HeaderProtectionKey {
		t.Errorf("HeaderProtectionKey should rotate across epochs")
	}
	if p0.H1 == p1.H1 && p0.H2 == p1.H2 && p0.H3 == p1.H3 && p0.H4 == p1.H4 {
		t.Errorf("H1..H4 should rotate across epochs")
	}
}
