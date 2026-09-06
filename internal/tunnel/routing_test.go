// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"testing"
)

func TestParseSubnetCIDR(t *testing.T) {
	tests := []struct {
		cidr        string
		expectedIP  string
		expectedMask string
		expectErr   bool
	}{
		{
			cidr:        "192.168.1.0/24",
			expectedIP:  "192.168.1.0",
			expectedMask: "255.255.255.0",
			expectErr:   false,
		},
		{
			cidr:        "10.0.0.0/8",
			expectedIP:  "10.0.0.0",
			expectedMask: "255.0.0.0",
			expectErr:   false,
		},
		{
			cidr:        "172.16.5.12/16",
			expectedIP:  "172.16.0.0",
			expectedMask: "255.255.0.0",
			expectErr:   false,
		},
		{
			cidr:        "192.168.100.50/32",
			expectedIP:  "192.168.100.50",
			expectedMask: "255.255.255.255",
			expectErr:   false,
		},
		{
			cidr:      "invalid",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		ip, mask, err := parseSubnetCIDR(tt.cidr)
		if tt.expectErr {
			if err == nil {
				t.Errorf("parseSubnetCIDR(%q) expected error, got nil", tt.cidr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSubnetCIDR(%q) unexpected error: %v", tt.cidr, err)
			continue
		}
		if ip != tt.expectedIP {
			t.Errorf("parseSubnetCIDR(%q) IP = %v, want %v", tt.cidr, ip, tt.expectedIP)
		}
		if mask != tt.expectedMask {
			t.Errorf("parseSubnetCIDR(%q) Mask = %v, want %v", tt.cidr, mask, tt.expectedMask)
		}
	}
}
