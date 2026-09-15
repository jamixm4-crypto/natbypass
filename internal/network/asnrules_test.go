// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"reflect"
	"testing"
)

func TestLookupCarrierASN(t *testing.T) {
	tests := []struct {
		input       string
		expectedOK  bool
		carrier     string
		predictable bool
	}{
		{"AS31133", true, "MegaFon/Yota", true},
		{"31133", true, "MegaFon/Yota", true},
		{"as8359", true, "MTS", true},
		{"AS21928", true, "T-Mobile", false},
		{"", false, "", false},
		{"UNKNOWN", false, "", false},
		{"AS999999", false, "", false},
	}

	for _, tc := range tests {
		rule, ok := LookupCarrierASN(tc.input)
		if ok != tc.expectedOK {
			t.Errorf("LookupCarrierASN(%q) ok = %v, expected %v", tc.input, ok, tc.expectedOK)
		}
		if ok {
			if rule.Carrier != tc.carrier {
				t.Errorf("LookupCarrierASN(%q) carrier = %q, expected %q", tc.input, rule.Carrier, tc.carrier)
			}
			if rule.PredictionViable != tc.predictable {
				t.Errorf("LookupCarrierASN(%q) predictable = %v, expected %v", tc.input, rule.PredictionViable, tc.predictable)
			}
		}
	}
}

func TestGenerateAdaptivePredictPorts_MegaFonSequential(t *testing.T) {
	ports := GenerateAdaptivePredictPorts(30000, 0, "AS31133")
	expected := []int{30000, 30001, 30002, 30003, 30004, 30005, 29999}
	if !reflect.DeepEqual(ports, expected) {
		t.Errorf("MegaFon sequential ports mismatch: got %v, expected %v", ports, expected)
	}
}

func TestGenerateAdaptivePredictPorts_MTSFixedStep(t *testing.T) {
	ports := GenerateAdaptivePredictPorts(40000, 0, "AS8359")
	expected := []int{40000, 40002, 40004, 40006, 40008, 40010, 39998}
	if !reflect.DeepEqual(ports, expected) {
		t.Errorf("MTS fixed step ports mismatch: got %v, expected %v", ports, expected)
	}
}

func TestGenerateAdaptivePredictPorts_TMobileRandom(t *testing.T) {
	ports := GenerateAdaptivePredictPorts(50000, 0, "AS21928")
	expected := []int{50000}
	if !reflect.DeepEqual(ports, expected) {
		t.Errorf("T-Mobile random NAT must return strictly single base port: got %v, expected %v", ports, expected)
	}
}

func TestGenerateAdaptivePredictPorts_Tele2Jitter(t *testing.T) {
	ports := GenerateAdaptivePredictPorts(25000, 0, "AS42610")
	if len(ports) < 10 {
		t.Errorf("Tele2 small jitter should generate wide jitter set: got %d ports", len(ports))
	}
	if ports[0] != 25000 {
		t.Errorf("first port must be base port: got %d", ports[0])
	}
}

func TestGenerateAdaptivePredictPorts_UnknownWithMeasuredDelta(t *testing.T) {
	ports := GenerateAdaptivePredictPorts(20000, 4, "")
	expected := []int{20000, 20004, 20008, 20012, 20016, 19996}
	if !reflect.DeepEqual(ports, expected) {
		t.Errorf("Unknown with delta=4 mismatch: got %v, expected %v", ports, expected)
	}
}

func TestGenerateAdaptivePredictPorts_InvalidEdgeCases(t *testing.T) {
	if ports := GenerateAdaptivePredictPorts(0, 0, ""); len(ports) != 0 {
		t.Errorf("port 0 should return empty: got %v", ports)
	}
	if ports := GenerateAdaptivePredictPorts(70000, 0, ""); len(ports) != 0 {
		t.Errorf("port 70000 should return empty: got %v", ports)
	}
}
