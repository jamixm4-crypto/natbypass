package peer

import (
	"reflect"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/signaling"
)

func TestRegistryUpsert_AWGPreservationAndUpdate(t *testing.T) {
	reg := NewRegistry()

	awg1 := &signaling.AWGParams{
		Jc:   4,
		Jmin: 40,
		Jmax: 70,
		S1:   48,
		S2:   32,
		H1:   "1428571428",
		H2:   "2147483647",
		H3:   "857142857",
		H4:   "1122334455",
	}

	p1 := &Peer{
		DeviceID:       "dev-1",
		Nickname:       "Peer1",
		VirtualIP:      "10.200.0.2",
		PublicKey:      "pub1",
		PublicIP:       "1.1.1.1",
		STUNAddr:       "1.1.1.1:51820",
		WGPubKey:       "wg1",
		WGPort:         51820,
		ActiveEndpoint: "1.1.1.1:51820",
		DirectP2P:      true,
		Latency:        20 * time.Millisecond,
		AWG:            awg1,
	}

	// 1. Initial Upsert with AWG
	reg.Upsert(p1)

	got, ok := reg.Get("dev-1")
	if !ok {
		t.Fatalf("Peer dev-1 not found in registry")
	}
	if got.AWG == nil {
		t.Fatalf("Expected AWG to be set on initial upsert")
	}
	if !reflect.DeepEqual(got.AWG, awg1) {
		t.Errorf("AWG mismatch: got %+v, want %+v", got.AWG, awg1)
	}

	// 2. Upsert with nil AWG - must PRESERVE existing AWG
	p2 := &Peer{
		DeviceID:  "dev-1",
		VirtualIP: "10.200.0.2",
		PublicKey: "pub1",
		PublicIP:  "1.1.1.1",
		STUNAddr:  "1.1.1.1:51820",
		WGPubKey:  "wg1",
		WGPort:    51820,
		AWG:       nil, // nil AWG in heartbeat
	}

	reg.Upsert(p2)

	got2, ok := reg.Get("dev-1")
	if !ok {
		t.Fatalf("Peer dev-1 not found after second upsert")
	}
	if got2.AWG == nil {
		t.Fatalf("Expected existing AWG to be preserved when nil AWG is upserted")
	}
	if !reflect.DeepEqual(got2.AWG, awg1) {
		t.Errorf("Preserved AWG mismatch: got %+v, want %+v", got2.AWG, awg1)
	}
	if !got2.DirectP2P {
		t.Errorf("DirectP2P was not preserved")
	}
	if got2.ActiveEndpoint != "1.1.1.1:51820" {
		t.Errorf("ActiveEndpoint was not preserved")
	}
	if got2.Latency != 20*time.Millisecond {
		t.Errorf("Latency was not preserved")
	}
	if got2.Nickname != "Peer1" {
		t.Errorf("Nickname was not preserved")
	}

	// 3. Upsert with updated AWG - must UPDATE existing AWG
	awg2 := &signaling.AWGParams{
		Jc:   8,
		Jmin: 50,
		Jmax: 100,
		S1:   64,
		S2:   48,
		H1:   "987654321",
		H2:   "123456789",
		H3:   "555555555",
		H4:   "444444444",
	}

	p3 := &Peer{
		DeviceID:  "dev-1",
		VirtualIP: "10.200.0.2",
		PublicKey: "pub1",
		PublicIP:  "1.1.1.1",
		STUNAddr:  "1.1.1.1:51820",
		WGPubKey:  "wg1",
		WGPort:    51820,
		AWG:       awg2,
	}

	reg.Upsert(p3)

	got3, ok := reg.Get("dev-1")
	if !ok {
		t.Fatalf("Peer dev-1 not found after third upsert")
	}
	if got3.AWG == nil {
		t.Fatalf("Expected updated AWG to be present")
	}
	if !reflect.DeepEqual(got3.AWG, awg2) {
		t.Errorf("Updated AWG mismatch: got %+v, want %+v", got3.AWG, awg2)
	}
}
