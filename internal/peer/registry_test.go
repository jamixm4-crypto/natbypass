package peer

import (
	"reflect"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/signaling"
)

func TestPeer_MergeFrom(t *testing.T) {
	existing := &Peer{
		DeviceID:       "dev-1",
		Nickname:       "OriginalNickname",
		DirectP2P:      true,
		ActiveEndpoint: "192.168.1.50:47832",
		Latency:        15 * time.Millisecond,
		PingMs:         15,
		HasMQTT:        true,
		LastMQTTSeen:   time.Now().Add(-5 * time.Second),
		AWG: &signaling.AWGParams{
			Jc: 4,
		},
	}

	newer := &Peer{
		DeviceID:  "dev-1",
		PublicIP:  "203.0.113.10",
		Channel:   "telegram",
		VirtualIP: "100.64.200.5",
	}

	existing.MergeFrom(newer)

	if !newer.DirectP2P {
		t.Errorf("expected DirectP2P to be preserved as true")
	}
	if newer.ActiveEndpoint != "192.168.1.50:47832" {
		t.Errorf("expected ActiveEndpoint to be preserved, got %s", newer.ActiveEndpoint)
	}
	if newer.Nickname != "OriginalNickname" {
		t.Errorf("expected Nickname to be preserved, got %s", newer.Nickname)
	}
	if newer.Latency != 15*time.Millisecond {
		t.Errorf("expected Latency to be preserved, got %v", newer.Latency)
	}
	if newer.Channel != "parallel" {
		t.Errorf("expected Channel to merge into 'parallel', got %s", newer.Channel)
	}
	if newer.AWG == nil || newer.AWG.Jc != 4 {
		t.Errorf("expected AWG to be preserved from existing")
	}
}

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
		VirtualIP:      "100.64.200.2",
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
		VirtualIP: "100.64.200.2",
		PublicKey: "pub1",
		PublicIP:  "1.1.1.1",
		STUNAddr:  "1.1.1.1:51820",
		WGPubKey:  "wg1",
		WGPort:    51820,
		AWG:       nil,
	}
	reg.Upsert(p2)

	got2, ok := reg.Get("dev-1")
	if !ok {
		t.Fatalf("Peer dev-1 not found after second upsert")
	}
	if got2.AWG == nil {
		t.Fatalf("Expected existing AWG to be preserved when newer peer has nil AWG")
	}
	if !reflect.DeepEqual(got2.AWG, awg1) {
		t.Errorf("AWG was altered unexpectedly: got %+v, want %+v", got2.AWG, awg1)
	}

	// 3. Upsert with updated AWG - must UPDATE to new AWG
	awg2 := &signaling.AWGParams{
		Jc:   10,
		Jmin: 50,
		Jmax: 80,
		S1:   64,
		S2:   64,
		H1:   "999999999",
	}
	p3 := &Peer{
		DeviceID:  "dev-1",
		VirtualIP: "100.64.200.2",
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
	if !reflect.DeepEqual(got3.AWG, awg2) {
		t.Errorf("AWG was not updated: got %+v, want %+v", got3.AWG, awg2)
	}
}

func TestRegistry_GhostPeerPruning(t *testing.T) {
	reg := NewRegistry()

	// 1. Старый узел Android с VIP 10.11.12.225 — помечен давно не видимым (stale)
	pOld := &Peer{
		DeviceID:       "Android-cd979911",
		Nickname:       "Android Phone",
		VirtualIP:      "10.11.12.225/24",
		PublicKey:      "pub_old",
		PublicIP:       "37.212.27.76",
		STUNAddr:       "37.212.27.76:1558",
		Online:         false,
		DirectP2P:      false,
		LastSeen:       time.Now().Add(-120 * time.Second), // BUG-10: > PeerOfflineThreshold(90s) → truly stale
	}
	reg.Upsert(pOld)

	if !reg.Exists("Android-cd979911") {
		t.Fatalf("expected Android-cd979911 to exist in registry")
	}

	// 2. Новый узел Android с тем же VIP 10.11.12.225
	pNew := &Peer{
		DeviceID:       "Android-c3f2027a",
		Nickname:       "Android Phone",
		VirtualIP:      "10.11.12.225",
		PublicKey:      "pub_new",
		PublicIP:       "37.212.27.76",
		STUNAddr:       "37.212.27.76:1548",
		Online:         true,
		DirectP2P:      true,
		PingMs:         157,
		LastSeen:       time.Now(),
	}
	reg.Upsert(pNew)

	// Старый фантом должен быть автоматически вытеснен из реестра
	if reg.Exists("Android-cd979911") {
		t.Errorf("expected stale peer Android-cd979911 to be pruned from registry on VIP conflict")
	}
	if !reg.Exists("Android-c3f2027a") {
		t.Errorf("expected active peer Android-c3f2027a to exist in registry")
	}

	// 3. GetByVirtualIP должен возвращать активный узел
	best, ok := reg.GetByVirtualIP("10.11.12.225")
	if !ok || best == nil {
		t.Fatalf("expected GetByVirtualIP to find peer for 10.11.12.225")
	}
	if best.DeviceID != "Android-c3f2027a" {
		t.Errorf("expected best peer Android-c3f2027a, got %s", best.DeviceID)
	}
}

func TestRegistry_GetByVirtualIP_Ranking(t *testing.T) {
	reg := NewRegistry()

	// Намеренно добавляем напрямую 2 пира с одинаковым VIP в map
	reg.mu.Lock()
	reg.peers["ghost-1"] = &Peer{
		DeviceID:  "ghost-1",
		VirtualIP: "10.11.12.100",
		Online:    false,
		DirectP2P: false,
		LastSeen:  time.Now().Add(-120 * time.Second),
	}
	reg.peers["live-1"] = &Peer{
		DeviceID:  "live-1",
		VirtualIP: "10.11.12.100",
		Online:    true,
		DirectP2P: true,
		PingMs:    45,
		LastSeen:  time.Now(),
	}
	reg.mu.Unlock()

	// GetByVirtualIP обязан выбрать live-1
	p, ok := reg.GetByVirtualIP("10.11.12.100")
	if !ok || p == nil {
		t.Fatalf("expected to find peer for 10.11.12.100")
	}
	if p.DeviceID != "live-1" {
		t.Errorf("expected live-1, got %s", p.DeviceID)
	}
}