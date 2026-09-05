package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/crypto"
)

func TestHopPort_NoRace(t *testing.T) {
	p, err := NewUDPPuncher(0, "test-dev-1", nil, nil)
	if err != nil {
		t.Fatalf("failed to create UDPPuncher: %v", err)
	}
	defer p.Close()

	initialPort := p.LocalPort()
	if initialPort == 0 {
		t.Fatalf("expected non-zero local port")
	}

	for i := 0; i < 3; i++ {
		newPort, err := p.HopPort()
		if err != nil {
			t.Fatalf("HopPort failed on iteration %d: %v", i, err)
		}
		if newPort == 0 {
			t.Fatalf("HopPort returned 0 port on iteration %d", i)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTrafficShaper_PuncherIntegration(t *testing.T) {
	p, err := NewUDPPuncher(0, "test-dev-shaper", nil, nil)
	if err != nil {
		t.Fatalf("failed to create UDPPuncher: %v", err)
	}
	defer p.Close()

	shaper := NewTrafficShaper(true)
	p.SetTrafficShaper(shaper)

	if p.trafficShaper == nil || !p.trafficShaper.IsEnabled() {
		t.Fatalf("expected traffic shaper to be set and enabled")
	}
}

func TestUDPPuncher_EncryptedTunnelData(t *testing.T) {
	key := "my-secret-mesh-network-key-12345"
	fakeIPv4 := []byte{
		0x45, 0x00, 0x00, 0x3c, // IPv4 header (IHL 5, Total Length 60)
		0x1c, 0x46, 0x40, 0x00,
		0x40, 0x01, 0x2e, 0x38, // Protocol ICMP
		10, 11, 12, 1,          // Src IP
		10, 11, 12, 2,          // Dst IP
		0x08, 0x00, 0x4d, 0x5a, // ICMP Echo Request
		0x00, 0x01, 0x00, 0x01,
	}

	nodeB, err := NewUDPPuncher(0, "node-b", nil, nil)
	if err != nil {
		t.Fatalf("failed to create nodeB: %v", err)
	}
	defer nodeB.Close()
	nodeB.SetCipherKey(key)

	receivedCh := make(chan []byte, 1)
	nodeB.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
		receivedCh <- payload
	})

	nodeA, err := NewUDPPuncher(0, "node-a", nil, nil)
	if err != nil {
		t.Fatalf("failed to create nodeA: %v", err)
	}
	defer nodeA.Close()
	nodeA.SetCipherKey(key)

	targetAddr := fmt.Sprintf("127.0.0.1:%d", nodeB.LocalPort())

	// Отправка с паддингом AmneziaWG (pmin=20, pmax=50)
	if err := nodeA.SendDataPacketWithPadding(targetAddr, fakeIPv4, 20, 50); err != nil {
		t.Fatalf("failed to send packet: %v", err)
	}

	select {
	case recvPkt := <-receivedCh:
		if len(recvPkt) != len(fakeIPv4) {
			t.Fatalf("expected packet length %d, got %d", len(fakeIPv4), len(recvPkt))
		}
		if recvPkt[0]>>4 != 4 {
			t.Fatalf("expected IPv4 packet, got version %d", recvPkt[0]>>4)
		}
		for i := range fakeIPv4 {
			if recvPkt[i] != fakeIPv4[i] {
				t.Fatalf("byte mismatch at index %d: expected 0x%02x, got 0x%02x", i, fakeIPv4[i], recvPkt[i])
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for decrypted packet on receiver")
	}
}

func TestUDPPuncher_EncryptedTunnelData_WrongKeyRejection(t *testing.T) {
	fakeIPv4 := []byte{
		0x45, 0x00, 0x00, 0x3c,
		0x1c, 0x46, 0x40, 0x00,
		0x40, 0x01, 0x2e, 0x38,
		10, 11, 12, 1,
		10, 11, 12, 2,
		0x08, 0x00, 0x4d, 0x5a,
	}

	nodeB, err := NewUDPPuncher(0, "node-b-wrong", nil, nil)
	if err != nil {
		t.Fatalf("failed to create nodeB: %v", err)
	}
	defer nodeB.Close()
	nodeB.SetCipherKey("wrong-key-bbbbbbbbbbbbbbbbbbbb")

	receivedCh := make(chan []byte, 1)
	nodeB.SetDataCallback(func(srcAddr *net.UDPAddr, payload []byte) {
		receivedCh <- payload
	})

	nodeA, err := NewUDPPuncher(0, "node-a-right", nil, nil)
	if err != nil {
		t.Fatalf("failed to create nodeA: %v", err)
	}
	defer nodeA.Close()
	nodeA.SetCipherKey("right-key-aaaaaaaaaaaaaaaaaaaa")

	targetAddr := fmt.Sprintf("127.0.0.1:%d", nodeB.LocalPort())

	_ = nodeA.SendDataPacketWithPadding(targetAddr, fakeIPv4, 10, 30)

	select {
	case pkt := <-receivedCh:
		// With wrong key, decryption fails, and raw ciphertext does NOT have IPv4 header (version 4)
		if len(pkt) > 0 && pkt[0]>>4 == 4 {
			t.Fatalf("CRITICAL SECURITY ERROR: receiver accepted packet with wrong key!")
		}
	case <-time.After(300 * time.Millisecond):
		// Expected: packet was not accepted or could not be decrypted as IPv4
	}
}

func TestFingerprintCGNAT_ParityAndPBA(t *testing.T) {
	// 1. Test Port Block Allocation (PBA 64): ports 24578, 24580, 24602 all share upper bits (24576 base)
	samplesPBA := []int{24578, 24580, 24602}
	profPBA := FingerprintCGNAT(samplesPBA)
	if profPBA.BlockSize != 64 {
		t.Fatalf("expected BlockSize 64, got %d", profPBA.BlockSize)
	}
	if profPBA.BlockBase != 24576 {
		t.Fatalf("expected BlockBase 24576, got %d", profPBA.BlockBase)
	}
	if !profPBA.ParityPreserved || profPBA.Parity != 0 {
		t.Fatalf("expected even parity preserved, got preserved=%v parity=%d", profPBA.ParityPreserved, profPBA.Parity)
	}

	p, err := NewUDPPuncher(0, "test-cgnat", nil, nil)
	if err != nil {
		t.Fatalf("failed to create puncher: %v", err)
	}
	defer p.Close()

	candidates := p.CandidatePortsAdvanced(24578, samplesPBA, profPBA, 1)
	if len(candidates) != 32 { // 64 / 2 (only even ports)
		t.Fatalf("expected 32 even candidates within PBA block, got %d", len(candidates))
	}
	for _, port := range candidates {
		if port < 24576 || port >= 24640 {
			t.Fatalf("candidate %d outside block [24576, 24640)", port)
		}
		if port%2 != 0 {
			t.Fatalf("candidate %d violates even parity", port)
		}
	}

	// 2. Test Linear Sequential CGNAT
	samplesLinear := []int{30000, 30004, 30008}
	profLinear := FingerprintCGNAT(samplesLinear)
	if !profLinear.IsSequential || profLinear.Delta != 4 {
		t.Fatalf("expected IsSequential with Delta 4, got isSeq=%v delta=%d", profLinear.IsSequential, profLinear.Delta)
	}
}

func TestQUICChameleonProbe_BuildAndParse(t *testing.T) {
	cKey := crypto.DeriveKey("quic-secret-key-999")
	devID := "node-alpha-test"

	probeBytes, err := BuildQUICChameleonProbe(devID, cKey)
	if err != nil {
		t.Fatalf("BuildQUICChameleonProbe failed: %v", err)
	}

	if len(probeBytes) < 30 {
		t.Fatalf("probe too short: %d bytes", len(probeBytes))
	}
	if probeBytes[0]&0xC0 != 0xC0 {
		t.Fatalf("expected Long Header 0xC0, got 0x%02x", probeBytes[0])
	}
	if binary.BigEndian.Uint32(probeBytes[1:5]) != QUICVersion1 {
		t.Fatalf("expected QUIC Version 1, got 0x%08x", binary.BigEndian.Uint32(probeBytes[1:5]))
	}

	// Parse and verify decryption
	decrypted, err := ParseQUICChameleonProbe(probeBytes, cKey)
	if err != nil {
		t.Fatalf("ParseQUICChameleonProbe failed: %v", err)
	}
	decStr := string(decrypted)
	if !strings.HasPrefix(decStr, constants.PingPrefix) {
		t.Fatalf("expected PingPrefix, got %s", decStr)
	}
	if !strings.Contains(decStr, devID) {
		t.Fatalf("expected devID in payload, got %s", decStr)
	}

	// PONG probe
	pongBytes, err := BuildQUICPongChameleonProbe(devID, "123456789", cKey)
	if err != nil {
		t.Fatalf("BuildQUICPongChameleonProbe failed: %v", err)
	}
	decPong, err := ParseQUICChameleonProbe(pongBytes, cKey)
	if err != nil {
		t.Fatalf("ParseQUICPongChameleonProbe failed: %v", err)
	}
	if !strings.HasPrefix(string(decPong), constants.PongPrefix) {
		t.Fatalf("expected PongPrefix, got %s", string(decPong))
	}
}

func TestHairpinning_Detection(t *testing.T) {
	// Case 1: Same Gateway (Home/Office LAN)
	hp1, prio1 := AnalyzeHairpinning("198.51.100.1", "192.168.1.1", "198.51.100.1", "192.168.1.1", []string{"192.168.1.55:4000"})
	if hp1 != HairpinSameLAN {
		t.Fatalf("expected HairpinSameLAN, got %v", hp1)
	}
	if len(prio1) != 1 || prio1[0] != "192.168.1.55:4000" {
		t.Fatalf("unexpected prioritized candidates: %v", prio1)
	}

	// Case 2: Same Public IP, Different Gateway (Operator CGNAT Cluster)
	hp2, prio2 := AnalyzeHairpinning("198.51.100.1", "100.64.1.1", "198.51.100.1", "100.64.2.1", []string{"100.64.2.55:4000", "192.168.0.10:4000"})
	if hp2 != HairpinSameWAN {
		t.Fatalf("expected HairpinSameWAN, got %v", hp2)
	}
	if len(prio2) != 1 || prio2[0] != "100.64.2.55:4000" {
		t.Fatalf("expected carrier subnet 100.64.2.55:4000 to be prioritized, got: %v", prio2)
	}

	// Case 3: Different Public IPs
	hp3, _ := AnalyzeHairpinning("198.51.100.1", "192.168.1.1", "203.0.113.5", "192.168.0.1", []string{"192.168.0.5:4000"})
	if hp3 != HairpinStandard {
		t.Fatalf("expected HairpinStandard, got %v", hp3)
	}
}

func TestAdaptiveProbeEngine_Feedback(t *testing.T) {
	cKey := crypto.DeriveKey("adaptive-key")
	engine := NewAdaptiveProbeEngine("127.0.0.1", 34500, cKey, true)

	p, err := NewUDPPuncher(0, "test-adaptive", nil, nil)
	if err != nil {
		t.Fatalf("failed to create puncher: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Simulate Port Unreachable trigger
	go func() {
		time.Sleep(50 * time.Millisecond)
		engine.NotifyFeedback(FeedbackPortUnreachable)
	}()

	_ = p.ExecuteAdaptiveProbing(ctx, engine)
}

