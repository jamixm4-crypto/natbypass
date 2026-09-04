package network

import (
	"fmt"
	"net"
	"testing"
	"time"
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
