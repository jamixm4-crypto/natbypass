package relay

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUDPRelayClient_EndToEnd(t *testing.T) {
	sessionKey := bytes.Repeat([]byte{0x42}, 32)

	// Mock UDP Relay Server
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to start mock relay server: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().String()

	var receivedMu sync.Mutex
	var receivedPayload []byte
	var receivedSrc string

	// Bob Client
	bobClient, err := NewUDPRelayClient(serverAddr, "bob-dev-id", sessionKey, func(srcDevID string, payload []byte) {
		receivedMu.Lock()
		defer receivedMu.Unlock()
		receivedSrc = srcDevID
		receivedPayload = payload
	})
	if err != nil {
		t.Fatalf("failed to create bob client: %v", err)
	}
	defer bobClient.Close()

	bobPort := bobClient.conn.LocalAddr().(*net.UDPAddr).Port
	bobDestAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: bobPort}

	// Alice Client
	aliceClient, err := NewUDPRelayClient(serverAddr, "alice-dev-id", sessionKey, nil)
	if err != nil {
		t.Fatalf("failed to create alice client: %v", err)
	}
	defer aliceClient.Close()

	// Server forwarding loop
	go func() {
		buf := make([]byte, 65535)
		for {
			n, rAddr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			data := string(buf[:n])
			if strings.HasPrefix(data, udpRelayKeepAlive) {
				_, _ = serverConn.WriteToUDP([]byte(udpRelayKeepAlive), rAddr)
			} else if strings.HasPrefix(data, udpRelayHeader) {
				_, _ = serverConn.WriteToUDP(buf[:n], bobDestAddr)
			}
		}
	}()

	time.Sleep(30 * time.Millisecond)

	testMsg := []byte("Hello, fast UDP relay payload!")
	if err := aliceClient.SendPacket("bob-dev-id", testMsg); err != nil {
		t.Fatalf("failed to send packet: %v", err)
	}

	// Wait for packet delivery
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		receivedMu.Lock()
		got := len(receivedPayload) > 0
		receivedMu.Unlock()
		if got {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	receivedMu.Lock()
	defer receivedMu.Unlock()
	if !bytes.Equal(receivedPayload, testMsg) {
		t.Fatalf("expected payload %q, got %q (src: %s)", string(testMsg), string(receivedPayload), receivedSrc)
	}
	if receivedSrc != "alice-dev-id" {
		t.Fatalf("expected src alice-dev-id, got %s", receivedSrc)
	}
}
