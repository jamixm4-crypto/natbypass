package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// UDPPunchResult — результат теста raw UDP punch
type UDPPunchResult struct {
	Success       bool
	LatencyMs     int64
	Bidirectional bool
	Error         string
}

// TestRawUDPPunch проверяет, проходит ли raw UDP между двумя узлами.
// Посылает несколько probe-пакетов на target и ждёт ответ.
// Использует ListenPort пира (порт probe listener'а), а не STUN-порт.
func TestRawUDPPunch(ctx context.Context, myNodeID string, peer *PeerInfo) *UDPPunchResult {
	result := &UDPPunchResult{}

	// Определяем адрес: берём IP из STUNAddr, порт из ListenPort (или STUN порт как fallback)
	targetAddr := peer.STUNAddr
	if peer.ListenPort > 0 && peer.STUNAddr != "" {
		parts := strings.Split(peer.STUNAddr, ":")
		if len(parts) >= 1 {
			targetAddr = fmt.Sprintf("%s:%d", parts[0], peer.ListenPort)
		}
	}

	logf("[UDP] %s → %s: raw UDP punch to %s", myNodeID, peer.NodeID, targetAddr)

	udpAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		result.Error = err.Error()
		logf("[UDP] Resolve error: %v", err)
		return result
	}

	// Создаём локальный сокет
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	// Probe packet: "NATPROBE:<myNodeID>><peerNodeID>"
	probe := []byte("NATPROBE:" + myNodeID + ">" + peer.NodeID)

	for attempt := 0; attempt < 5; attempt++ {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		start := time.Now()
		_, err = conn.WriteToUDP(probe, udpAddr)
		if err != nil {
			continue
		}

		buf := make([]byte, 256)
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil && n > 0 {
			result.Success = true
			result.LatencyMs = time.Since(start).Milliseconds()
			result.Bidirectional = true
			logf("[UDP] %s → %s: SUCCESS (%dms)", myNodeID, peer.NodeID, result.LatencyMs)
			return result
		}

		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return result
		default:
			time.Sleep(500 * time.Millisecond)
		}
	}

	result.Error = "no response after 5 attempts"
	logf("[UDP] %s → %s: FAIL (no response)", myNodeID, peer.NodeID)
	return result
}

