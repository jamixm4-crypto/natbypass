package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// netDeadline возвращает время deadline через n секунд.
func netDeadline(seconds int) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}

// startUDPProbeListener запускает UDP echo-сервер для приёма probe-пакетов.
// Пакеты вида "NATPROBE:<remoteID>><myID>" получают ответ "NATREPLY:<myID>".
// Возвращает адрес "host:port".
func startUDPProbeListener(ctx context.Context, port int, myNodeID string) string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
		if err != nil {
			logf("[UDP-SRV] Failed to start listener: %v", err)
			return fmt.Sprintf("0.0.0.0:%d (failed)", port)
		}
		logf("[UDP-SRV] Port %d busy, using %s", port, conn.LocalAddr())
	}

	listenAddr := conn.LocalAddr().String()

	go func() {
		defer conn.Close()
		buf := make([]byte, 512)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if ctx.Err() != nil {
					return
				}
				continue
			}

			msg := string(buf[:n])
			if strings.HasPrefix(msg, "NATPROBE:") {
				reply := []byte("NATREPLY:" + myNodeID)
				_, _ = conn.WriteToUDP(reply, remoteAddr)
				logf("[UDP-SRV] Probe from %s", remoteAddr)
			}
		}
	}()

	return listenAddr
}