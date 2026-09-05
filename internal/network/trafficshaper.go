package network

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"runtime"
	"sync"
	"time"

)

// TrafficShaper маскирует VPN-трафик под видеоконференции (WebRTC/Zoom).
type TrafficShaper struct {
	enabled      bool
	jitterMin    time.Duration // 5ms
	jitterMax    time.Duration // 50ms
	maxFrameSize int           // 1350 bytes (video frame slice)
	fakeAckProb  float32       // 0.3 (30% вероятность)
	mu           sync.RWMutex
}

// NewTrafficShaper создаёт новый экземпляр TrafficShaper.
func NewTrafficShaper(enabled bool) *TrafficShaper {
	return &TrafficShaper{
		enabled:      enabled,
		jitterMin:    5 * time.Millisecond,
		jitterMax:    50 * time.Millisecond,
		maxFrameSize: 1350,
		fakeAckProb:  0.30,
	}
}

// SetEnabled включает или отключает маскировку трафика.
func (s *TrafficShaper) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
}

// IsEnabled возвращает текущее состояние шейпера.
func (s *TrafficShaper) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// SendPacket отправляет IP-пакет с динамическим джиттером, нарезкой на кадры и генерацией Fake ACK.
func (s *TrafficShaper) SendPacket(conn *net.UDPConn, addr *net.UDPAddr, payload []byte) error {
	if conn == nil || addr == nil || len(payload) == 0 {
		return nil
	}

	s.mu.RLock()
	enabled := s.enabled
	jMin := s.jitterMin
	jMax := s.jitterMax
	frameSize := s.maxFrameSize
	ackProb := s.fakeAckProb
	s.mu.RUnlock()

	if !enabled {
		_, err := conn.WriteToUDP(payload, addr)
		return err
	}

	// 1. Добавление динамического джиттера (5-50ms)
	diff := int64(jMax - jMin)
	if diff > 0 {
		nBig, err := rand.Int(rand.Reader, big.NewInt(diff))
		if err == nil {
			jitter := jMin + time.Duration(nBig.Int64())
			time.Sleep(jitter)
		}
	}

	// 2. Нарезка больших пакетов на видеокадры (<= 1350 bytes)
	var sendErr error
	if len(payload) > frameSize {
		for offset := 0; offset < len(payload); offset += frameSize {
			end := offset + frameSize
			if end > len(payload) {
				end = len(payload)
			}
			chunk := payload[offset:end]
			_, err := conn.WriteToUDP(chunk, addr)
			if err != nil {
				sendErr = err
			}
			if runtime.GOARCH != "mips" && runtime.GOARCH != "mipsle" && runtime.GOARCH != "arm" {
				time.Sleep(2 * time.Millisecond)
			}
		}
	} else {
		_, sendErr = conn.WriteToUDP(payload, addr)
	}

	// 3. Генерация Fake ACK пакета (30% вероятность для имитации двустороннего RTP/RTCP видеопотока)
	nRand, err := rand.Int(rand.Reader, big.NewInt(100))
	if err == nil && float32(nRand.Int64())/100.0 < ackProb {
		var fakeAck [16]byte
		_, _ = rand.Read(fakeAck[:])
		fakeAck[0] = 0x80 // RTP version 2
		fakeAck[1] = 0xc8 // RTCP Sender Report marker
		binary.BigEndian.PutUint16(fakeAck[14:], uint16(len(payload)))
		_, _ = conn.WriteToUDP(fakeAck[:], addr)
	}

	return sendErr
}
