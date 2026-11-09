// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
)

// TrafficProfile defines camouflage shaping patterns against DPI.
type TrafficProfile string

const (
	ProfileDefault TrafficProfile = "webrtc"
	ProfileWebRTC  TrafficProfile = "webrtc"
	ProfileYouTube TrafficProfile = "youtube"
	ProfileZoom    TrafficProfile = "zoom"
)

// TrafficShaper маскирует VPN-трафик под видеоконференции (WebRTC/Zoom) или потоковое видео (YouTube).
type TrafficShaper struct {
	enabled      bool
	profile      TrafficProfile
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
		profile:      ProfileWebRTC,
		jitterMin:    5 * time.Millisecond,
		jitterMax:    50 * time.Millisecond,
		maxFrameSize: 1350,
		fakeAckProb:  0.30,
	}
}

// SetProfile configures shaping parameters for specific camouflage profile (YouTube, Zoom, WebRTC).
func (s *TrafficShaper) SetProfile(profile TrafficProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profile = profile
	switch profile {
	case ProfileYouTube:
		s.jitterMin = 2 * time.Millisecond
		s.jitterMax = 30 * time.Millisecond
		s.maxFrameSize = 1380
		s.fakeAckProb = 0.10
	case ProfileZoom:
		s.jitterMin = 15 * time.Millisecond
		s.jitterMax = 25 * time.Millisecond
		s.maxFrameSize = 1200
		s.fakeAckProb = 0.40
	default:
		s.profile = ProfileWebRTC
		s.jitterMin = 5 * time.Millisecond
		s.jitterMax = 50 * time.Millisecond
		s.maxFrameSize = 1350
		s.fakeAckProb = 0.30
	}
}

// GetProfile returns the current traffic shaping camouflage profile.
func (s *TrafficShaper) GetProfile() TrafficProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.profile == "" {
		return ProfileWebRTC
	}
	return s.profile
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

	// 1. Добавление динамического джиттера (5-50ms) без аллокаций в куче (MIPS zero-allocation)
	diffMs := int64(jMax - jMin) / int64(time.Millisecond)
	if diffMs > 0 {
		var jitterBuf [1]byte
		if _, err := io.ReadFull(rand.Reader, jitterBuf[:]); err == nil {
			jitter := jMin + time.Duration(int64(jitterBuf[0])%(diffMs+1))*time.Millisecond
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

	// 3. Генерация Fake ACK пакета (имитация двустороннего RTP/RTCP видеопотока)
	// Zero-allocation: целочисленная проверка без math/big и без float32
	var ackRand [1]byte
	if _, err := io.ReadFull(rand.Reader, ackRand[:]); err == nil {
		probInt := int(ackProb * 100)
		if int(ackRand[0]%100) < probInt {
			var fakeAck [16]byte
			if _, err := io.ReadFull(rand.Reader, fakeAck[:]); err == nil {
				fakeAck[0] = 0x80 // RTP version 2
				fakeAck[1] = 0xc8 // RTCP Sender Report marker
				binary.BigEndian.PutUint16(fakeAck[14:], uint16(len(payload)))
				_, _ = conn.WriteToUDP(fakeAck[:], addr)
			}
		}
	}

	return sendErr
}

// AdaptivePadding computes the dynamic trailer padding length for a packet.
// It quantizes packet sizes into discrete bins [128, 256, 512, 1024, 1360]
// and adds random jitter (0-31 bytes) to defeat statistical flow analysis (histogram fingerprinting) by DPI/TSPU.
// If payload is already near or above maxFrameSize, it adds minimal padding to prevent MTU fragmentation.
func (s *TrafficShaper) AdaptivePadding(payloadLen int) int {
	if payloadLen <= 0 {
		return 0
	}
	s.mu.RLock()
	maxSize := s.maxFrameSize
	prof := s.profile
	s.mu.RUnlock()

	if maxSize <= 0 {
		maxSize = 1350
	}

	// If packet already exceeds target max size, don't pad
	if payloadLen >= maxSize {
		return 0
	}

	// Discrete bins for packet size quantization (profile-tuned, zero heap allocation)
	var bins [5]int
	switch prof {
	case ProfileYouTube:
		bins = [5]int{256, 512, 1024, 1280, maxSize}
	case ProfileZoom:
		bins = [5]int{160, 320, 640, 1024, maxSize}
	default:
		bins = [5]int{128, 256, 512, 1024, maxSize}
	}

	targetBin := maxSize
	for _, b := range bins {
		if payloadLen <= b {
			targetBin = b
			break
		}
	}

	diff := targetBin - payloadLen
	if diff <= 0 {
		return 0
	}

	// Add random variation within the bin so packets form a continuous distribution rather than exact multiples
	var jitterByte [1]byte
	if _, err := io.ReadFull(rand.Reader, jitterByte[:]); err != nil {
		jitterByte[0] = byte(time.Now().UnixNano() & 0xFF)
	}
	jitter := int(jitterByte[0] % 32) // 0-31 bytes

	padLen := diff
	if padLen > jitter {
		padLen = padLen - jitter
	}
	if payloadLen+padLen > maxSize {
		padLen = maxSize - payloadLen
	}
	if padLen < 0 {
		padLen = 0
	}
	return padLen
}

// ApplyAdaptivePadding appends random cryptographic padding to an IPv4 payload
// without altering the IPv4 Total Length field, allowing the receiver to cleanly strip it.
func (s *TrafficShaper) ApplyAdaptivePadding(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}
	padLen := s.AdaptivePadding(len(payload))
	if padLen <= 0 {
		return payload
	}

	padded := make([]byte, len(payload)+padLen)
	copy(padded, payload)
	if _, err := io.ReadFull(rand.Reader, padded[len(payload):]); err != nil {
		return payload
	}
	return padded
}

// GetWaveletResistantKeepalive computes a non-linear randomized keepalive interval
// centered around baseInterval (default 25s if <= 0).
// Discrete Wavelet Transform (DWT) classifiers (such as FlowFrontiers wavelet-vpn-detection)
// rely on rigid periodic signals (e.g. strict 25.0s pulses) to detect VPNs with 99% accuracy.
// Introducing pseudo-random Poisson/Gaussian-like jitter destroys spectral detail coefficients
// across wavelet decomposition scales without risking NAT session expiration.
func GetWaveletResistantKeepalive(baseInterval time.Duration) time.Duration {
	if baseInterval <= 0 {
		baseInterval = 25 * time.Second
	}

	// Range: base - 6s to base + 6s with non-linear distribution
	var entropy [2]byte
	if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
		entropy[0] = byte(time.Now().UnixNano() & 0xFF)
		entropy[1] = byte((time.Now().UnixNano() >> 8) & 0xFF)
	}

	// Pseudo-Poisson dispersion: sum of 2 independent random variables
	val := int(entropy[0]%7) + int(entropy[1]%7) - 6 // -6 to +6 seconds
	result := baseInterval + time.Duration(val)*time.Second
	if result < 15*time.Second {
		result = 15 * time.Second
	}
	return result
}

// ApplyMultimodalPadding expands payload with multimodal generative padding,
// emulating real WebRTC audio/video or Zoom codecs (inspired by aivpn generative distributions).
func (s *TrafficShaper) ApplyMultimodalPadding(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}

	s.mu.RLock()
	prof := s.profile
	maxSize := s.maxFrameSize
	s.mu.RUnlock()

	if maxSize <= 0 {
		maxSize = 1350
	}

	// For small packets (< 280 bytes, e.g. control, pings, or audio),
	// mimic audio codec packets (e.g. Opus/SILK frames 140-260 bytes).
	if len(payload) < 280 {
		targetSize := 160
		switch prof {
		case ProfileZoom:
			targetSize = 180
		case ProfileWebRTC:
			targetSize = 210
		}

		if len(payload) < targetSize {
			var b [1]byte
			if _, err := io.ReadFull(rand.Reader, b[:]); err == nil {
				jitter := int(b[0] % 32)
				needed := (targetSize + jitter) - len(payload)
				if needed > 0 && len(payload)+needed <= maxSize {
					padded := make([]byte, len(payload)+needed)
					copy(padded, payload)
					_, _ = io.ReadFull(rand.Reader, padded[len(payload):])
					return padded
				}
			}
		}
	}

	// Fallback to standard adaptive bin padding
	return s.ApplyAdaptivePadding(payload)
}
