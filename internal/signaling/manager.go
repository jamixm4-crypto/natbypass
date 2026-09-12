// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package signaling

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type BrokerInfo struct {
	URL       string `json:"url"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Connected bool   `json:"connected"`
	IsActive  bool   `json:"is_active"`
	LastError string `json:"last_error,omitempty"`
	LastUsed  string `json:"last_used,omitempty"`
}

type ChannelStatus struct {
	Name      string
	Available bool
	LastError error
	LastUsed  time.Time
}

type FallbackManager struct {
	mu             sync.RWMutex
	channels       []SignalingChannel
	currentIdx     int
	consecFailures map[string]int
	circuitBreaker map[string]time.Time
	statuses       map[string]*ChannelStatus
}

var _ SignalingChannel = (*FallbackManager)(nil)

func NewFallbackManager(channels []SignalingChannel) *FallbackManager {
	fm := &FallbackManager{
		channels:       channels,
		currentIdx:     0,
		consecFailures: make(map[string]int),
		circuitBreaker: make(map[string]time.Time),
		statuses:       make(map[string]*ChannelStatus),
	}

	for _, ch := range channels {
		name := ch.Name()
		fm.statuses[name] = &ChannelStatus{
			Name:      name,
			Available: true,
		}
	}

	return fm
}

func (m *FallbackManager) Send(ctx context.Context, payload *Payload) error {
	m.mu.RLock()
	n := len(m.channels)
	m.mu.RUnlock()

	if n == 0 {
		return fmt.Errorf("no signaling channels available")
	}

	// For signaling packets (discovery beacons, remote diag, punch coordination),
	// broadcast in parallel to all configured channels so peers on different brokers
	// (HiveMQ, Mosquitto, etc.) all receive beacons.
	isBroadcast := (payload.RemoteDiag != nil || payload.Coordination != nil || payload.SymPunch != nil || payload.Rendezvous != nil || payload.VirtualIP != "" || payload.Offline || payload.Leave)
	if isBroadcast && n > 1 {
		m.mu.RLock()
		chList := make([]SignalingChannel, len(m.channels))
		copy(chList, m.channels)
		m.mu.RUnlock()

		var wg sync.WaitGroup
		var firstErr error
		var sentCount int
		var broadcastMu sync.Mutex

		for _, ch := range chList {
			wg.Add(1)
			go func(c SignalingChannel) {
				defer wg.Done()
				sCtx, sCancel := context.WithTimeout(ctx, 4*time.Second)
				defer sCancel()
				err := m.sendWithRetry(sCtx, c, payload)
				broadcastMu.Lock()
				if err == nil {
					sentCount++
				} else if firstErr == nil {
					firstErr = err
				}
				broadcastMu.Unlock()
			}(ch)
		}
		wg.Wait()
		if sentCount > 0 {
			return nil
		}
		return firstErr
	}

	// Single-channel fallback with retry for high-volume data
	m.mu.Lock()
	startIdx := m.currentIdx
	m.mu.Unlock()

	for i := 0; i < n; i++ {
		m.mu.Lock()
		idx := (startIdx + i) % n
		ch := m.channels[idx]
		name := ch.Name()

		if breakerTime, ok := m.circuitBreaker[name]; ok {
			if n > 1 && time.Since(breakerTime) < 20*time.Second {
				m.mu.Unlock()
				continue
			}
			delete(m.circuitBreaker, name)
			m.consecFailures[name] = 0
		}
		m.statuses[name].LastUsed = time.Now()
		m.mu.Unlock()

		// Perform network I/O without holding mu
		err := m.sendWithRetry(ctx, ch, payload)

		m.mu.Lock()
		if err == nil {
			if m.currentIdx != idx {
				oldName := m.channels[m.currentIdx].Name()
				log.Info().Str("from", oldName).Str("to", name).Msg("🔀 FallbackManager: успешный авто-фейловер на резервный сигнальный канал")
				m.currentIdx = idx
			}
			m.consecFailures[name] = 0
			m.statuses[name].Available = true
			m.statuses[name].LastError = nil
			m.mu.Unlock()
			return nil
		}

		log.Warn().Str("channel", name).Err(err).Msg("Failed to send on channel")
		m.consecFailures[name]++
		m.statuses[name].LastError = err

		if m.consecFailures[name] >= 3 {
			log.Warn().Str("channel", name).Msg("Channel failed 3 times, temporary cooldown 20s")
			m.circuitBreaker[name] = time.Now()
			m.statuses[name].Available = false
		}
		m.mu.Unlock()
	}

	return fmt.Errorf("all signaling channels failed")
}

func (m *FallbackManager) sendWithRetry(ctx context.Context, ch SignalingChannel, payload *Payload) error {
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		err = ch.Send(ctx, payload)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return err
}

func (m *FallbackManager) Receive(ctx context.Context) (<-chan *Payload, error) {
	out := make(chan *Payload, 128)
	var wg sync.WaitGroup

	for _, ch := range m.channels {
		in, err := ch.Receive(ctx)
		if err != nil {
			log.Error().Str("channel", ch.Name()).Err(err).Msg("Failed to initialize receiver")
			continue
		}
		wg.Add(1)
		go func(c <-chan *Payload, name string) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case p, ok := <-c:
					if !ok {
						return
					}
					select {
					case out <- p:
					case <-ctx.Done():
						return
					}
				}
			}
		}(in, ch.Name())
	}

	go func() {
		wg.Wait()
		close(out) // ✅ Гарантированное закрытие канала
	}()

	return out, nil
}

func (m *FallbackManager) SwitchTo(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, ch := range m.channels {
		if ch.Name() == name {
			m.currentIdx = i
			return nil
		}
	}
	return fmt.Errorf("channel %s not found", name)
}

func (m *FallbackManager) CurrentChannel() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.channels) == 0 {
		return ""
	}
	return m.channels[m.currentIdx].Name()
}

func (m *FallbackManager) Status() []ChannelStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var statuses []ChannelStatus
	for _, ch := range m.channels {
		if s, ok := m.statuses[ch.Name()]; ok {
			statuses = append(statuses, *s)
		}
	}
	return statuses
}

// ActiveBroker возвращает URL активного MQTT брокера (или имя канала)
func (m *FallbackManager) ActiveBroker() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.channels) == 0 {
		return ""
	}
	if ch, ok := m.channels[m.currentIdx].(*MQTTChannel); ok {
		return ch.BrokerURL()
	}
	return m.channels[m.currentIdx].Name()
}

// SwitchToBroker переключает текущий активный канал на указанный адрес брокера
func (m *FallbackManager) SwitchToBroker(brokerURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cleanTarget := strings.TrimSpace(strings.ToLower(brokerURL))
	for i, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok {
			cleanCh := strings.TrimSpace(strings.ToLower(mqttCh.BrokerURL()))
			if cleanCh == cleanTarget || strings.Contains(cleanCh, cleanTarget) || strings.Contains(cleanTarget, cleanCh) {
				m.currentIdx = i
				delete(m.circuitBreaker, ch.Name())
				m.consecFailures[ch.Name()] = 0
				log.Info().Str("broker", mqttCh.BrokerURL()).Msg("✅ FallbackManager: активный брокер переключен")
				return nil
			}
		}
	}

	// Если канал с таким URL не найден, переподключаем первый доступный MQTTChannel
	for _, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok {
			if err := mqttCh.ReconnectWithBroker(brokerURL); err == nil {
				delete(m.circuitBreaker, ch.Name())
				m.consecFailures[ch.Name()] = 0
				log.Info().Str("broker", brokerURL).Msg("✅ FallbackManager: MQTT канал переподключен к новому брокеру")
				return nil
			} else {
				return err
			}
		}
	}

	return fmt.Errorf("MQTT канал не найден для переключения на %s", brokerURL)
}

// UpdateMQTTBroker динамически переключает активный брокер
func (m *FallbackManager) UpdateMQTTBroker(newBrokerURL string) {
	_ = m.SwitchToBroker(newBrokerURL)
}

// BrokerStatuses возвращает информацию о статусе всех настроенных MQTT брокеров
func (m *FallbackManager) BrokerStatuses() []BrokerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []BrokerInfo
	for i, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok {
			info := BrokerInfo{
				URL:       mqttCh.BrokerURL(),
				Name:      mqttCh.Name(),
				Connected: mqttCh.IsConnected(),
				IsActive:  (i == m.currentIdx),
			}
			if st, exists := m.statuses[ch.Name()]; exists && st != nil {
				info.Available = st.Available
				if st.LastError != nil {
					info.LastError = st.LastError.Error()
				}
				if !st.LastUsed.IsZero() {
					info.LastUsed = st.LastUsed.Format("15:04:05")
				}
			} else {
				info.Available = mqttCh.IsConnected()
			}
			result = append(result, info)
		}
	}
	return result
}

// UpdateMQTTTopic динамически обновляет топик во всех активных MQTT каналах
func (m *FallbackManager) UpdateMQTTTopic(newTopic string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok {
			mqttCh.UpdateTopic(newTopic)
		}
	}
}

// PublishTunnelData пересылает сырой IP пакет через активный или подключенный MQTT канал
func (m *FallbackManager) PublishTunnelData(targetDevID string, pkt []byte) error {
	m.mu.RLock()
	// Пробуем сначала текущий активный канал
	if m.currentIdx < len(m.channels) {
		if mqttCh, ok := m.channels[m.currentIdx].(*MQTTChannel); ok && mqttCh.IsConnected() {
			m.mu.RUnlock()
			return mqttCh.PublishTunnelData(targetDevID, pkt)
		}
	}
	// Затем любой подключенный канал
	for _, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok && mqttCh.IsConnected() {
			m.mu.RUnlock()
			return mqttCh.PublishTunnelData(targetDevID, pkt)
		}
	}
	// Если ни один не подключен, пробуем первый MQTT канал
	for _, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok {
			m.mu.RUnlock()
			return mqttCh.PublishTunnelData(targetDevID, pkt)
		}
	}
	m.mu.RUnlock()
	return fmt.Errorf("no MQTT channels available for tunnel data")
}

// SubscribeTunnelData подписывается на входящие пакеты туннеля для текущего узла
func (m *FallbackManager) SubscribeTunnelData(myDevID string, onPkt func(pkt []byte)) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok {
			mqttCh.SubscribeTunnelData(myDevID, onPkt)
		}
	}
}

// SetNetworkKey updates the network authentication key for all underlying signaling channels.
func (m *FallbackManager) SetNetworkKey(networkKey string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok {
			mqttCh.SetNetworkKey(networkKey)
		}
	}
}

// Name returns the name of the fallback manager and its active channel.
func (m *FallbackManager) Name() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.channels) == 0 {
		return "fallback"
	}
	return "fallback:" + m.channels[m.currentIdx].Name()
}

// IsAvailable checks if the active channel or any underlying channel is available.
func (m *FallbackManager) IsAvailable(ctx context.Context) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.channels) == 0 {
		return false
	}
	// Check active channel first
	if m.currentIdx < len(m.channels) && m.channels[m.currentIdx].IsAvailable(ctx) {
		return true
	}
	// Check any channel
	for _, ch := range m.channels {
		if ch.IsAvailable(ctx) {
			return true
		}
	}
	return false
}

// Close closes all underlying signaling channels.
func (m *FallbackManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var lastErr error
	for _, ch := range m.channels {
		if err := ch.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}


