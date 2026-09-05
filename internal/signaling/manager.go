package signaling

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

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
	// BUG-08 FIX: Do not hold mu.Lock() during network I/O (can block up to 600ms).
	// Strategy: try each channel without holding the lock; update statistics briefly.
	m.mu.Lock()
	n := len(m.channels)
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
			m.currentIdx = idx
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

// PublishTunnelData пересылает сырой IP пакет через активный MQTT канал
func (m *FallbackManager) PublishTunnelData(targetDevID string, pkt []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ch := range m.channels {
		if mqttCh, ok := ch.(*MQTTChannel); ok {
			return mqttCh.PublishTunnelData(targetDevID, pkt)
		}
	}
	return nil
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


