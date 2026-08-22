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
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := 0; i < len(m.channels); i++ {
		idx := (m.currentIdx + i) % len(m.channels)
		ch := m.channels[idx]
		name := ch.Name()

		if breakerTime, ok := m.circuitBreaker[name]; ok {
			if time.Since(breakerTime) < 5*time.Minute {
				continue
			}
			delete(m.circuitBreaker, name)
			m.consecFailures[name] = 0
		}

		m.statuses[name].LastUsed = time.Now()

		err := m.sendWithRetry(ctx, ch, payload)
		if err == nil {
			m.currentIdx = idx
			m.consecFailures[name] = 0
			m.statuses[name].Available = true
			m.statuses[name].LastError = nil
			return nil
		}

		log.Warn().Str("channel", name).Err(err).Msg("Failed to send on channel")
		
		m.consecFailures[name]++
		m.statuses[name].LastError = err

		if m.consecFailures[name] >= 3 {
			log.Error().Str("channel", name).Msg("Circuit breaker open: channel marked unavailable")
			m.circuitBreaker[name] = time.Now()
			m.statuses[name].Available = false
		}
	}

	return fmt.Errorf("all signaling channels failed")
}

func (m *FallbackManager) sendWithRetry(ctx context.Context, ch SignalingChannel, payload *Payload) error {
	var err error
	backoff := 1 * time.Second

	for attempt := 1; attempt <= 5; attempt++ {
		err = ch.Send(ctx, payload)
		if err == nil {
			return nil
		}
		
		log.Debug().Str("channel", ch.Name()).Err(err).Int("attempt", attempt).Msg("Send failed, retrying")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}

	return err
}

func (m *FallbackManager) Receive(ctx context.Context) (<-chan *Payload, error) {
	out := make(chan *Payload, 128)

	for _, ch := range m.channels {
		in, err := ch.Receive(ctx)
		if err != nil {
			log.Error().Str("channel", ch.Name()).Err(err).Msg("Failed to initialize receiver")
			continue
		}
		go func(c <-chan *Payload, name string) {
			for {
				select {
				case <-ctx.Done():
					return
				case p, ok := <-c:
					if !ok {
						log.Warn().Str("channel", name).Msg("Receiver channel closed")
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
