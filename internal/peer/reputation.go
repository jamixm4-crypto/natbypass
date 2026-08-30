package peer

import (
	"sync"
	"time"
)

// Reputation отслеживает качество связи и надёжность пира для защиты от poisoning и подмены маршрутов.
type Reputation struct {
	successfulPings int
	failedPings     int
	avgRTT          time.Duration
	score           float64
	lastUpdate      time.Time
	mu              sync.RWMutex
}

// NewReputation создаёт новый экземпляр репутации с базовым нейтральным рейтингом 0.5.
func NewReputation() *Reputation {
	return &Reputation{
		score:      0.5,
		lastUpdate: time.Now(),
	}
}

// RecordSuccess фиксирует успешный пинг/передачу пакета и повышает рейтинг узла.
func (r *Reputation) RecordSuccess(rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.successfulPings++
	if r.avgRTT == 0 {
		r.avgRTT = rtt
	} else {
		r.avgRTT = time.Duration(float64(r.avgRTT)*0.8 + float64(rtt)*0.2)
	}

	r.score += 0.05
	if r.score > 1.0 {
		r.score = 1.0
	}
	r.lastUpdate = time.Now()
}

// RecordFailure фиксирует таймаут или сбой доставки и снижает рейтинг узла.
func (r *Reputation) RecordFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.failedPings++
	r.score -= 0.15
	if r.score < 0.0 {
		r.score = 0.0
	}
	r.lastUpdate = time.Now()
}

// Score возвращает текущий рейтинг надёжности пира (от 0.0 до 1.0).
func (r *Reputation) Score() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.score
}

// IsTrusted возвращает true, если рейтинг пира превышает порог доверия (>= 0.7).
func (r *Reputation) IsTrusted() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.score >= 0.70
}

// AvgRTT возвращает сглаженный RTT пира.
func (r *Reputation) AvgRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.avgRTT
}
