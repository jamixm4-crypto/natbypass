// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package system

import (
	"runtime"
	"sync"
	"time"
)

// Metrics содержит системные и процессные метрики узла
type Metrics struct {
	// Процессор
	ProcessCPUPercent float64 `json:"process_cpu_percent"`
	SystemCPUPercent  float64 `json:"system_cpu_percent"`
	NumCPU            int     `json:"num_cpu"`

	// Память процесса (в байтах и мегабайтах)
	ProcessAllocBytes uint64  `json:"process_alloc_bytes"`
	ProcessAllocMB    float64 `json:"process_alloc_mb"`
	ProcessSysBytes   uint64  `json:"process_sys_bytes"`
	ProcessSysMB      float64 `json:"process_sys_mb"`

	// Системная память
	SystemTotalRAMBytes uint64  `json:"system_total_ram_bytes"`
	SystemTotalRAMMB    float64 `json:"system_total_ram_mb"`
	SystemUsedRAMBytes  uint64  `json:"system_used_ram_bytes"`
	SystemUsedRAMMB     float64 `json:"system_used_ram_mb"`
	SystemRAMPercent    float64 `json:"system_ram_percent"`

	// Рантайм и горутины
	Goroutines int       `json:"goroutines"`
	NumGC      uint32    `json:"num_gc"`
	UptimeSec  int64     `json:"uptime_sec"`
	Timestamp  time.Time `json:"timestamp"`
}

var (
	startTime      = time.Now()
	metricsMu      sync.RWMutex
	cachedMetrics  Metrics
	lastSampleTime time.Time
	minSampleGap   = 1500 * time.Millisecond // Защита от перегрузки CPU: не опрашивать чаще 1.5 сек
)

// GetMetrics возвращает текущие метрики с кэшированием для защиты от нагрузки.
func GetMetrics() Metrics {
	metricsMu.RLock()
	now := time.Now()
	if now.Sub(lastSampleTime) < minSampleGap && !lastSampleTime.IsZero() {
		m := cachedMetrics
		metricsMu.RUnlock()
		return m
	}
	metricsMu.RUnlock()

	metricsMu.Lock()
	defer metricsMu.Unlock()

	// Повторная проверка под блокировкой
	if time.Since(lastSampleTime) < minSampleGap && !lastSampleTime.IsZero() {
		return cachedMetrics
	}

	m := sampleMetrics()
	cachedMetrics = m
	lastSampleTime = time.Now()
	return m
}

// sampleMetrics собирает базовые метрики Go-рантайма и вызывает платформо-зависимый сбор
func sampleMetrics() Metrics {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	m := Metrics{
		NumCPU:            runtime.NumCPU(),
		ProcessAllocBytes: ms.Alloc,
		ProcessAllocMB:    float64(ms.Alloc) / (1024 * 1024),
		ProcessSysBytes:   ms.Sys,
		ProcessSysMB:      float64(ms.Sys) / (1024 * 1024),
		Goroutines:        runtime.NumGoroutine(),
		NumGC:             ms.NumGC,
		UptimeSec:         int64(time.Since(startTime).Seconds()),
		Timestamp:         time.Now(),
	}

	// Вызов платформо-зависимого сбора (CPU и системной RAM)
	collectPlatformMetrics(&m)

	return m
}
