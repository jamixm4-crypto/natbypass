// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package system

import (
	"testing"
	"time"
)

func TestGetMetrics(t *testing.T) {
	// Первый вызов инициализирует базовые точки отсчета
	m1 := GetMetrics()
	if m1.NumCPU <= 0 {
		t.Errorf("expected NumCPU > 0, got %d", m1.NumCPU)
	}
	if m1.Goroutines <= 0 {
		t.Errorf("expected Goroutines > 0, got %d", m1.Goroutines)
	}
	if m1.ProcessAllocBytes <= 0 {
		t.Errorf("expected ProcessAllocBytes > 0, got %d", m1.ProcessAllocBytes)
	}

	// Делаем небольшую задержку и некоторую работу для замера дельты
	time.Sleep(100 * time.Millisecond)
	// Сбрасываем lastSampleTime для теста чтобы проверить сбор дельт
	metricsMu.Lock()
	lastSampleTime = time.Time{}
	metricsMu.Unlock()

	// Нагружаем немного CPU
	sum := 0
	for i := 0; i < 5000000; i++ {
		sum += i
	}
	_ = sum

	m2 := GetMetrics()
	t.Logf("Metrics sample 2: Process CPU=%.2f%%, System CPU=%.2f%%, Process Alloc=%.2f MB, System RAM=%.2f MB (%.1f%%), Goroutines=%d",
		m2.ProcessCPUPercent, m2.SystemCPUPercent, m2.ProcessAllocMB, m2.SystemTotalRAMMB, m2.SystemRAMPercent, m2.Goroutines)

	if m2.SystemTotalRAMMB <= 0 {
		t.Logf("Warning: SystemTotalRAMMB is 0 (may happen in some test containers)")
	}
}
