// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//go:build linux || android

package system

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	prevLinuxSysIdle  uint64
	prevLinuxSysTotal uint64

	prevLinuxProcTicks uint64
	prevLinuxWallTime  time.Time
)

func collectPlatformMetrics(m *Metrics) {
	// 1. Системная RAM из /proc/meminfo
	if memData, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := bytes.Split(memData, []byte("\n"))
		var totalKB, availKB, freeKB, buffersKB, cachedKB uint64
		hasAvail := false

		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			parts := strings.Fields(string(line))
			if len(parts) < 2 {
				continue
			}
			val, _ := strconv.ParseUint(parts[1], 10, 64)
			switch parts[0] {
			case "MemTotal:":
				totalKB = val
			case "MemAvailable:":
				availKB = val
				hasAvail = true
			case "MemFree:":
				freeKB = val
			case "Buffers:":
				buffersKB = val
			case "Cached:":
				cachedKB = val
			}
		}

		if totalKB > 0 {
			m.SystemTotalRAMBytes = totalKB * 1024
			m.SystemTotalRAMMB = float64(m.SystemTotalRAMBytes) / (1024 * 1024)

			var usedKB uint64
			if hasAvail && availKB > 0 && totalKB >= availKB {
				usedKB = totalKB - availKB
			} else {
				freeCombined := freeKB + buffersKB + cachedKB
				if totalKB >= freeCombined {
					usedKB = totalKB - freeCombined
				}
			}
			m.SystemUsedRAMBytes = usedKB * 1024
			m.SystemUsedRAMMB = float64(m.SystemUsedRAMBytes) / (1024 * 1024)
			m.SystemRAMPercent = 100.0 * float64(usedKB) / float64(totalKB)
		}
	}

	// 2. Системный CPU из /proc/stat
	if statData, err := os.ReadFile("/proc/stat"); err == nil {
		lines := bytes.Split(statData, []byte("\n"))
		for _, line := range lines {
			if bytes.HasPrefix(line, []byte("cpu ")) {
				fields := strings.Fields(string(line))
				if len(fields) >= 5 {
					// user, nice, system, idle, iowait...
					var total uint64
					var idle uint64
					for i := 1; i < len(fields); i++ {
						v, _ := strconv.ParseUint(fields[i], 10, 64)
						total += v
						if i == 4 || i == 5 { // idle and iowait
							idle += v
						}
					}

					if prevLinuxSysTotal != 0 && total > prevLinuxSysTotal {
						deltaTotal := total - prevLinuxSysTotal
						deltaIdle := idle - prevLinuxSysIdle
						if deltaTotal >= deltaIdle {
							sysPct := 100.0 * float64(deltaTotal-deltaIdle) / float64(deltaTotal)
							if sysPct < 0 {
								sysPct = 0
							} else if sysPct > 100 {
								sysPct = 100
							}
							m.SystemCPUPercent = sysPct
						}
					}
					prevLinuxSysTotal = total
					prevLinuxSysIdle = idle
				}
				break
			}
		}
	}

	// 3. CPU процесса из /proc/self/stat
	if selfStat, err := os.ReadFile("/proc/self/stat"); err == nil {
		// Парсим после закрывающей скобки имени процесса ')'
		lastParen := bytes.LastIndexByte(selfStat, ')')
		if lastParen != -1 && lastParen+2 < len(selfStat) {
			fields := strings.Fields(string(selfStat[lastParen+2:]))
			// В /proc/self/stat utime - поле 14, stime - поле 15 (1-based от начала)
			// Так как мы отрезали pid и comm, utime - индекс 11, stime - индекс 12 (0-based)
			if len(fields) >= 13 {
				utime, _ := strconv.ParseUint(fields[11], 10, 64)
				stime, _ := strconv.ParseUint(fields[12], 10, 64)
				curTicks := utime + stime
				now := time.Now()

				if prevLinuxProcTicks != 0 && !prevLinuxWallTime.IsZero() && now.After(prevLinuxWallTime) {
					wallElapsed := now.Sub(prevLinuxWallTime).Seconds()
					deltaTicks := curTicks - prevLinuxProcTicks
					// На Linux/MIPS CLK_TCK обычно равен 100 Гц
					if wallElapsed > 0 && m.NumCPU > 0 {
						procPct := 100.0 * (float64(deltaTicks) / 100.0) / (wallElapsed * float64(m.NumCPU))
						if procPct < 0 {
							procPct = 0
						} else if procPct > 100 {
							procPct = 100
						}
						m.ProcessCPUPercent = procPct
					}
				}
				prevLinuxProcTicks = curTicks
				prevLinuxWallTime = now
			}
		}
	}
}
