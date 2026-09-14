// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//go:build windows

package system

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemTimes       = modkernel32.NewProc("GetSystemTimes")
	procGetProcessTimes      = modkernel32.NewProc("GetProcessTimes")
	procGetCurrentProcess    = modkernel32.NewProc("GetCurrentProcess")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")

	prevSysIdle   uint64
	prevSysKernel uint64
	prevSysUser   uint64

	prevProcTime uint64
	prevWallTime time.Time
)

type filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (ft filetime) toUint64() uint64 {
	return (uint64(ft.HighDateTime) << 32) | uint64(ft.LowDateTime)
}

type memoryStatusEx struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func collectPlatformMetrics(m *Metrics) {
	// 1. Сбор системной RAM
	var memEx memoryStatusEx
	memEx.cbSize = uint32(unsafe.Sizeof(memEx))
	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memEx)))
	if r1 != 0 {
		m.SystemTotalRAMBytes = memEx.ullTotalPhys
		m.SystemTotalRAMMB = float64(memEx.ullTotalPhys) / (1024 * 1024)
		if memEx.ullTotalPhys >= memEx.ullAvailPhys {
			m.SystemUsedRAMBytes = memEx.ullTotalPhys - memEx.ullAvailPhys
			m.SystemUsedRAMMB = float64(m.SystemUsedRAMBytes) / (1024 * 1024)
		}
		m.SystemRAMPercent = float64(memEx.dwMemoryLoad)
	}

	// 2. Сбор системного CPU
	var idle, kernel, user filetime
	r1, _, _ = procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r1 != 0 {
		curIdle := idle.toUint64()
		curKernel := kernel.toUint64()
		curUser := user.toUint64()

		if prevSysKernel != 0 && prevSysUser != 0 {
			deltaKernel := curKernel - prevSysKernel
			deltaUser := curUser - prevSysUser
			deltaIdle := curIdle - prevSysIdle
			totalDelta := deltaKernel + deltaUser

			if totalDelta > 0 && totalDelta >= deltaIdle {
				sysPct := 100.0 * float64(totalDelta-deltaIdle) / float64(totalDelta)
				if sysPct < 0 {
					sysPct = 0
				} else if sysPct > 100 {
					sysPct = 100
				}
				m.SystemCPUPercent = sysPct
			}
		}

		prevSysIdle = curIdle
		prevSysKernel = curKernel
		prevSysUser = curUser
	}

	// 3. Сбор процессного CPU
	hCurProcess, _, _ := procGetCurrentProcess.Call()
	var creationTime, exitTime, procKernel, procUser filetime
	r1, _, _ = procGetProcessTimes.Call(
		hCurProcess,
		uintptr(unsafe.Pointer(&creationTime)),
		uintptr(unsafe.Pointer(&exitTime)),
		uintptr(unsafe.Pointer(&procKernel)),
		uintptr(unsafe.Pointer(&procUser)),
	)
	if r1 != 0 {
		curProcTime := procKernel.toUint64() + procUser.toUint64()
		now := time.Now()

		if prevProcTime != 0 && !prevWallTime.IsZero() && now.After(prevWallTime) {
			wallElapsed := now.Sub(prevWallTime)
			// FILETIME считает в интервалах по 100 нс
			procDelta100ns := curProcTime - prevProcTime
			wall100ns := uint64(wallElapsed.Nanoseconds() / 100)

			if wall100ns > 0 && m.NumCPU > 0 {
				procPct := 100.0 * float64(procDelta100ns) / (float64(wall100ns) * float64(m.NumCPU))
				if procPct < 0 {
					procPct = 0
				} else if procPct > 100 {
					procPct = 100
				}
				m.ProcessCPUPercent = procPct
			}
		}

		prevProcTime = curProcTime
		prevWallTime = now
	}
}
