//go:build !windows
// +build !windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var lockFileHold *os.File

// AcquireProcessLock ensures that only a single instance of NatBypass runs at any time on Unix/Linux/Keenetic.
func AcquireProcessLock() (func(), error) {
	candidates := []string{
		"/opt/var/run/natbypass.lock",
		"/run/natbypass.lock",
		"/var/run/natbypass.lock",
		filepath.Join(os.TempDir(), "natbypass.lock"),
	}

	var lockPath string
	for _, p := range candidates {
		dir := filepath.Dir(p)
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			lockPath = p
			break
		}
	}
	if lockPath == "" {
		lockPath = filepath.Join(os.TempDir(), "natbypass.lock")
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return func() {}, nil
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		existingPID := ""
		data, readErr := os.ReadFile(lockPath)
		if readErr == nil && len(data) > 0 {
			existingPID = strings.TrimSpace(string(data))
		}
		_ = f.Close()
		if existingPID != "" {
			return nil, fmt.Errorf("процесс уже запущен (PID %s, lockfile: %s)", existingPID, lockPath)
		}
		return nil, fmt.Errorf("процесс уже запущен (lockfile: %s)", lockPath)
	}

	lockFileHold = f
	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	_ = f.Sync()

	unlock := func() {
		if lockFileHold != nil {
			_ = syscall.Flock(int(lockFileHold.Fd()), syscall.LOCK_UN)
			_ = lockFileHold.Close()
			_ = os.Remove(lockPath)
			lockFileHold = nil
		}
	}

	return unlock, nil
}
