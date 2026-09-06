//go:build !windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package daemon

import (
	"context"
	"errors"
)

var ErrNotSupported = errors.New("windows service is only supported on Windows")

func IsWindowsService() bool {
	return false
}

func RunService(runFunc func(ctx context.Context) error) error {
	return ErrNotSupported
}

func InstallService(configPath string) error {
	return ErrNotSupported
}

func UninstallService() error {
	return ErrNotSupported
}

func StartWindowsService() error {
	return ErrNotSupported
}

func StopWindowsService() error {
	return ErrNotSupported
}

func QueryServiceStatus() (string, error) {
	return "NOT_SUPPORTED", nil
}