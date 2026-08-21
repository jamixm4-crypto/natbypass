//go:build !windows

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