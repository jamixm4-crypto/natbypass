//go:build !linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package daemon

// SetupSyslog is a no-op on non-Linux platforms.
func SetupSyslog(appName string) error {
	// Syslog не поддерживается на данной платформе
	return nil
}
