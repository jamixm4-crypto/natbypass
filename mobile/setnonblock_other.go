//go:build !linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mobile

// setTunNonblock is a no-op on non-Linux platforms (Windows, macOS).
// The mobile package is only compiled and used on Android (Linux),
// so this stub exists solely to allow `go build ./...` on development machines.
func setTunNonblock(_ int) error {
	return nil
}
