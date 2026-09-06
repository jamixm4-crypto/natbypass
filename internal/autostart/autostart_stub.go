//go:build !windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package autostart

func SetAutoStart(name, execPath string, enable bool) error {
	return nil
}

func IsAutoStartEnabled(name string) bool {
	return false
}
