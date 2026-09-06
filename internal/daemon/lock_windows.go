//go:build windows
// +build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package daemon

// AcquireProcessLock on Windows returns a no-op unlock func as single instance is handled by Windows Service / Mutex.
func AcquireProcessLock() (func(), error) {
	return func() {}, nil
}
