//go:build !windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

// EncryptConfigData on non-Windows platforms acts as a passthrough.
func EncryptConfigData(plain []byte) ([]byte, error) {
	return plain, nil
}

// DecryptConfigData on non-Windows platforms acts as a passthrough.
func DecryptConfigData(enc []byte) ([]byte, error) {
	return enc, nil
}
