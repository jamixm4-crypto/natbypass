//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import "golang.org/x/sys/windows"

func checkIsAdmin() bool {
	var token windows.Token
	h := windows.CurrentProcess()
	err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
