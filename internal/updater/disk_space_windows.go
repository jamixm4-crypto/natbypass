//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package updater

import (
	"golang.org/x/sys/windows"
)

// getFreeDiskSpace returns available disk space in bytes for the volume containing path.
func getFreeDiskSpace(path string) (uint64, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	err = windows.GetDiskFreeSpaceEx(pathPtr, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)
	if err != nil {
		return 0, err
	}
	return freeBytesAvailable, nil
}
