//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"os"
	"testing"
)

func TestEnsureWintunDLL(t *testing.T) {
	path, err := EnsureWintunDLL()
	if err != nil {
		t.Fatalf("EnsureWintunDLL failed: %v", err)
	}
	if path == "" {
		t.Fatal("EnsureWintunDLL returned empty path")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if fi.Size() < minWintunDLLSize {
		t.Fatalf("File size %d is less than min %d", fi.Size(), minWintunDLLSize)
	}
	t.Logf("Found or downloaded Wintun DLL at: %s (size: %d bytes)", path, fi.Size())
}
