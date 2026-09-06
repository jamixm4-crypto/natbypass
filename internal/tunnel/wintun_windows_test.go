//go:build windows

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
