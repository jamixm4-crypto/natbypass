package crypto

import (
	"bytes"
	"testing"
)

func TestSafeRandomBytes(t *testing.T) {
	buf := make([]byte, 32)
	_ = SafeRandomBytes(buf)

	zeroes := make([]byte, 32)
	if bytes.Equal(buf, zeroes) {
		t.Fatal("SafeRandomBytes returned all zeroes")
	}

	// Multiple calls should produce distinct bytes
	buf2 := make([]byte, 32)
	_ = SafeRandomBytes(buf2)
	if bytes.Equal(buf, buf2) {
		t.Fatal("SafeRandomBytes returned identical buffers on consecutive calls")
	}
}
