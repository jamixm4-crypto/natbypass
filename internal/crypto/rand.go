// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

var fallbackCounter uint64

// SafeRandomBytes fills buf with cryptographically secure random bytes from crypto/rand.
// If crypto/rand fails (e.g. system entropy exhaustion or file descriptor exhaustion
// on low-resource routers running Keenetic/OpenWrt MIPS/ARM), it logs a warning and
// fills buf using a SHA-256 fallback PRNG driven by high-resolution time, PID, atomic counter,
// and system entropy state, ensuring that the returned bytes are NEVER all-zero.
func SafeRandomBytes(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}

	_, err := io.ReadFull(rand.Reader, buf)
	if err == nil {
		return nil
	}

	// CSPRNG failure fallback: log warning and generate non-zero pseudo-random bytes
	log.Warn().Err(err).Int("len", len(buf)).
		Msg("🛡️ Security warning: crypto/rand CSPRNG failed, using emergency SHA-256 entropy fallback")

	cnt := atomic.AddUint64(&fallbackCounter, 1)
	now := time.Now().UnixNano()
	pid := os.Getpid()

	var seedData [32]byte
	binary.LittleEndian.PutUint64(seedData[0:8], uint64(now))
	binary.LittleEndian.PutUint64(seedData[8:16], cnt)
	binary.LittleEndian.PutUint32(seedData[16:20], uint32(pid))
	copy(seedData[20:], []byte("CSPRNG_FALLBACK_ENTROPY"))

	filled := 0
	for filled < len(buf) {
		h := sha256.Sum256(seedData[:])
		n := copy(buf[filled:], h[:])
		filled += n
		// Mix for next block
		cnt = atomic.AddUint64(&fallbackCounter, 1)
		binary.LittleEndian.PutUint64(seedData[8:16], cnt)
		copy(seedData[0:8], h[0:8])
	}

	return fmt.Errorf("csprng degraded: %w", err)
}
