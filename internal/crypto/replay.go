// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package crypto

import (
	"sync"
)

const (
	// ReplayWindowWords is the number of 64-bit words in the sliding window.
	// 32 words * 64 bits = 2048 packets window (RFC 6479 recommendation).
	ReplayWindowWords = 32
	// ReplayWindowSize is the total number of packets tracked by the replay filter.
	ReplayWindowSize = ReplayWindowWords * 64
)

// ReplayFilter implements a zero-allocation sliding-window anti-replay filter
// based on RFC 6479 (IPsec / WireGuard Anti-Replay with 2048-packet window).
// It prevents re-injection of captured packets by middleboxes or attackers.
type ReplayFilter struct {
	mu          sync.Mutex
	initialized bool
	highestSeq  uint64
	bitmap      [ReplayWindowWords]uint64
}

// NewReplayFilter initializes a fresh anti-replay sliding window.
func NewReplayFilter() *ReplayFilter {
	return &ReplayFilter{}
}

// ValidateAndAccept tests whether seq is a fresh, un-replayed sequence number.
// If valid, it marks seq as received and returns true.
// If seq is a duplicate or too old to be validated, it returns false.
func (f *ReplayFilter) ValidateAndAccept(seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.initialized {
		f.initialized = true
		f.highestSeq = seq
		wordIdx := (seq / 64) % ReplayWindowWords
		bitIdx := seq % 64
		f.bitmap[wordIdx] = 1 << bitIdx
		return true
	}

	// Case 1: Sequence number is newer than highestSeq
	if seq > f.highestSeq {
		diff := seq - f.highestSeq
		oldWord := f.highestSeq / 64
		newWord := seq / 64

		if diff >= ReplayWindowSize || (newWord-oldWord) >= ReplayWindowWords {
			// Complete window rollover — clear all words
			for i := 0; i < ReplayWindowWords; i++ {
				f.bitmap[i] = 0
			}
		} else {
			// Clear words between oldWord+1 and newWord inclusive
			for w := oldWord + 1; w <= newWord; w++ {
				f.bitmap[w%ReplayWindowWords] = 0
			}
		}

		wordIdx := (seq / 64) % ReplayWindowWords
		bitIdx := seq % 64
		f.bitmap[wordIdx] |= (1 << bitIdx)
		f.highestSeq = seq
		return true
	}

	// Case 2: Sequence number is older or equal to highestSeq
	diff := f.highestSeq - seq

	// If packet is older than the window capacity, drop it
	if diff >= ReplayWindowSize {
		return false
	}

	wordIdx := (seq / 64) % ReplayWindowWords
	bitIdx := seq % 64
	mask := uint64(1) << bitIdx

	// If bit is already set, this is a replay attack!
	if (f.bitmap[wordIdx] & mask) != 0 {
		return false
	}

	// Mark bit as seen
	f.bitmap[wordIdx] |= mask
	return true
}

// Reset clears the filter state upon session rekeying.
func (f *ReplayFilter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initialized = false
	f.highestSeq = 0
	for i := 0; i < ReplayWindowWords; i++ {
		f.bitmap[i] = 0
	}
}

// HighestSeq returns the highest sequence number accepted so far.
func (f *ReplayFilter) HighestSeq() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.highestSeq
}
