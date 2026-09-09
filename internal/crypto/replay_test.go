// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package crypto

import (
	"sync"
	"testing"
)

func TestReplayFilter_Sequential(t *testing.T) {
	rf := NewReplayFilter()

	for seq := uint64(1); seq <= 5000; seq++ {
		if !rf.ValidateAndAccept(seq) {
			t.Fatalf("Expected seq %d to be accepted", seq)
		}
		// Immediately duplicate should be rejected
		if rf.ValidateAndAccept(seq) {
			t.Fatalf("Expected immediate duplicate of seq %d to be rejected", seq)
		}
	}

	if rf.HighestSeq() != 5000 {
		t.Errorf("Expected highest seq 5000, got %d", rf.HighestSeq())
	}
}

func TestReplayFilter_OutOfOrderWithinWindow(t *testing.T) {
	rf := NewReplayFilter()

	// Initial packet
	if !rf.ValidateAndAccept(100) {
		t.Fatal("Initial seq 100 rejected")
	}

	// Out of order packets within window
	order := []uint64{95, 99, 90, 85, 96, 88}
	for _, seq := range order {
		if !rf.ValidateAndAccept(seq) {
			t.Fatalf("Out-of-order seq %d should be accepted", seq)
		}
		// Duplicate must be rejected
		if rf.ValidateAndAccept(seq) {
			t.Fatalf("Duplicate of out-of-order seq %d should be rejected", seq)
		}
	}

	// Advance window forward
	if !rf.ValidateAndAccept(150) {
		t.Fatal("Seq 150 should be accepted")
	}

	// Packet 92 (still in window 150-2048 < 92)
	if !rf.ValidateAndAccept(92) {
		t.Fatal("Seq 92 should be accepted")
	}
	if rf.ValidateAndAccept(92) {
		t.Fatal("Duplicate seq 92 should be rejected")
	}
}

func TestReplayFilter_TooOldDropped(t *testing.T) {
	rf := NewReplayFilter()

	if !rf.ValidateAndAccept(5000) {
		t.Fatal("Seq 5000 rejected")
	}

	// 5000 - 2048 = 2952. Anything <= 2952 should be rejected as too old.
	if rf.ValidateAndAccept(2952) {
		t.Fatal("Seq 2952 is at window boundary and should be rejected")
	}
	if rf.ValidateAndAccept(2000) {
		t.Fatal("Seq 2000 is too old and should be rejected")
	}
	if rf.ValidateAndAccept(1) {
		t.Fatal("Seq 1 is too old and should be rejected")
	}

	// Seq 2953 is within window: 5000 - 2953 = 2047 < 2048 -> should be accepted!
	if !rf.ValidateAndAccept(2953) {
		t.Fatal("Seq 2953 is within window and should be accepted")
	}
	if rf.ValidateAndAccept(2953) {
		t.Fatal("Duplicate seq 2953 should be rejected")
	}
}

func TestReplayFilter_MassiveJump(t *testing.T) {
	rf := NewReplayFilter()

	if !rf.ValidateAndAccept(10) {
		t.Fatal("Seq 10 rejected")
	}

	// Jump forward by more than the entire window
	if !rf.ValidateAndAccept(100000) {
		t.Fatal("Seq 100000 rejected")
	}

	// Duplicate of 100000 rejected
	if rf.ValidateAndAccept(100000) {
		t.Fatal("Duplicate 100000 should be rejected")
	}

	// Old seq 10 must now be rejected
	if rf.ValidateAndAccept(10) {
		t.Fatal("Seq 10 should be rejected after massive jump")
	}

	// Seq 99990 should be accepted (within window)
	if !rf.ValidateAndAccept(99990) {
		t.Fatal("Seq 99990 should be accepted")
	}
}

func TestReplayFilter_Concurrent(t *testing.T) {
	rf := NewReplayFilter()
	var wg sync.WaitGroup

	// Launch multiple concurrent goroutines sending disjoint sequences
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(base uint64) {
			defer wg.Done()
			for i := uint64(0); i < 200; i++ {
				seq := base + i
				_ = rf.ValidateAndAccept(seq)
			}
		}(uint64(g * 500))
	}

	wg.Wait()
}

func TestReplayFilter_Reset(t *testing.T) {
	rf := NewReplayFilter()

	if !rf.ValidateAndAccept(100) {
		t.Fatal("Seq 100 rejected")
	}

	rf.Reset()

	// After reset, seq 100 can be accepted as new first packet
	if !rf.ValidateAndAccept(100) {
		t.Fatal("Seq 100 should be accepted after Reset")
	}
	if rf.ValidateAndAccept(100) {
		t.Fatal("Duplicate 100 should be rejected")
	}
}
