package peer

import (
	"testing"
	"time"
)

func TestReputation_Scoring(t *testing.T) {
	rep := NewReputation()
	if rep.Score() != 0.5 {
		t.Fatalf("expected initial score 0.5, got %f", rep.Score())
	}
	if rep.IsTrusted() {
		t.Fatalf("score 0.5 should not be trusted initially")
	}

	// Record successes
	for i := 0; i < 5; i++ {
		rep.RecordSuccess(20 * time.Millisecond)
	}

	if !rep.IsTrusted() {
		t.Fatalf("expected peer to become trusted after 5 successes, score: %f", rep.Score())
	}

	// Record failures
	for i := 0; i < 6; i++ {
		rep.RecordFailure()
	}

	if rep.IsTrusted() {
		t.Fatalf("expected peer to become untrusted after failures, score: %f", rep.Score())
	}
}
