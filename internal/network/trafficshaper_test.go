package network

import (
	"testing"
	"time"
)

func TestTrafficShaper_Configuration(t *testing.T) {
	shaper := NewTrafficShaper(true)
	if !shaper.IsEnabled() {
		t.Fatalf("expected shaper to be enabled")
	}

	shaper.SetEnabled(false)
	if shaper.IsEnabled() {
		t.Fatalf("expected shaper to be disabled")
	}

	shaper.SetEnabled(true)
	if shaper.jitterMin != 5*time.Millisecond || shaper.maxFrameSize != 1350 {
		t.Fatalf("invalid default shaper parameters: %+v", shaper)
	}
}
