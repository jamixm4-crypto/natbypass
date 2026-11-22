// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package testbench

import (
	"context"
	"testing"
	"time"
)

func TestTestbench_RunAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := Config{
		TargetTest:      "all",
		SpeedTestSizeMB: 2, // 2MB for fast unit test
		Timeout:         25 * time.Second,
	}

	report, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Testbench Run returned error: %v", err)
	}

	if report.Failed > 0 {
		for _, res := range report.Results {
			if res.Status == StatusFail {
				t.Errorf("Test failed: %s: %s", res.Name, res.Message)
			}
		}
	}

	t.Logf("Testbench executed %d tests (%d passed, %d failed, %d skipped)",
		report.TotalTests, report.Passed, report.Failed, report.Skipped)
}
