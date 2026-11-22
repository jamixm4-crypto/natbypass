// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package testbench

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
)

// Run executes the testbench according to the provided configuration.
func Run(parentCtx context.Context, cfg Config) (*SummaryReport, error) {
	startTime := time.Now()

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	vm, err := NewVirtualMesh(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize virtual mesh: %w", err)
	}
	defer vm.Close()

	if cfg.SimulateLoss > 0 {
		vm.SetPacketLoss(cfg.SimulateLoss)
	}

	report := &SummaryReport{
		Timestamp: startTime,
		Version:   constants.CurrentVersion,
		Results:   make([]TestResult, 0),
	}

	target := strings.ToLower(strings.TrimSpace(cfg.TargetTest))
	if target == "" {
		target = "all"
	}

	runAll := target == "all"

	// 1. P2P Direct & Bilateral Tests
	if runAll || target == "p2p" {
		report.Results = append(report.Results, RunP2PTests(ctx, vm)...)
	}

	// 2. Internet Exit Node & DNS Tests
	if runAll || target == "exitnode" || target == "dns" {
		report.Results = append(report.Results, RunExitNodeTests(ctx, vm)...)
	}

	// 3. Subnet Routing & Forwarding Tests
	if runAll || target == "subnets" || target == "subnet" {
		report.Results = append(report.Results, RunSubnetTests(ctx, vm)...)
	}

	// 4. Throughput & Speed Benchmarks
	if runAll || target == "speed" || target == "throughput" {
		report.Results = append(report.Results, RunSpeedTests(ctx, vm, cfg.SpeedTestSizeMB)...)
	}

	// 5. Engine Rules Verification (Android / Linux / Windows)
	if runAll || target == "engines" || target == "engine" {
		report.Results = append(report.Results, RunEngineTests(ctx, vm)...)
	}

	// Compute summaries
	report.TotalDuration = time.Since(startTime)
	report.TotalTests = len(report.Results)
	for _, r := range report.Results {
		switch r.Status {
		case StatusPass:
			report.Passed++
		case StatusFail:
			report.Failed++
		case StatusSkip, StatusWarn:
			report.Skipped++
		}
	}

	return report, nil
}
