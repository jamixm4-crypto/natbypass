// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/natbypass/natbypass/internal/testbench"
)

func main() {
	var (
		flagTest    = flag.String("test", "all", "Target test suite: all, p2p, exitnode, dns, subnets, speed, engines")
		flagSizeMB  = flag.Int("size", 10, "Speed test transfer volume in Megabytes (default: 10)")
		flagTimeout = flag.Duration("timeout", 45*time.Second, "Overall execution timeout")
		flagJSON    = flag.Bool("json", false, "Output results in machine-readable JSON format")
		flagLoss    = flag.Float64("loss", 0.0, "Simulate packet loss rate (0.0 - 1.0)")
	)
	flag.Parse()

	cfg := testbench.Config{
		TargetTest:      *flagTest,
		SpeedTestSizeMB: *flagSizeMB,
		Timeout:         *flagTimeout,
		JSONOutput:      *flagJSON,
		SimulateLoss:    *flagLoss,
	}

	ctx := context.Background()
	report, err := testbench.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing testbench: %v\n", err)
		os.Exit(1)
	}

	if *flagJSON {
		jsonStr, err := report.RenderJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonStr)
	} else {
		fmt.Print(report.RenderCLI())
	}

	if report.Failed > 0 {
		os.Exit(1)
	}
}
