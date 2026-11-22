// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package testbench

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Status represents the outcome of a test case.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
	StatusWarn Status = "WARN"
)

// TestResult records the execution outcome and telemetry of a single test case.
type TestResult struct {
	Name           string        `json:"name"`
	Category       string        `json:"category"`
	Status         Status        `json:"status"`
	Duration       time.Duration `json:"duration"`
	Message        string        `json:"message,omitempty"`
	ThroughputMbps float64       `json:"throughput_mbps,omitempty"`
	RTT            time.Duration `json:"rtt,omitempty"`
	PacketLoss     float64       `json:"packet_loss_pct,omitempty"`
	PacketsSent    int           `json:"packets_sent,omitempty"`
	PacketsRecv    int           `json:"packets_recv,omitempty"`
	BytesSent      uint64        `json:"bytes_sent,omitempty"`
	BytesRecv      uint64        `json:"bytes_recv,omitempty"`
	Details        []string      `json:"details,omitempty"`
}

// Config controls test execution parameters.
type Config struct {
	TargetTest     string        // "all", "p2p", "tcp", "exitnode", "dns", "subnets", "speed", "engines"
	SpeedTestSizeMB int          // Data volume for throughput test in MB (default 20MB)
	Timeout        time.Duration // Overall test timeout
	Verbose        bool          // Detailed logging
	JSONOutput     bool          // Output raw JSON report
	SimulateLoss   float64       // Simulated packet loss rate (0.0 - 1.0)
	SimulateDelay  time.Duration // Simulated link latency
}

// SummaryReport consolidates all executed tests.
type SummaryReport struct {
	Timestamp     time.Time     `json:"timestamp"`
	Version       string        `json:"version"`
	TotalTests    int           `json:"total_tests"`
	Passed        int           `json:"passed"`
	Failed        int           `json:"failed"`
	Skipped       int           `json:"skipped"`
	TotalDuration time.Duration `json:"total_duration"`
	Results       []TestResult  `json:"results"`
}

// ANSI color helpers
const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiRed     = "\033[91m"
	ansiGreen   = "\033[92m"
	ansiYellow  = "\033[93m"
	ansiBlue    = "\033[94m"
	ansiMagenta = "\033[95m"
	ansiCyan    = "\033[96m"
	ansiWhite   = "\033[97m"
)

// RenderCLI renders the summary report in human-readable colored terminal format.
func (sr *SummaryReport) RenderCLI() string {
	var b strings.Builder

	b.WriteString("\n" + ansiBold + ansiCyan + "================================================================================" + ansiReset + "\n")
	b.WriteString(fmt.Sprintf("%s%s  NATBYPASS AUTOMATED INTEGRATION TESTBENCH v%s%s\n", ansiBold, ansiWhite, sr.Version, ansiReset))
	b.WriteString(fmt.Sprintf("%s  Timestamp: %s | Total Duration: %v%s\n", ansiDim, sr.Timestamp.Format("2006-01-02 15:04:05"), sr.TotalDuration.Round(time.Millisecond), ansiReset))
	b.WriteString(ansiBold + ansiCyan + "================================================================================" + ansiReset + "\n\n")

	currentCat := ""
	for _, res := range sr.Results {
		if res.Category != currentCat {
			currentCat = res.Category
			b.WriteString(fmt.Sprintf("%s%s[%s]%s\n", ansiBold, ansiYellow, strings.ToUpper(currentCat), ansiReset))
		}

		statusBadge := ""
		switch res.Status {
		case StatusPass:
			statusBadge = ansiBold + ansiGreen + " PASS " + ansiReset
		case StatusFail:
			statusBadge = ansiBold + ansiRed + " FAIL " + ansiReset
		case StatusWarn:
			statusBadge = ansiBold + ansiYellow + " WARN " + ansiReset
		case StatusSkip:
			statusBadge = ansiDim + " SKIP " + ansiReset
		}

		b.WriteString(fmt.Sprintf("  [%s] %-42s (%6v)", statusBadge, res.Name, res.Duration.Round(time.Millisecond)))

		if res.ThroughputMbps > 0 {
			b.WriteString(fmt.Sprintf(" | %s%6.2f Mbps%s", ansiBold+ansiCyan, res.ThroughputMbps, ansiReset))
		}
		if res.RTT > 0 {
			b.WriteString(fmt.Sprintf(" | RTT: %s%v%s", ansiCyan, res.RTT.Round(time.Microsecond), ansiReset))
		}
		if res.PacketLoss > 0 {
			b.WriteString(fmt.Sprintf(" | Loss: %s%.1f%%%s", ansiRed, res.PacketLoss, ansiReset))
		}
		b.WriteString("\n")

		if res.Message != "" {
			b.WriteString(fmt.Sprintf("         %s%s%s\n", ansiDim, res.Message, ansiReset))
		}
		for _, det := range res.Details {
			b.WriteString(fmt.Sprintf("         %s- %s%s\n", ansiDim, det, ansiReset))
		}
	}

	b.WriteString("\n" + ansiBold + ansiCyan + "--------------------------------------------------------------------------------" + ansiReset + "\n")
	statusColor := ansiGreen
	if sr.Failed > 0 {
		statusColor = ansiRed
	}

	b.WriteString(fmt.Sprintf("%sTEST SUMMARY: %d Total | %s%d Passed%s | ", ansiBold, sr.TotalTests, ansiGreen, sr.Passed, ansiReset))
	if sr.Failed > 0 {
		b.WriteString(fmt.Sprintf("%s%s%d Failed%s | ", ansiBold, ansiRed, sr.Failed, ansiReset))
	} else {
		b.WriteString(fmt.Sprintf("%d Failed | ", sr.Failed))
	}
	b.WriteString(fmt.Sprintf("%d Skipped%s\n", sr.Skipped, ansiReset))

	if sr.Failed == 0 {
		b.WriteString(fmt.Sprintf("%s%s>>> ALL SUBSYSTEM TESTS PASSED SUCCESSFULLY! PROJECT IS HEALTHY FOR RELEASE <<<%s\n", ansiBold, statusColor, ansiReset))
	} else {
		b.WriteString(fmt.Sprintf("%s%s>>> CAUTION: %d REGRESSION(S) DETECTED! DO NOT RELEASE UNTIL FIXED <<<%s\n", ansiBold, statusColor, sr.Failed, ansiReset))
	}
	b.WriteString(ansiBold + ansiCyan + "================================================================================" + ansiReset + "\n\n")

	return b.String()
}

// RenderJSON outputs report in JSON format.
func (sr *SummaryReport) RenderJSON() (string, error) {
	data, err := json.MarshalIndent(sr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
