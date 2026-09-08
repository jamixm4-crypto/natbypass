// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package diagnostic

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/updater"
)

// PayloadSender sends a signaling payload across the signaling fabric.
type PayloadSender interface {
	Send(ctx context.Context, payload *signaling.Payload) error
}

// PayloadSenderFunc is an adapter to allow the use of ordinary functions as PayloadSender.
type PayloadSenderFunc func(ctx context.Context, payload *signaling.Payload) error

func (f PayloadSenderFunc) Send(ctx context.Context, payload *signaling.Payload) error {
	return f(ctx, payload)
}

// ExecuteLocalDiagScript runs the built-in Go diagnostic engine.
// It is 100% offline, self-contained, lightning-fast (~1.5s), and ensures identical
// structured diagnostic output across Windows, Linux, MIPS/Keenetic, OpenWrt, and Android.
func ExecuteLocalDiagScript(ctx context.Context) string {
	report := RunFullDiagnostics()
	return FormatGoDiagnosticsReport(report)
}

// FormatGoDiagnosticsReport formats a DiagnosticReport into human-readable text.
func FormatGoDiagnosticsReport(report *DiagnosticReport) string {
	if report == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("=== NatBypass Go Diagnostics Report ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", report.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Host: %s | OS: %s | Arch: %s\n", report.Hostname, report.OS, report.Arch))
	sb.WriteString(fmt.Sprintf("Admin/Root: %t | All Passed: %t\n\n", report.IsAdmin, report.AllPassed))
	for _, item := range report.Items {
		status := "[OK]"
		if !item.Passed {
			status = "[FAIL]"
		}
		sb.WriteString(fmt.Sprintf("%s %-38s (%v): %s\n", status, item.Name, item.Elapsed.Round(time.Millisecond), item.Message))
		if item.Details != "" {
			sb.WriteString(fmt.Sprintf("%s\n", item.Details))
		}
	}
	return sb.String()
}


// ExecuteLocalUpdate triggers an in-place beta update using the updater subsystem.
func ExecuteLocalUpdate(ctx context.Context, currentVersion string) string {
	opts := updater.CheckOptions{
		Channel:           "beta",
		IncludePrerelease: true,
	}
	info, err := updater.CheckUpdateWithOptions(ctx, currentVersion, opts)
	if err != nil {
		return fmt.Sprintf("Error checking for beta update: %v", err)
	}
	if info == nil || !info.HasUpdate {
		return fmt.Sprintf("Node is already up-to-date (Current: %s)", currentVersion)
	}
	if info.AssetURL == "" {
		return fmt.Sprintf("Found update %s but no asset URL available for platform %s/%s", info.LatestVersion, runtime.GOOS, runtime.GOARCH)
	}

	if err := updater.ApplyUpdate(ctx, info.AssetURL); err != nil {
		return fmt.Sprintf("Failed to apply update %s: %v", info.LatestVersion, err)
	}

	return fmt.Sprintf("Successfully applied update to %s. Service restarting...", info.LatestVersion)
}

// HandleRemoteDiagSignal processes remote diagnostic and update requests.
// Strictly active ONLY in beta builds (version string containing "beta").
func HandleRemoteDiagSignal(
	ctx context.Context,
	sig *signaling.RemoteDiagSignal,
	myDevID, version string,
	networkKey string,
	sender PayloadSender,
) {
	if sig == nil || sender == nil {
		return
	}

	// 1. Safety Gate: ONLY active in beta builds
	if !strings.Contains(strings.ToLower(version), "beta") {
		return
	}

	// 2. Ignore requests addressed to another specific node
	if sig.TargetID != "" && sig.TargetID != myDevID {
		return
	}

	// 3. Ignore our own requests
	if sig.SenderID == myDevID {
		return
	}

	switch sig.Action {
	case "request_diag":
		go func() {
			execCtx, execCancel := context.WithTimeout(context.Background(), 25*time.Second)
			report := ExecuteLocalDiagScript(execCtx)
			execCancel()

			sendCtx, sendCancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer sendCancel()

			chunks := SplitIntoChunks(report, 9000)
			totalChunks := len(chunks)

			for idx, chunk := range chunks {
				respSig := &signaling.RemoteDiagSignal{
					Action:      "response_diag",
					TargetID:    sig.SenderID,
					SenderID:    myDevID,
					SessionID:   sig.SessionID,
					ChunkIndex:  idx,
					TotalChunks: totalChunks,
					Payload:     chunk,
					Status:      "ok",
					OS:          runtime.GOOS,
					Arch:        runtime.GOARCH,
					Version:     version,
					Timestamp:   time.Now().Unix(),
				}

				payload := &signaling.Payload{
					DeviceID:   myDevID,
					RemoteDiag: respSig,
					Timestamp:  time.Now(),
				}

				toSend := payload
				if networkKey != "" {
					if enc, err := signaling.EncryptPayloadWithKey(payload, networkKey); err == nil && enc != nil {
						toSend = enc
					}
				}

				_ = sender.Send(sendCtx, toSend)
				if totalChunks > 1 {
					time.Sleep(60 * time.Millisecond)
				}
			}
		}()

	case "request_update":
		go func() {
			updateCtx, updateCancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer updateCancel()

			// Send intermediate progress signal
			initSig := &signaling.RemoteDiagSignal{
				Action:      "response_update",
				TargetID:    sig.SenderID,
				SenderID:    myDevID,
				SessionID:   sig.SessionID,
				ChunkIndex:  0,
				TotalChunks: 1,
				Payload:     fmt.Sprintf("Starting beta update from %s...", version),
				Status:      "updating",
				OS:          runtime.GOOS,
				Arch:        runtime.GOARCH,
				Version:     version,
				Timestamp:   time.Now().Unix(),
			}
			initPayload := &signaling.Payload{
				DeviceID:   myDevID,
				RemoteDiag: initSig,
				Timestamp:  time.Now(),
			}
			toSendInit := initPayload
			if networkKey != "" {
				if enc, err := signaling.EncryptPayloadWithKey(initPayload, networkKey); err == nil && enc != nil {
					toSendInit = enc
				}
			}
			_ = sender.Send(updateCtx, toSendInit)

			// Perform update
			result := ExecuteLocalUpdate(updateCtx, version)
			status := "ok"
			if strings.HasPrefix(result, "Error") || strings.HasPrefix(result, "Failed") {
				status = "error"
			}

			finalSig := &signaling.RemoteDiagSignal{
				Action:      "response_update",
				TargetID:    sig.SenderID,
				SenderID:    myDevID,
				SessionID:   sig.SessionID,
				ChunkIndex:  0,
				TotalChunks: 1,
				Payload:     result,
				Status:      status,
				OS:          runtime.GOOS,
				Arch:        runtime.GOARCH,
				Version:     version,
				Timestamp:   time.Now().Unix(),
			}
			finalPayload := &signaling.Payload{
				DeviceID:   myDevID,
				RemoteDiag: finalSig,
				Timestamp:  time.Now(),
			}
			toSendFinal := finalPayload
			if networkKey != "" {
				if enc, err := signaling.EncryptPayloadWithKey(finalPayload, networkKey); err == nil && enc != nil {
					toSendFinal = enc
				}
			}

			sendCtx, sendCancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer sendCancel()
			_ = sender.Send(sendCtx, toSendFinal)
		}()
	}
}

// SplitIntoChunks splits string s into chunks of up to chunkSize runes.
func SplitIntoChunks(s string, chunkSize int) []string {
	if chunkSize <= 0 {
		chunkSize = 9000
	}
	runes := []rune(s)
	total := len(runes)
	if total == 0 {
		return []string{""}
	}
	if total <= chunkSize {
		return []string{s}
	}
	var chunks []string
	for i := 0; i < total; i += chunkSize {
		end := i + chunkSize
		if end > total {
			end = total
		}
		chunks = append(chunks, string(runes[i:end]))
	}
	return chunks
}
