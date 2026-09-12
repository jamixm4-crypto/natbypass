// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package updater

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestParallelDownloader_RangeSupported tests multi-threaded chunked download
// when the server fully supports HTTP 206 Partial Content and Range headers.
func TestParallelDownloader_RangeSupported(t *testing.T) {
	// 4 MB test payload
	testSize := 4 * 1024 * 1024
	testData := make([]byte, testSize)
	_, _ = rand.Read(testData)
	expectedHash := sha256.Sum256(testData)

	var requestCount atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		rangeHdr := r.Header.Get("Range")

		if rangeHdr == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(testData)))
			w.Header().Set("Accept-Ranges", "bytes")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(testData)
			return
		}

		// Handle Range header: bytes=start-end
		if !strings.HasPrefix(rangeHdr, "bytes=") {
			http.Error(w, "invalid range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		raw := strings.TrimPrefix(rangeHdr, "bytes=")
		parts := strings.Split(raw, "-")
		if len(parts) != 2 {
			http.Error(w, "invalid range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		start, err1 := strconv.ParseInt(parts[0], 10, 64)
		end, err2 := strconv.ParseInt(parts[1], 10, 64)
		if err1 != nil || err2 != nil || start > end || start >= int64(len(testData)) {
			http.Error(w, "invalid range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if end >= int64(len(testData)) {
			end = int64(len(testData)) - 1
		}

		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(testData)))
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(testData[start : end+1])
	}))
	defer server.Close()

	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "test_download.bin")

	var progressCalled bool
	var maxPercent int

	cfg := DownloaderConfig{
		Workers:         4,
		MinChunkSize:    512 * 1024,
		MaxChunkRetries: 3,
		RequestTimeout:  10 * time.Second,
		OnProgress: func(downloaded, total int64, speed float64, percent int, workers int) {
			progressCalled = true
			if percent > maxPercent {
				maxPercent = percent
			}
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := DownloadFile(ctx, server.URL, destPath, cfg)
	if err != nil {
		t.Fatalf("DownloadFile failed: %v", err)
	}

	// Verify file content and hash
	downloadedData, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if len(downloadedData) != testSize {
		t.Fatalf("expected size %d, got %d", testSize, len(downloadedData))
	}

	gotHash := sha256.Sum256(downloadedData)
	if !bytes.Equal(gotHash[:], expectedHash[:]) {
		t.Fatalf("SHA256 mismatch! Got %x, expected %x", gotHash, expectedHash)
	}

	if !progressCalled {
		t.Fatalf("expected progress callback to be called")
	}

	if maxPercent < 100 {
		t.Fatalf("expected progress to reach 100%%, got %d%%", maxPercent)
	}

	// Range probe + 4 chunk workers = at least 5 requests
	reqCount := requestCount.Load()
	if reqCount < 4 {
		t.Fatalf("expected at least 4 parallel chunk requests, got %d", reqCount)
	}
}

// TestParallelDownloader_FallbackToSingleStream tests fallback when the server does not support Range.
func TestParallelDownloader_FallbackToSingleStream(t *testing.T) {
	testSize := 1024 * 1024 // 1 MB
	testData := make([]byte, testSize)
	_, _ = rand.Read(testData)
	expectedHash := sha256.Sum256(testData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore Range header and always return 200 OK
		w.Header().Set("Content-Length", strconv.Itoa(len(testData)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(testData)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "test_fallback.bin")

	var progressCalled bool
	cfg := DownloaderConfig{
		Workers:         4,
		MinChunkSize:    256 * 1024,
		MaxChunkRetries: 3,
		RequestTimeout:  10 * time.Second,
		OnProgress: func(downloaded, total int64, speed float64, percent int, workers int) {
			progressCalled = true
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := DownloadFile(ctx, server.URL, destPath, cfg)
	if err != nil {
		t.Fatalf("DownloadFile fallback failed: %v", err)
	}

	downloadedData, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	gotHash := sha256.Sum256(downloadedData)
	if !bytes.Equal(gotHash[:], expectedHash[:]) {
		t.Fatalf("SHA256 mismatch! Got %x, expected %x", gotHash, expectedHash)
	}

	if !progressCalled {
		t.Fatalf("expected progress callback to be called in fallback mode")
	}
}

// TestParallelDownloader_ChunkRetry tests automatic retry of failed chunk requests.
func TestParallelDownloader_ChunkRetry(t *testing.T) {
	testSize := 2 * 1024 * 1024
	testData := make([]byte, testSize)
	_, _ = rand.Read(testData)
	expectedHash := sha256.Sum256(testData)

	var failuresRemaining atomic.Int32
	failuresRemaining.Store(2) // Fail the first 2 chunk requests, then succeed

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHdr := r.Header.Get("Range")
		if rangeHdr == "bytes=0-0" {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-0/%d", len(testData)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(testData[0:1])
			return
		}

		if failuresRemaining.Add(-1) >= 0 {
			// Simulate connection drop / reset on cell tower switch
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
				return
			}
			http.Error(w, "temporary mobile dropout", http.StatusServiceUnavailable)
			return
		}

		// Success
		raw := strings.TrimPrefix(rangeHdr, "bytes=")
		parts := strings.Split(raw, "-")
		start, _ := strconv.ParseInt(parts[0], 10, 64)
		end, _ := strconv.ParseInt(parts[1], 10, 64)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(testData)))
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(testData[start : end+1])
	}))
	defer server.Close()

	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "test_retry.bin")

	cfg := DownloaderConfig{
		Workers:         2,
		MinChunkSize:    512 * 1024,
		MaxChunkRetries: 4,
		RequestTimeout:  5 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := DownloadFile(ctx, server.URL, destPath, cfg)
	if err != nil {
		t.Fatalf("DownloadFile should have succeeded after retrying: %v", err)
	}

	downloadedData, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	gotHash := sha256.Sum256(downloadedData)
	if !bytes.Equal(gotHash[:], expectedHash[:]) {
		t.Fatalf("SHA256 mismatch! Got %x, expected %x", gotHash, expectedHash)
	}
}
