// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
	"github.com/rs/zerolog/log"
)

// rotatingFileWriter limits disk log growth and rotates files on size threshold.
// Protects tight router flash partitions from "No space left on device" errors.
type rotatingFileWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	curSize  int64
}

func newRotatingFileWriter(path string, maxBytes int64) (*rotatingFileWriter, error) {
	// If existing log exceeds limit, rotate/truncate on startup immediately
	if fi, err := os.Stat(path); err == nil && fi.Size() >= maxBytes {
		rotateFile(path)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	curSize := int64(0)
	if fi, err := f.Stat(); err == nil {
		curSize = fi.Size()
	}
	return &rotatingFileWriter{
		path:     path,
		maxBytes: maxBytes,
		file:     f,
		curSize:  curSize,
	}, nil
}

func rotateFile(path string) {
	old1 := path + ".1"
	_ = os.Remove(old1)
	_ = os.Rename(path, old1)
}

func (w *rotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	pLen := int64(len(p))
	if w.curSize+pLen > w.maxBytes {
		if w.file != nil {
			_ = w.file.Close()
		}
		rotateFile(w.path)
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return 0, err
		}
		w.file = f
		w.curSize = 0
	}

	if w.file == nil {
		return 0, os.ErrClosed
	}
	n, err = w.file.Write(p)
	w.curSize += int64(n)
	return n, err
}

func (w *rotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// setupLogging initializes application logging with console formatting or JSON output.
func setupLogging(level, logFile string) {
	var consoleWriter io.Writer
	if runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" || runtime.GOARCH == "arm" {
		consoleWriter = os.Stderr
	} else {
		consoleWriter = zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
			NoColor:    false,
		}
	}

	output := consoleWriter
	if logFile != "" {
		maxBytes := int64(4 * 1024 * 1024) // 4 MB default for desktop/server
		if runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" || runtime.GOARCH == "arm" {
			maxBytes = 512 * 1024 // 512 KB max on embedded routers (Keenetic / OpenWrt)
		}
		if rf, err := newRotatingFileWriter(logFile, maxBytes); err == nil {
			fileWriter := zerolog.ConsoleWriter{
				Out:        rf,
				TimeFormat: time.RFC3339,
				NoColor:    true,
			}
			output = io.MultiWriter(consoleWriter, fileWriter)
		}
	}

	if runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" || runtime.GOARCH == "arm" {
		output = diode.NewWriter(output, 1000, 10*time.Millisecond, func(missed int) {})
		if level == "info" {
			level = "warn"
		}
	}

	zerolog.TimeFieldFormat = time.RFC3339
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	log.Logger = zerolog.New(output).
		Level(lvl).
		With().
		Timestamp().
		Logger()
}
