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
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
	"github.com/rs/zerolog/log"
)

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
		if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			fileWriter := zerolog.ConsoleWriter{
				Out:        f,
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