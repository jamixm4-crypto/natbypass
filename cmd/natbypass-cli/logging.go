package main

import (
	"io"
	"os"
	"runtime"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// setupLogging initializes application logging with console formatting or JSON output.
func setupLogging(level, logFile string) {
	var output io.Writer

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			output = os.Stderr
		} else {
			output = f
		}
	} else {
		// On embedded router architectures (mips, mipsle, arm), use raw JSON output without ANSI escape codes
		if runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" || runtime.GOARCH == "arm" {
			output = os.Stderr
		} else {
			cw := zerolog.ConsoleWriter{
				Out:        os.Stderr,
				TimeFormat: time.RFC3339,
				NoColor:    false,
			}
			output = cw
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