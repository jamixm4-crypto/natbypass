//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func initConsole() {
	stdout := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(stdout, &mode); err == nil {
		mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.ENABLE_PROCESSED_OUTPUT
		_ = windows.SetConsoleMode(stdout, mode)
	}
	stderr := windows.Handle(os.Stderr.Fd())
	if err := windows.GetConsoleMode(stderr, &mode); err == nil {
		mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.ENABLE_PROCESSED_OUTPUT
		_ = windows.SetConsoleMode(stderr, mode)
	}
}
