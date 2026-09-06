//go:build linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package daemon

import (
	"fmt"
	"log/syslog"
)

// SetupSyslog configures syslog output on Linux.
func SetupSyslog(appName string) error {
	syslogWriter, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, appName)
	if err != nil {
		return fmt.Errorf("ошибка настройки syslog: %w", err)
	}

	// This is a minimal implementation. 
	// For zerolog integration, you would use syslogWriter as the zerolog output.
	_ = syslogWriter
	
	return nil
}
