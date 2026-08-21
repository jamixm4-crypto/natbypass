//go:build linux

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
