//go:build !linux

package daemon

// SetupSyslog is a no-op on non-Linux platforms.
func SetupSyslog(appName string) error {
	// Syslog не поддерживается на данной платформе
	return nil
}
