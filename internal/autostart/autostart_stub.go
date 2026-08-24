//go:build !windows

package autostart

func SetAutoStart(name, execPath string, enable bool) error {
	return nil
}
