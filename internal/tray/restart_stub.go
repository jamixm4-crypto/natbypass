//go:build !windows

package tray

func RestartSelf() error {
	return nil
}