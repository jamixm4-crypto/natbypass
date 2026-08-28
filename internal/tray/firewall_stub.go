//go:build !windows

package tray

func EnsureFirewallRule(port int) error {
	return nil
}