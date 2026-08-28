//go:build !windows

package tray

func InstallWebView2RuntimeIfNeeded() (bool, error) {
	return false, nil
}