//go:build !windows

package tray

func IsDesktopExperienceAvailable() bool {
	return false
}

func IsWebView2RuntimeAvailable() bool {
	return false
}