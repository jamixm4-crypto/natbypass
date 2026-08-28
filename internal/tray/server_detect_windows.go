//go:build windows

package tray

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// IsDesktopExperienceAvailable returns true if running on Windows Client or Windows Server
// with Desktop Experience (GUI). On headless Server Core it returns false.
func IsDesktopExperienceAvailable() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return true // Fallback to desktop mode if registry is inaccessible (e.g. Wine)
	}
	defer k.Close()

	installType, _, err := k.GetStringValue("InstallationType")
	if err != nil {
		return true
	}
	return !strings.EqualFold(installType, "Server Core")
}

// IsWebView2RuntimeAvailable checks if Microsoft Edge WebView2 Runtime is installed in the system.
func IsWebView2RuntimeAvailable() bool {
	// 1. Check WOW6432Node
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BEB-D151A21E16CD}`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if pv, _, err := k.GetStringValue("pv"); err == nil && pv != "" && pv != "0.0.0.0" {
			return true
		}
	}

	// 2. Check Native HKLM
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BEB-D151A21E16CD}`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if pv, _, err := k.GetStringValue("pv"); err == nil && pv != "" && pv != "0.0.0.0" {
			return true
		}
	}

	// 3. Check HKCU (Per-user installation)
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BEB-D151A21E16CD}`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if pv, _, err := k.GetStringValue("pv"); err == nil && pv != "" && pv != "0.0.0.0" {
			return true
		}
	}

	return false
}