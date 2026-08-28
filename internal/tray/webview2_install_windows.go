//go:build windows

package tray

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modShell32Install    = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteWRun = modShell32Install.NewProc("ShellExecuteW")
)

// InstallWebView2RuntimeIfNeeded extracts the embedded Evergreen bootstrapper and
// executes silent installation with UAC elevation if WebView2 is missing.
func InstallWebView2RuntimeIfNeeded() (bool, error) {
	if IsWebView2RuntimeAvailable() {
		return true, nil
	}

	if len(webview2Bootstrapper) == 0 {
		return false, fmt.Errorf("embedded webview2 bootstrapper payload is empty")
	}

	// 1. Write embedded bootstrapper to temp file
	tmpFile, err := os.CreateTemp("", "webview2-setup-*.exe")
	if err != nil {
		return false, fmt.Errorf("failed to create temp installer file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(webview2Bootstrapper); err != nil {
		_ = tmpFile.Close()
		return false, fmt.Errorf("failed to write installer payload: %w", err)
	}
	_ = tmpFile.Close()

	// 2. Launch installer with UAC elevation ("runas") and silent flags ("/silent /install")
	procPtr, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return false, err
	}
	verbPtr, _ := windows.UTF16PtrFromString("runas")
	argsPtr, _ := windows.UTF16PtrFromString("/silent /install")

	ret, _, _ := procShellExecuteWRun.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(procPtr)),
		uintptr(unsafe.Pointer(argsPtr)),
		0,
		windows.SW_HIDE,
	)

	if ret <= 32 {
		return false, fmt.Errorf("ShellExecuteW failed to launch installer with elevation (code %d)", ret)
	}

	// 3. Poll registry for installation completion (every 2 seconds up to 5 minutes)
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		if IsWebView2RuntimeAvailable() {
			return true, nil
		}
		time.Sleep(2 * time.Second)
	}

	return false, fmt.Errorf("WebView2 runtime installation timed out")
}