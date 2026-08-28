//go:build windows

package tray

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const webview2BootstrapperURL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

func downloadWebView2Bootstrapper() (string, error) {
	tmpFile, err := os.CreateTemp("", "webview2-setup-*.exe")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(webview2BootstrapperURL)
	if err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to download WebView2 setup from Microsoft CDN: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("Microsoft CDN returned status %d", resp.StatusCode)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to save WebView2 setup: %w", err)
	}

	return tmpFile.Name(), nil
}

// InstallWebView2RuntimeIfNeeded downloads and installs the official Microsoft WebView2 runtime if missing.
func InstallWebView2RuntimeIfNeeded() (bool, error) {
	if IsWebView2RuntimeAvailable() {
		return true, nil
	}

	// 1. Download official bootstrapper on-demand from Microsoft CDN
	installerPath, err := downloadWebView2Bootstrapper()
	if err != nil {
		return false, err
	}
	defer os.Remove(installerPath)

	// 2. Launch silent installation
	cmd := exec.Command(installerPath, "/silent", "/install")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("failed to start WebView2 installer: %w", err)
	}

	// 3. Poll registry for installation completion (every 2s up to 5 minutes)
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		if IsWebView2RuntimeAvailable() {
			return true, nil
		}
		time.Sleep(2 * time.Second)
	}

	return false, fmt.Errorf("WebView2 installation timed out")
}