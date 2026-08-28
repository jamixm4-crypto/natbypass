//go:build !windows

package main

func acquireSingleInstanceMutex(cfgPath string, port int) bool {
	return true
}

func releaseSingleInstanceMutex() {}

func cleanupTrayIcon() {}

func openAppWindow(port int) {}

