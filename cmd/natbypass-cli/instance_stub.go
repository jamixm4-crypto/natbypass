//go:build !windows

package main

func acquireSingleInstanceMutex(port int) bool {
	return true
}

func releaseSingleInstanceMutex() {}

func openAppWindow(port int) {}
