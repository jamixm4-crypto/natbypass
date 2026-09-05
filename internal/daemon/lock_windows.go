//go:build windows
// +build windows

package daemon

// AcquireProcessLock on Windows returns a no-op unlock func as single instance is handled by Windows Service / Mutex.
func AcquireProcessLock() (func(), error) {
	return func() {}, nil
}
