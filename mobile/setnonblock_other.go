//go:build !linux

package mobile

// setTunNonblock is a no-op on non-Linux platforms (Windows, macOS).
// The mobile package is only compiled and used on Android (Linux),
// so this stub exists solely to allow `go build ./...` on development machines.
func setTunNonblock(_ int) error {
	return nil
}
