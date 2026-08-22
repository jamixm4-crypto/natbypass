//go:build !windows

package config

// EncryptConfigData on non-Windows platforms acts as a passthrough.
func EncryptConfigData(plain []byte) ([]byte, error) {
	return plain, nil
}

// DecryptConfigData on non-Windows platforms acts as a passthrough.
func DecryptConfigData(enc []byte) ([]byte, error) {
	return enc, nil
}
