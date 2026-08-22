//go:build windows

package config

import (
	"encoding/base64"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	crypt32              = syscall.NewLazyDLL("crypt32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree        = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{cbData: 0, pbData: nil}
	}
	return &dataBlob{
		cbData: uint32(len(d)),
		pbData: &d[0],
	}
}

func (b *dataBlob) toByteArray() []byte {
	if b.cbData == 0 || b.pbData == nil {
		return []byte{}
	}
	d := make([]byte, b.cbData)
	copy(d, unsafe.Slice(b.pbData, b.cbData))
	return d
}

// dpapiProtect encrypts raw bytes with Windows DPAPI (CryptProtectData).
func dpapiProtect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	inBlob := newBlob(data)
	var outBlob dataBlob

	// dwFlags: 0x1 = CRYPTPROTECT_UI_FORBIDDEN
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(inBlob)),
		0, // szDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		1, // dwFlags: CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	return outBlob.toByteArray(), nil
}

// dpapiUnprotect decrypts raw bytes with Windows DPAPI (CryptUnprotectData).
func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	inBlob := newBlob(data)
	var outBlob dataBlob

	// dwFlags: 0x1 = CRYPTPROTECT_UI_FORBIDDEN
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(inBlob)),
		0, // ppszDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		1, // dwFlags: CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	return outBlob.toByteArray(), nil
}

// EncryptConfigData encrypts plain config YAML using Windows DPAPI and formats it
// with header "# NATBYPASS_ENCRYPTED_CONFIG:v1\n" + base64 encoded ciphertext.
func EncryptConfigData(plain []byte) ([]byte, error) {
	ciphertext, err := dpapiProtect(plain)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(ciphertext)
	out := fmt.Sprintf("%s\n%s\n", HeaderEncryptedConfig, b64)
	return []byte(out), nil
}

// DecryptConfigData checks if data starts with "# NATBYPASS_ENCRYPTED_CONFIG:v1".
// If so, it decodes the base64 payload and decrypts it with Windows DPAPI.
// Otherwise, it returns the data as-is (plain YAML).
func DecryptConfigData(enc []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(enc))
	if strings.HasPrefix(trimmed, HeaderEncryptedConfig) {
		payloadStr := strings.TrimSpace(strings.TrimPrefix(trimmed, HeaderEncryptedConfig))
		if payloadStr == "" {
			return []byte{}, nil
		}
		ciphertext, err := base64.StdEncoding.DecodeString(payloadStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 encrypted config: %w", err)
		}
		plain, err := dpapiUnprotect(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt config with DPAPI: %w", err)
		}
		return plain, nil
	}
	return enc, nil
}
