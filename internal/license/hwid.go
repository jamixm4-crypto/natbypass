//go:build windows

package license

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modkernel32Lic     = windows.NewLazySystemDLL("kernel32.dll")
	procGetVolumeInfoW = modkernel32Lic.NewProc("GetVolumeInformationW")
)

// GetHWID returns a stable SHA-256 hardware fingerprint derived from
// disk volume serial, primary MAC address, hostname, and Windows MachineGUID.
// On failure falls back to a file-based UUID in %APPDATA%.
func GetHWID() string {
	parts := []string{}

	// 1. Disk C:\ volume serial number
	if serial := getDiskSerial(); serial != "" {
		parts = append(parts, "disk:"+serial)
	}

	// 2. Primary MAC address (first non-loopback)
	if mac := getPrimaryMAC(); mac != "" {
		parts = append(parts, "mac:"+mac)
	}

	// 3. Machine hostname
	if hn, err := os.Hostname(); err == nil && hn != "" {
		parts = append(parts, "host:"+strings.ToLower(hn))
	}

	// 4. Windows MachineGUID from registry
	if guid := getMachineGUID(); guid != "" {
		parts = append(parts, "guid:"+guid)
	}

	if len(parts) == 0 {
		return getOrCreateFallbackHWID()
	}

	combined := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%X", sum[:12]) // 24-char hex
}

// getDiskSerial reads the volume serial number of the C:\ drive.
func getDiskSerial() string {
	root, err := syscall.UTF16PtrFromString(`C:\`)
	if err != nil {
		return ""
	}
	var volumeSerial uint32
	ret, _, _ := procGetVolumeInfoW.Call(
		uintptr(unsafe.Pointer(root)),
		0, 0,
		uintptr(unsafe.Pointer(&volumeSerial)),
		0, 0, 0, 0,
	)
	if ret == 0 {
		return ""
	}
	return fmt.Sprintf("%08X", volumeSerial)
}

// getPrimaryMAC returns the hardware address of the first non-loopback interface.
func getPrimaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) < 6 {
			continue
		}
		if iface.Flags&net.FlagUp != 0 {
			return strings.ReplaceAll(iface.HardwareAddr.String(), ":", "")
		}
	}
	return ""
}

// getMachineGUID reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid.
func getMachineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(v, "-", "")
}

// getOrCreateFallbackHWID generates or retrieves a persistent UUID from AppData.
func getOrCreateFallbackHWID() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	dir := filepath.Join(appData, "NatBypass")
	_ = os.MkdirAll(dir, 0700)
	hwidFile := filepath.Join(dir, ".hwid")

	if data, err := os.ReadFile(hwidFile); err == nil && len(data) >= 24 {
		return strings.TrimSpace(string(data))
	}

	// Use disk serial + hostname hash as deterministic fallback
	h := sha256.New()
	hn, _ := os.Hostname()
	fmt.Fprintf(h, "natbypass-fallback-%s", hn)
	hwid := fmt.Sprintf("%X", h.Sum(nil))[:24]
	_ = os.WriteFile(hwidFile, []byte(hwid), 0600)
	return hwid
}
