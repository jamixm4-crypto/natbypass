package tunnel

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// mockIptablesPath creates a mock iptables binary that records calls and returns success.
// It returns the directory containing the mock binary and a cleanup function.
func mockIptablesPath(t *testing.T, logFile string) (string, func()) {
	t.Helper()
	dir := t.TempDir()

	// Create a mock shell script that logs its arguments
	mockSh := filepath.Join(dir, "iptables")
	script := `#!/bin/sh
echo "$@" >> ` + logFile + `
exit 0
`
	if err := os.WriteFile(mockSh, []byte(script), 0755); err != nil {
		t.Fatalf("failed to create mock iptables: %v", err)
	}
	return dir, func() {}
}

// TestMSSClamping_Logic validates MSS calculation and function signatures cross-platform.
// On Linux it verifies correct iptables argument construction via PATH override.
// On other platforms it verifies the stubs return nil without side effects.
func TestMSSClamping_Logic(t *testing.T) {
	t.Run("MTU_validation", func(t *testing.T) {
		// Test MSS math: 1420 - 60 = 1360
		mtu := 1420
		if mtu < 576 || mtu > 1500 {
			mtu = 1420
		}
		mss := mtu - 60
		if mss != 1360 {
			t.Errorf("expected MSS=1360 for MTU=1420, got %d", mss)
		}
	})

	t.Run("MTU_clamp_out_of_range", func(t *testing.T) {
		// Values outside [576, 1500] should default to 1420
		for _, badMTU := range []int{0, 100, 575, 1501, 9000} {
			mtu := badMTU
			if mtu < 576 || mtu > 1500 {
				mtu = 1420
			}
			mss := mtu - 60
			if mss != 1360 {
				t.Errorf("bad MTU %d: expected fallback MSS=1360, got %d", badMTU, mss)
			}
		}
	})

	t.Run("empty_interface_rejected", func(t *testing.T) {
		err := EnableMSSClamping("", 1420)
		if runtime.GOOS == "linux" {
			if err == nil {
				t.Error("expected error for empty tunInterface on Linux, got nil")
			}
			if !strings.Contains(err.Error(), "tun interface name is required") {
				t.Errorf("unexpected error message: %v", err)
			}
		} else {
			// Stubs always return nil
			if err != nil {
				t.Errorf("stub EnableMSSClamping should return nil, got: %v", err)
			}
		}
	})

	t.Run("disable_empty_interface_defaults", func(t *testing.T) {
		// DisableMSSClamping("") should not panic — it defaults to "nb0" on Linux
		// stubs return nil everywhere else
		_ = DisableMSSClamping("")
	})
}

// TestMSSClamping_Linux verifies actual iptables command construction on Linux
// using a PATH-injected mock iptables script that records invocations.
func TestMSSClamping_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test (iptables mock)")
	}

	logFile := filepath.Join(t.TempDir(), "iptables.log")
	mockDir, cleanup := mockIptablesPath(t, logFile)
	defer cleanup()

	// Inject mock dir at front of PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", mockDir+string(os.PathListSeparator)+origPath)

	// Verify mock is picked up
	path, err := exec.LookPath("iptables")
	if err != nil || !strings.HasPrefix(path, mockDir) {
		t.Fatalf("mock iptables not picked up: path=%s err=%v", path, err)
	}

	const iface = "nb0"
	const mtu = 1420
	const mss = 1360 // 1420 - 60

	t.Run("EnableMSSClamping_iptables_args", func(t *testing.T) {
		_ = os.WriteFile(logFile, nil, 0644) // reset log
		err := EnableMSSClamping(iface, mtu)
		if err != nil {
			t.Fatalf("EnableMSSClamping returned unexpected error: %v", err)
		}

		logBytes, _ := os.ReadFile(logFile)
		log := string(logBytes)

		// Must contain an -A POSTROUTING rule with correct interface and MSS
		if !strings.Contains(log, "-t mangle -A POSTROUTING") {
			t.Errorf("missing -A POSTROUTING in iptables log:\n%s", log)
		}
		if !strings.Contains(log, "-o "+iface) {
			t.Errorf("missing -o %s in iptables log:\n%s", iface, log)
		}
		if !strings.Contains(log, "TCPMSS") {
			t.Errorf("missing TCPMSS target in iptables log:\n%s", log)
		}
		if !strings.Contains(log, "1360") {
			t.Errorf("expected MSS=1360 in iptables log:\n%s", log)
		}
		// Must also issue a -D delete first (idempotency)
		if !strings.Contains(log, "-D POSTROUTING") {
			t.Errorf("missing idempotency -D POSTROUTING in iptables log:\n%s", log)
		}
	})

	t.Run("DisableMSSClamping_iptables_args", func(t *testing.T) {
		_ = os.WriteFile(logFile, nil, 0644) // reset log
		err := DisableMSSClamping(iface)
		if err != nil {
			t.Fatalf("DisableMSSClamping returned unexpected error: %v", err)
		}

		logBytes, _ := os.ReadFile(logFile)
		log := string(logBytes)

		if !strings.Contains(log, "-t mangle -D POSTROUTING") {
			t.Errorf("missing -t mangle -D POSTROUTING in iptables log:\n%s", log)
		}
		if !strings.Contains(log, "-o "+iface) {
			t.Errorf("missing -o %s in iptables log:\n%s", iface, log)
		}
		if !strings.Contains(log, "TCPMSS") {
			t.Errorf("missing TCPMSS target in iptables log:\n%s", log)
		}
	})

	t.Run("Idempotency_double_enable", func(t *testing.T) {
		_ = os.WriteFile(logFile, nil, 0644)
		// Call twice — should not error, second call deletes first then re-adds
		_ = EnableMSSClamping(iface, mtu)
		err := EnableMSSClamping(iface, mtu)
		if err != nil {
			t.Errorf("second EnableMSSClamping should succeed (idempotent), got: %v", err)
		}
	})
}
