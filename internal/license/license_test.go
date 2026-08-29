//go:build windows

package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestGetHWID(t *testing.T) {
	hwid := GetHWID()
	if hwid == "" {
		t.Fatal("expected non-empty HWID")
	}
	if len(hwid) < 12 {
		t.Fatalf("HWID too short: %s", hwid)
	}
	// Verify deterministic
	hwid2 := GetHWID()
	if hwid != hwid2 {
		t.Fatalf("HWID is not deterministic: %s != %s", hwid, hwid2)
	}
}

func TestTrialManager(t *testing.T) {
	tm, err := NewTrialManager()
	if err != nil {
		t.Fatalf("NewTrialManager failed: %v", err)
	}
	if !tm.IsTrialActive() {
		t.Errorf("expected trial to be active on fresh run")
	}
	if tm.IsTrialExpired() {
		t.Errorf("expected trial not to be expired")
	}
	days := tm.GetDaysRemaining()
	if days < 0 || days > TrialDays {
		t.Errorf("unexpected days remaining: %d", days)
	}
	status := tm.GetStatus()
	if status.HWID == "" {
		t.Errorf("status HWID is empty")
	}
}

func TestLicenseKeyValidation(t *testing.T) {
	hwid := GetHWID()
	issuedTo := "Tester"
	futureUnix := time.Now().Add(30 * 24 * time.Hour).Unix()
	licType := "pro"

	// Create valid signature
	payload := fmt.Sprintf("%s:%d:%s:%s", issuedTo, futureUnix, licType, hwid)
	mac := hmac.New(sha256.New, []byte(licenseSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	key := fmt.Sprintf("%s:%d:%s:%s:%s", issuedTo, futureUnix, licType, hwid, sig)

	info, err := parseAndValidateLicenseKey(key, hwid)
	if err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if info.IssuedTo != issuedTo || info.LicenseType != licType {
		t.Errorf("unexpected license info: %+v", info)
	}

	// Test invalid signature
	badKey := fmt.Sprintf("%s:%d:%s:%s:%s", issuedTo, futureUnix, licType, hwid, "deadbeef1234")
	if _, err := parseAndValidateLicenseKey(badKey, hwid); err == nil {
		t.Errorf("expected bad signature to fail")
	}

	// Test mismatched HWID
	otherHWID := "OTHERHWID123456789012"
	if _, err := parseAndValidateLicenseKey(key, otherHWID); err == nil {
		t.Errorf("expected mismatched HWID to fail")
	}
}
