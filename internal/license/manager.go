//go:build windows

package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// licenseSecret is the HMAC key used to sign offline license keys.
// In production, rotate this and embed it obfuscated.
const licenseSecret = "NatBypass-License-2026-SecretKey-v1"

const (
	LicenseTypeTrial      = "trial"
	LicenseTypePersonal   = "personal"
	LicenseTypePro        = "pro"
	LicenseTypeEnterprise = "enterprise"
)

// LicenseInfo represents a decoded and validated license.
type LicenseInfo struct {
	LicenseKey  string
	LicenseType string
	IssuedTo    string
	ValidUntil  time.Time
	Features    []string
	HWID        string
}

// LicenseManager manages license validation and persistence.
type LicenseManager struct {
	hwid         string
	current      *LicenseInfo
	trialManager *TrialManager
}

// NewLicenseManager creates a LicenseManager, loading any saved license.
func NewLicenseManager(tm *TrialManager) *LicenseManager {
	lm := &LicenseManager{
		hwid:         tm.HWID(),
		trialManager: tm,
	}
	lm.current = lm.loadSavedLicense()
	return lm
}

// GetCurrentLicense returns the active license (or nil if only trial).
func (lm *LicenseManager) GetCurrentLicense() *LicenseInfo {
	return lm.current
}

// GetLicenseType returns the active license type string.
func (lm *LicenseManager) GetLicenseType() string {
	if lm.current != nil && !lm.current.ValidUntil.Before(time.Now()) {
		return lm.current.LicenseType
	}
	return LicenseTypeTrial
}

// IsExpired returns true if the active license (or trial) has expired.
func (lm *LicenseManager) IsExpired() bool {
	if lm.current != nil {
		return lm.current.ValidUntil.Before(time.Now())
	}
	return lm.trialManager.IsTrialExpired()
}

// HasFeature checks if a given feature is available in the current license.
func (lm *LicenseManager) HasFeature(feature string) bool {
	switch lm.GetLicenseType() {
	case LicenseTypeEnterprise:
		return true
	case LicenseTypePro:
		return feature != "enterprise_sso"
	case LicenseTypePersonal:
		return feature == "basic" || feature == "awg" || feature == "profiles"
	}
	// trial
	switch feature {
	case "basic", "awg":
		return !lm.trialManager.IsTrialExpired()
	}
	return false
}

// MaxDevices returns the max device count based on license.
func (lm *LicenseManager) MaxDevices() int {
	switch lm.GetLicenseType() {
	case LicenseTypeEnterprise:
		return 9999
	case LicenseTypePro:
		return 50
	case LicenseTypePersonal:
		return 10
	}
	return 2 // trial
}

// ActivateOffline validates and saves an offline license key.
// Key format: BASE:ISSUEDTO:EXPIRY_UNIX:TYPE:HWID:HMAC_HEX
func (lm *LicenseManager) ActivateOffline(key string) error {
	info, err := parseAndValidateLicenseKey(key, lm.hwid)
	if err != nil {
		return err
	}
	lm.current = info
	return lm.saveLicense(key, info)
}

// StatusLine returns a single-line status for the UI.
func (lm *LicenseManager) StatusLine() string {
	switch lm.GetLicenseType() {
	case LicenseTypeEnterprise:
		return fmt.Sprintf("✅ Enterprise — %s | до %s", lm.current.IssuedTo, lm.current.ValidUntil.Format("02.01.2006"))
	case LicenseTypePro:
		return fmt.Sprintf("✅ Pro — %s | до %s", lm.current.IssuedTo, lm.current.ValidUntil.Format("02.01.2006"))
	case LicenseTypePersonal:
		return fmt.Sprintf("✅ Personal — %s | до %s", lm.current.IssuedTo, lm.current.ValidUntil.Format("02.01.2006"))
	}
	return lm.trialManager.GetStatus().FormatStatus()
}

// ---- Key parsing & validation ----

func parseAndValidateLicenseKey(key, hwid string) (*LicenseInfo, error) {
	// Format: ISSUEDTO:EXPIRY_UNIX:TYPE:HWID:HMAC
	parts := strings.Split(strings.TrimSpace(key), ":")
	if len(parts) != 5 {
		return nil, fmt.Errorf("неверный формат ключа лицензии")
	}
	issuedTo := parts[0]
	expiryStr := parts[1]
	licType := strings.ToLower(parts[2])
	keyHWID := parts[3]
	givenMAC := parts[4]

	// Validate HWID binding (lenient: allow "*" for universal keys)
	if keyHWID != "*" && !strings.EqualFold(keyHWID, hwid) {
		return nil, fmt.Errorf("лицензионный ключ привязан к другому устройству (HWID не совпадает)")
	}

	// Parse expiry
	var expiryUnix int64
	if _, err := fmt.Sscanf(expiryStr, "%d", &expiryUnix); err != nil {
		return nil, fmt.Errorf("ошибка разбора даты истечения лицензии")
	}
	expiry := time.Unix(expiryUnix, 0)

	// Validate HMAC
	payload := fmt.Sprintf("%s:%s:%s:%s", issuedTo, expiryStr, licType, keyHWID)
	mac := hmac.New(sha256.New, []byte(licenseSecret))
	mac.Write([]byte(payload))
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(givenMAC), []byte(expectedMAC)) {
		return nil, fmt.Errorf("неверная подпись лицензионного ключа")
	}

	if expiry.Before(time.Now()) {
		return nil, fmt.Errorf("лицензионный ключ истёк %s", expiry.Format("02.01.2006"))
	}

	features := featuresForType(licType)
	return &LicenseInfo{
		LicenseKey:  key,
		LicenseType: licType,
		IssuedTo:    issuedTo,
		ValidUntil:  expiry,
		Features:    features,
		HWID:        keyHWID,
	}, nil
}

func featuresForType(t string) []string {
	switch t {
	case LicenseTypeEnterprise:
		return []string{"basic", "awg", "profiles", "exit_node", "subnet_routing", "enterprise_sso"}
	case LicenseTypePro:
		return []string{"basic", "awg", "profiles", "exit_node", "subnet_routing"}
	case LicenseTypePersonal:
		return []string{"basic", "awg", "profiles"}
	}
	return []string{"basic"}
}

// ---- Persistence ----

type savedLicenseFile struct {
	Key  string `json:"key"`
	HWID string `json:"hwid"`
}

func (lm *LicenseManager) saveLicense(key string, info *LicenseInfo) error {
	// Save to registry
	k, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err == nil {
		defer k.Close()
		_ = k.SetStringValue("LicenseKey", key)
		_ = k.SetStringValue("LicenseType", info.LicenseType)
		_ = k.SetStringValue("LicenseIssuedTo", info.IssuedTo)
	}

	// Also save to AppData file as backup
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return nil
	}
	dir := filepath.Join(appData, "NatBypass")
	_ = os.MkdirAll(dir, 0700)
	data, err := json.Marshal(savedLicenseFile{Key: key, HWID: lm.hwid})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ".license"), data, 0600)
}

func (lm *LicenseManager) loadSavedLicense() *LicenseInfo {
	key := ""

	// Try registry first
	k, err := registry.OpenKey(registry.CURRENT_USER, regKeyPath, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		v, _, e := k.GetStringValue("LicenseKey")
		if e == nil {
			key = v
		}
	}

	// Fallback to file
	if key == "" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			if data, err := os.ReadFile(filepath.Join(appData, "NatBypass", ".license")); err == nil {
				var sf savedLicenseFile
				if json.Unmarshal(data, &sf) == nil {
					key = sf.Key
				}
			}
		}
	}

	if key == "" {
		return nil
	}

	info, err := parseAndValidateLicenseKey(key, lm.hwid)
	if err != nil {
		return nil // expired or invalid — treat as trial
	}
	return info
}
