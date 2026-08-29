//go:build !windows

package license

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"
)

const (
	TrialDays             = 14
	LicenseTypeTrial      = "trial"
	LicenseTypePersonal   = "personal"
	LicenseTypePro        = "pro"
	LicenseTypeEnterprise = "enterprise"
)

type TrialStatus struct {
	IsActive      bool
	IsExpired     bool
	DaysRemaining int
	InstallDate   time.Time
	HWID          string
}

type LicenseInfo struct {
	LicenseKey  string
	LicenseType string
	IssuedTo    string
	ValidUntil  time.Time
	Features    []string
	HWID        string
}

type TrialManager struct {
	hwid string
}

func NewTrialManager() (*TrialManager, error) {
	return &TrialManager{hwid: GetHWID()}, nil
}

func (tm *TrialManager) IsTrialActive() bool      { return true }
func (tm *TrialManager) IsTrialExpired() bool     { return false }
func (tm *TrialManager) GetDaysRemaining() int    { return 14 }
func (tm *TrialManager) HWID() string             { return tm.hwid }
func (tm *TrialManager) GetStatus() TrialStatus {
	return TrialStatus{
		IsActive:      true,
		IsExpired:     false,
		DaysRemaining: 14,
		InstallDate:   time.Now(),
		HWID:          tm.hwid,
	}
}

type LicenseManager struct {
	hwid string
}

func NewLicenseManager(tm *TrialManager) *LicenseManager {
	return &LicenseManager{hwid: tm.HWID()}
}

func (lm *LicenseManager) GetCurrentLicense() *LicenseInfo { return nil }
func (lm *LicenseManager) GetLicenseType() string         { return LicenseTypePro }
func (lm *LicenseManager) IsExpired() bool                { return false }
func (lm *LicenseManager) HasFeature(f string) bool       { return true }
func (lm *LicenseManager) MaxDevices() int                { return 50 }
func (lm *LicenseManager) ActivateOffline(k string) error { return nil }
func (lm *LicenseManager) StatusLine() string             { return "Лицензия активна" }

func GetHWID() string {
	hn, _ := os.Hostname()
	sum := sha256.Sum256([]byte("natbypass-" + hn))
	return fmt.Sprintf("%X", sum[:12])
}

func (ts TrialStatus) FormatStatus() string {
	return "✅ Лицензия активна"
}
