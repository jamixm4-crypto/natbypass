//go:build windows

package license

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	TrialDays    = 14
	regKeyPath   = `SOFTWARE\NatBypass`
	regInstall   = "InstallDate"
	regHWID      = "HWID"
)

// TrialStatus describes the current state of the trial.
type TrialStatus struct {
	IsActive      bool
	IsExpired     bool
	DaysRemaining int
	InstallDate   time.Time
	HWID          string
}

// TrialManager manages the 14-day trial period.
type TrialManager struct {
	installDate time.Time
	hwid        string
}

// NewTrialManager loads or creates the trial state.
func NewTrialManager() (*TrialManager, error) {
	hwid := GetHWID()
	installDate := loadOrCreateInstallDate(hwid)
	return &TrialManager{
		installDate: installDate,
		hwid:        hwid,
	}, nil
}

// IsTrialActive returns true if the trial period has not expired.
func (tm *TrialManager) IsTrialActive() bool {
	return time.Since(tm.installDate) < time.Duration(TrialDays)*24*time.Hour
}

// IsTrialExpired returns true if the trial period has expired.
func (tm *TrialManager) IsTrialExpired() bool {
	return !tm.IsTrialActive()
}

// GetDaysRemaining returns how many days remain in the trial (0 if expired).
func (tm *TrialManager) GetDaysRemaining() int {
	elapsed := time.Since(tm.installDate)
	remaining := time.Duration(TrialDays)*24*time.Hour - elapsed
	if remaining <= 0 {
		return 0
	}
	days := int(remaining.Hours() / 24)
	return days
}

// GetStatus returns a complete TrialStatus snapshot.
func (tm *TrialManager) GetStatus() TrialStatus {
	return TrialStatus{
		IsActive:      tm.IsTrialActive(),
		IsExpired:     tm.IsTrialExpired(),
		DaysRemaining: tm.GetDaysRemaining(),
		InstallDate:   tm.installDate,
		HWID:          tm.hwid,
	}
}

// HWID returns the machine hardware ID.
func (tm *TrialManager) HWID() string { return tm.hwid }

// loadOrCreateInstallDate reads the install date from registry, or writes it on first run.
func loadOrCreateInstallDate(hwid string) time.Time {
	// Try registry first
	k, err := registry.OpenKey(registry.CURRENT_USER, regKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		// Key doesn't exist — create it
		k, _, err = registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
		if err != nil {
			return loadOrCreateFallbackDate()
		}
	}
	defer k.Close()

	// Write HWID
	_ = k.SetStringValue(regHWID, hwid)

	// Check existing date
	v, _, err := k.GetStringValue(regInstall)
	if err == nil && v != "" {
		t, parseErr := time.Parse(time.RFC3339, v)
		if parseErr == nil {
			return t
		}
	}

	// First run — save current time
	now := time.Now().UTC()
	_ = k.SetStringValue(regInstall, now.Format(time.RFC3339))
	return now
}

// loadOrCreateFallbackDate uses a JSON file in AppData as fallback.
func loadOrCreateFallbackDate() time.Time {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	dir := filepath.Join(appData, "NatBypass")
	_ = os.MkdirAll(dir, 0700)
	file := filepath.Join(dir, ".trial")

	type trialFile struct {
		InstallDate string `json:"install_date"`
	}

	if data, err := os.ReadFile(file); err == nil {
		var tf trialFile
		if json.Unmarshal(data, &tf) == nil && tf.InstallDate != "" {
			if t, err := time.Parse(time.RFC3339, tf.InstallDate); err == nil {
				return t
			}
		}
	}

	now := time.Now().UTC()
	tf := trialFile{InstallDate: now.Format(time.RFC3339)}
	data, _ := json.Marshal(tf)
	_ = os.WriteFile(file, data, 0600)
	return now
}

// FormatStatus returns a human-readable status string for the UI.
func (ts TrialStatus) FormatStatus() string {
	if ts.IsExpired {
		return "⛔ Пробный период истёк"
	}
	if ts.DaysRemaining <= 3 {
		return fmt.Sprintf("⚠️ Trial: осталось %d дн. — Скоро истечёт!", ts.DaysRemaining)
	}
	return fmt.Sprintf("✅ Trial: осталось %d из %d дней", ts.DaysRemaining, TrialDays)
}
