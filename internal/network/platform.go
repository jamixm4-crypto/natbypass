package network

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	countryCacheMu sync.RWMutex
	countryCache   = make(map[string]string)
)

// DetectPlatform returns the human-readable platform / OS name with emoji.
func DetectPlatform() (rawOS string, displayName string, emoji string) {
	goos := runtime.GOOS

	switch goos {
	case "windows":
		return "windows", "Windows", "🪟"
	case "darwin":
		return "darwin", "macOS", "🍎"
	case "android":
		return "android", "Android", "🤖"
	case "linux":
		// Detect Keenetic Entware / NDM
		if _, err := os.Stat("/opt/etc/ndm"); err == nil {
			return "keenetic", "Keenetic", "🌐"
		}
		if _, err := os.Stat("/opt/bin/ndmc"); err == nil {
			return "keenetic", "Keenetic", "🌐"
		}
		// Detect OpenWrt
		if _, err := os.Stat("/etc/openwrt_release"); err == nil {
			return "openwrt", "OpenWrt", "📡"
		}
		// Detect Debian / Ubuntu / generic Linux
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			content := string(data)
			if strings.Contains(content, "ID=debian") {
				return "debian", "Debian", "🐧"
			}
			if strings.Contains(content, "ID=ubuntu") {
				return "ubuntu", "Ubuntu", "🐧"
			}
			if strings.Contains(content, "ID=alpine") {
				return "alpine", "Alpine", "🏔️"
			}
		}
		return "linux", "Linux", "🐧"
	default:
		return goos, strings.Title(goos), "💻"
	}
}

// CountryCodeToFlag converts ISO 3166-1 alpha-2 (e.g. "RU", "DE", "US") to Unicode Emoji Flag.
func CountryCodeToFlag(countryCode string) string {
	cc := strings.ToUpper(strings.TrimSpace(countryCode))
	if len(cc) != 2 {
		return ""
	}
	if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	r1 := rune(0x1F1E6 + int(cc[0]-'A'))
	r2 := rune(0x1F1E6 + int(cc[1]-'A'))
	return string([]rune{r1, r2})
}

// LookupCountryFlag queries a fast GeoIP endpoint for a public IP and returns the country flag emoji.
func LookupCountryFlag(ctx context.Context, ip string) string {
	cleanIP := strings.TrimSpace(ip)
	if idx := strings.Index(cleanIP, ":"); idx != -1 {
		cleanIP = cleanIP[:idx]
	}
	if cleanIP == "" || cleanIP == "127.0.0.1" || strings.HasPrefix(cleanIP, "10.") || strings.HasPrefix(cleanIP, "192.168.") || strings.HasPrefix(cleanIP, "172.16.") {
		return ""
	}

	countryCacheMu.RLock()
	if flag, found := countryCache[cleanIP]; found {
		countryCacheMu.RUnlock()
		return flag
	}
	countryCacheMu.RUnlock()

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.country.is/"+cleanIP, nil)
	if err != nil {
		return ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var res struct {
		Country string `json:"country"`
	}
	if err := json.Unmarshal(body, &res); err == nil && res.Country != "" {
		flag := CountryCodeToFlag(res.Country)
		if flag != "" {
			countryCacheMu.Lock()
			countryCache[cleanIP] = flag
			countryCacheMu.Unlock()
			return flag
		}
	}

	return ""
}
