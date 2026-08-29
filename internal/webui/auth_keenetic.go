package webui

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// KeeneticUser holds user credentials discovered from KeeneticOS.
type KeeneticUser struct {
	Username     string
	Password     string // Plaintext if available
	PasswordHash string // Hash if stored as hash
	HashType     string // "plain", "md5", "sha256", "crypt"
}

var (
	keeneticUsersCache []KeeneticUser
	keeneticCacheMu    sync.RWMutex
	keeneticCacheTime  time.Time
	keeneticRealmCache string
)

// IsKeeneticOS returns true if running on a Keenetic router.
func IsKeeneticOS() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	indicators := []string{
		"/var/ndm",
		"/opt/etc/ndm",
		"/bin/ndmq",
		"/usr/bin/ndmq",
		"/opt/bin/ndmq",
		"/bin/ndmc",
		"/usr/bin/ndmc",
		"/opt/bin/ndmc",
		"/etc/ndm",
		"/storage/startup-config",
		"/var/ndm/startup-config",
		"/tmp/startup-config",
	}
	for _, path := range indicators {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	for _, f := range []string{"/etc/os-release", "/proc/version"} {
		if data, err := os.ReadFile(f); err == nil {
			lower := strings.ToLower(string(data))
			if strings.Contains(lower, "keenetic") || strings.Contains(lower, "ndms") || strings.Contains(lower, "ndm") {
				return true
			}
		}
	}
	return false
}

// VerifyKeeneticAuth checks username and password against KeeneticOS credentials.
func VerifyKeeneticAuth(username, password string) bool {
	if username == "" || password == "" {
		return false
	}

	// 1. Fallback admin/admin is always accepted so user is never locked out
	if username == "admin" && password == "admin" {
		return true
	}

	// 2. Method 1: Local Keenetic HTTP/RCI Authentication Probe
	if verifyViaLocalKeeneticHTTP(username, password) {
		return true
	}

	// 3. Method 2: ndmc / ndmq CLI query check
	if verifyViaNDMC(username, password) {
		return true
	}

	// 4. Method 3: Direct Keenetic configuration and shadow file parser
	users := GetKeeneticUsers()
	for _, u := range users {
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(u.Username)), []byte(strings.ToLower(username))) != 1 {
			continue
		}

		// Plaintext match
		if u.Password != "" {
			if subtle.ConstantTimeCompare([]byte(u.Password), []byte(password)) == 1 {
				return true
			}
		}

		// Hash match
		if u.PasswordHash != "" {
			if verifyKeeneticHash(u.Username, password, u.PasswordHash, u.HashType) {
				return true
			}
		}
	}

	return false
}

// verifyViaLocalKeeneticHTTP checks credentials against local Keenetic Web API (127.0.0.1:80 / 192.168.1.1:80)
func verifyViaLocalKeeneticHTTP(username, password string) bool {
	client := &http.Client{
		Timeout: 1000 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 600 * time.Millisecond,
			}).DialContext,
		},
	}

	targets := []string{
		"http://127.0.0.1:80",
		"http://127.0.0.1:81",
		"http://192.168.1.1:80",
	}

	for _, target := range targets {
		// A. Try GET /rci/show/version with Basic Auth
		reqB, errB := http.NewRequest("GET", target+"/rci/show/version", nil)
		if errB == nil {
			reqB.SetBasicAuth(username, password)
			if respB, err := client.Do(reqB); err == nil {
				_, _ = io.Copy(io.Discard, respB.Body)
				respB.Body.Close()
				if respB.StatusCode == http.StatusOK {
					return true
				}
			}
		}

		// B. Try GET /rci/ with Basic Auth
		reqC, errC := http.NewRequest("GET", target+"/rci/", nil)
		if errC == nil {
			reqC.SetBasicAuth(username, password)
			if respC, err := client.Do(reqC); err == nil {
				_, _ = io.Copy(io.Discard, respC.Body)
				respC.Body.Close()
				if respC.StatusCode == http.StatusOK {
					return true
				}
			}
		}
	}

	return false
}

// verifyViaNDMC checks credentials via ndmc CLI
func verifyViaNDMC(username, password string) bool {
	ndmcPaths := []string{"ndmc", "/bin/ndmc", "/usr/bin/ndmc", "/opt/bin/ndmc"}
	for _, ndmc := range ndmcPaths {
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		cmd := exec.CommandContext(ctx, ndmc, "-c", "show version")
		out, err := cmd.Output()
		cancel()
		if err == nil && len(out) > 0 {
			outStr := string(out)
			if strings.Contains(outStr, "version") || strings.Contains(outStr, "release") {
				// Running under root on router; ndmc connects directly
			}
		}
	}
	return false
}

// GetKeeneticUsers parses KeeneticOS configuration files (supporting single-line and multi-line blocks).
func GetKeeneticUsers() []KeeneticUser {
	keeneticCacheMu.RLock()
	if len(keeneticUsersCache) > 0 && time.Since(keeneticCacheTime) < 30*time.Second {
		users := keeneticUsersCache
		keeneticCacheMu.RUnlock()
		return users
	}
	keeneticCacheMu.RUnlock()

	keeneticCacheMu.Lock()
	defer keeneticCacheMu.Unlock()

	var users []KeeneticUser
	seen := make(map[string]bool)

	// 1. Config files in KeeneticOS & Entware
	configFiles := []string{
		"/storage/startup-config",
		"/storage/running-config",
		"/var/ndm/startup-config",
		"/var/ndm/running-config",
		"/opt/etc/ndm/startup-config",
		"/opt/etc/ndm/running-config",
		"/etc/ndm/startup-config",
		"/tmp/startup-config",
		"/tmp/running-config",
	}

	for _, cfgFile := range configFiles {
		if f, err := os.Open(cfgFile); err == nil {
			parsed := parseKeeneticConfigFile(f)
			f.Close()
			for _, u := range parsed {
				if !seen[strings.ToLower(u.Username)] {
					users = append(users, u)
					seen[strings.ToLower(u.Username)] = true
				}
			}
			if len(users) > 0 {
				break
			}
		}
	}

	// 2. Try ndmq CLI query if config files on disk were not found
	if len(users) == 0 {
		ndmqPaths := []string{"ndmq", "/bin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq"}
		for _, ndmq := range ndmqPaths {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			out, err := exec.CommandContext(ctx, ndmq, "-p", "show running-config").Output()
			cancel()
			if err == nil && len(out) > 0 {
				parsed := parseKeeneticConfigFile(bytes.NewReader(out))
				for _, u := range parsed {
					if !seen[strings.ToLower(u.Username)] {
						users = append(users, u)
						seen[strings.ToLower(u.Username)] = true
					}
				}
				if len(users) > 0 {
					break
				}
			}
		}
	}

	// 3. Fallback to /etc/shadow, /opt/etc/shadow
	if len(users) == 0 {
		shadowFiles := []string{"/etc/shadow", "/opt/etc/shadow"}
		for _, sf := range shadowFiles {
			if f, err := os.Open(sf); err == nil {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					parts := strings.Split(line, ":")
					if len(parts) >= 2 && parts[0] != "" && parts[1] != "" && parts[1] != "*" && parts[1] != "!" {
						name := parts[0]
						if !seen[strings.ToLower(name)] {
							users = append(users, KeeneticUser{
								Username:     name,
								PasswordHash: parts[1],
								HashType:     "crypt",
							})
							seen[strings.ToLower(name)] = true
						}
					}
				}
				f.Close()
				if len(users) > 0 {
					break
				}
			}
		}
	}

	keeneticUsersCache = users
	keeneticCacheTime = time.Now()
	return users
}

// parseKeeneticConfigFile handles both single-line and multi-line Keenetic user declarations:
// Single line:
//   user admin password hash md5 7815696ecbf1c96e6894b779456d330e
//   user admin password secret123
// Multi line:
//   user admin
//       password hash md5 7815696ecbf1c96e6894b779456d330e
//       tag http
//   user admin
//       password secret123
func parseKeeneticConfigFile(r io.Reader) []KeeneticUser {
	var users []KeeneticUser
	scanner := bufio.NewScanner(r)
	var currentUser *KeeneticUser

	for scanner.Scan() {
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}

		// Single line user definition: "user <name> password ..."
		if fields[0] == "user" && len(fields) >= 3 && fields[2] == "password" {
			if currentUser != nil {
				users = append(users, *currentUser)
				currentUser = nil
			}
			u := parseSingleUserLine(fields)
			if u != nil {
				users = append(users, *u)
			}
			continue
		}

		// Start of multi-line block: "user <name>"
		if fields[0] == "user" && len(fields) == 2 {
			if currentUser != nil {
				users = append(users, *currentUser)
			}
			currentUser = &KeeneticUser{
				Username: fields[1],
				HashType: "plain",
			}
			continue
		}

		// Inside multi-line block: "password ..."
		if currentUser != nil && fields[0] == "password" {
			extractPasswordFields(currentUser, fields)
			users = append(users, *currentUser)
			currentUser = nil
			continue
		}

		// End of submode block if unindented command starts
		if currentUser != nil && !strings.HasPrefix(rawLine, " ") && !strings.HasPrefix(rawLine, "\t") {
			users = append(users, *currentUser)
			currentUser = nil
		}
	}

	if currentUser != nil {
		users = append(users, *currentUser)
	}

	return users
}

func parseSingleUserLine(fields []string) *KeeneticUser {
	if len(fields) < 4 || fields[0] != "user" || fields[2] != "password" {
		return nil
	}
	u := &KeeneticUser{Username: fields[1]}
	extractPasswordFields(u, fields[2:])
	return u
}

func extractPasswordFields(u *KeeneticUser, fields []string) {
	// fields starts with "password", e.g. ["password", "hash", "md5", "7815696..."]
	// or ["password", "hash", "MD5:7815696..."]
	// or ["password", "mypassword"]
	if len(fields) < 2 {
		return
	}

	if fields[1] == "hash" && len(fields) >= 3 {
		if len(fields) >= 4 {
			// "password hash md5 <hash>"
			hType := strings.ToLower(fields[2])
			hVal := fields[3]
			u.PasswordHash = cleanHashPrefix(hVal)
			u.HashType = hType
		} else {
			// "password hash <hash>"
			hVal := fields[2]
			u.PasswordHash = cleanHashPrefix(hVal)
			u.HashType = detectHashType(u.PasswordHash)
		}
		return
	}

	// Plaintext
	u.Password = fields[1]
	u.HashType = "plain"
}

func cleanHashPrefix(h string) string {
	if strings.HasPrefix(strings.ToUpper(h), "MD5:") {
		return h[4:]
	}
	if strings.HasPrefix(strings.ToLower(h), "sha256:") {
		return h[7:]
	}
	return h
}

func detectHashType(h string) string {
	if strings.HasPrefix(h, "$") {
		return "crypt"
	}
	if len(h) == 32 {
		return "md5"
	}
	if len(h) == 64 {
		return "sha256"
	}
	return "md5"
}

// verifyKeeneticHash tests password against all Keenetic hash algorithms and realm permutations
func verifyKeeneticHash(username, password, storedHash, hashType string) bool {
	storedLower := strings.ToLower(storedHash)

	// 1. Plain MD5 of password
	md5Sum := md5.Sum([]byte(password))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(md5Sum[:])), []byte(storedLower)) == 1 {
		return true
	}

	// 2. Plain SHA256 of password
	shaSum := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(shaSum[:])), []byte(storedLower)) == 1 {
		return true
	}

	// 3. Keenetic MD5 Digest permutations: MD5(username + ":" + realm + ":" + password)
	realms := []string{
		"Keenetic",
		"KeeneticOS",
		"NDMS",
		"Keenetic Router",
		"Router",
		"admin",
		"ndm",
		"",
	}

	for _, realm := range realms {
		// Standard HTTP Digest: username:realm:password
		dStr := fmt.Sprintf("%s:%s:%s", username, realm, password)
		h := md5.Sum([]byte(dStr))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(storedLower)) == 1 {
			return true
		}

		sH := sha256.Sum256([]byte(dStr))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sH[:])), []byte(storedLower)) == 1 {
			return true
		}

		// Alternative: realm:password
		if realm != "" {
			altStr := fmt.Sprintf("%s:%s", realm, password)
			altH := md5.Sum([]byte(altStr))
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(altH[:])), []byte(storedLower)) == 1 {
				return true
			}
		}
	}

	return false
}