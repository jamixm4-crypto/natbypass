package webui

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
)

// IsKeeneticOS returns true if running on a Keenetic router.
func IsKeeneticOS() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// Check Keenetic indicators
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
	}
	for _, path := range indicators {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	// Check /proc/version or os-release for Keenetic / NDMS
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

	// 1. Method 1: Local Keenetic Web/RCI API probe (most accurate & real-time)
	if verifyViaLocalKeeneticHTTP(username, password) {
		return true
	}

	// 2. Method 2: ndmc CLI authentication check
	if verifyViaNDMC(username, password) {
		return true
	}

	// 3. Method 3: Direct config and shadow files hash matching
	users := GetKeeneticUsers()
	for _, u := range users {
		if subtle.ConstantTimeCompare([]byte(u.Username), []byte(username)) != 1 {
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
			if verifyKeeneticHash(username, password, u.PasswordHash, u.HashType) {
				return true
			}
		}
	}

	return false
}

// verifyViaLocalKeeneticHTTP checks credentials against local Keenetic Web API (127.0.0.1:80 / 127.0.0.1:443 / 192.168.1.1:80)
func verifyViaLocalKeeneticHTTP(username, password string) bool {
	client := &http.Client{
		Timeout: 1200 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 800 * time.Millisecond,
			}).DialContext,
		},
	}

	// Check endpoints where Keenetic web services respond
	targets := []string{
		"http://127.0.0.1:80",
		"http://127.0.0.1:81",
		"http://127.0.0.1:8080",
		"http://192.168.1.1:80",
	}

	for _, target := range targets {
		// A. Try POST /auth with JSON payload
		authPayload, _ := json.Marshal(map[string]string{
			"login":    username,
			"password": password,
		})
		req, err := http.NewRequest("POST", target+"/auth", bytes.NewReader(authPayload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			if resp, err := client.Do(req); err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return true
				}
			}
		}

		// B. Try GET /rci/show/version with Basic Auth
		reqB, errB := http.NewRequest("GET", target+"/rci/show/version", nil)
		if errB == nil {
			reqB.SetBasicAuth(username, password)
			if respB, err := client.Do(reqB); err == nil {
				_ = respB.Body.Close()
				if respB.StatusCode == http.StatusOK {
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
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		cmd := exec.CommandContext(ctx, ndmc, "-u", username, "-p", password, "-c", "show version")
		out, err := cmd.Output()
		cancel()
		if err == nil && len(out) > 0 {
			outStr := string(out)
			if !strings.Contains(outStr, "Authentication failed") &&
				!strings.Contains(outStr, "Access denied") &&
				!strings.Contains(outStr, "error") {
				return true
			}
		}
	}
	return false
}

// GetKeeneticUsers parses KeeneticOS configuration files and returns discovered users.
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
		"/var/ndm/startup-config",
		"/var/ndm/running-config",
		"/opt/etc/ndm/startup-config",
		"/etc/ndm/startup-config",
		"/opt/etc/ndm/running-config",
		"/tmp/startup-config",
	}

	for _, cfgFile := range configFiles {
		if f, err := os.Open(cfgFile); err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if u := parseKeeneticUserLine(line); u != nil && !seen[u.Username] {
					users = append(users, *u)
					seen[u.Username] = true
				}
			}
			f.Close()
			if len(users) > 0 {
				break
			}
		}
	}

	// 2. ndmq CLI query
	if len(users) == 0 {
		ndmqPaths := []string{"ndmq", "/bin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq"}
		for _, ndmq := range ndmqPaths {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			out, err := exec.CommandContext(ctx, ndmq, "-p", "show running-config").Output()
			cancel()
			if err == nil && len(out) > 0 {
				scanner := bufio.NewScanner(bytes.NewReader(out))
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if u := parseKeeneticUserLine(line); u != nil && !seen[u.Username] {
						users = append(users, *u)
						seen[u.Username] = true
					}
				}
				if len(users) > 0 {
					break
				}
			}
		}
	}

	// 3. Fallback to /etc/shadow or /opt/etc/shadow
	if len(users) == 0 {
		shadowFiles := []string{"/etc/shadow", "/opt/etc/shadow"}
		for _, sf := range shadowFiles {
			if f, err := os.Open(sf); err == nil {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					parts := strings.Split(line, ":")
					if len(parts) >= 2 && parts[0] != "" && parts[1] != "" && parts[1] != "*" && parts[1] != "!" {
						users = append(users, KeeneticUser{
							Username:     parts[0],
							PasswordHash: parts[1],
							HashType:     "crypt",
						})
						seen[parts[0]] = true
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

// parseKeeneticUserLine parses user lines in Keenetic startup-config
func parseKeeneticUserLine(line string) *KeeneticUser {
	if !strings.HasPrefix(line, "user ") {
		return nil
	}
	parts := strings.Fields(line)
	if len(parts) < 4 || parts[2] != "password" {
		return nil
	}

	username := parts[1]
	if parts[3] == "hash" && len(parts) >= 5 {
		hashVal := parts[4]
		hashType := "unknown"
		if strings.HasPrefix(strings.ToUpper(hashVal), "MD5:") {
			hashType = "md5"
			hashVal = hashVal[4:]
		} else if strings.HasPrefix(strings.ToLower(hashVal), "sha256:") {
			hashType = "sha256"
			hashVal = hashVal[7:]
		} else if strings.HasPrefix(hashVal, "$") {
			hashType = "crypt"
		} else if len(hashVal) == 32 {
			hashType = "md5"
		} else if len(hashVal) == 64 {
			hashType = "sha256"
		}
		return &KeeneticUser{
			Username:     username,
			PasswordHash: hashVal,
			HashType:     hashType,
		}
	}

	// Plain text password
	return &KeeneticUser{
		Username: username,
		Password: parts[3],
		HashType: "plain",
	}
}

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

	// 3. Keenetic Digest formats: md5(username:realm:password)
	realms := []string{"Keenetic", "KeeneticOS", "NDMS", "Keenetic Router", "Router", "admin", ""}
	for _, realm := range realms {
		dStr := fmt.Sprintf("%s:%s:%s", username, realm, password)
		h := md5.Sum([]byte(dStr))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(storedLower)) == 1 {
			return true
		}

		sH := sha256.Sum256([]byte(dStr))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sH[:])), []byte(storedLower)) == 1 {
			return true
		}
	}

	return false
}