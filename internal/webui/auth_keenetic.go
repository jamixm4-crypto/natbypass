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
		"/etc/ndm",
	}
	for _, path := range indicators {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	// Check /proc/version or os-release for Keenetic / NDMS
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "keenetic") || strings.Contains(strings.ToLower(string(data)), "ndms") {
			return true
		}
	}
	return false
}

// GetKeeneticUsers parses KeeneticOS configuration and returns discovered users.
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

	// 1. Try reading Keenetic config files
	configFiles := []string{
		"/var/ndm/startup-config",
		"/var/ndm/running-config",
		"/opt/etc/ndm/startup-config",
		"/etc/ndm/startup-config",
		"/opt/etc/ndm/running-config",
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

	// 2. Try ndmq CLI query if config files were unreadable
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

// parseKeeneticUserLine parses lines like:
// "user admin password MyPass123"
// "user admin password hash MD5:c4ca4238a0b923820dcc509a6f75849b"
// "user admin password hash sha256:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
// "user admin password hash $1$..."
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

// VerifyKeeneticAuth checks username and password against KeeneticOS credentials.
func VerifyKeeneticAuth(username, password string) bool {
	users := GetKeeneticUsers()
	if len(users) == 0 {
		// Default fallback if no Keenetic users discovered
		return (username == "admin" && password == "admin")
	}

	for _, u := range users {
		if subtle.ConstantTimeCompare([]byte(u.Username), []byte(username)) != 1 {
			continue
		}

		// 1. Plaintext match
		if u.Password != "" {
			if subtle.ConstantTimeCompare([]byte(u.Password), []byte(password)) == 1 {
				return true
			}
		}

		// 2. Hash match
		if u.PasswordHash != "" {
			if verifyHash(password, u.PasswordHash, u.HashType) {
				return true
			}
		}
	}

	return false
}

func verifyHash(password, storedHash, hashType string) bool {
	storedLower := strings.ToLower(storedHash)

	// MD5 check
	md5Sum := md5.Sum([]byte(password))
	md5Hex := hex.EncodeToString(md5Sum[:])
	if subtle.ConstantTimeCompare([]byte(md5Hex), []byte(storedLower)) == 1 {
		return true
	}

	// SHA256 check
	shaSum := sha256.Sum256([]byte(password))
	shaHex := hex.EncodeToString(shaSum[:])
	if subtle.ConstantTimeCompare([]byte(shaHex), []byte(storedLower)) == 1 {
		return true
	}

	// MD5 Keenetic format: md5(username:realm:password) or md5(password)
	adminRealmMD5 := md5.Sum([]byte(fmt.Sprintf("admin:Keenetic:%s", password)))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(adminRealmMD5[:])), []byte(storedLower)) == 1 {
		return true
	}

	return false
}