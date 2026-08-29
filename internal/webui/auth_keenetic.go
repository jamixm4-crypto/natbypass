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
	keeneticUsersCache    []KeeneticUser
	keeneticCacheMu       sync.RWMutex
	keeneticCacheTime     time.Time
	keeneticHostnameCache string
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

	// 1. Method 1: Official Keenetic RCI Challenge-Response HTTP Authentication
	if verifyKeeneticRCIChallenge(username, password) {
		return true
	}

	// 2. Method 2: Direct local RCI probe with Basic Auth
	if verifyViaLocalKeeneticHTTP(username, password) {
		return true
	}

	// 3. Method 3: Direct Keenetic configuration parser and multi-realm hash verification
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

		// Hash match (MD5/SHA256 with hostname, Keenetic, NDMS realms)
		if u.PasswordHash != "" {
			if verifyKeeneticHash(u.Username, password, u.PasswordHash, u.HashType) {
				return true
			}
		}
	}

	return false
}

// verifyKeeneticRCIChallenge performs official KeeneticOS 2-step challenge-response authentication:
// 1. GET /auth -> reads X-NDM-Challenge and X-NDM-Realm
// 2. Computes SHA256 / MD5 digest with challenge
// 3. POST /auth with {"login": username, "password": challenge_hash} -> 200 OK
func verifyKeeneticRCIChallenge(username, password string) bool {
	client := &http.Client{
		Timeout: 1200 * time.Millisecond,
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
		// Step 1: Request challenge
		req, err := http.NewRequest("GET", target+"/auth", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		challenge := resp.Header.Get("X-NDM-Challenge")
		realm := resp.Header.Get("X-NDM-Realm")
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if challenge == "" {
			// Older KeeneticOS might use /rci/ auth
			continue
		}

		if realm == "" {
			realm = "Keenetic"
		}

		// Try MD5 and SHA256 challenge permutations
		hashesToTest := []string{}

		// A. KeeneticOS standard MD5 challenge:
		// h1 = MD5(username + ":" + realm + ":" + password)
		// auth = SHA256(challenge + hex(h1)) or MD5(challenge + hex(h1)) or SHA256(challenge + password)
		md5h1 := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", username, realm, password)))
		md5h1Hex := hex.EncodeToString(md5h1[:])

		sha256h1 := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", username, realm, password)))
		sha256h1Hex := hex.EncodeToString(sha256h1[:])

		// Challenge hashes:
		c1 := sha256.Sum256([]byte(challenge + md5h1Hex))
		hashesToTest = append(hashesToTest, hex.EncodeToString(c1[:]))

		c2 := sha256.Sum256([]byte(challenge + sha256h1Hex))
		hashesToTest = append(hashesToTest, hex.EncodeToString(c2[:]))

		c3 := md5.Sum([]byte(challenge + md5h1Hex))
		hashesToTest = append(hashesToTest, hex.EncodeToString(c3[:]))

		c4 := sha256.Sum256([]byte(challenge + password))
		hashesToTest = append(hashesToTest, hex.EncodeToString(c4[:]))

		// Plain password
		hashesToTest = append(hashesToTest, password)

		for _, authPass := range hashesToTest {
			payload, _ := json.Marshal(map[string]string{
				"login":    username,
				"password": authPass,
			})
			pReq, pErr := http.NewRequest("POST", target+"/auth", bytes.NewReader(payload))
			if pErr != nil {
				continue
			}
			pReq.Header.Set("Content-Type", "application/json")
			pResp, pErr := client.Do(pReq)
			if pErr == nil {
				_, _ = io.Copy(io.Discard, pResp.Body)
				pResp.Body.Close()
				if pResp.StatusCode == http.StatusOK {
					return true
				}
			}
		}
	}

	return false
}

// verifyViaLocalKeeneticHTTP checks credentials against local Keenetic Web API with Basic Auth
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
		req, err := http.NewRequest("GET", target+"/rci/show/version", nil)
		if err == nil {
			req.SetBasicAuth(username, password)
			if resp, err := client.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return true
				}
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
			parsed, hn := parseKeeneticConfigFile(f)
			f.Close()
			if hn != "" {
				keeneticHostnameCache = hn
			}
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

	// 2. ndmq CLI query
	if len(users) == 0 {
		ndmqPaths := []string{"ndmq", "/bin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq"}
		for _, ndmq := range ndmqPaths {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			out, err := exec.CommandContext(ctx, ndmq, "-p", "show running-config").Output()
			cancel()
			if err == nil && len(out) > 0 {
				parsed, hn := parseKeeneticConfigFile(bytes.NewReader(out))
				if hn != "" {
					keeneticHostnameCache = hn
				}
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

// parseKeeneticConfigFile parses configuration and extracts users and system hostname.
func parseKeeneticConfigFile(r io.Reader) ([]KeeneticUser, string) {
	var users []KeeneticUser
	var hostname string
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

		// Detect system hostname
		if (fields[0] == "system" && len(fields) >= 3 && fields[1] == "hostname") ||
			(fields[0] == "hostname" && len(fields) >= 2) {
			if len(fields) >= 3 && fields[0] == "system" {
				hostname = fields[2]
			} else {
				hostname = fields[1]
			}
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

	return users, hostname
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
	if len(fields) < 2 {
		return
	}

	if fields[1] == "hash" && len(fields) >= 3 {
		if len(fields) >= 4 {
			hType := strings.ToLower(fields[2])
			hVal := fields[3]
			u.PasswordHash = cleanHashPrefix(hVal)
			u.HashType = hType
		} else {
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

	if keeneticHostnameCache != "" {
		realms = append([]string{keeneticHostnameCache}, realms...)
	}
	if hn, err := os.Hostname(); err == nil && hn != "" {
		realms = append([]string{hn}, realms...)
	}

	for _, realm := range realms {
		// A. MD5(username + ":" + realm + ":" + password)
		dStr := fmt.Sprintf("%s:%s:%s", username, realm, password)
		h := md5.Sum([]byte(dStr))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(storedLower)) == 1 {
			return true
		}

		// B. SHA256(username + ":" + realm + ":" + password)
		sH := sha256.Sum256([]byte(dStr))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sH[:])), []byte(storedLower)) == 1 {
			return true
		}

		// C. MD5(realm + ":" + password)
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