// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package webui

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/md4"
)

// KeeneticUser holds user credentials discovered from KeeneticOS.
type KeeneticUser struct {
	Username     string
	Password     string // Plaintext if available
	PasswordHash string // Hash if stored as hash
	HashType     string // "plain", "md5", "sha256", "crypt"
	NTHash       string // NTLM (MD4) hash from "password nt <hash>"
}

var (
	keeneticUsersCache    []KeeneticUser
	keeneticCacheMu       sync.RWMutex
	keeneticCacheTime     time.Time
	keeneticHostnameCache string
	keeneticModelCache    string
	keeneticRealmHttp     string
)

// IsKeeneticOS returns true if running on a genuine Keenetic router.
func IsKeeneticOS() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// Keenetic routers run solely on MIPS, MIPSEL, ARM, or ARM64 architectures (never x86 / amd64 / 386).
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
		return false
	}

	// 1. Check for Keenetic native CLI management binaries
	for _, p := range []string{"/bin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq", "/bin/ndmc", "/usr/bin/ndmc", "/opt/bin/ndmc"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return true
		}
	}

	// 2. Check for KeeneticOS firmware version descriptor
	for _, f := range []string{"/etc/ndm/version", "/var/ndm/version"} {
		if fi, err := os.Stat(f); err == nil && !fi.IsDir() {
			return true
		}
	}

	// 3. Check /proc/version for Keenetic / NDMS kernel signature
	if data, err := os.ReadFile("/proc/version"); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "keenetic") || strings.Contains(lower, "ndms") || strings.Contains(lower, "(root@ndm)") {
			return true
		}
	}

	// 4. Check /etc/os-release for KeeneticOS distribution ID
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "keenetic") || strings.Contains(lower, "id=ndms") || strings.Contains(lower, "id=\"ndms\"") {
			return true
		}
	}

	return false
}

// computeNTLMHash calculates the Windows NT (NTLM / MD4) hash of a password encoded in UTF-16LE.
// KeeneticOS stores this hash for every user as "password nt <hex_hash>".
func computeNTLMHash(password string) string {
	runes := []rune(password)
	utf16Bytes := make([]byte, len(runes)*2)
	for i, r := range runes {
		utf16Bytes[i*2] = byte(r)
		utf16Bytes[i*2+1] = byte(r >> 8)
	}
	h := md4.New()
	h.Write(utf16Bytes)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyKeeneticAuth strictly checks username and password against KeeneticOS credentials.
func VerifyKeeneticAuth(username, password string) bool {
	if username == "" || password == "" {
		return false
	}

	// 1. Method 1: Check offline config hashes first (instant 0ms response)
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

		// NTLM (MD4) match from "password nt <hash>" — standard in KeeneticOS
		if u.NTHash != "" {
			ntlm := computeNTLMHash(password)
			if subtle.ConstantTimeCompare([]byte(strings.ToLower(ntlm)), []byte(strings.ToLower(u.NTHash))) == 1 {
				return true
			}
		}

		// Hash match (MD5/SHA256 with model, hostname, Keenetic, NDMS realms)
		if u.PasswordHash != "" {
			if verifyKeeneticHash(u.Username, password, u.PasswordHash, u.HashType) {
				return true
			}
		}
	}

	// 2. Method 2: Official Keenetic RCI Challenge-Response HTTP Authentication with CookieJar
	if verifyKeeneticRCIChallenge(username, password) {
		return true
	}

	// 3. Method 3: Direct local RCI Basic Auth
	if verifyViaLocalKeeneticHTTP(username, password) {
		return true
	}

	return false
}

// getKeeneticProbeTargets dynamically gathers local IP addresses and ports to probe Keenetic web services
func getKeeneticProbeTargets() []string {
	targets := []string{
		"http://127.0.0.1:80",
		"https://127.0.0.1:443",
		"http://192.168.1.1:80",
		"https://192.168.1.1:443",
		"http://192.168.0.1:80",
		"https://192.168.0.1:443",
	}

	seen := map[string]bool{
		"http://127.0.0.1:80":     true,
		"https://127.0.0.1:443":   true,
		"http://192.168.1.1:80":   true,
		"https://192.168.1.1:443": true,
		"http://192.168.0.1:80":   true,
		"https://192.168.0.1:443": true,
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, i := range ifaces {
			nameLower := strings.ToLower(i.Name)
			// Skip VPN, mesh, cellular PPP, docker, or wireguard interfaces
			if strings.Contains(nameLower, "tun") || strings.Contains(nameLower, "wg") ||
				strings.Contains(nameLower, "awg") || strings.Contains(nameLower, "ppp") ||
				strings.Contains(nameLower, "docker") {
				continue
			}

			addrs, err := i.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() || ip.To4() == nil {
					continue
				}
				// Strictly RFC 1918 private LAN addresses
				if !ip.IsPrivate() {
					continue
				}
				// Skip NatBypass VIP subnets (10.1.x.x, 100.64.x.x)
				if (ip[0] == 10 && ip[1] == 1) || (ip[0] == 100 && (ip[1]&0xC0) == 64) {
					continue
				}

				ipStr := ip.String()
				u1 := "http://" + ipStr + ":80"
				u2 := "https://" + ipStr + ":443"
				if !seen[u1] {
					seen[u1] = true
					// Prioritize router LAN bridge br0
					if strings.Contains(nameLower, "br") || strings.Contains(nameLower, "lan") {
						targets = append([]string{u1, u2}, targets...)
					} else {
						targets = append(targets, u1, u2)
					}
				}
			}
		}
	}
	return targets
}

// verifyKeeneticRCIChallenge performs the official KeeneticOS 2-step challenge-response authentication:
// 1. GET /auth -> reads X-NDM-Challenge and X-NDM-Realm, storing session cookies
// 2. Computes:
//      md5_hash = md5(username + ":" + realm + ":" + password)
//      auth_hash = sha256(challenge + hex(md5_hash))
// 3. POST /auth with {"login": username, "password": auth_hash} -> 200 OK
func verifyKeeneticRCIChallenge(username, password string) bool {
	targets := getKeeneticProbeTargets()

	var wg sync.WaitGroup
	var authSuccess int32

	for _, target := range targets {
		wg.Add(1)
		go func(tgt string) {
			defer wg.Done()
			if atomic.LoadInt32(&authSuccess) == 1 {
				return
			}

			jar, _ := cookiejar.New(nil)
			client := &http.Client{
				Jar:     jar,
				Timeout: 1500 * time.Millisecond,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					DialContext: (&net.Dialer{
						Timeout: 800 * time.Millisecond,
					}).DialContext,
				},
			}

			// Step 1: Request challenge
			req, err := http.NewRequest("GET", tgt+"/auth", nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}

			// Handle HTTP to HTTPS redirect on /auth
			if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound ||
				resp.StatusCode == http.StatusTemporaryRedirect {
				loc := resp.Header.Get("Location")
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if loc != "" {
					if strings.HasPrefix(loc, "/") {
						loc = tgt + loc
					}
					reqRedir, rErr := http.NewRequest("GET", loc, nil)
					if rErr == nil {
						resp, err = client.Do(reqRedir)
						if err != nil {
							return
						}
					}
				}
			}

			challenge := resp.Header.Get("X-NDM-Challenge")
			realm := resp.Header.Get("X-NDM-Realm")
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if challenge == "" {
				return
			}

			if realm != "" {
				keeneticCacheMu.Lock()
				keeneticRealmHttp = realm
				keeneticCacheMu.Unlock()
			}

			realmsToTry := []string{}
			if realm != "" {
				// Exact realm returned directly by router /auth endpoint
				realmsToTry = append(realmsToTry, realm)
			} else {
				realmsToTry = append(realmsToTry, "Keenetic", "KeeneticOS")
				if keeneticHostnameCache != "" {
					realmsToTry = append(realmsToTry, keeneticHostnameCache)
				}
				if keeneticModelCache != "" {
					realmsToTry = append(realmsToTry, keeneticModelCache)
				}
			}

			for _, r := range realmsToTry {
				if atomic.LoadInt32(&authSuccess) == 1 {
					return
				}

				// Official Keenetic RCI:
				// 1. md5_hash = hex(md5(username:realm:password))
				// 2. auth_hash = hex(sha256(challenge + md5_hash))
				md5Raw := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", username, r, password)))
				md5Hex := hex.EncodeToString(md5Raw[:])

				sha256Raw := sha256.Sum256([]byte(challenge + md5Hex))
				sha256Hex := hex.EncodeToString(sha256Raw[:])

				payload, _ := json.Marshal(map[string]string{
					"login":    username,
					"password": sha256Hex,
				})

				pReq, pErr := http.NewRequest("POST", tgt+"/auth", bytes.NewReader(payload))
				if pErr != nil {
					continue
				}
				pReq.Header.Set("Content-Type", "application/json; charset=utf-8")
				pResp, pErr := client.Do(pReq)
				if pErr == nil {
					_, _ = io.Copy(io.Discard, pResp.Body)
					pResp.Body.Close()
					if pResp.StatusCode >= 200 && pResp.StatusCode < 300 {
						atomic.StoreInt32(&authSuccess, 1)
						return
					}
				}

				if atomic.LoadInt32(&authSuccess) == 1 {
					return
				}

				// Alternative: SHA256 of login:realm:password
				sha256P := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", username, r, password)))
				sha256PHex := hex.EncodeToString(sha256P[:])
				cSha := sha256.Sum256([]byte(challenge + sha256PHex))
				cShaHex := hex.EncodeToString(cSha[:])

				payload2, _ := json.Marshal(map[string]string{
					"login":    username,
					"password": cShaHex,
				})
				pReq2, pErr2 := http.NewRequest("POST", tgt+"/auth", bytes.NewReader(payload2))
				if pErr2 == nil {
					pReq2.Header.Set("Content-Type", "application/json; charset=utf-8")
					pResp2, pErr2 := client.Do(pReq2)
					if pErr2 == nil {
						_, _ = io.Copy(io.Discard, pResp2.Body)
						pResp2.Body.Close()
						if pResp2.StatusCode >= 200 && pResp2.StatusCode < 300 {
							atomic.StoreInt32(&authSuccess, 1)
							return
						}
					}
				}
			}
		}(target)
	}

	wg.Wait()
	return atomic.LoadInt32(&authSuccess) == 1
}

// verifyViaLocalKeeneticHTTP checks credentials against local Keenetic Web API with Basic Auth
func verifyViaLocalKeeneticHTTP(username, password string) bool {
	client := &http.Client{
		Timeout: 1000 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 600 * time.Millisecond,
			}).DialContext,
		},
	}

	targets := getKeeneticProbeTargets()
	var wg sync.WaitGroup
	var success int32

	for _, target := range targets {
		wg.Add(1)
		go func(tgt string) {
			defer wg.Done()
			if atomic.LoadInt32(&success) == 1 {
				return
			}
			req, err := http.NewRequest("GET", tgt+"/rci/show/version", nil)
			if err == nil {
				req.SetBasicAuth(username, password)
				if resp, err := client.Do(req); err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						atomic.StoreInt32(&success, 1)
					}
				}
			}
		}(target)
	}
	wg.Wait()
	return atomic.LoadInt32(&success) == 1
}

// GetKeeneticUsers parses KeeneticOS configuration files and returns discovered users.
func GetKeeneticUsers() []KeeneticUser {
	keeneticCacheMu.RLock()
	if len(keeneticUsersCache) > 0 && time.Since(keeneticCacheTime) < 5*time.Minute {
		users := make([]KeeneticUser, len(keeneticUsersCache))
		copy(users, keeneticUsersCache)
		keeneticCacheMu.RUnlock()
		return users
	}
	keeneticCacheMu.RUnlock()

	keeneticCacheMu.Lock()
	defer keeneticCacheMu.Unlock()

	// Load model if not cached
	if keeneticModelCache == "" {
		for _, mf := range []string{"/tmp/sysinfo/model", "/proc/device-tree/model", "/etc/openwrt_release"} {
			if data, err := os.ReadFile(mf); err == nil {
				keeneticModelCache = strings.TrimSpace(string(data))
				break
			}
		}
	}

	var users []KeeneticUser
	seen := make(map[string]bool)

	// KeeneticOS stores active configuration in startup-config.draft, startup-config, or startup-config.txt
	configFiles := []string{
		"/storage/startup-config.draft",
		"/storage/startup-config",
		"/storage/startup-config.txt",
		"/storage/running-config",
		"/opt/etc/ndm/startup-config.draft",
		"/opt/etc/ndm/startup-config",
		"/opt/etc/ndm/running-config",
		"/var/ndm/startup-config.draft",
		"/var/ndm/startup-config",
		"/var/ndm/running-config",
		"/flash/startup-config.draft",
		"/flash/startup-config",
		"/etc/ndm/startup-config.draft",
		"/etc/ndm/startup-config",
		"/tmp/startup-config.draft",
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

	// 2. ndmc CLI query (official Keenetic CLI command runner)
	if len(users) == 0 {
		for _, ndmc := range []string{"/bin/ndmc", "/usr/bin/ndmc", "/opt/bin/ndmc", "ndmc"} {
			var cmdPath string
			if ndmc == "ndmc" {
				if lp, err := exec.LookPath(ndmc); err == nil {
					cmdPath = lp
				}
			} else if fi, err := os.Stat(ndmc); err == nil && !fi.IsDir() {
				cmdPath = ndmc
			}
			if cmdPath != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
				cmd := exec.CommandContext(ctx, cmdPath, "-c", "show running-config")
				cmd.Stdin = bytes.NewReader(nil)
				out, err := cmd.Output()
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
				}
				if len(users) > 0 {
					break
				}
			}
		}
	}

	// 3. ndmq CLI query (official Keenetic low-level IPC tool)
	if len(users) == 0 {
		var resolvedNdmq string
		for _, p := range []string{"/bin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq", "ndmq"} {
			if p == "ndmq" {
				if lp, err := exec.LookPath(p); err == nil {
					resolvedNdmq = lp
					break
				}
			} else if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				resolvedNdmq = p
				break
			}
		}

		if resolvedNdmq != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
			cmd := exec.CommandContext(ctx, resolvedNdmq, "-p", "show running-config")
			cmd.Stdin = bytes.NewReader(nil)
			out, err := cmd.Output()
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
			}
		}
	}

	// 4. Fallback to /etc/shadow, /opt/etc/shadow, /etc/passwd
	if len(users) == 0 {
		shadowFiles := []string{"/etc/shadow", "/opt/etc/shadow", "/etc/passwd", "/opt/etc/passwd"}
		for _, sf := range shadowFiles {
			if f, err := os.Open(sf); err == nil {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					parts := strings.Split(line, ":")
					if len(parts) >= 2 && parts[0] != "" && parts[1] != "" && parts[1] != "*" && parts[1] != "!" && parts[1] != "x" {
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

	flushCurrentUser := func() {
		if currentUser != nil {
			if currentUser.Password != "" || currentUser.PasswordHash != "" || currentUser.NTHash != "" {
				users = append(users, *currentUser)
			}
			currentUser = nil
		}
	}

	for scanner.Scan() {
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)

		// Check for router model in comments (e.g. "! $$$ Model: Keenetic Titan (KN-1810)" or "! Model: Keenetic Giga")
		if strings.HasPrefix(trimmed, "!") {
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "model:") {
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) == 2 {
					mName := strings.TrimSpace(parts[1])
					if mName != "" {
						keeneticCacheMu.Lock()
						keeneticModelCache = mName
						keeneticCacheMu.Unlock()
					}
				}
			}
			continue
		}

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
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
		if fields[0] == "user" && len(fields) >= 3 && (fields[2] == "password" || fields[2] == "md5" || fields[2] == "nt" || fields[2] == "sha256" || fields[2] == "sha" || fields[2] == "encrypted") {
			flushCurrentUser()
			u := parseSingleUserLine(fields)
			if u != nil {
				users = append(users, *u)
			}
			continue
		}

		// Start of multi-line user block: "user <name>"
		if fields[0] == "user" && len(fields) == 2 {
			flushCurrentUser()
			currentUser = &KeeneticUser{
				Username: fields[1],
				HashType: "plain",
			}
			continue
		}

		// Inside multi-line user block: indented lines with "password ...", "password nt ...", "password md5 ...", "password sha256 ..."
		if currentUser != nil && (fields[0] == "password" || fields[0] == "md5" || fields[0] == "nt" || fields[0] == "sha256" || fields[0] == "sha" || fields[0] == "encrypted") {
			extractPasswordFields(currentUser, fields)
			continue
		}

		// Other indented user attributes (tag http, tag cli, etc.): keep currentUser open
		if currentUser != nil && (strings.HasPrefix(rawLine, " ") || strings.HasPrefix(rawLine, "\t")) {
			continue
		}

		// End of submode block if unindented command starts
		if currentUser != nil && !strings.HasPrefix(rawLine, " ") && !strings.HasPrefix(rawLine, "\t") {
			flushCurrentUser()
		}
	}

	flushCurrentUser()

	return users, hostname
}

func parseSingleUserLine(fields []string) *KeeneticUser {
	if len(fields) < 3 || fields[0] != "user" {
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

	// formats:
	// ["password", "nt", "7921563a..."] -> NTLM hash
	// ["nt", "7921563a..."]
	// ["password", "md5", "7815696..."]
	// ["md5", "7815696..."]
	// ["password", "hash", "md5", "7815696..."]
	// ["password", "hash", "sha256", "8c69..."]
	// ["password", "mypassword"]

	if fields[0] == "nt" {
		u.NTHash = cleanHashPrefix(fields[1])
		return
	}

	if fields[1] == "nt" && len(fields) >= 3 {
		u.NTHash = cleanHashPrefix(fields[2])
		return
	}

	if fields[0] == "md5" {
		u.PasswordHash = cleanHashPrefix(fields[1])
		u.HashType = "md5"
		return
	}

	if fields[1] == "md5" && len(fields) >= 3 {
		u.PasswordHash = cleanHashPrefix(fields[2])
		u.HashType = "md5"
		return
	}

	if fields[0] == "sha256" || fields[0] == "sha" {
		u.PasswordHash = cleanHashPrefix(fields[1])
		u.HashType = "sha256"
		return
	}

	if (fields[1] == "sha256" || fields[1] == "sha") && len(fields) >= 3 {
		u.PasswordHash = cleanHashPrefix(fields[2])
		u.HashType = "sha256"
		return
	}

	if fields[0] == "encrypted" || fields[1] == "encrypted" {
		targetVal := fields[1]
		if fields[1] == "encrypted" && len(fields) >= 3 {
			targetVal = fields[2]
		}
		u.PasswordHash = cleanHashPrefix(targetVal)
		u.HashType = detectHashType(u.PasswordHash)
		return
	}

	if fields[1] == "hash" && len(fields) >= 3 {
		if len(fields) >= 4 {
			hType := strings.ToLower(fields[2])
			hVal := fields[3]
			if hType == "nt" {
				u.NTHash = cleanHashPrefix(hVal)
			} else {
				u.PasswordHash = cleanHashPrefix(hVal)
				u.HashType = hType
			}
		} else {
			hVal := fields[2]
			u.PasswordHash = cleanHashPrefix(hVal)
			u.HashType = detectHashType(u.PasswordHash)
		}
		return
	}

	// Auto-detect hex hashes and crypt hashes before assuming plaintext
	cleaned := cleanHashPrefix(fields[1])
	if len(cleaned) == 64 && isHexString(cleaned) {
		u.PasswordHash = cleaned
		u.HashType = "sha256"
		return
	}
	if len(cleaned) == 32 && isHexString(cleaned) {
		u.PasswordHash = cleaned
		u.HashType = "md5"
		return
	}
	if strings.HasPrefix(cleaned, "$") {
		u.PasswordHash = cleaned
		u.HashType = "crypt"
		return
	}

	// Plaintext
	u.Password = fields[1]
	u.HashType = "plain"
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func cleanHashPrefix(h string) string {
	h = strings.Trim(h, "\"'")
	if strings.HasPrefix(strings.ToUpper(h), "MD5:") {
		return h[4:]
	}
	if strings.HasPrefix(strings.ToLower(h), "sha256:") {
		return h[7:]
	}
	if strings.HasPrefix(strings.ToLower(h), "nt:") {
		return h[3:]
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
	storedLower := strings.ToLower(strings.Trim(storedHash, "\"'"))

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
		"Router",
		"admin",
		"ndm",
		"",
	}

	keeneticCacheMu.RLock()
	cachedRealm := keeneticRealmHttp
	cachedModel := keeneticModelCache
	keeneticCacheMu.RUnlock()
	if cachedRealm != "" {
		realms = append([]string{cachedRealm}, realms...)
	}
	if cachedModel != "" {
		// e.g. "Keenetic Titan (KN-1810)", "Keenetic Titan", "Titan"
		realms = append([]string{cachedModel}, realms...)
		trimmed := strings.TrimPrefix(cachedModel, "Keenetic ")
		realms = append(realms, trimmed)
		if idx := strings.Index(cachedModel, "("); idx > 0 {
			base := strings.TrimSpace(cachedModel[:idx])
			realms = append(realms, base, strings.TrimPrefix(base, "Keenetic "))
		}
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