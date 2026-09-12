// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package webui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type loginAttemptInfo struct {
	count        int
	firstAttempt time.Time
	blockedUntil time.Time
}

var (
	sessionStore    = make(map[string]SessionEntry)
	sessionStoreMu  sync.RWMutex
	sessionFilePath = getSessionStoragePath()

	loginLimiterMu sync.Mutex
	loginAttempts  = make(map[string]*loginAttemptInfo)
)

type SessionEntry struct {
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func checkLoginRateLimit(ip string) (bool, time.Duration) {
	loginLimiterMu.Lock()
	defer loginLimiterMu.Unlock()

	now := time.Now()
	info, exists := loginAttempts[ip]
	if !exists {
		return true, 0
	}

	if now.Before(info.blockedUntil) {
		return false, info.blockedUntil.Sub(now)
	}

	if now.Sub(info.firstAttempt) > time.Minute {
		delete(loginAttempts, ip)
		return true, 0
	}

	if info.count >= 5 {
		info.blockedUntil = now.Add(30 * time.Second)
		return false, 30 * time.Second
	}

	return true, 0
}

func recordFailedLogin(ip string) {
	loginLimiterMu.Lock()
	defer loginLimiterMu.Unlock()

	now := time.Now()
	info, exists := loginAttempts[ip]
	if !exists || now.Sub(info.firstAttempt) > time.Minute {
		loginAttempts[ip] = &loginAttemptInfo{
			count:        1,
			firstAttempt: now,
		}
		return
	}

	info.count++
	if info.count >= 5 {
		info.blockedUntil = now.Add(30 * time.Second)
	}
}

func resetLoginRateLimit(ip string) {
	loginLimiterMu.Lock()
	defer loginLimiterMu.Unlock()
	delete(loginAttempts, ip)
}

func getSessionStoragePath() string {
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/opt/var/run"); err == nil {
			return "/opt/var/run/.natbypass_sessions.json"
		}
		// Предпочитаем изолированные системные директории с правами 0700 вместо /tmp
		for _, dir := range []string{"/var/run/natbypass", "/var/lib/natbypass", "/etc/natbypass"} {
			if _, err := os.Stat(dir); err == nil {
				return filepath.Join(dir, ".natbypass_sessions.json")
			}
			if err := os.MkdirAll(dir, 0700); err == nil {
				return filepath.Join(dir, ".natbypass_sessions.json")
			}
		}
		if _, err := os.Stat("/tmp"); err == nil {
			return "/tmp/.natbypass_sessions.json"
		}
	}
	return ".sessions.json"
}

func init() {
	loadSessionsFromDisk()
}

func loadSessionsFromDisk() {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()
	if data, err := os.ReadFile(sessionFilePath); err == nil {
		var loaded map[string]SessionEntry
		if err := json.Unmarshal(data, &loaded); err == nil && loaded != nil {
			now := time.Now()
			for k, v := range loaded {
				if now.Before(v.ExpiresAt) {
					sessionStore[k] = v
				}
			}
		}
	}
}

func saveSessionsToDisk() {
	sessionStoreMu.RLock()
	defer sessionStoreMu.RUnlock()
	if data, err := json.Marshal(sessionStore); err == nil {
		_ = os.WriteFile(sessionFilePath, data, 0600)
	}
}

func generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		h := sha256.Sum256([]byte(fmt.Sprintf("fallback-session-%d", time.Now().UnixNano())))
		copy(b, h[:])
	}
	return hex.EncodeToString(b)
}

func createSession(username string) string {
	token := generateSessionToken()
	sessionStoreMu.Lock()
	sessionStore[token] = SessionEntry{
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
	}
	sessionStoreMu.Unlock()
	saveSessionsToDisk()
	return token
}

func deleteSession(token string) {
	sessionStoreMu.Lock()
	delete(sessionStore, token)
	sessionStoreMu.Unlock()
	saveSessionsToDisk()
}

func isValidSession(token string) bool {
	if token == "" {
		return false
	}
	sessionStoreMu.RLock()
	defer sessionStoreMu.RUnlock()
	s, ok := sessionStore[token]
	if !ok {
		return false
	}
	if time.Now().After(s.ExpiresAt) {
		return false
	}
	return true
}

func getSessionUsername(token string) string {
	sessionStoreMu.RLock()
	defer sessionStoreMu.RUnlock()
	if s, ok := sessionStore[token]; ok {
		return s.Username
	}
	return "admin"
}

func (s *Server) checkCredentials(username, password string) bool {
	if username == "" || password == "" {
		return false
	}

	// 1. Configured static credentials (from config.yaml)
	if s.user != "" && s.password != "" {
		uMatch := subtle.ConstantTimeCompare([]byte(s.user), []byte(username)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(s.password), []byte(password)) == 1
		if uMatch && pMatch {
			return true
		}
	}

	// 2. KeeneticOS: STRICTLY check router system credentials, ZERO fallback to admin/admin
	if IsKeeneticOS() {
		if s.customAuth != nil && s.customAuth(username, password) {
			return true
		}
		return VerifyKeeneticAuth(username, password)
	}

	// 3. Custom external authenticator if provided
	if s.customAuth != nil && s.customAuth(username, password) {
		return true
	}

	// 4. Default fallback when no custom password set in config: admin / admin
	if (s.user == "" || s.user == "admin") && (s.password == "" || s.password == "admin") {
		if subtle.ConstantTimeCompare([]byte(username), []byte("admin")) == 1 &&
			subtle.ConstantTimeCompare([]byte(password), []byte("admin")) == 1 {
			return true
		}
	}

	return false
}

// handleLogin — POST /api/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, nil, "неверный формат запроса")
		return
	}

	clientIP, _, ipErr := net.SplitHostPort(r.RemoteAddr)
	if ipErr != nil {
		clientIP = r.RemoteAddr
	}
	clientIP = strings.TrimSpace(clientIP)

	allowed, waitDur := checkLoginRateLimit(clientIP)
	if !allowed {
		s.jsonResponse(w, http.StatusTooManyRequests, nil, fmt.Sprintf("Слишком много неудачных попыток входа. Повторите попытку через %d сек.", int(waitDur.Seconds())+1))
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if !s.checkCredentials(req.Username, req.Password) {
		recordFailedLogin(clientIP)
		time.Sleep(300 * time.Millisecond) // Защита от timing attacks и замедление брутфорса
		if IsKeeneticOS() {
			s.jsonResponse(w, http.StatusUnauthorized, nil, "Неверный логин или пароль. Введите учетные данные администратора вашего роутера Keenetic.")
		} else {
			s.jsonResponse(w, http.StatusUnauthorized, nil, "Неверный логин или пароль.")
		}
		return
	}

	resetLoginRateLimit(clientIP)


	token := createSession(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "nb_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"username": req.Username,
		"token":    token,
	}, "")
}

// handleLogout — POST /api/auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("nb_session")
	if err == nil && cookie != nil {
		sessionStoreMu.Lock()
		delete(sessionStore, cookie.Value)
		sessionStoreMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "nb_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})

	s.jsonResponse(w, http.StatusOK, map[string]bool{"ok": true}, "")
}

// handleAuthCheck — GET /api/auth/check
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	isWindows := (runtime.GOOS == "windows")
	var authRequired bool
	if isWindows {
		authRequired = (s.password != "" || s.customAuth != nil)
	} else {
		authRequired = (s.password != "" || s.customAuth != nil || IsKeeneticOS())
	}
	
	// Check session cookie
	if cookie, err := r.Cookie("nb_session"); err == nil && isValidSession(cookie.Value) {
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"authenticated": true,
			"auth_required": authRequired,
			"username":      getSessionUsername(cookie.Value),
			"is_keenetic":   IsKeeneticOS(),
			"is_windows":    isWindows,
			"os":            runtime.GOOS,
		}, "")
		return
	}

	// Check Basic Auth
	if user, pass, ok := r.BasicAuth(); ok && s.checkCredentials(user, pass) {
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"authenticated": true,
			"auth_required": authRequired,
			"username":      user,
			"is_keenetic":   IsKeeneticOS(),
			"is_windows":    isWindows,
			"os":            runtime.GOOS,
		}, "")
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"authenticated": !authRequired,
		"auth_required": authRequired,
		"is_keenetic":   IsKeeneticOS(),
			"is_windows":    isWindows,
			"os":            runtime.GOOS,
	}, "")
}