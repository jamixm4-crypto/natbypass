package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)



var (
	sessionStore   = make(map[string]SessionEntry)
	sessionStoreMu sync.RWMutex
	sessionFilePath = getSessionStoragePath()
)

type SessionEntry struct {
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func getSessionStoragePath() string {
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/opt/var/run"); err == nil {
			return "/opt/var/run/.natbypass_sessions.json"
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
	_, _ = rand.Read(b)
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

	// 4. Default fallback on non-router systems (Linux/Windows generic admin/admin)
	if (username == "admin" || username == "root") && (password == "admin" || password == "admin123") {
		return true
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

	req.Username = strings.TrimSpace(req.Username)
	if !s.checkCredentials(req.Username, req.Password) {
		if IsKeeneticOS() {
			s.jsonResponse(w, http.StatusUnauthorized, nil, "Неверный логин или пароль. Введите учетные данные администратора вашего роутера Keenetic.")
		} else {
			s.jsonResponse(w, http.StatusUnauthorized, nil, "Неверный логин или пароль.")
		}
		return
	}


	token := createSession(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "nb_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		HttpOnly: false,
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
		HttpOnly: false,
	})

	s.jsonResponse(w, http.StatusOK, map[string]bool{"ok": true}, "")
}

// handleAuthCheck — GET /api/auth/check
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	authRequired := (s.password != "" || s.customAuth != nil || IsKeeneticOS() || runtime.GOOS != "windows")
	
	// Check session cookie
	if cookie, err := r.Cookie("nb_session"); err == nil && isValidSession(cookie.Value) {
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"authenticated": true,
			"auth_required": authRequired,
			"username":      getSessionUsername(cookie.Value),
			"is_keenetic":   IsKeeneticOS(),
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
			"os":            runtime.GOOS,
		}, "")
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"authenticated": !authRequired,
		"auth_required": authRequired,
		"is_keenetic":   IsKeeneticOS(),
			"os":            runtime.GOOS,
	}, "")
}