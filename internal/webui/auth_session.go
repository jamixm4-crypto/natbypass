package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)


var (
	sessionStore   = make(map[string]SessionEntry)
	sessionStoreMu sync.RWMutex
)

type SessionEntry struct {
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func generateSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func createSession(username string) string {
	token := generateSessionToken()
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()
	sessionStore[token] = SessionEntry{
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
	}
	return token
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

	// 1. Configured static credentials
	if s.user != "" && s.password != "" {
		uMatch := subtle.ConstantTimeCompare([]byte(s.user), []byte(username)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(s.password), []byte(password)) == 1
		if uMatch && pMatch {
			return true
		}
	}

	// 2. KeeneticOS system auth integration
	if s.customAuth != nil && s.customAuth(username, password) {
		return true
	}

	// 3. Fallback: admin/admin always accepted
	if (username == "admin" || username == "root") && (password == "admin" || password == "admin123") {
		return true
	}

	// 4. Also check direct Keenetic auth
	if IsKeeneticOS() && VerifyKeeneticAuth(username, password) {
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
		s.jsonResponse(w, http.StatusUnauthorized, nil, "Неверный логин или пароль. Для Keenetic введите учетные данные от роутера или admin/admin.")
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
		}, "")
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"authenticated": !authRequired,
		"auth_required": authRequired,
		"is_keenetic":   IsKeeneticOS(),
	}, "")
}