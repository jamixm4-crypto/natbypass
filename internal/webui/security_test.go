package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFMiddleware(t *testing.T) {
	s := NewServer(0, "admin", "secret", nil, nil)
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	handler := s.csrfMiddleware(dummyHandler)

	// GET request sets csrf_token cookie
	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatalf("expected csrf_token cookie on GET")
	}

	// POST without CSRF header must fail with 403
	postReq := httptest.NewRequest("POST", "/api/settings/save", strings.NewReader("{}"))
	postReq.AddCookie(csrfCookie)
	wPost := httptest.NewRecorder()
	handler.ServeHTTP(wPost, postReq)
	if wPost.Code != http.StatusForbidden {
		t.Fatalf("POST without X-CSRF-Token expected 403, got %d", wPost.Code)
	}

	// POST with valid X-CSRF-Token must succeed
	postValid := httptest.NewRequest("POST", "/api/settings/save", strings.NewReader("{}"))
	postValid.AddCookie(csrfCookie)
	postValid.Header.Set("X-CSRF-Token", csrfCookie.Value)
	wValid := httptest.NewRecorder()
	handler.ServeHTTP(wValid, postValid)
	if wValid.Code != http.StatusOK {
		t.Fatalf("POST with valid X-CSRF-Token expected 200, got %d", wValid.Code)
	}
}

func TestIPWhitelistMiddleware(t *testing.T) {
	s := NewServer(0, "admin", "secret", nil, nil)
	s.SetAllowedIPs([]string{"127.0.0.1", "100.64.200.0/24"})

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.ipWhitelistMiddleware(dummyHandler)

	// Allowed localhost IP
	reqLocal := httptest.NewRequest("GET", "/api/status", nil)
	reqLocal.RemoteAddr = "127.0.0.1:54321"
	wLocal := httptest.NewRecorder()
	handler.ServeHTTP(wLocal, reqLocal)
	if wLocal.Code != http.StatusOK {
		t.Fatalf("allowed IP expected 200, got %d", wLocal.Code)
	}

	// Allowed Mesh subnet IP
	reqMesh := httptest.NewRequest("GET", "/api/status", nil)
	reqMesh.RemoteAddr = "100.64.200.5:12345"
	wMesh := httptest.NewRecorder()
	handler.ServeHTTP(wMesh, reqMesh)
	if wMesh.Code != http.StatusOK {
		t.Fatalf("allowed subnet IP expected 200, got %d", wMesh.Code)
	}

	// Denied outside IP
	reqDeny := httptest.NewRequest("GET", "/api/status", nil)
	reqDeny.RemoteAddr = "198.51.100.22:4567"
	wDeny := httptest.NewRecorder()
	handler.ServeHTTP(wDeny, reqDeny)
	if wDeny.Code != http.StatusForbidden {
		t.Fatalf("denied IP expected 403, got %d", wDeny.Code)
	}
}
