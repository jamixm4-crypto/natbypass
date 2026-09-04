package webui

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)


func TestParseKeeneticConfigFile(t *testing.T) {
	configSample := `
! KeeneticOS Configuration File
system hostname Keenetic-Hero
!
user admin
    password hash md5 d3bcc0e272f164e15e886cf4cd3e5498
    tag http
    tag cli
!
user operator
    password MySecret99
    tag http
!
user singleline password hash sha256 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
`
	users, hostname := parseKeeneticConfigFile(strings.NewReader(configSample))
	if hostname != "Keenetic-Hero" {
		t.Fatalf("expected hostname Keenetic-Hero, got %q", hostname)
	}
	if len(users) != 3 {
		t.Fatalf("expected 3 users, got %d: %+v", len(users), users)
	}


	if users[0].Username != "admin" || users[0].PasswordHash != "d3bcc0e272f164e15e886cf4cd3e5498" {
		t.Fatalf("unexpected users[0]: %+v", users[0])
	}

	if users[1].Username != "operator" || users[1].Password != "MySecret99" {
		t.Fatalf("unexpected users[1]: %+v", users[1])
	}

	if users[2].Username != "singleline" || users[2].PasswordHash != "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" {
		t.Fatalf("unexpected users[2]: %+v", users[2])
	}
}

func TestVerifyKeeneticAuth(t *testing.T) {
	// Mocked Keenetic users from config
	keeneticCacheTime = time.Now()
	keeneticUsersCache = []KeeneticUser{
		{Username: "admin", PasswordHash: "d3bcc0e272f164e15e886cf4cd3e5498", HashType: "md5"}, // "secret" with realm Keenetic
		{Username: "operator", Password: "MySecret99", HashType: "plain"},
	}

	// 1. Valid router credentials
	if !VerifyKeeneticAuth("admin", "secret") {
		t.Fatal("expected admin with router password 'secret' to pass")
	}

	if !VerifyKeeneticAuth("operator", "MySecret99") {
		t.Fatal("expected operator with router password 'MySecret99' to pass")
	}

	// 2. Reject wrong passwords and unauthorized users
	if VerifyKeeneticAuth("admin", "wrong_admin_password") {
		t.Fatal("expected wrong password to fail")
	}

	if VerifyKeeneticAuth("operator", "wrongpassword") {
		t.Fatal("expected wrong password to fail")
	}
}

func TestCheckCredentials_DefaultAdmin(t *testing.T) {
	s := NewServer(0, "admin", "admin", nil, nil)
	if !s.checkCredentials("admin", "admin") {
		t.Fatal("expected admin/admin to be accepted by default")
	}
	if s.checkCredentials("admin", "wrong") {
		t.Fatal("expected admin/wrong to be rejected")
	}
	if s.checkCredentials("user", "admin") {
		t.Fatal("expected user/admin to be rejected")
	}

	// Server with empty password should also fallback to admin/admin
	s2 := &Server{user: "admin", password: ""}
	if !s2.checkCredentials("admin", "admin") {
		t.Fatal("expected s2 fallback to accept admin/admin")
	}
}

func TestAdminPasswordChange(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	s := NewServer(0, "admin", "admin", nil, nil)
	s.SetConfigPath(cfgPath)

	// 1. Wrong current password -> should fail
	reqBodyBad := strings.NewReader(`{"current_password":"wrong","new_password":"mysecretpass"}`)
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("POST", "/api/admin/password", reqBodyBad)
	s.handleAdminPasswordChange(w1, r1)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong current password, got %d", w1.Code)
	}

	// 2. Correct current password -> should succeed
	reqBodyGood := strings.NewReader(`{"current_password":"admin","new_password":"mysecretpass"}`)
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/api/admin/password", reqBodyGood)
	s.handleAdminPasswordChange(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid password change, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify password updated in server memory
	if !s.checkCredentials("admin", "mysecretpass") {
		t.Fatal("expected new password to be accepted")
	}
	if s.checkCredentials("admin", "admin") {
		t.Fatal("expected old password 'admin' to be rejected")
	}
}