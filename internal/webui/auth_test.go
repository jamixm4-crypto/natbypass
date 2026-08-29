package webui

import (
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
	users := parseKeeneticConfigFile(strings.NewReader(configSample))
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
	// 1. admin/admin always succeeds
	if !VerifyKeeneticAuth("admin", "admin") {
		t.Fatal("expected admin/admin fallback to pass")
	}

	// 2. Mocked Keenetic users from config
	keeneticCacheTime = time.Now()
	keeneticUsersCache = []KeeneticUser{
		{Username: "admin", PasswordHash: "d3bcc0e272f164e15e886cf4cd3e5498", HashType: "md5"}, // "secret" with realm Keenetic
		{Username: "operator", Password: "MySecret99", HashType: "plain"},
	}


	if !VerifyKeeneticAuth("admin", "secret") {
		t.Fatal("expected admin with router password 'secret' to pass")
	}

	if !VerifyKeeneticAuth("operator", "MySecret99") {
		t.Fatal("expected operator with router password 'MySecret99' to pass")
	}

	if VerifyKeeneticAuth("operator", "wrongpassword") {
		t.Fatal("expected wrong password to fail")
	}
}