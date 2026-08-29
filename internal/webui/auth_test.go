package webui

import (
	"testing"
)

func TestParseKeeneticUserLine(t *testing.T) {
	// Plaintext password line
	u1 := parseKeeneticUserLine("user admin password secret123")
	if u1 == nil || u1.Username != "admin" || u1.Password != "secret123" {
		t.Fatalf("unexpected u1: %+v", u1)
	}

	// MD5 hash line
	u2 := parseKeeneticUserLine("user root password hash MD5:c4ca4238a0b923820dcc509a6f75849b")
	if u2 == nil || u2.Username != "root" || u2.PasswordHash != "c4ca4238a0b923820dcc509a6f75849b" || u2.HashType != "md5" {
		t.Fatalf("unexpected u2: %+v", u2)
	}

	// SHA256 hash line
	u3 := parseKeeneticUserLine("user operator password hash sha256:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918")
	if u3 == nil || u3.Username != "operator" || u3.HashType != "sha256" {
		t.Fatalf("unexpected u3: %+v", u3)
	}
}

func TestVerifyKeeneticAuth(t *testing.T) {
	// When cache is empty, fallback to admin/admin
	keeneticUsersCache = nil
	if !VerifyKeeneticAuth("admin", "admin") {
		t.Fatal("expected admin/admin to succeed on empty cache fallback")
	}
	if VerifyKeeneticAuth("admin", "wrongpassword") {
		t.Fatal("expected wrong password to fail")
	}

	// Set mocked Keenetic users
	keeneticUsersCache = []KeeneticUser{
		{Username: "admin", Password: "RouterPassword99", HashType: "plain"},
		{Username: "user2", PasswordHash: "c4ca4238a0b923820dcc509a6f75849b", HashType: "md5"}, // "1"
	}

	if !VerifyKeeneticAuth("admin", "RouterPassword99") {
		t.Fatal("expected admin plaintext to match")
	}
	if !VerifyKeeneticAuth("user2", "1") {
		t.Fatal("expected user2 md5 to match")
	}
	if VerifyKeeneticAuth("user2", "2") {
		t.Fatal("expected user2 wrong password to fail")
	}
}