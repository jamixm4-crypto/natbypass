package webui

import (
	"testing"
)

func TestParseKeeneticUserLine(t *testing.T) {
	u1 := parseKeeneticUserLine("user admin password secret123")
	if u1 == nil || u1.Username != "admin" || u1.Password != "secret123" {
		t.Fatalf("unexpected u1: %+v", u1)
	}

	u2 := parseKeeneticUserLine("user root password hash MD5:c4ca4238a0b923820dcc509a6f75849b")
	if u2 == nil || u2.Username != "root" || u2.PasswordHash != "c4ca4238a0b923820dcc509a6f75849b" || u2.HashType != "md5" {
		t.Fatalf("unexpected u2: %+v", u2)
	}

	u3 := parseKeeneticUserLine("user operator password hash sha256:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918")
	if u3 == nil || u3.Username != "operator" || u3.HashType != "sha256" {
		t.Fatalf("unexpected u3: %+v", u3)
	}
}

func TestVerifyKeeneticHash(t *testing.T) {
	// Plain MD5
	if !verifyKeeneticHash("admin", "1", "c4ca4238a0b923820dcc509a6f75849b", "md5") {
		t.Fatal("expected MD5 to match")
	}

	// Keenetic Realm MD5: md5("admin:Keenetic:secret") = "d3bcc0e272f164e15e886cf4cd3e5498"
	if !verifyKeeneticHash("admin", "secret", "d3bcc0e272f164e15e886cf4cd3e5498", "md5") {
		t.Fatal("expected Keenetic realm MD5 to match")
	}

	// Wrong password
	if verifyKeeneticHash("admin", "wrong", "d3bcc0e272f164e15e886cf4cd3e5498", "md5") {
		t.Fatal("expected wrong password to fail")
	}

}