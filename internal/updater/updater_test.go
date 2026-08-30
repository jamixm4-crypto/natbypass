package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestVersionCompare(t *testing.T) {
	if compareVersions("1.9.080", "1.9.070") <= 0 {
		t.Fatalf("expected 1.9.080 > 1.9.070")
	}
	if compareVersions("1.9.070", "1.9.080") >= 0 {
		t.Fatalf("expected 1.9.070 < 1.9.080")
	}
	if compareVersions("1.9.080", "1.9.080") != 0 {
		t.Fatalf("expected 1.9.080 == 1.9.080")
	}
}

func TestUpdater_Ed25519Verification(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	updater := NewUpdater("1.9.080", pubKey)
	if updater.currentVersion != "1.9.080" {
		t.Fatalf("expected 1.9.080, got %s", updater.currentVersion)
	}

	data := []byte("binary payload content v1.9.080")
	sig := ed25519.Sign(privKey, data)

	if !ed25519.Verify(pubKey, data, sig) {
		t.Fatalf("expected signature verification to pass")
	}
}
