package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestUpdater_RejectsUnsignedUpdate(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("binary data without valid signature"))
	}))
	defer server.Close()

	updater := NewUpdater("1.9.080", pubKey)
	release := &ReleaseInfo{
		LatestVersion: "1.9.085",
		AssetURL:      server.URL + "/NatBypass.exe",
	}

	_, err = updater.DownloadAndVerify(release)
	if err == nil {
		t.Fatalf("expected DownloadAndVerify to reject unsigned update when public key is configured")
	}
}
