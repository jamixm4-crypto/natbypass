package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"runtime"
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

func TestSemVerCompare_BetaPrerelease(t *testing.T) {
	// 1. Beta.1 of new version is newer than previous stable version
	if !isNewer("v1.9.222-beta.1", "v1.9.221") {
		t.Fatalf("expected v1.9.222-beta.1 > v1.9.221")
	}

	// 2. Beta.2 is newer than Beta.1
	if !isNewer("v1.9.222-beta.2", "v1.9.222-beta.1") {
		t.Fatalf("expected v1.9.222-beta.2 > v1.9.222-beta.1")
	}

	// 2b. Beta.3 is newer than Beta.2
	if !isNewer("v1.9.222-beta.3", "v1.9.222-beta.2") {
		t.Fatalf("expected v1.9.222-beta.3 > v1.9.222-beta.2")
	}

	// 2c. Beta.4 is newer than Beta.3
	if !isNewer("v1.9.222-beta.4", "v1.9.222-beta.3") {
		t.Fatalf("expected v1.9.222-beta.4 > v1.9.222-beta.3")
	}

	// 2d. Beta.5 is newer than Beta.4, stable is newer than Beta.5
	if !isNewer("v1.9.222-beta.5", "v1.9.222-beta.4") {
		t.Fatalf("expected v1.9.222-beta.5 > v1.9.222-beta.4")
	}
	if !isNewer("v1.9.222", "v1.9.222-beta.5") {
		t.Fatalf("expected v1.9.222 > v1.9.222-beta.5")
	}

	// 3. Stable 1.9.222 is newer than any beta
	if !isNewer("v1.9.222", "v1.9.222-beta.2") {
		t.Fatalf("expected v1.9.222 > v1.9.222-beta.2")
	}

	// 4. RC is newer than Beta with same version
	if compareSemVer("v1.9.222-rc.1", "v1.9.222-beta.2") <= 0 {
		t.Fatalf("expected v1.9.222-rc.1 > v1.9.222-beta.2")
	}

	// 5. Stable is not newer than itself
	if isNewer("v1.9.220", "v1.9.220") {
		t.Fatalf("expected v1.9.220 not newer than v1.9.220")
	}

	// 6. Old version is not newer than current
	if isNewer("v1.9.220", "v1.9.222-beta.12") {
		t.Fatalf("expected v1.9.220 not newer than v1.9.222-beta.12")
	}

	// 7. Beta.14 is newer than Beta.13
	if !isNewer("v1.9.222-beta.14", "v1.9.222-beta.13") {
		t.Fatalf("expected v1.9.222-beta.14 > v1.9.222-beta.13")
	}
	if !isNewer("v1.9.222-beta.14", "1.9.222-beta.13") {
		t.Fatalf("expected v1.9.222-beta.14 > 1.9.222-beta.13")
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

func TestPickAsset_Logic(t *testing.T) {
	assets := []GitHubAsset{
		{Name: "NatBypass.exe", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/NatBypass.exe", Size: 13414400},
		{Name: "NatBypass-GUI.exe", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/NatBypass-GUI.exe", Size: 10266624},
		{Name: "natbypass-cli.exe", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/natbypass-cli.exe", Size: 13414400},
		{Name: "NatBypass-Diag.exe", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/NatBypass-Diag.exe", Size: 7759360},
		{Name: "natbypass-linux-amd64", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/natbypass-linux-amd64", Size: 11976856},
		{Name: "natbypass-linux-arm64", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/natbypass-linux-arm64", Size: 11534488},
		{Name: "natbypass-keenetic-mipsle", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/natbypass-keenetic-mipsle", Size: 13041847},
		{Name: "natbypass-router-mipsle", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/natbypass-router-mipsle", Size: 13041847},
		{Name: "natbypass-router-mips", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/natbypass-router-mips", Size: 13041847},
		{Name: "NatBypass-v1.9.222-beta.14.apk", BrowserDownloadURL: "https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.222-beta.14/NatBypass-v1.9.222-beta.14.apk", Size: 83527646},
	}

	url, name, size := pickAsset(assets)
	t.Logf("Running pickAsset on %s/%s -> name=%s, size=%d, url=%s", runtime.GOOS, runtime.GOARCH, name, size, url)
	if url == "" || name == "" {
		t.Fatalf("expected pickAsset to find an asset for current platform, got empty")
	}
}

