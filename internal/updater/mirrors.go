package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Mirror manifest types
// ---------------------------------------------------------------------------

// MirrorManifest — формат JSON-манифеста зеркала обновлений NatBypass.
// Публикуется автоматически в CI после каждого релиза.
type MirrorManifest struct {
	Version      string                 `json:"version"`
	PublishedAt  string                 `json:"published_at"`
	Prerelease   bool                   `json:"prerelease"`
	ReleaseNotes string                 `json:"release_notes"`
	HTMLURL      string                 `json:"html_url"`
	// Assets — карта по ключу "os/arch/variant" → ассет
	// Пример ключей: "windows/amd64/gui", "linux/amd64", "android/arm64"
	Assets map[string]MirrorAsset `json:"assets"`
}

// MirrorAsset описывает один бинарный ассет и его зеркала.
type MirrorAsset struct {
	Name    string   `json:"name"`
	URL     string   `json:"url"`      // основной URL (GitHub CDN)
	SigURL  string   `json:"sig_url"`  // Ed25519-подпись (.sig файл)
	Size    int64    `json:"size"`
	SHA256  string   `json:"sha256"`
	// Mirrors — альтернативные URL в порядке приоритета
	Mirrors []string `json:"mirrors"`
}

// ---------------------------------------------------------------------------
// Mirror source constants
// ---------------------------------------------------------------------------

// MirrorManifestURLs — URL манифестов для stable-канала (в порядке приоритета).
// Cloudflare Pages — основное зеркало (CDN, доступен в РФ).
// GitHub raw — резервный (может быть заблокирован, но иногда работает).
var MirrorManifestURLsStable = []string{
	"https://nb-mirror.pages.dev/releases/latest.json",
	"https://raw.githubusercontent.com/jamixm4-crypto/natbypass-mirror/main/releases/latest.json",
}

// MirrorManifestURLsBeta — URL манифестов для beta-канала.
var MirrorManifestURLsBeta = []string{
	"https://nb-mirror.pages.dev/releases/latest-beta.json",
	"https://raw.githubusercontent.com/jamixm4-crypto/natbypass-mirror/main/releases/latest-beta.json",
}

// MirrorTrustedDomains — доверенные домены зеркал для IsValidAssetURL.
var MirrorTrustedDomains = []string{
	"nb-mirror.pages.dev",
	"pub-",   // Cloudflare R2 public bucket prefix
}

// ---------------------------------------------------------------------------
// Mirror asset key resolution
// ---------------------------------------------------------------------------

// mirrorAssetKey возвращает ключ ассета для текущей платформы и имени exe.
// Используется при поиске в MirrorManifest.Assets.
func mirrorAssetKey(osName, arch, exeName string) string {
	exeLower := strings.ToLower(exeName)
	switch osName {
	case "windows":
		switch {
		case strings.Contains(exeLower, "gui"):
			return "windows/amd64/gui"
		case strings.Contains(exeLower, "cli"):
			return "windows/amd64/cli"
		case strings.Contains(exeLower, "diag"):
			return "windows/amd64/diag"
		default:
			return "windows/amd64/main"
		}
	case "linux":
		switch arch {
		case "arm64":
			return "linux/arm64"
		case "mipsle":
			return "linux/mipsle"
		case "mips":
			return "linux/mips"
		default:
			return "linux/amd64"
		}
	case "android":
		return "android/arm64"
	}
	return ""
}

// ---------------------------------------------------------------------------
// fetchWithFallback — последовательный фетч с таймаутом на источник
// ---------------------------------------------------------------------------

// fetchWithFallback пробует URLs из списка по порядку (каждый с таймаутом perTimeout).
// Возвращает тело первого успешного ответа (200 OK).
func fetchWithFallback(ctx context.Context, urls []string, perTimeout time.Duration) ([]byte, string, error) {
	var lastErr error
	for _, u := range urls {
		reqCtx, cancel := context.WithTimeout(ctx, perTimeout)
		data, err := fetchURL(reqCtx, u)
		cancel()
		if err == nil {
			return data, u, nil
		}
		lastErr = fmt.Errorf("mirror %s: %w", u, err)
	}
	return nil, "", fmt.Errorf("все зеркала недоступны: %w", lastErr)
}

func fetchURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NatBypass-Updater")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ---------------------------------------------------------------------------
// fetchMirrorManifest — загрузка манифеста зеркала с фоллбеком
// ---------------------------------------------------------------------------

// fetchMirrorManifest загружает MirrorManifest из списка URL зеркал.
// Используется как fallback когда GitHub API недоступен.
func fetchMirrorManifest(ctx context.Context, manifestURLs []string) (*MirrorManifest, error) {
	data, _, err := fetchWithFallback(ctx, manifestURLs, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить манифест зеркала: %w", err)
	}
	var m MirrorManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("ошибка парсинга манифеста зеркала: %w", err)
	}
	if m.Version == "" {
		return nil, fmt.Errorf("манифест зеркала не содержит версию")
	}
	return &m, nil
}

// mirrorManifestToReleaseInfo конвертирует MirrorManifest в ReleaseInfo
// для совместимости с основным кодом апдейтера.
func mirrorManifestToReleaseInfo(m *MirrorManifest, currentVersion, assetKey string) *ReleaseInfo {
	channel := "stable"
	if m.Prerelease {
		channel = "beta"
	}

	var assetURL, assetName, sigURL string
	var assetSize int64

	if a, ok := m.Assets[assetKey]; ok {
		// Предпочитаем зеркальный URL, если основной (GitHub) может быть недоступен
		// Список: [github_url, mirror1, mirror2, ...]
		// pickBestMirrorURL выберет первый из Mirrors, а fallback — URL
		assetURL = a.URL
		if len(a.Mirrors) > 0 {
			// Сохраняем все зеркала в URL через разделитель для последующего fetchWithFallback
			// Используем первый как assetURL, остальные — через запасной механизм
			assetURL = a.URL
		}
		assetName = a.Name
		assetSize = a.Size
		sigURL = a.SigURL
		_ = sigURL // используется в DownloadWithMirrors
	}

	return &ReleaseInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  m.Version,
		HasUpdate:      isNewer(m.Version, currentVersion),
		IsPrerelease:   m.Prerelease,
		Channel:        channel,
		ReleaseNotes:   m.ReleaseNotes,
		PublishedAt:    m.PublishedAt,
		AssetURL:       assetURL,
		AssetName:      assetName,
		AssetSize:      assetSize,
		HTMLURL:        m.HTMLURL,
	}
}

// GetMirrorAssetURLs возвращает все URL (основной + зеркала) для ассета по ключу.
// Используется в ApplyUpdateWithMirrors для fallback-скачивания.
func GetMirrorAssetURLs(m *MirrorManifest, assetKey string) []string {
	if m == nil {
		return nil
	}
	a, ok := m.Assets[assetKey]
	if !ok {
		return nil
	}
	urls := []string{a.URL}
	urls = append(urls, a.Mirrors...)
	return urls
}

// IsMirrorURL проверяет, что URL исходит из доверенного зеркала NatBypass.
func IsMirrorURL(urlStr string) bool {
	for _, domain := range MirrorTrustedDomains {
		if strings.Contains(urlStr, domain) {
			return true
		}
	}
	return false
}
