package updater

import (
	"crypto/ed25519"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	GithubRepo        = "jamixm4-crypto/natbypass"
	GithubAPI         = "https://api.github.com/repos/" + GithubRepo + "/releases/latest"
	GithubAPIReleases = "https://api.github.com/repos/" + GithubRepo + "/releases?per_page=30"
)

type GitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	PublishedAt string        `json:"published_at"`
	HTMLURL     string        `json:"html_url"`
	Prerelease  bool          `json:"prerelease"`
	Draft       bool          `json:"draft"`
	Assets      []GitHubAsset `json:"assets"`
}

type GitHubAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type CheckOptions struct {
	IncludePrerelease bool
	Channel           string // "stable" | "beta"
}

type ReleaseInfo struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	HasUpdate      bool   `json:"has_update"`
	IsRollback     bool   `json:"is_rollback"`
	IsPrerelease   bool   `json:"is_prerelease"`
	Channel        string `json:"channel"`
	ReleaseNotes   string `json:"release_notes"`
	PublishedAt    string `json:"published_at"`
	AssetURL       string `json:"asset_url"`
	AssetName      string `json:"asset_name"`
	AssetSize      int64  `json:"asset_size"`
	HTMLURL        string `json:"html_url"`
}

type UpdateStatus struct {
	InProgress bool   `json:"in_progress"`
	Percent    int    `json:"percent"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Completed  bool   `json:"completed"`
}

var (
	currentStatus UpdateStatus
	statusMu      sync.RWMutex
)

// GetStatus возвращает текущий прогресс процесса обновления
func GetStatus() UpdateStatus {
	statusMu.RLock()
	defer statusMu.RUnlock()
	return currentStatus
}

func setStatus(inProgress bool, percent int, msg string, err string, completed bool) {
	statusMu.Lock()
	defer statusMu.Unlock()
	currentStatus = UpdateStatus{
		InProgress: inProgress,
		Percent:    percent,
		Status:     msg,
		Error:      err,
		Completed:  completed,
	}
}

// DefaultReleasePublicKey — глобальный публичный ключ для проверки подписи обновлений
var DefaultReleasePublicKey ed25519.PublicKey

// Updater обеспечивает безопасную проверку и установку обновлений с GitHub Releases с верификацией Ed25519.
type Updater struct {
	currentVersion string
	githubRepo     string
	publicKey      ed25519.PublicKey
}

// NewUpdater создаёт экземпляр автообновлятора с открытым ключом релизов.
func NewUpdater(currentVersion string, pubKey ed25519.PublicKey) *Updater {
	return &Updater{
		currentVersion: currentVersion,
		githubRepo:     GithubRepo,
		publicKey:      pubKey,
	}
}

// DownloadAndVerify скачивает бинарник релиза и проверяет цифровую подпись Ed25519.
func (u *Updater) DownloadAndVerify(release *ReleaseInfo) (string, error) {
	if release == nil || release.AssetURL == "" {
		return "", fmt.Errorf("empty release asset URL")
	}

	resp, err := http.Get(release.AssetURL)
	if err != nil {
		return "", fmt.Errorf("failed to download release binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP status %d", resp.StatusCode)
	}

	binaryData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read binary data: %w", err)
	}

	// Если задан публичный ключ — проверка подписи ОБЯЗАТЕЛЬНА
	if len(u.publicKey) == ed25519.PublicKeySize {
		sigURL := release.AssetURL + ".sig"
		sigResp, err := http.Get(sigURL)
		if err != nil {
			return "", fmt.Errorf("CRITICAL: signature file unavailable, refusing update: %w", err)
		}
		defer sigResp.Body.Close()

		if sigResp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("CRITICAL: signature file returned HTTP %d, refusing update", sigResp.StatusCode)
		}

		signature, err := io.ReadAll(sigResp.Body)
		if err != nil {
			return "", fmt.Errorf("CRITICAL: failed to read signature: %w", err)
		}

		if len(signature) != ed25519.SignatureSize {
			return "", fmt.Errorf("CRITICAL: invalid signature size %d", len(signature))
		}

		if !ed25519.Verify(u.publicKey, binaryData, signature) {
			return "", fmt.Errorf("CRITICAL: Ed25519 signature verification FAILED, possible tampering")
		}
	}

	tmpFile, err := os.CreateTemp("", "natbypass-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(binaryData); err != nil {
		return "", fmt.Errorf("failed to write update binary: %w", err)
	}

	_ = os.Chmod(tmpFile.Name(), 0755)
	return tmpFile.Name(), nil
}

// CheckUpdateWithOptions проверяет наличие новой версии с учетом заданного канала (stable/beta).
func CheckUpdateWithOptions(ctx context.Context, currentVersion string, opts CheckOptions) (*ReleaseInfo, error) {
	includePrerelease := opts.IncludePrerelease || strings.EqualFold(opts.Channel, "beta")

	apiURL := GithubAPI
	if includePrerelease {
		apiURL = GithubAPIReleases
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NatBypass-Updater/"+currentVersion)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка запроса к GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API вернул статус: %d", resp.StatusCode)
	}

	var targetRelease *GitHubRelease

	if includePrerelease {
		var releases []GitHubRelease
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
			return nil, fmt.Errorf("ошибка парсинга списка релизов: %w", err)
		}
		// Находим релиз с максимальной семантической версией среди non-draft
		for i := range releases {
			rel := &releases[i]
			if rel.Draft {
				continue
			}
			if targetRelease == nil || compareSemVer(rel.TagName, targetRelease.TagName) > 0 {
				targetRelease = rel
			}
		}
		if targetRelease == nil {
			return nil, fmt.Errorf("нет доступных релизов на GitHub")
		}
	} else {
		var rel GitHubRelease
		if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
			return nil, fmt.Errorf("ошибка парсинга релиза: %w", err)
		}
		targetRelease = &rel
	}

	hasUpdate := isNewer(targetRelease.TagName, currentVersion)
	isRollback := false

	// Если текущая версия — бета/пре-релиз, а запрошен стабильный канал,
	// то стабильный релиз отличается от текущей версии, и мы предлагаем откат на стабильную версию:
	isCurrentBeta := strings.Contains(strings.ToLower(currentVersion), "beta") ||
		strings.Contains(strings.ToLower(currentVersion), "rc") ||
		strings.Contains(currentVersion, "-")

	if !includePrerelease && isCurrentBeta && strings.TrimPrefix(targetRelease.TagName, "v") != strings.TrimPrefix(currentVersion, "v") {
		hasUpdate = true
		isRollback = true
	}

	// Подбираем подходящий бинарник под текущую ОС и архитектуру
	assetURL, assetName, assetSize := pickAsset(targetRelease.Assets)

	channel := "stable"
	if targetRelease.Prerelease {
		channel = "beta"
	}

	info := &ReleaseInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  targetRelease.TagName,
		HasUpdate:      hasUpdate,
		IsRollback:     isRollback,
		IsPrerelease:   targetRelease.Prerelease,
		Channel:        channel,
		ReleaseNotes:   targetRelease.Body,
		PublishedAt:    targetRelease.PublishedAt,
		AssetURL:       assetURL,
		AssetName:      assetName,
		AssetSize:      assetSize,
		HTMLURL:        targetRelease.HTMLURL,
	}

	return info, nil
}

// CheckUpdate проверяет наличие новой версии на GitHub Releases (стабильный канал по умолчанию)
func CheckUpdate(ctx context.Context, currentVersion string) (*ReleaseInfo, error) {
	return CheckUpdateWithOptions(ctx, currentVersion, CheckOptions{IncludePrerelease: false, Channel: "stable"})
}

// isNewer сравнивает семантические версии с поддержкой пре-релизов SemVer 2.0
func isNewer(latest, current string) bool {
	if latest == "" || current == "" || current == "dev" || current == "custom" {
		return false
	}
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")
	if latest == current {
		return false
	}
	return compareSemVer(latest, current) > 0
}

// compareSemVer сравнивает версии с полной поддержкой SemVer 2.0 (пре-релизы -beta, -rc)
func compareSemVer(v1, v2 string) int {
	v1 = strings.TrimPrefix(strings.TrimSpace(v1), "v")
	v2 = strings.TrimPrefix(strings.TrimSpace(v2), "v")
	if v1 == v2 {
		return 0
	}

	// Отделяем метаданные сборки (+)
	if idx := strings.Index(v1, "+"); idx != -1 {
		v1 = v1[:idx]
	}
	if idx := strings.Index(v2, "+"); idx != -1 {
		v2 = v2[:idx]
	}

	// Отделяем суффикс пре-релиза (-)
	var pre1, pre2 string
	if idx := strings.Index(v1, "-"); idx != -1 {
		pre1 = v1[idx+1:]
		v1 = v1[:idx]
	}
	if idx := strings.Index(v2, "-"); idx != -1 {
		pre2 = v2[idx+1:]
		v2 = v2[:idx]
	}

	// Сравнение основной версии Major.Minor.Patch...
	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")
	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}
	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(p1) {
			_, _ = fmt.Sscanf(p1[i], "%d", &n1)
		}
		if i < len(p2) {
			_, _ = fmt.Sscanf(p2[i], "%d", &n2)
		}
		if n1 > n2 {
			return 1
		}
		if n1 < n2 {
			return -1
		}
	}

	// SemVer 2.0 §11.3: нормальный релиз имеет больший приоритет, чем пре-релиз
	if pre1 == "" && pre2 != "" {
		return 1 // например, 1.9.221 (stable) > 1.9.221-beta.1
	}
	if pre1 != "" && pre2 == "" {
		return -1 // например, 1.9.221-beta.1 < 1.9.221 (stable)
	}
	if pre1 != "" && pre2 != "" {
		return comparePrerelease(pre1, pre2)
	}

	return 0
}

func comparePrerelease(p1, p2 string) int {
	parts1 := strings.Split(p1, ".")
	parts2 := strings.Split(p2, ".")
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		if i >= len(parts1) {
			return -1
		}
		if i >= len(parts2) {
			return 1
		}
		s1, s2 := parts1[i], parts2[i]
		if s1 == s2 {
			continue
		}

		var n1, n2 int
		_, err1 := fmt.Sscanf(s1, "%d", &n1)
		_, err2 := fmt.Sscanf(s2, "%d", &n2)
		isNum1 := (err1 == nil && fmt.Sprintf("%d", n1) == s1)
		isNum2 := (err2 == nil && fmt.Sprintf("%d", n2) == s2)

		// Числовой идентификатор имеет меньший приоритет, чем строковый
		if isNum1 && isNum2 {
			if n1 > n2 {
				return 1
			}
			if n1 < n2 {
				return -1
			}
		} else if isNum1 && !isNum2 {
			return -1
		} else if !isNum1 && isNum2 {
			return 1
		} else {
			if s1 > s2 {
				return 1
			}
			if s1 < s2 {
				return -1
			}
		}
	}
	return 0
}

func compareVersions(v1, v2 string) int {
	return compareSemVer(v1, v2)
}


// pickAsset находит ассет для текущей операционной системы и архитектуры
func pickAsset(assets []GitHubAsset) (string, string, int64) {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	// 1. Исключаем нерелевантные файлы (диагностику, сборщики роутеров, тулкиты, тестовые архивы)
	var filtered []GitHubAsset
	for _, a := range assets {
		nl := strings.ToLower(a.Name)
		if strings.Contains(nl, "diag") || strings.Contains(nl, "builder") || strings.Contains(nl, "toolkit") || strings.HasPrefix(nl, "test-") || strings.HasSuffix(nl, ".zip") || strings.HasSuffix(nl, ".tar.gz") || strings.HasSuffix(nl, ".example") {
			continue
		}
		if osName == "windows" {
			// На Windows подходят ТОЛЬКО файлы с расширением .exe
			if !strings.HasSuffix(nl, ".exe") {
				continue
			}
		} else if osName == "linux" {
			// На Linux исключаем файлы .exe и .apk
			if strings.HasSuffix(nl, ".exe") || strings.HasSuffix(nl, ".apk") {
				continue
			}
		} else if osName == "android" {
			if !strings.HasSuffix(nl, ".apk") && !strings.Contains(nl, "android") {
				continue
			}
		}
		filtered = append(filtered, a)
	}

	currentExe := ""
	if ep, err := os.Executable(); err == nil {
		currentExe = strings.ToLower(filepath.Base(ep))
	}

	if osName == "windows" {
		if strings.Contains(currentExe, "gui") {
			for _, a := range filtered {
				if strings.EqualFold(a.Name, "NatBypass-GUI.exe") {
					return a.BrowserDownloadURL, a.Name, a.Size
				}
			}
		} else if strings.Contains(currentExe, "cli") {
			for _, a := range filtered {
				if strings.EqualFold(a.Name, "natbypass-cli.exe") {
					return a.BrowserDownloadURL, a.Name, a.Size
				}
			}
		} else if strings.Contains(currentExe, "diag") {
			for _, a := range filtered {
				if strings.EqualFold(a.Name, "NatBypass-Diag.exe") {
					return a.BrowserDownloadURL, a.Name, a.Size
				}
			}
		} else {
			// Запущен NatBypass.exe — строго возвращаем NatBypass.exe
			for _, a := range filtered {
				if strings.EqualFold(a.Name, "NatBypass.exe") {
					return a.BrowserDownloadURL, a.Name, a.Size
				}
			}
		}
	}

	var candidates []string
	if osName == "linux" {
		if arch == "arm64" {
			candidates = []string{"-linux-arm64", "linux-arm64", "arm64"}
		} else if arch == "mipsle" {
			candidates = []string{"-router-mipsle", "-linux-mipsle", "mipsle", "mipsel"}
		} else if arch == "mips" {
			candidates = []string{"-router-mips", "-linux-mips", "mips"}
		} else {
			candidates = []string{"-linux-amd64", "linux-amd64", "amd64"}
		}
	} else if osName == "android" {
		candidates = []string{".apk", "android-arm64"}
	}

	for _, cand := range candidates {
		for _, a := range filtered {
			nameLower := strings.ToLower(a.Name)
			// Исключаем версии gui и cli при подборе основного бинарника
			if !strings.Contains(cand, "gui") && strings.Contains(nameLower, "-gui") {
				continue
			}
			if !strings.Contains(cand, "cli") && strings.Contains(nameLower, "-cli") {
				continue
			}
			if !strings.Contains(cand, "diag") && strings.Contains(nameLower, "-diag") {
				continue
			}
			if nameLower == cand || strings.Contains(nameLower, cand) {
				return a.BrowserDownloadURL, a.Name, a.Size
			}
		}
	}



	// Fallback на первый подходящий отфильтрованный ассет
	if len(filtered) > 0 {
		return filtered[0].BrowserDownloadURL, filtered[0].Name, filtered[0].Size
	}

	return "", "", 0
}

// IsValidAssetURL проверяет, что URL обновления исходит исключительно из доверенного официального репозитория GitHub.
func IsValidAssetURL(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	// Разрешаем только официальные релизы репозитория или подписанный CDN GitHub
	return strings.HasPrefix(urlStr, "https://github.com/"+GithubRepo+"/releases/download/") ||
		strings.HasPrefix(urlStr, "https://objects.githubusercontent.com/github-production-release-asset-")
}

// ApplyUpdate выполняет скачивание, атомарную замену бинарника и перезапуск
func ApplyUpdate(ctx context.Context, assetURL string) error {
	if assetURL == "" {
		return fmt.Errorf("URL для скачивания обновления не задан")
	}

	if !IsValidAssetURL(assetURL) {
		err := fmt.Errorf("отклонено: недоверенный источник обновления (%s)", assetURL)
		setStatus(false, 0, "", err.Error(), false)
		return err
	}

	setStatus(true, 5, "Инициализация скачивания...", "", false)

	execPath, err := os.Executable()
	if err != nil {
		setStatus(false, 0, "", "Не удалось определить путь к текущему исполняемому файлу: "+err.Error(), false)
		return err
	}
	execPath, _ = filepath.EvalSymlinks(execPath)

	tmpPath := execPath + ".new"
	_ = os.Remove(tmpPath)

	req, err := http.NewRequestWithContext(ctx, "GET", assetURL, nil)
	if err != nil {
		setStatus(false, 0, "", "Ошибка запроса: "+err.Error(), false)
		return err
	}
	req.Header.Set("User-Agent", "NatBypass-Updater")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		setStatus(false, 0, "", "Ошибка скачивания: "+err.Error(), false)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		setStatus(false, 0, "", fmt.Sprintf("Сервер вернул ошибку скачивания: %d", resp.StatusCode), false)
		return fmt.Errorf("download failed status: %d", resp.StatusCode)
	}

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		setStatus(false, 0, "", "Ошибка создания временного файла: "+err.Error(), false)
		return err
	}

	totalSize := resp.ContentLength
	var downloaded int64

	buf := make([]byte, 64*1024)
	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			_, wErr := out.Write(buf[:n])
			if wErr != nil {
				out.Close()
				_ = os.Remove(tmpPath)
				setStatus(false, 0, "", "Ошибка записи файла: "+wErr.Error(), false)
				return wErr
			}
			downloaded += int64(n)
			pct := 10
			if totalSize > 0 {
				pct = 10 + int((float64(downloaded)/float64(totalSize))*80)
			}
			setStatus(true, pct, fmt.Sprintf("Скачивание обновления... %d%% (%d / %d KB)", pct, downloaded/1024, totalSize/1024), "", false)

		}
		if rErr != nil {
			if rErr == io.EOF {
				break
			}
			out.Close()
			_ = os.Remove(tmpPath)
			setStatus(false, 0, "", "Ошибка при передаче данных: "+rErr.Error(), false)
			return rErr
		}
	}
	out.Close()

	// Валидация целостности и сигнатуры исполняемого файла
	fi, statErr := os.Stat(tmpPath)
	if statErr != nil || fi.Size() < 500*1024 {
		_ = os.Remove(tmpPath)
		setStatus(false, 0, "", "Скачанный файл поврежден или неполон", false)
		return fmt.Errorf("downloaded file is incomplete")
	}

	headerBuf := make([]byte, 4)
	if fCheck, err := os.Open(tmpPath); err == nil {
		_, _ = io.ReadFull(fCheck, headerBuf)
		fCheck.Close()
		if runtime.GOOS == "windows" {
			if headerBuf[0] != 'M' || headerBuf[1] != 'Z' {
				_ = os.Remove(tmpPath)
				setStatus(false, 0, "", "Ошибка: скачанный файл не является исполняемым файлом Windows (MZ PE)", false)
				return fmt.Errorf("downloaded asset is not a valid Windows executable")
			}
		} else if runtime.GOOS == "linux" {
			if headerBuf[0] != 0x7F || headerBuf[1] != 'E' || headerBuf[2] != 'L' || headerBuf[3] != 'F' {
				_ = os.Remove(tmpPath)
				setStatus(false, 0, "", "Ошибка: скачанный файл не является ELF файлом Linux", false)
				return fmt.Errorf("downloaded asset is not a valid Linux ELF executable")
			}
		}
	}

	_ = os.Chmod(tmpPath, 0755)

	// Проверка цифровой подписи Ed25519 релиза (если доступен файл .sig)
	sigURL := assetURL + ".sig"
	sigReq, sErr := http.NewRequestWithContext(ctx, "GET", sigURL, nil)
	if sErr == nil {
		sigReq.Header.Set("User-Agent", "NatBypass-Updater")
		if sigResp, err := client.Do(sigReq); err == nil && sigResp.StatusCode == http.StatusOK {
			sigData, _ := io.ReadAll(sigResp.Body)
			sigResp.Body.Close()
			if len(sigData) == ed25519.SignatureSize && len(DefaultReleasePublicKey) == ed25519.PublicKeySize {
				binData, _ := os.ReadFile(tmpPath)
				if !ed25519.Verify(DefaultReleasePublicKey, binData, sigData) {
					_ = os.Remove(tmpPath)
					setStatus(false, 0, "", "КРИТИЧЕСКАЯ ОШИБКА: цифровая подпись Ed25519 не прошла проверку!", false)
					return fmt.Errorf("Ed25519 signature verification failed")
				}
			}
		}
	}

	setStatus(true, 85, "Применение обновления и замена исполняемого файла...", "", false)

	// Атомарная замена исполняемого файла
	if runtime.GOOS == "windows" {
		oldPath := fmt.Sprintf("%s.old.%d", execPath, time.Now().UnixNano())
		if err := os.Rename(execPath, oldPath); err != nil {
			setStatus(false, 0, "", "Не удалось переименовать старый файл Windows: "+err.Error(), false)
			return err
		}
		if err := os.Rename(tmpPath, execPath); err != nil {
			_ = os.Rename(oldPath, execPath) // откат
			setStatus(false, 0, "", "Не удалось установить новый файл Windows: "+err.Error(), false)
			return err
		}
	} else {
		// Linux / MIPS / OpenWrt / Keenetic
		oldPath := execPath + ".old"
		_ = os.Remove(oldPath)
		_ = os.Rename(execPath, oldPath)
		if err := os.Rename(tmpPath, execPath); err != nil {
			// Fallback copy
			input, errRead := os.ReadFile(tmpPath)
			if errRead == nil {
				_ = os.WriteFile(execPath, input, 0755)
			}
			_ = os.Remove(tmpPath)
		}
		_ = os.Chmod(execPath, 0755)
		_ = os.Remove(oldPath)
	}


	setStatus(true, 100, "Обновление успешно скачано! Перезапуск службы NatBypass...", "", true)

	// Даем браузеру 2.5 секунды получить статус 100%, затем перезапускаем службу
	go func() {
		time.Sleep(2500 * time.Millisecond)
		restartService(execPath)
	}()
	return nil
}
