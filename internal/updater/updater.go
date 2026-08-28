package updater

import (
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
	GithubRepo = "jamixm4-crypto/natbypass"
	GithubAPI  = "https://api.github.com/repos/" + GithubRepo + "/releases/latest"
)

type GitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	PublishedAt string        `json:"published_at"`
	HTMLURL     string        `json:"html_url"`
	Assets      []GitHubAsset `json:"assets"`
}

type GitHubAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ReleaseInfo struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	HasUpdate      bool   `json:"has_update"`
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

// CheckUpdate проверяет наличие новой версии на GitHub Releases
func CheckUpdate(ctx context.Context, currentVersion string) (*ReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", GithubAPI, nil)
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

	var rel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("ошибка парсинга релиза: %w", err)
	}

	latestVer := strings.TrimPrefix(rel.TagName, "v")
	curVer := strings.TrimPrefix(currentVersion, "v")

	hasUpdate := isNewer(latestVer, curVer)

	// Подбираем подходящий бинарник под текущую ОС и архитектуру
	assetURL, assetName, assetSize := pickAsset(rel.Assets)

	info := &ReleaseInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  rel.TagName,
		HasUpdate:      hasUpdate,
		ReleaseNotes:   rel.Body,
		PublishedAt:    rel.PublishedAt,
		AssetURL:       assetURL,
		AssetName:      assetName,
		AssetSize:      assetSize,
		HTMLURL:        rel.HTMLURL,
	}

	return info, nil
}

// isNewer сравнивает семантические версии вида 1.1.8 vs 1.1.7, 1.1.10 vs 1.1.9
func isNewer(latest, current string) bool {
	if latest == "" || current == "" || current == "dev" || current == "custom" {
		return false
	}
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")
	if latest == current {
		return false
	}
	return compareVersions(latest, current) > 0
}

func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			var err error
			n1, err = parseLeadingInt(parts1[i])
			if err != nil {
				n1 = 0
			}
		}
		if i < len(parts2) {
			var err error
			n2, err = parseLeadingInt(parts2[i])
			if err != nil {
				n2 = 0
			}
		}
		if n1 > n2 {
			return 1
		}
		if n1 < n2 {
			return -1
		}
	}
	return 0
}

func parseLeadingInt(s string) (int, error) {
	var numStr string
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			numStr += string(ch)
		} else {
			break
		}
	}
	if numStr == "" {
		return 0, fmt.Errorf("no digits")
	}
	var res int
	fmt.Sscanf(numStr, "%d", &res)
	return res, nil
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

	var candidates []string
	if osName == "windows" {
		candidates = []string{
			"natbypass-v",
			"natbypass-",
			"windows-amd64.exe",
			"natbypass.exe",
		}
	} else if osName == "linux" {
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
			// Избегаем cli версии при подборе для GUI
			if strings.Contains(nameLower, "-cli") && !strings.Contains(cand, "-cli") {
				continue
			}
			if strings.Contains(nameLower, cand) {
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

// ApplyUpdate выполняет скачивание, атомарную замену бинарника и перезапуск
func ApplyUpdate(ctx context.Context, assetURL string) error {
	if assetURL == "" {
		return fmt.Errorf("URL для скачивания обновления не задан")
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
				pct = 10 + int((float64(downloaded)/float64(totalSize))*70)
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


	setStatus(true, 95, "Перезапуск службы NatBypass...", "", false)

	// Перезапуск службы или процесса в фоновом режиме
	go func() {
		time.Sleep(500 * time.Millisecond)
		restartService(execPath)
	}()

	setStatus(true, 100, "Обновление завершено! Страница обновится автоматически.", "", true)
	return nil
}
