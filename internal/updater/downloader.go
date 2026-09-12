// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DownloaderProgressCallback передаёт текущее состояние процесса загрузки:
// downloaded — скачано байт, total — общий размер файла (-1 если неизвестен),
// speedBytesSec — мгновенная скорость в байт/сек, percent — процент 0..100,
// workers — количество параллельных потоков.
type DownloaderProgressCallback func(downloaded, total int64, speedBytesSec float64, percent int, workers int)

// DownloaderConfig определяет параметры многопоточной загрузки.
type DownloaderConfig struct {
	// Количество параллельных потоков (0 = автовыбор: 3-4 для роутеров, 6 для ПК/серверов)
	Workers int
	// Минимальный размер сегмента (по умолчанию 512 КБ)
	MinChunkSize int64
	// Максимальное количество попыток для каждого отдельного сегмента
	MaxChunkRetries int
	// Таймаут отдельного HTTP-запроса сегмента
	RequestTimeout time.Duration
	// Функция обратного вызова для обновления прогресса
	OnProgress DownloaderProgressCallback
}

// DefaultDownloaderConfig возвращает оптимальную конфигурацию с учётом платформы
func DefaultDownloaderConfig() DownloaderConfig {
	workers := 6
	if isLowPowerArch() {
		// Для слабых процессоров Keenetic/OpenWrt (MIPS/ARM) ограничиваем число потоков
		// и сетевых дескрипторов, чтобы не вызвать OOM и не забить память ядра.
		workers = 4
	}
	return DownloaderConfig{
		Workers:         workers,
		MinChunkSize:    512 * 1024, // 512 KB
		MaxChunkRetries: 4,
		RequestTimeout:  45 * time.Second,
	}
}

func isLowPowerArch() bool {
	switch runtime.GOARCH {
	case "mips", "mipsle", "mips64", "mips64le", "arm":
		return true
	default:
		return false
	}
}

// DownloadFile выполняет ускоренную многопоточную загрузку файла по HTTP(S)
// с авто-определением поддержки HTTP Range (RFC 7233) и fallback на один поток.
func DownloadFile(ctx context.Context, rawURL string, destPath string, cfg DownloaderConfig) error {
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultDownloaderConfig().Workers
	}
	if cfg.MinChunkSize <= 0 {
		cfg.MinChunkSize = 512 * 1024
	}
	if cfg.MaxChunkRetries <= 0 {
		cfg.MaxChunkRetries = 4
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 45 * time.Second
	}

	client := &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			req.Header.Set("User-Agent", "NatBypass-Updater")
			return nil
		},
	}

	// 1. Probe: Проверяем размер файла и поддержку Range через GET с Range: bytes=0-0
	// (Многие CDN и прокси блокируют HEAD, поэтому GET Range: bytes=0-0 надёжнее на 100%)
	totalSize, acceptRanges, finalURL, err := probeServerCapabilities(ctx, client, rawURL)
	if err != nil {
		// Если зонд провалился, пробуем обычный стриминг по исходному URL
		return downloadSingleStream(ctx, client, rawURL, destPath, cfg.OnProgress)
	}

	// 2. Если сервер поддерживает Range и файл достаточно велик — запускаем параллельную загрузку
	numWorkers := cfg.Workers
	if acceptRanges && totalSize >= cfg.MinChunkSize*2 {
		maxPossibleWorkers := int(totalSize / cfg.MinChunkSize)
		if maxPossibleWorkers < numWorkers {
			numWorkers = maxPossibleWorkers
		}
		if numWorkers > 1 {
			err = downloadMultiThreaded(ctx, client, finalURL, destPath, totalSize, numWorkers, cfg)
			if err == nil {
				return nil
			}
			// При сбое многопоточности — плавный fallback на надежный однопоточный режим
		}
	}

	// 3. Fallback: Однопоточная потоковая загрузка
	return downloadSingleStream(ctx, client, finalURL, destPath, cfg.OnProgress)
}

// probeServerCapabilities определяет размер ресурса и поддержку Range: bytes
func probeServerCapabilities(ctx context.Context, client *http.Client, targetURL string) (int64, bool, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return 0, false, targetURL, err
	}
	req.Header.Set("User-Agent", "NatBypass-Updater")
	req.Header.Set("Range", "bytes=0-0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, false, targetURL, err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()

	// Если сервер вернул 206 Partial Content
	if resp.StatusCode == http.StatusPartialContent {
		cr := resp.Header.Get("Content-Range")
		if cr != "" {
			// Формат: bytes 0-0/15113216
			parts := strings.Split(cr, "/")
			if len(parts) == 2 {
				if total, parseErr := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64); parseErr == nil && total > 0 {
					return total, true, finalURL, nil
				}
			}
		}
	}

	// Если сервер вернул 200 OK — Range не поддерживается, но Content-Length известен
	if resp.StatusCode == http.StatusOK {
		total := resp.ContentLength
		return total, false, finalURL, nil
	}

	return 0, false, finalURL, fmt.Errorf("unexpected probe status: %d", resp.StatusCode)
}

type chunkDesc struct {
	index int
	start int64
	end   int64
}

// downloadMultiThreaded скачивает файл параллельными сегментами
func downloadMultiThreaded(
	ctx context.Context,
	client *http.Client,
	targetURL string,
	destPath string,
	totalSize int64,
	numWorkers int,
	cfg DownloaderConfig,
) error {
	tmpPath := destPath + ".part"
	_ = os.Remove(tmpPath)

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create dest file: %w", err)
	}
	defer out.Close()

	// Преаллокация дискового пространства для устранения фрагментации ФС при параллельной записи
	if err := out.Truncate(totalSize); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("truncate dest file to %d bytes: %w", totalSize, err)
	}

	// Разбиваем файл на сегменты
	chunkSize := totalSize / int64(numWorkers)
	chunks := make([]chunkDesc, numWorkers)
	for i := 0; i < numWorkers; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize - 1
		if i == numWorkers-1 {
			end = totalSize - 1 // последний сегмент забирает остаток
		}
		chunks[i] = chunkDesc{
			index: i,
			start: start,
			end:   end,
		}
	}

	var downloadedTotal atomic.Int64
	errChan := make(chan error, numWorkers)
	var wg sync.WaitGroup

	// Горутина прогресса и измерения реальной скорости
	stopProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()

		var lastBytes int64
		lastTime := time.Now()

		for {
			select {
			case <-stopProgress:
				return
			case now := <-ticker.C:
				current := downloadedTotal.Load()
				dt := now.Sub(lastTime).Seconds()
				var speed float64
				if dt > 0.05 {
					speed = float64(current-lastBytes) / dt
					if speed < 0 {
						speed = 0
					}
				}
				lastBytes = current
				lastTime = now

				pct := 0
				if totalSize > 0 {
					pct = int((float64(current) / float64(totalSize)) * 100)
					if pct > 100 {
						pct = 100
					}
				}
				if cfg.OnProgress != nil {
					cfg.OnProgress(current, totalSize, speed, pct, numWorkers)
				}
			}
		}
	}()

	// Запуск параллельных воркеров
	for _, ch := range chunks {
		wg.Add(1)
		go func(c chunkDesc) {
			defer wg.Done()
			wErr := downloadChunkWithRetry(ctx, client, targetURL, out, c, &downloadedTotal, cfg)
			if wErr != nil {
				select {
				case errChan <- fmt.Errorf("chunk %d [%d-%d] failed: %w", c.index, c.start, c.end, wErr):
				default:
				}
			}
		}(ch)
	}

	wg.Wait()
	close(stopProgress)

	// Проверяем ошибки воркеров
	select {
	case wErr := <-errChan:
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return wErr
	default:
	}

	// Синхронизация дискового кэша
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync dest file: %w", err)
	}
	_ = out.Close()

	// Атомарное перемещение временного файла в целевой
	_ = os.Remove(destPath)
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename to target: %w", err)
	}

	if cfg.OnProgress != nil {
		cfg.OnProgress(totalSize, totalSize, 0, 100, numWorkers)
	}
	return nil
}

// downloadChunkWithRetry скачивает отдельный байтовый сегмент с повторами при сбоях
func downloadChunkWithRetry(
	ctx context.Context,
	client *http.Client,
	targetURL string,
	out *os.File,
	chunk chunkDesc,
	downloadedTotal *atomic.Int64,
	cfg DownloaderConfig,
) error {
	curOffset := chunk.start
	retries := 0

	bufSize := 64 * 1024
	if isLowPowerArch() {
		bufSize = 32 * 1024
	}
	buf := make([]byte, bufSize)

	for curOffset <= chunk.end {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "NatBypass-Updater")
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", curOffset, chunk.end))

		resp, err := client.Do(req)
		if err != nil {
			retries++
			if retries > cfg.MaxChunkRetries {
				return fmt.Errorf("network error after %d retries: %w", retries, err)
			}
			time.Sleep(time.Duration(retries*400) * time.Millisecond)
			continue
		}

		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			retries++
			if retries > cfg.MaxChunkRetries {
				return fmt.Errorf("HTTP status %d", resp.StatusCode)
			}
			time.Sleep(time.Duration(retries*400) * time.Millisecond)
			continue
		}

		// Читаем тело ответа и пишем по смещению curOffset
		readErr := func() error {
			defer resp.Body.Close()
			for curOffset <= chunk.end {
				toRead := len(buf)
				remain := int(chunk.end - curOffset + 1)
				if remain < toRead {
					toRead = remain
				}

				n, rErr := resp.Body.Read(buf[:toRead])
				if n > 0 {
					_, wErr := out.WriteAt(buf[:n], curOffset)
					if wErr != nil {
						return fmt.Errorf("writeAt: %w", wErr)
					}
					curOffset += int64(n)
					downloadedTotal.Add(int64(n))
				}
				if rErr != nil {
					if rErr == io.EOF {
						break
					}
					return rErr
				}
			}
			return nil
		}()

		if readErr != nil {
			retries++
			if retries > cfg.MaxChunkRetries {
				return fmt.Errorf("read error: %w", readErr)
			}
			time.Sleep(time.Duration(retries*400) * time.Millisecond)
			continue
		}

		// Если сегмент успешно скачан целиком
		if curOffset > chunk.end {
			break
		}
	}

	return nil
}

// downloadSingleStream надёжная однопоточная потоковая загрузка с прогрессом
func downloadSingleStream(
	ctx context.Context,
	client *http.Client,
	targetURL string,
	destPath string,
	onProgress DownloaderProgressCallback,
) error {
	tmpPath := destPath + ".part"
	_ = os.Remove(tmpPath)

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NatBypass-Updater")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	totalSize := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 64*1024)

	lastUpdate := time.Now()
	var lastBytes int64

	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := out.Write(buf[:n]); wErr != nil {
				_ = out.Close()
				_ = os.Remove(tmpPath)
				return wErr
			}
			downloaded += int64(n)

			now := time.Now()
			dt := now.Sub(lastUpdate).Seconds()
			if dt >= 0.25 || (totalSize > 0 && downloaded == totalSize) {
				speed := float64(downloaded-lastBytes) / dt
				pct := 0
				if totalSize > 0 {
					pct = int((float64(downloaded) / float64(totalSize)) * 100)
				}
				if onProgress != nil {
					onProgress(downloaded, totalSize, speed, pct, 1)
				}
				lastBytes = downloaded
				lastUpdate = now
			}
		}
		if rErr != nil {
			if rErr == io.EOF {
				break
			}
			_ = out.Close()
			_ = os.Remove(tmpPath)
			return rErr
		}
	}

	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	_ = out.Close()

	_ = os.Remove(destPath)
	if err := os.Rename(tmpPath, destPath); err != nil {
		return err
	}

	if onProgress != nil {
		onProgress(downloaded, totalSize, 0, 100, 1)
	}
	return nil
}
