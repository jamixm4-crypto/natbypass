package webui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
)

func TestUIStringIntegrity(t *testing.T) {
	reg := peer.NewRegistry()
	sig := signaling.NewFallbackManager(nil)
	server := NewServer(0, "", "", reg, sig)


	// Create test HTTP server with webui handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/api/diagnose", server.handleDiagnose)
	mux.HandleFunc("/api/status", server.handleStatus)

	ts := httptest.NewServer(server.corsMiddleware(mux))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx

	// 1. Test GET / (index.html)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("Failed to GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "charset=utf-8") {
		t.Errorf("Expected Content-Type to contain 'charset=utf-8', got %q", contentType)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if !utf8.Valid(bodyBytes) {
		t.Errorf("Response body is not valid UTF-8!")
	}

	body := string(bodyBytes)

	// 2. Assert REQUIRED EXACT strings are present
	requiredStrings := []string{
		"ПОИСК УСТРОЙСТВ В СЕТИ",
		"ОЖИДАНИЕ СВЯЗИ",
		"СИСТЕМНАЯ ДИАГНОСТИКА",
		"Имя, которое увидят",
		"Задайте уникальный",
		"Сети и профили",
	}

	for _, req := range requiredStrings {
		if !strings.Contains(body, req) {
			t.Errorf("Missing required string in index.html: %q", req)
		}
	}

	// 3. Assert CORRUPTED strings are ABSENT
	forbiddenStrings := []string{
		"в•",
		"Ђ",
		"Р…",
		"Рµ",
		"ОЖДАНЕ",
		"ПОСК ",
		"Задйте",
		"СССТЕМ",
		"Сети_Профили",
		"\u02dc",
	}

	for _, forb := range forbiddenStrings {
		if strings.Contains(body, forb) {
			t.Errorf("Forbidden corrupted string found in index.html: %q", forb)
		}
	}
}