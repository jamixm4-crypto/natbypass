package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestWindowOpenAPI(t *testing.T) {
	port := 18086
	server := NewServer(port, "admin", "admin", nil, nil)

	opened := make(chan bool, 1)
	server.SetOnOpenWindow(func() {
		opened <- true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	if !server.WaitForReady(5 * time.Second) {
		t.Fatal("Server not ready within 5s")
	}

	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/window/open", port))
	if err != nil {
		t.Fatalf("GET /api/window/open failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var res map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if res["ok"] != true {
		t.Fatalf("Expected ok=true, got %v", res["ok"])
	}

	select {
	case <-opened:
		t.Log("SUCCESS: onOpenWindow callback triggered via /api/window/open")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for onOpenWindow callback")
	}
}
