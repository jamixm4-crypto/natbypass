package signaling

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type WebhookChannel struct {
	postURL string
	pollURL string
	secret  string
	client  *http.Client
}

func NewWebhookChannel(postURL, pollURL, secret string) *WebhookChannel {
	return &WebhookChannel{
		postURL: postURL,
		pollURL: pollURL,
		secret:  secret,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *WebhookChannel) Name() string {
	return "webhook"
}

func (w *WebhookChannel) Send(ctx context.Context, payload *Payload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, []byte(w.secret))
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, "POST", w.postURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NatBypass-Sig", sig)

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (w *WebhookChannel) Receive(ctx context.Context) (<-chan *Payload, error) {
	out := make(chan *Payload, 128)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				req, err := http.NewRequestWithContext(ctx, "GET", w.pollURL, nil)
				if err != nil {
					continue
				}

				resp, err := w.client.Do(req)
				if err != nil {
					continue
				}
				
				if resp.StatusCode == http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					var p Payload
					if err := json.Unmarshal(body, &p); err == nil {
						select {
						case out <- &p:
						case <-ctx.Done():
							resp.Body.Close()
							return
						}
					}
				}
				resp.Body.Close()
			}
		}
	}()

	return out, nil
}

func (w *WebhookChannel) IsAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", w.postURL, nil)
	if err != nil {
		return false
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

func (w *WebhookChannel) Close() error {
	return nil
}
