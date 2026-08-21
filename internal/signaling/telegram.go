package signaling

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

type TelegramChannel struct {
	token  string
	chatID string
	client *http.Client
}

func NewTelegramChannel(token, chatID, httpProxy string) *TelegramChannel {
	client := &http.Client{Timeout: 60 * time.Second}

	if httpProxy != "" {
		proxyURL, err := url.Parse(httpProxy)
		if err == nil {
			if proxyURL.Scheme == "socks5" {
				dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
				if err == nil {
					client.Transport = &http.Transport{
						DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
							return dialer.Dial(network, addr)
						},
					}
				}
			} else {
				client.Transport = &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				}
			}
		}
	}

	return &TelegramChannel{
		token:  token,
		chatID: chatID,
		client: client,
	}
}

func (t *TelegramChannel) Name() string {
	return "telegram"
}

func (t *TelegramChannel) Send(ctx context.Context, payload *Payload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg := base64.StdEncoding.EncodeToString(data)

	reqBody, _ := json.Marshal(map[string]string{
		"chat_id": t.chatID,
		"text":    msg,
	})

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(body))
	}
	return nil
}

func (t *TelegramChannel) Receive(ctx context.Context) (<-chan *Payload, error) {
	out := make(chan *Payload)

	go func() {
		offset := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
				apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=30", t.token, offset)
				req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
				if err != nil {
					time.Sleep(5 * time.Second)
					continue
				}

				resp, err := t.client.Do(req)
				if err != nil {
					time.Sleep(5 * time.Second)
					continue
				}

				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}

				var result struct {
					Ok     bool `json:"ok"`
					Result []struct {
						UpdateID int `json:"update_id"`
						Message  struct {
							Text string `json:"text"`
						} `json:"message"`
					} `json:"result"`
				}

				if err := json.Unmarshal(body, &result); err == nil && result.Ok {
					for _, update := range result.Result {
						offset = update.UpdateID + 1
						
						data, err := base64.StdEncoding.DecodeString(update.Message.Text)
						if err != nil {
							continue
						}

						var p Payload
						if err := json.Unmarshal(data, &p); err == nil {
							out <- &p
						}
					}
				}
			}
		}
	}()

	return out, nil
}

func (t *TelegramChannel) IsAvailable(ctx context.Context) bool {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", t.token)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func (t *TelegramChannel) Close() error {
	return nil
}
