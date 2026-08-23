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
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type TelegramChannel struct {
	token   string
	chatID  string
	client  *http.Client
	seenMu  sync.Mutex
	seenIDs map[int]bool
}

func NewTelegramChannel(token, chatID, httpProxy string) *TelegramChannel {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, "\"' \r\n\t")
	chatID = strings.TrimSpace(chatID)
	chatID = strings.Trim(chatID, "\"' \r\n\t")

	tr := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	}

	if httpProxy != "" {
		proxyURL, err := url.Parse(httpProxy)
		if err == nil {
			if proxyURL.Scheme == "socks5" {
				dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
				if err == nil {
					tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						return dialer.Dial(network, addr)
					}
				}
			} else {
				tr.Proxy = http.ProxyURL(proxyURL)
			}
		}
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
	}

	return &TelegramChannel{
		token:   token,
		chatID:  chatID,
		client:  client,
		seenIDs: make(map[int]bool),
	}
}

func (t *TelegramChannel) Name() string {
	return "telegram"
}

func (t *TelegramChannel) Send(ctx context.Context, payload *Payload) error {
	if t.token == "" || t.chatID == "" {
		return fmt.Errorf("telegram token or chat_id is empty")
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg := "/peer " + base64.StdEncoding.EncodeToString(data)

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
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

func (t *TelegramChannel) Receive(ctx context.Context) (<-chan *Payload, error) {
	out := make(chan *Payload, 128)

	if t.token == "" {
		return out, nil
	}

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=-40&limit=50&timeout=4", t.token)
				req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
				if err != nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}

				resp, err := t.client.Do(req)
				if err != nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}

				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusOK {
					select {
					case <-ctx.Done():
						return
					case <-time.After(3 * time.Second):
					}
					continue
				}

				var result struct {
					Ok     bool `json:"ok"`
					Result []struct {
						UpdateID int `json:"update_id"`
						Message  *struct {
							Text string `json:"text"`
						} `json:"message"`
						ChannelPost *struct {
							Text string `json:"text"`
						} `json:"channel_post"`
						EditedMessage *struct {
							Text string `json:"text"`
						} `json:"edited_message"`
					} `json:"result"`
				}

				if err := json.Unmarshal(body, &result); err == nil && result.Ok {
					for _, update := range result.Result {
						t.seenMu.Lock()
						if t.seenIDs[update.UpdateID] {
							t.seenMu.Unlock()
							continue
						}
						t.seenIDs[update.UpdateID] = true
						if len(t.seenIDs) > 1000 {
							t.seenIDs = make(map[int]bool)
							t.seenIDs[update.UpdateID] = true
						}
						t.seenMu.Unlock()

						var rawText string
						if update.Message != nil && update.Message.Text != "" {
							rawText = update.Message.Text
						} else if update.ChannelPost != nil && update.ChannelPost.Text != "" {
							rawText = update.ChannelPost.Text
						} else if update.EditedMessage != nil && update.EditedMessage.Text != "" {
							rawText = update.EditedMessage.Text
						}

						if rawText != "" {
							rawText = strings.TrimPrefix(rawText, "/peer ")
							rawText = strings.TrimPrefix(rawText, "/peer")
							rawText = strings.TrimPrefix(rawText, "/nb ")
							rawText = strings.TrimPrefix(rawText, "/nb")
							rawText = strings.TrimSpace(rawText)

							data, err := base64.StdEncoding.DecodeString(rawText)
							if err != nil {
								data = []byte(rawText)
							}

							var p Payload
							if err := json.Unmarshal(data, &p); err == nil && p.DeviceID != "" {
								p.Channel = "telegram"
								select {
								case out <- &p:
								case <-ctx.Done():
									return
								}
							}
						}
					}
				}

				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}
	}()

	return out, nil
}

func (t *TelegramChannel) IsAvailable(ctx context.Context) bool {
	if t.token == "" {
		return false
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", t.token)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	return resp.StatusCode == http.StatusOK
}

func (t *TelegramChannel) Close() error {
	return nil
}
