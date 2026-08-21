package signaling

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type DNSChannel struct {
	cfAPIToken string
	zoneID     string
	recordName string
	client     *http.Client
}

func NewDNSChannel(cfAPIToken, zoneID, recordName string) *DNSChannel {
	return &DNSChannel{
		cfAPIToken: cfAPIToken,
		zoneID:     zoneID,
		recordName: recordName,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *DNSChannel) Name() string {
	return "dns"
}

func (d *DNSChannel) Send(ctx context.Context, payload *Payload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(data)

	// In a real implementation, you'd list records to find the ID and then PUT or POST
	// For simplicity, assuming a POST to create a new TXT record. Cloudflare might require updating.
	apiURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", d.zoneID)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"type":    "TXT",
		"name":    d.recordName,
		"content": encoded,
		"ttl":     60,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.cfAPIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare API error, status: %d", resp.StatusCode)
	}

	return nil
}

func (d *DNSChannel) Receive(ctx context.Context) (<-chan *Payload, error) {
	out := make(chan *Payload)

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				apiURL := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=TXT", d.recordName)
				req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("Accept", "application/dns-json")

				resp, err := d.client.Do(req)
				if err != nil {
					continue
				}

				if resp.StatusCode == http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					var result struct {
						Answer []struct {
							Data string `json:"data"`
						} `json:"Answer"`
					}
					if err := json.Unmarshal(body, &result); err == nil {
						for _, ans := range result.Answer {
							// CF returns data in quotes
							content := ans.Data
							if len(content) >= 2 && content[0] == '"' && content[len(content)-1] == '"' {
								content = content[1 : len(content)-1]
							}
							
							decoded, err := base64.StdEncoding.DecodeString(content)
							if err != nil {
								continue
							}

							var p Payload
							if err := json.Unmarshal(decoded, &p); err == nil {
								out <- &p
							}
						}
					}
				}
				resp.Body.Close()
			}
		}
	}()

	return out, nil
}

func (d *DNSChannel) IsAvailable(ctx context.Context) bool {
	apiURL := "https://api.cloudflare.com/client/v4/user/tokens/verify"
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+d.cfAPIToken)

	resp, err := d.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func (d *DNSChannel) Close() error {
	return nil
}
