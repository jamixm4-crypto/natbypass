package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var defaultIPAPIs = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
	"https://checkip.amazonaws.com",
	"https://ipinfo.io/ip",
	"https://ipecho.net/plain",
}

type Discoverer struct {
	apis   []string
	client *http.Client

	mu         sync.Mutex
	cachedIP   net.IP
	cachedTime time.Time
}

func NewDiscoverer(apis []string, timeout time.Duration) *Discoverer {
	if len(apis) == 0 {
		apis = defaultIPAPIs
	}

	return &Discoverer{
		apis: apis,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (d *Discoverer) GetPublicIP(ctx context.Context) (net.IP, error) {
	var lastErr error

	for _, api := range d.apis {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := d.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		ipStr := strings.TrimSpace(string(body))
		ip := net.ParseIP(ipStr)
		if ip != nil {
			return ip, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("failed to discover public IP")
}

func (d *Discoverer) GetPublicIPCached(ctx context.Context, maxAge time.Duration) (net.IP, error) {
	d.mu.Lock()
	if d.cachedIP != nil && time.Since(d.cachedTime) < maxAge {
		ip := d.cachedIP
		d.mu.Unlock()
		return ip, nil
	}
	d.mu.Unlock()

	ip, err := d.GetPublicIP(ctx)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.cachedIP = ip
	d.cachedTime = time.Now()
	d.mu.Unlock()

	return ip, nil
}
