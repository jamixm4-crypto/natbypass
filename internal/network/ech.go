// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package network

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultCloudflareECHConfigB64 is the fallback ECHConfigList for Cloudflare edge domains.
// Decodes to ECH draft-13 (0xfe0d) ECHConfigList targeting cloudflare-ech.com.
const DefaultCloudflareECHConfigB64 = "AEX+DQBBNgAgACBc25Kn75BoPMkgzYKg/dXgaMCgmHg8eHg37zltEo7pFgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

type cachedECH struct {
	data      []byte
	expiresAt time.Time
}

// ECHManager handles DoH discovery, validation, caching, and fallback of ECHConfigList
// structures (RFC 8744) to encrypt SNI in TLS 1.3 connections against DPI/TSPU inspection.
type ECHManager struct {
	cache           sync.Map
	httpClient      *http.Client
	fallbackConfigs map[string][]byte
}

var (
	defaultECHManager     *ECHManager
	defaultECHManagerOnce sync.Once
)

// GetDefaultECHManager returns the shared singleton instance of ECHManager.
func GetDefaultECHManager() *ECHManager {
	defaultECHManagerOnce.Do(func() {
		defaultECHManager = NewECHManager()
	})
	return defaultECHManager
}

// NewECHManager initializes a new ECHManager with fallback configs.
func NewECHManager() *ECHManager {
	m := &ECHManager{
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
		},
		fallbackConfigs: make(map[string][]byte),
	}

	// Pre-load default Cloudflare fallback
	if defBytes, err := base64.StdEncoding.DecodeString(DefaultCloudflareECHConfigB64); err == nil && len(defBytes) > 0 {
		m.fallbackConfigs["default"] = defBytes
		m.fallbackConfigs["cloudflare.com"] = defBytes
		m.fallbackConfigs["crypto.cloudflare.com"] = defBytes
		m.fallbackConfigs["gateway.icloud.com"] = defBytes
		m.fallbackConfigs["mozilla.cloudflare-dns.com"] = defBytes
	}

	return m
}

type doHResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// ExtractECHFromData parses the "ech=<base64>" parameter from a DNS HTTPS/SVCB record string.
func ExtractECHFromData(recordData string) ([]byte, error) {
	fields := strings.Fields(recordData)
	for _, f := range fields {
		if strings.HasPrefix(f, "ech=") {
			b64Val := strings.TrimPrefix(f, "ech=")
			decoded, err := base64.StdEncoding.DecodeString(b64Val)
			if err != nil {
				return nil, fmt.Errorf("ech base64 decode error: %w", err)
			}
			if len(decoded) < 4 {
				return nil, fmt.Errorf("ech config too short: %d bytes", len(decoded))
			}
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("no ech parameter found in record data")
}

// ResolveDoH queries DoH endpoints for HTTPS (type 65) DNS records to extract ECHConfigList.
func (m *ECHManager) ResolveDoH(ctx context.Context, domain string) ([]byte, error) {
	endpoints := []string{
		fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=65", domain),
		fmt.Sprintf("https://dns.google/resolve?name=%s&type=65", domain),
	}

	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", ep, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := m.httpClient.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		var doh doHResponse
		if err := json.Unmarshal(body, &doh); err != nil {
			continue
		}

		for _, ans := range doh.Answer {
			if ans.Type == 65 {
				if echBytes, err := ExtractECHFromData(ans.Data); err == nil && len(echBytes) > 0 {
					return echBytes, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no valid ECH records found for domain %s via DoH", domain)
}

// GetECHConfigList retrieves the serialized ECHConfigList for domain, using cache, DoH, or fallback.
func (m *ECHManager) GetECHConfigList(ctx context.Context, domain string) ([]byte, error) {
	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	if cleanDomain == "" {
		cleanDomain = "default"
	}

	now := time.Now()

	// 1. Check cache
	if val, ok := m.cache.Load(cleanDomain); ok {
		if c, ok := val.(cachedECH); ok && now.Before(c.expiresAt) {
			return c.data, nil
		}
	}

	// 2. Try DoH resolution
	if cleanDomain != "default" {
		echBytes, err := m.ResolveDoH(ctx, cleanDomain)
		if err == nil && len(echBytes) > 0 {
			m.cache.Store(cleanDomain, cachedECH{
				data:      echBytes,
				expiresAt: now.Add(24 * time.Hour),
			})
			return echBytes, nil
		}
	}

	// 3. Fallback to baked-in ECH configs
	if fb, ok := m.fallbackConfigs[cleanDomain]; ok && len(fb) > 0 {
		m.cache.Store(cleanDomain, cachedECH{
			data:      fb,
			expiresAt: now.Add(24 * time.Hour),
		})
		return fb, nil
	}

	if def, ok := m.fallbackConfigs["default"]; ok && len(def) > 0 {
		return def, nil
	}

	return nil, fmt.Errorf("no ECH config available for %s", domain)
}

// ApplyECH configures Encrypted Client Hello on tls.Config for the given domain.
// Sets EncryptedClientHelloConfigList and ensures MinVersion is TLS 1.3 (RFC 8744 requirement).
func (m *ECHManager) ApplyECH(tlsConf *tls.Config, domain string) bool {
	if tlsConf == nil || domain == "" {
		return false
	}

	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	// ECH is only applicable to public domain names, not IP addresses, localhost, or LAN hostnames
	if net.ParseIP(cleanDomain) != nil || cleanDomain == "localhost" || strings.HasSuffix(cleanDomain, ".local") || strings.HasSuffix(cleanDomain, ".lan") {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	echBytes, err := m.GetECHConfigList(ctx, cleanDomain)
	if err != nil || len(echBytes) == 0 {
		return false
	}

	tlsConf.EncryptedClientHelloConfigList = echBytes
	tlsConf.MinVersion = tls.VersionTLS13
	return true
}

// ApplyDefaultECH configures ECH using the default global ECHManager.
func ApplyDefaultECH(tlsConf *tls.Config, domain string) bool {
	return GetDefaultECHManager().ApplyECH(tlsConf, domain)
}
