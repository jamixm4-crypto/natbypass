// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	DefaultUpstreams = []string{
		"https://1.1.1.1/dns-query",       // Cloudflare
		"https://dns.google/dns-query",    // Google
		"https://dns.quad9.net/dns-query", // Quad9
	}
	ErrAllUpstreamsFailed = errors.New("all DoH upstreams failed")
	ErrInvalidDNSQuery    = errors.New("invalid or truncated DNS query")
)

type cacheEntry struct {
	response []byte
	expires  time.Time
}

// DoHResolver resolves DNS queries over encrypted HTTPS (RFC 8484)
// and provides in-memory caching to eliminate DNS leaks and ISP hijacking.
type DoHResolver struct {
	mu         sync.RWMutex
	httpClient *http.Client
	upstreams  []string
	cache      map[string]cacheEntry
	maxCache   int
}

// NewDoHResolver initializes a DoHResolver with specified upstreams.
func NewDoHResolver(upstreams []string) *DoHResolver {
	if len(upstreams) == 0 {
		upstreams = DefaultUpstreams
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	return &DoHResolver{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
		},
		upstreams: upstreams,
		cache:     make(map[string]cacheEntry),
		maxCache:  512, // Strict limit for low-memory MIPS routers (<1MB RAM)
	}
}

// Resolve forwards a binary DNS wire query over DoH and returns the binary DNS response.
func (r *DoHResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, ErrInvalidDNSQuery
	}

	// Extract question key for caching (excluding Transaction ID in bytes 0..1)
	qKey := extractQuestionKey(query)

	if qKey != "" {
		r.mu.RLock()
		if entry, ok := r.cache[qKey]; ok {
			if time.Now().Before(entry.expires) {
				// Cache hit! Clone response and re-apply original Transaction ID
				resp := make([]byte, len(entry.response))
				copy(resp, entry.response)
				resp[0], resp[1] = query[0], query[1]
				r.mu.RUnlock()
				return resp, nil
			}
		}
		r.mu.RUnlock()
	}

	// Query upstream DoH servers with fallback
	var lastErr error
	for _, upstream := range r.upstreams {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream, bytes.NewReader(query))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		httpResp, err := r.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if httpResp.StatusCode != http.StatusOK {
			httpResp.Body.Close()
			lastErr = fmt.Errorf("upstream %s returned HTTP %d", upstream, httpResp.StatusCode)
			continue
		}

		respBody, err := io.ReadAll(httpResp.Body)
		httpResp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if len(respBody) < 12 {
			lastErr = errors.New("upstream returned truncated response")
			continue
		}

		// Store in cache
		if qKey != "" {
			ttl := extractTTL(respBody)
			if ttl <= 0 {
				ttl = 60 * time.Second
			} else if ttl > 3600*time.Second {
				ttl = 3600 * time.Second
			}

			r.mu.Lock()
			if len(r.cache) >= r.maxCache {
				// Evict expired or random entry
				now := time.Now()
				for k, v := range r.cache {
					if now.After(v.expires) {
						delete(r.cache, k)
					}
				}
				if len(r.cache) >= r.maxCache {
					// Hard clear half of cache if still full
					count := 0
					for k := range r.cache {
						delete(r.cache, k)
						count++
						if count >= r.maxCache/2 {
							break
						}
					}
				}
			}
			r.cache[qKey] = cacheEntry{
				response: respBody,
				expires:  time.Now().Add(ttl),
			}
			r.mu.Unlock()
		}

		respBody[0], respBody[1] = query[0], query[1]
		return respBody, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrAllUpstreamsFailed, lastErr)
	}
	return nil, ErrAllUpstreamsFailed
}

// extractQuestionKey extracts the QNAME + QTYPE from a DNS message for caching.
func extractQuestionKey(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	// Skip 12 bytes of DNS header
	offset := 12
	for offset < len(msg) {
		length := int(msg[offset])
		if length == 0 {
			offset++
			break
		}
		offset += 1 + length
	}
	// QTYPE + QCLASS (4 bytes)
	if offset+4 <= len(msg) {
		return string(msg[12 : offset+4])
	}
	return ""
}

// extractTTL parses the TTL of the first Answer record.
func extractTTL(msg []byte) time.Duration {
	if len(msg) < 12 {
		return 60 * time.Second
	}
	ancount := binary.BigEndian.Uint16(msg[6:8])
	if ancount == 0 {
		return 30 * time.Second
	}

	// Skip Question section
	offset := 12
	for offset < len(msg) {
		length := int(msg[offset])
		if length == 0 {
			offset += 5 // skip 0x00 + QTYPE(2) + QCLASS(2)
			break
		}
		offset += 1 + length
	}

	// First Answer record: Name (pointer or labels), Type(2), Class(2), TTL(4), RDLENGTH(2)
	if offset < len(msg) {
		// Skip name
		if (msg[offset] & 0xC0) == 0xC0 {
			offset += 2 // compression pointer
		} else {
			for offset < len(msg) {
				l := int(msg[offset])
				if l == 0 {
					offset++
					break
				}
				offset += 1 + l
			}
		}
		// Skip Type(2) + Class(2)
		offset += 4
		if offset+4 <= len(msg) {
			ttlSeconds := binary.BigEndian.Uint32(msg[offset : offset+4])
			return time.Duration(ttlSeconds) * time.Second
		}
	}
	return 60 * time.Second
}

// DoHProxyServer is a local UDP DNS listener that receives standard DNS queries,
// resolves them over DoH via DoHResolver, and writes answers back.
type DoHProxyServer struct {
	resolver   *DoHResolver
	conn       *net.UDPConn
	closed     chan struct{}
	closeOnce  sync.Once
	listenAddr string
}

// NewDoHProxyServer starts a DNS proxy listening on listenAddr.
func NewDoHProxyServer(listenAddr string, resolver *DoHResolver) (*DoHProxyServer, error) {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:53"
	}
	if resolver == nil {
		resolver = NewDoHResolver(nil)
	}

	uAddr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp4", uAddr)
	if err != nil {
		return nil, err
	}

	s := &DoHProxyServer{
		resolver:   resolver,
		conn:       conn,
		closed:     make(chan struct{}),
		listenAddr: conn.LocalAddr().String(),
	}

	go s.serve()
	return s, nil
}

// Addr returns the bound listener address.
func (s *DoHProxyServer) Addr() string {
	return s.listenAddr
}

func (s *DoHProxyServer) serve() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.closed:
			return
		default:
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.closed:
				return
			default:
				continue
			}
		}

		if n < 12 {
			continue
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		go func(q []byte, rAddr *net.UDPAddr) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			resp, err := s.resolver.Resolve(ctx, q)
			if err != nil || len(resp) < 12 {
				return
			}
			_, _ = s.conn.WriteToUDP(resp, rAddr)
		}(query, remoteAddr)
	}
}

// Close gracefully stops the DoH proxy server.
func (s *DoHProxyServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.conn != nil {
			_ = s.conn.Close()
		}
	})
	return nil
}
