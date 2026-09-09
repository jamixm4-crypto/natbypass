// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dns

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// buildDummyDNSQuery builds a valid wire-format DNS query for example.com (type A).
func buildDummyDNSQuery(txID uint16) []byte {
	return []byte{
		byte(txID >> 8), byte(txID & 0xFF), // ID
		0x01, 0x00,                         // Flags: Standard query, recursion desired
		0x00, 0x01,                         // QDCOUNT: 1
		0x00, 0x00,                         // ANCOUNT: 0
		0x00, 0x00,                         // NSCOUNT: 0
		0x00, 0x00,                         // ARCOUNT: 0
		// QNAME: 7example3com0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // QTYPE: A
		0x00, 0x01, // QCLASS: IN
	}
}

func buildDummyDNSResponse(txID uint16, ttl uint32) []byte {
	return []byte{
		byte(txID >> 8), byte(txID & 0xFF), // ID
		0x81, 0x80,                         // Flags: Standard query response, No error
		0x00, 0x01,                         // QDCOUNT: 1
		0x00, 0x01,                         // ANCOUNT: 1
		0x00, 0x00,                         // NSCOUNT: 0
		0x00, 0x00,                         // ARCOUNT: 0
		// Question
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01,
		0x00, 0x01,
		// Answer: pointer to QNAME (0xc00c), Type A(1), Class IN(1), TTL, RDLENGTH(4), RDATA(93.184.216.34)
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl & 0xFF),
		0x00, 0x04,
		93, 184, 216, 34,
	}
}

func TestDoHResolver_MockResolutionAndCache(t *testing.T) {
	queriesHandled := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queriesHandled++
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			t.Errorf("Expected application/dns-message, got %s", r.Header.Get("Content-Type"))
		}

		resp := buildDummyDNSResponse(0x1234, 120)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	}))
	defer ts.Close()

	resolver := NewDoHResolver([]string{ts.URL})

	// First query: goes to mock HTTP server
	q1 := buildDummyDNSQuery(0x1111)
	resp1, err := resolver.Resolve(context.Background(), q1)
	if err != nil {
		t.Fatalf("First resolve failed: %v", err)
	}
	if len(resp1) < 12 {
		t.Fatal("Response too short")
	}
	// Transaction ID must match client query
	if resp1[0] != 0x11 || resp1[1] != 0x11 {
		t.Errorf("Expected TxID 0x1111, got 0x%02x%02x", resp1[0], resp1[1])
	}
	if queriesHandled != 1 {
		t.Fatalf("Expected 1 query handled, got %d", queriesHandled)
	}

	// Second query with different TxID: should HIT CACHE and not call mock HTTP server
	q2 := buildDummyDNSQuery(0x2222)
	resp2, err := resolver.Resolve(context.Background(), q2)
	if err != nil {
		t.Fatalf("Second resolve failed: %v", err)
	}
	if resp2[0] != 0x22 || resp2[1] != 0x22 {
		t.Errorf("Expected TxID 0x2222 from cache, got 0x%02x%02x", resp2[0], resp2[1])
	}
	if queriesHandled != 1 {
		t.Errorf("Expected cache hit (queriesHandled=1), got %d", queriesHandled)
	}
}

func TestDoHResolver_FallbackUpstream(t *testing.T) {
	// First server always fails (500)
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts1.Close()

	// Second server succeeds
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildDummyDNSResponse(0x9999, 60)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	}))
	defer ts2.Close()

	resolver := NewDoHResolver([]string{ts1.URL, ts2.URL})
	q := buildDummyDNSQuery(0x7777)
	resp, err := resolver.Resolve(context.Background(), q)
	if err != nil {
		t.Fatalf("Fallback resolve failed: %v", err)
	}
	if resp[0] != 0x77 || resp[1] != 0x77 {
		t.Errorf("Expected TxID 0x7777, got 0x%02x%02x", resp[0], resp[1])
	}
}

func TestDoHProxyServer_UDPEndToEnd(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildDummyDNSResponse(0xABCD, 300)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	}))
	defer ts.Close()

	resolver := NewDoHResolver([]string{ts.URL})

	// Bind proxy server to dynamic UDP port
	proxy, err := NewDoHProxyServer("127.0.0.1:0", resolver)
	if err != nil {
		t.Fatalf("Failed to create DoHProxyServer: %v", err)
	}
	defer proxy.Close()

	// Connect client to proxy
	clientConn, err := net.Dial("udp", proxy.Addr())
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer clientConn.Close()

	query := buildDummyDNSQuery(0x5555)
	if _, err := clientConn.Write(query); err != nil {
		t.Fatalf("Failed to write query: %v", err)
	}

	buf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if n < 12 {
		t.Fatalf("Response too short: %d bytes", n)
	}
	if buf[0] != 0x55 || buf[1] != 0x55 {
		t.Errorf("Expected TxID 0x5555, got 0x%02x%02x", buf[0], buf[1])
	}
}
