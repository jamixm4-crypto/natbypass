// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package shadowtls

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildNginxHTTPResponse(t *testing.T) {
	resp := BuildNginxHTTPResponse()
	respStr := string(resp)

	if !strings.Contains(respStr, "HTTP/1.1 200 OK") {
		t.Errorf("expected HTTP 200 OK, got: %s", respStr)
	}
	if !strings.Contains(respStr, "Server: nginx/1.24.0 (Ubuntu)") {
		t.Errorf("expected Server: nginx header, got: %s", respStr)
	}
	if !strings.Contains(respStr, "Welcome to nginx!") {
		t.Errorf("expected nginx body content, got: %s", respStr)
	}
}

func TestServeNginxHTTP(t *testing.T) {
	client, server := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeNginxHTTP(server)
	}()

	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("failed to read from server: %v", err)
	}
	_ = client.Close()

	<-done

	respStr := string(buf[:n])
	if !strings.Contains(respStr, "Welcome to nginx!") {
		t.Errorf("expected welcome to nginx, got: %s", respStr)
	}
}

func TestServeNginxTLS(t *testing.T) {
	client, server := net.Pipe()

	var testKey [32]byte
	copy(testKey[:], []byte("test-key-32-bytes-long-123456789"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeNginxTLS(server, testKey, "example.com")
	}()

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
	})

	writeDone := make(chan error, 1)
	go func() {
		_ = tlsClient.SetDeadline(time.Now().Add(2 * time.Second))
		_, err := tlsClient.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("failed to write HTTP request: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out writing HTTP request")
	}

	buf := new(bytes.Buffer)
	tmp := make([]byte, 1024)
	for {
		_ = tlsClient.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := tlsClient.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	_ = tlsClient.Close()
	<-done

	respStr := buf.String()
	if !strings.Contains(respStr, "Welcome to nginx!") {
		t.Errorf("expected Nginx page over TLS, got: %s", respStr)
	}
}
