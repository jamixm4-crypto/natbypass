// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package shadowtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const nginxBody = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`

// BuildNginxHTTPResponse builds a byte-perfect HTTP 1.1 200 OK response matching Ubuntu Nginx 1.24.
func BuildNginxHTTPResponse() []byte {
	dateStr := time.Now().UTC().Format(http.TimeFormat)
	hdr := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n" +
			"Server: nginx/1.24.0 (Ubuntu)\r\n" +
			"Date: %s\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: %d\r\n" +
			"Last-Modified: Mon, 11 Jun 2024 10:00:00 GMT\r\n" +
			"Connection: close\r\n" +
			"ETag: \"66682280-264\"\r\n" +
			"Accept-Ranges: bytes\r\n\r\n",
		dateStr, len(nginxBody),
	)
	resp := make([]byte, len(hdr)+len(nginxBody))
	copy(resp, hdr)
	copy(resp[len(hdr):], nginxBody)
	return resp
}

// ServeNginxHTTP responds to non-TLS probes (e.g. plain HTTP scanners, Shodan, Censys)
// with an authentic Nginx 200 OK response and gracefully closes the connection.
func ServeNginxHTTP(conn net.Conn) {
	defer conn.Close()
	resp := BuildNginxHTTPResponse()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(resp)
	time.Sleep(50 * time.Millisecond)
}

// ServeNginxTLS completes a TLS handshake and serves the Nginx 200 OK response over HTTPS
// when upstream proxying to SNI fails or is blocked, deflecting active HTTPS probing.
func ServeNginxTLS(conn net.Conn, networkKey [32]byte, sni string) {
	defer conn.Close()

	cert, err := GetOrCreateMeshCertificate("mesh-server", "", networkKey)
	if err != nil {
		return
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}

	tlsConn := tls.Server(conn, serverConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}

	// Read probe request with short deadline
	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	_, _ = tlsConn.Read(buf)

	// Send Nginx response over TLS
	resp := BuildNginxHTTPResponse()
	_ = tlsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = tlsConn.Write(resp)
	time.Sleep(50 * time.Millisecond)
}

// SafeDrainAndDiscard reads and drains up to 4KB from conn without blocking.
func SafeDrainAndDiscard(r io.Reader) {
	var buf [512]byte
	for {
		n, err := r.Read(buf[:])
		if err != nil || n == 0 {
			break
		}
	}
}
