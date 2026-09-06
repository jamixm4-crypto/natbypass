// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TCPTestResult — результат TCP-теста
type TCPTestResult struct {
	Port      int
	Success   bool
	LatencyMs int64
	Error     string
}

// TestTCPConnectivity проверяет TCP соединение на нескольких портах
func TestTCPConnectivity(ctx context.Context, myNodeID, targetNodeID, targetHost string) []TCPTestResult {
	ports := []int{443, 80, 8080, 22, 3478}
	results := make([]TCPTestResult, 0, len(ports))

	for _, port := range ports {
		result := TCPTestResult{Port: port}
		addr := fmt.Sprintf("%s:%d", targetHost, port)

		ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		d := net.Dialer{}
		conn, err := d.DialContext(ctxTimeout, "tcp", addr)
		cancel()

		if err == nil {
			conn.Close()
			result.Success = true
			result.LatencyMs = time.Since(start).Milliseconds()
			logf("[TCP] %s → %s:%d: SUCCESS (%dms)", myNodeID, targetHost, port, result.LatencyMs)
		} else {
			result.Error = err.Error()
			logf("[TCP] %s → %s:%d: FAIL", myNodeID, targetHost, port)
		}
		results = append(results, result)
	}
	return results
}
