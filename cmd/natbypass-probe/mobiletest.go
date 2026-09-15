// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pion/stun/v3"
)

// MobileSTUNSample represents a single STUN query result in the 10-probe series.
type MobileSTUNSample struct {
	Index      int    `json:"index"`
	Server     string `json:"server"`
	LocalPort  int    `json:"local_port"`
	MappedIP   string `json:"mapped_ip"`
	MappedPort int    `json:"mapped_port"`
	Delta      int    `json:"delta"` // difference from previous mapped port
	LatencyMs  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
}

// MobileTestReport contains the complete analysis of the carrier's CGNAT port allocation behavior.
type MobileTestReport struct {
	Timestamp            time.Time          `json:"timestamp"`
	Operator             string             `json:"operator"` // e.g. "MTS", "MegaFon", "Beeline", "Tele2", or ISP name
	ISP                  string             `json:"isp"`
	ASN                  string             `json:"asn"` // e.g. "AS31133"
	Country              string             `json:"country"`
	PublicIP             string             `json:"public_ip"`
	LocalIP              string             `json:"local_ip"`
	InterfaceType        string             `json:"interface_type"` // Cellular, Wi-Fi, Ethernet
	NATType              string             `json:"nat_type"`       // Cone, Symmetric
	PortAllocation       string             `json:"port_allocation"` // "sequential" | "fixed_step" | "small_jitter" | "random" | "cone_stable"
	BaseDelta            int                `json:"base_delta"`
	Confidence           float64            `json:"confidence"` // 0.0 .. 1.0 (fraction of deltas matching pattern)
	PortPredictionViable bool               `json:"port_prediction_viable"`
	Recommendation       string             `json:"recommendation"`
	Samples              []MobileSTUNSample `json:"samples"`
}

var mobileTestSTUNServers = []string{
	"162.159.207.0:3478",   // Cloudflare STUN direct IP
	"74.125.250.129:19302", // Google STUN direct IP
	"212.53.40.43:3478",    // Sipnet direct IP
	"195.201.201.32:443",   // Nextcloud port 443 direct IP
	"stun.cloudflare.com:3478",
	"stun.sipnet.ru:3478",
	"stun.miwifi.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.nextcloud.com:443",
}

// RunMobileTest executes the 10-probe STUN analysis and prints a detailed verdict.
func RunMobileTest(ctx context.Context, outputPath string, preferredPort int) error {
	logf("\n===========================================================")
	logf("📱 NATBYPASS MOBILE CGNAT & PORT ALLOCATION TEST (--mobile-test)")
	logf("===========================================================")
	logf("Анализ поведения симметричного CGNAT мобильных операторов (РФ/СНГ)")
	logf("Серия из 10 последовательных STUN-запросов из единого UDP-сокета...")

	report := &MobileTestReport{
		Timestamp: time.Now(),
		Samples:   make([]MobileSTUNSample, 0, len(mobileTestSTUNServers)),
	}

	// 1. Detect ISP, ASN, Public IP
	detectISPAndASN(ctx, report)
	logf("\n🌐 Провайдер / Сеть:")
	logf("  • Оператор / ISP: %s (%s)", report.ISP, report.Operator)
	logf("  • ASN:            %s", report.ASN)
	logf("  • Внешний IP:     %s", report.PublicIP)
	logf("  • Страна:         %s", report.Country)

	// 2. Open UDP Socket
	lAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", preferredPort))
	if err != nil {
		lAddr, _ = net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	}
	conn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP socket: %w", err)
	}
	defer conn.Close()

	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	report.LocalIP = conn.LocalAddr().String()
	logf("  • Локальный UDP порт: %d", localPort)

	logf("\n📡 Отправка серии из 10 STUN-зондов (интервал 150мс):")
	logf("----------------------------------------------------------------------")
	logf("%-4s | %-26s | %-21s | %-6s | %-5s", "#", "STUN Сервер", "Внешний эндпоинт", "Дельта", "RTT")
	logf("----------------------------------------------------------------------")

	prevPort := 0
	var successfulPorts []int
	var deltas []int

	buf := make([]byte, 2048)

	for i, srv := range mobileTestSTUNServers {
		sample := MobileSTUNSample{
			Index:     i + 1,
			Server:    srv,
			LocalPort: localPort,
		}

		srvAddr, err := net.ResolveUDPAddr("udp4", srv)
		if err != nil {
			sample.Error = err.Error()
			report.Samples = append(report.Samples, sample)
			logf("[%02d] | %-26s | Ошибка разрешения DNS  |   --   |  --", i+1, srv)
			continue
		}

		var txID [stun.TransactionIDSize]byte
		_, _ = rand.Read(txID[:])
		msg := stun.New()
		msg.TransactionID = txID
		msg.Type = stun.BindingRequest
		msg.WriteHeader()

		start := time.Now()
		if _, err := conn.WriteToUDP(msg.Raw, srvAddr); err != nil {
			sample.Error = err.Error()
			report.Samples = append(report.Samples, sample)
			logf("[%02d] | %-26s | Ошибка отправки пакета |   --   |  --", i+1, srv)
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		gotReply := false

		for {
			nRead, _, rErr := conn.ReadFromUDP(buf)
			if rErr != nil {
				break
			}
			if nRead <= 0 {
				continue
			}

			var resp stun.Message
			resp.Raw = buf[:nRead]
			if err := resp.Decode(); err != nil {
				continue
			}
			if resp.TransactionID != txID {
				continue // not our probe
			}

			sample.LatencyMs = time.Since(start).Milliseconds()

			var mappedIP net.IP
			var mappedPort int
			var xor stun.XORMappedAddress
			if err := xor.GetFrom(&resp); err == nil {
				mappedIP = xor.IP
				mappedPort = xor.Port
			} else {
				var plain stun.MappedAddress
				if err := plain.GetFrom(&resp); err == nil {
					mappedIP = plain.IP
					mappedPort = plain.Port
				}
			}

			if mappedPort > 0 {
				sample.MappedIP = mappedIP.String()
				sample.MappedPort = mappedPort
				successfulPorts = append(successfulPorts, mappedPort)

				deltaStr := "  --"
				if prevPort > 0 {
					d := mappedPort - prevPort
					sample.Delta = d
					deltas = append(deltas, d)
					deltaStr = fmt.Sprintf("%+6d", d)
				}
				prevPort = mappedPort
				gotReply = true

				endpointStr := fmt.Sprintf("%s:%d", mappedIP.String(), mappedPort)
				logf("[%02d] | %-26s | %-21s | %-6s | %3dms", i+1, srv, endpointStr, deltaStr, sample.LatencyMs)
			}
			break
		}

		if !gotReply {
			sample.Error = "timeout"
			logf("[%02d] | %-26s | Таймаут (нет ответа)   |   --   |  --", i+1, srv)
		}

		report.Samples = append(report.Samples, sample)
		time.Sleep(150 * time.Millisecond) // RFC pacing against carrier burst policing
	}

	logf("----------------------------------------------------------------------")

	// 3. Analyze Port Allocation
	analyzePortAllocation(report, successfulPorts, deltas)

	// 4. Output Summary Verdict
	logf("\n📊 ВЕРДИКТ И РЕКОМЕНДАЦИИ:")
	logf("  • Тип NAT:               %s", strings.ToUpper(report.NATType))
	logf("  • Стратегия портов:      %s", strings.ToUpper(report.PortAllocation))
	logf("  • Базовая дельта (Δ):    %+d", report.BaseDelta)
	logf("  • Достоверность:         %.1f%%", report.Confidence*100)
	predictionStr := "❌ НЕ ПРИМЕНИМО (Random allocation / Cone NAT)"
	if report.PortPredictionViable {
		predictionStr = fmt.Sprintf("✅ ПРИМЕНИМО (Уровень 4: Port Prediction с дельтой %+d)", report.BaseDelta)
	}
	logf("  • Port Prediction:       %s", predictionStr)
	logf("  • Рекомендация:          %s", report.Recommendation)

	// 5. Save report JSON if requested
	if outputPath == "" {
		safeOp := strings.ToLower(strings.ReplaceAll(report.Operator, " ", "_"))
		if safeOp == "" {
			safeOp = "cgnat"
		}
		outputPath = fmt.Sprintf("mobile_test_%s_%s.json", safeOp, time.Now().Format("20060102_150405"))
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		if writeErr := os.WriteFile(outputPath, data, 0644); writeErr == nil {
			logf("\n💾 Полный JSON-отчет сохранен в: %s", outputPath)
		}
	}

	logf("===========================================================\n")
	return nil
}

func analyzePortAllocation(report *MobileTestReport, ports []int, deltas []int) {
	if len(ports) < 2 {
		report.NATType = "unknown"
		report.PortAllocation = "insufficient_data"
		report.Recommendation = "Не удалось получить достаточное количество ответов STUN для надежного анализа."
		return
	}

	// Check if all ports are identical (Cone NAT)
	allSame := true
	for i := 1; i < len(ports); i++ {
		if ports[i] != ports[0] {
			allSame = false
			break
		}
	}

	if allSame {
		report.NATType = "full_cone"
		report.PortAllocation = "cone_stable"
		report.BaseDelta = 0
		report.Confidence = 1.0
		report.PortPredictionViable = false
		report.Recommendation = "Симметричный CGNAT отсутствует (Cone NAT). Прямой Hole Punching (Уровень 2) работает без предсказания портов."
		return
	}

	report.NATType = "symmetric"

	if len(deltas) == 0 {
		report.PortAllocation = "unknown"
		return
	}

	// Count delta occurrences
	counts := make(map[int]int)
	for _, d := range deltas {
		counts[d]++
	}

	// Find mode delta
	bestDelta := deltas[0]
	maxFreq := 0
	for d, count := range counts {
		if count > maxFreq {
			maxFreq = count
			bestDelta = d
		}
	}

	confidence := float64(maxFreq) / float64(len(deltas))
	report.BaseDelta = bestDelta
	report.Confidence = confidence

	// Check for sequential (+1 or -1)
	if (bestDelta == 1 || bestDelta == -1) && confidence >= 0.6 {
		report.PortAllocation = "sequential"
		report.PortPredictionViable = true
		report.Recommendation = fmt.Sprintf("Оператор использует последовательное выделение портов (дельта %+d). Port Prediction (Уровень 4) высокоэффективен!", bestDelta)
		return
	}

	// Check for fixed step (|delta| <= 16)
	absDelta := bestDelta
	if absDelta < 0 {
		absDelta = -absDelta
	}
	if absDelta > 1 && absDelta <= 16 && confidence >= 0.5 {
		report.PortAllocation = "fixed_step"
		report.PortPredictionViable = true
		report.Recommendation = fmt.Sprintf("Оператор использует фиксированный шаг портов (дельта %+d). Port Prediction (Уровень 4) применим с окном ±%d портов.", bestDelta, absDelta*2)
		return
	}

	// Check for small jitter (majority of deltas within [-16..+16])
	smallJitterCount := 0
	for _, d := range deltas {
		if d >= -16 && d <= 16 {
			smallJitterCount++
		}
	}
	jitterRatio := float64(smallJitterCount) / float64(len(deltas))
	if jitterRatio >= 0.7 {
		report.PortAllocation = "small_jitter"
		report.PortPredictionViable = true
		report.Recommendation = "Оператор выделяет порты с небольшим разбросом (Small Jitter). Port Prediction (Уровень 4) возможен с веерным окном ±10..15 портов."
		return
	}

	// High variance / random
	report.PortAllocation = "random"
	report.PortPredictionViable = false
	report.Recommendation = "Оператор использует полностью случайное выделение портов (RFC 4787 Random CGNAT). Port Prediction неэффективен; связь гарантируется через Уровень 3 (Coordinated Punch) или Уровень 5 (Peer-as-Relay)."
}

func detectISPAndASN(ctx context.Context, report *MobileTestReport) {
	report.Operator = "Unknown"
	report.ISP = "Unknown"
	report.ASN = "Unknown"
	report.Country = "RU"

	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,query", nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		// Fallback to ipinfo.io
		detectISPFromIpinfo(ctx, report)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var data struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Query       string `json:"query"`
	}

	if err := json.Unmarshal(body, &data); err == nil && data.Status == "success" {
		report.PublicIP = data.Query
		report.ISP = data.ISP
		report.Country = data.CountryCode
		if parts := strings.Split(data.AS, " "); len(parts) > 0 {
			report.ASN = parts[0]
		} else {
			report.ASN = data.AS
		}
		report.Operator = normalizeRussianOperator(data.ISP + " " + data.Org + " " + data.AS)
	} else {
		detectISPFromIpinfo(ctx, report)
	}
}

func detectISPFromIpinfo(ctx context.Context, report *MobileTestReport) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		Org     string `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		if report.PublicIP == "" {
			report.PublicIP = data.IP
		}
		if report.Country == "" || report.Country == "RU" {
			report.Country = data.Country
		}
		report.ISP = data.Org
		if parts := strings.Split(data.Org, " "); len(parts) > 0 && strings.HasPrefix(parts[0], "AS") {
			report.ASN = parts[0]
		}
		report.Operator = normalizeRussianOperator(data.Org)
	}
}

func normalizeRussianOperator(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "megafon") || strings.Contains(lower, "мегафон") || strings.Contains(lower, "31133"):
		return "MegaFon"
	case strings.Contains(lower, "mts") || strings.Contains(lower, "мтс") || strings.Contains(lower, "8359"):
		return "MTS"
	case strings.Contains(lower, "beeline") || strings.Contains(lower, "vimpelcom") || strings.Contains(lower, "билайн") || strings.Contains(lower, "3216"):
		return "Beeline"
	case strings.Contains(lower, "tele2") || strings.Contains(lower, "теле2") || strings.Contains(lower, "t2") || strings.Contains(lower, "rostelecom") || strings.Contains(lower, "41552"):
		return "Tele2"
	case strings.Contains(lower, "yota") || strings.Contains(lower, "йота"):
		return "Yota"
	case strings.Contains(lower, "tinkoff") || strings.Contains(lower, "тинькофф"):
		return "T-Mobile / Tinkoff"
	default:
		if len(text) > 25 {
			return text[:25]
		}
		return text
	}
}
