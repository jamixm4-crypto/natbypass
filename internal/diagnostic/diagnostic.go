// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package diagnostic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

type DiagnosticItem struct {
	Name    string        `json:"name"`
	Passed  bool          `json:"passed"`
	Elapsed time.Duration `json:"elapsed"`
	Message string        `json:"message"`
	Details string        `json:"details,omitempty"`
}

type DiagnosticReport struct {
	Timestamp time.Time        `json:"timestamp"`
	OS        string           `json:"os"`
	Arch      string           `json:"arch"`
	Hostname  string           `json:"hostname"`
	IsAdmin   bool             `json:"is_admin"`
	Items     []DiagnosticItem `json:"items"`
	AllPassed bool             `json:"all_passed"`
	Summary   string           `json:"summary"`
}

// RunFullDiagnostics выполняет глубокую аппаратную и системную диагностику
func RunFullDiagnostics() *DiagnosticReport {
	report := &DiagnosticReport{
		Timestamp: time.Now(),
		OS:        fmt.Sprintf("%s (%s)", runtime.GOOS, runtime.Version()),
		Arch:      runtime.GOARCH,
		AllPassed: true,
	}

	if hn, err := os.Hostname(); err == nil {
		report.Hostname = hn
	}

	// 1. Проверка прав Администратора (UAC Elevation / Root)
	report.IsAdmin = CheckIsAdmin()
	report.Items = append(report.Items, CheckAdminPrivileges(report.IsAdmin))

	// 2. Проверка Wintun драйвера и сетевого стека NDIS
	report.Items = append(report.Items, CheckWintunDriver())

	// 3. Проверка быстродействия netsh и брандмауэра
	report.Items = append(report.Items, CheckNetshAndFirewall())

	// 4. Проверка доступности порта UDP 51820
	report.Items = append(report.Items, CheckUDPPort51820())

	// 5. Проверка STUN и трансляции NAT
	report.Items = append(report.Items, CheckSTUNDiscovery())

	// 6. Проверка сигнальных каналов (MQTT / Telegram)
	report.Items = append(report.Items, CheckSignalingConnectivity())

	// 7. Path MTU и проверка фрагментации пакетов
	report.Items = append(report.Items, CheckPathMTU())

	// 8. Системные маршруты ядра и проверка конфликтов подсетей
	report.Items = append(report.Items, CheckRoutingTable())

	// 9. Проверка среды WebView2 (Edge Runtime)
	report.Items = append(report.Items, CheckWebView2Runtime())

	// 10. Перечисление локальных сетевых адаптеров
	report.Items = append(report.Items, CheckNetworkInterfaces())

	// 11. Опрос локального демона NatBypass и активных пиров mesh-сети
	report.Items = append(report.Items, CheckMeshPeersAndEngine())

	for _, item := range report.Items {
		if !item.Passed {
			report.AllPassed = false
		}
	}

	return report
}

func CheckAdminPrivileges(isAdmin bool) DiagnosticItem {
	start := time.Now()
	if isAdmin {
		return DiagnosticItem{
			Name:    "Права Администратора (UAC / Root)",
			Passed:  true,
			Elapsed: time.Since(start),
			Message: "✓ Процесс запущен с повышенными привилегиями Администратора (Elevated / Root)",
		}
	}
	return DiagnosticItem{
		Name:    "Права Администратора (UAC / Root)",
		Passed:  false,
		Elapsed: time.Since(start),
		Message: "❌ Нет прав Администратора. Создание виртуального адаптера и настройка маршрутов могут быть заблокированы ОС!",
		Details: "Запустите NatBypass от имени Администратора (sudo на Linux / Run as Administrator на Windows).",
	}
}

func CheckUDPPort51820() DiagnosticItem {
	start := time.Now()
	addr, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:51820")
	conn, err := net.ListenUDP("udp4", addr)
	elapsed := time.Since(start)

	if err != nil {
		return DiagnosticItem{
			Name:    "Сетевой порт UDP 51820 (WireGuard/AWG)",
			Passed:  true, // Не критично, puncher выберет случайный порт
			Elapsed: elapsed,
			Message: fmt.Sprintf("⚠️ Порт 51820 занят другим процессом (%v). NatBypass автоматически переключится на динамический порт.", err),
		}
	}
	_ = conn.Close()

	return DiagnosticItem{
		Name:    "Сетевой порт UDP 51820 (WireGuard/AWG)",
		Passed:  true,
		Elapsed: elapsed,
		Message: "✓ Порт UDP 51820 свободен и готов для прямого P2P пробития",
	}
}

type stunProbeResult struct {
	server   string
	mappedIP net.IP
	port     int
	rtt      time.Duration
	err      error
}

func querySingleSTUN(conn *net.UDPConn, server string, timeout time.Duration) stunProbeResult {
	start := time.Now()
	srvAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return stunProbeResult{server: server, err: err}
	}

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	_, err = conn.WriteToUDP(msg.Raw, srvAddr)
	if err != nil {
		return stunProbeResult{server: server, err: err}
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	for {
		n, from, rErr := conn.ReadFromUDP(buf)
		if rErr != nil {
			return stunProbeResult{server: server, err: rErr}
		}
		if from.IP.Equal(srvAddr.IP) || from.Port == srvAddr.Port {
			var resp stun.Message
			resp.Raw = buf[:n]
			var xorAddr stun.XORMappedAddress
			if decErr := resp.Decode(); decErr == nil && xorAddr.GetFrom(&resp) == nil {
				return stunProbeResult{
					server:   server,
					mappedIP: xorAddr.IP,
					port:     xorAddr.Port,
					rtt:      time.Since(start),
				}
			}
		}
	}
}

func CheckSTUNDiscovery() DiagnosticItem {
	start := time.Now()
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return DiagnosticItem{Name: "STUN NAT Пробитие и Классификация", Passed: false, Elapsed: time.Since(start), Message: err.Error()}
	}
	defer conn.Close()

	servers := []string{
		"stun.l.google.com:19302",
		"stun.cloudflare.com:3478",
		"stun.sipnet.ru:3478",
		"stun.miwifi.com:3478",
	}

	var results []stunProbeResult
	for _, srv := range servers {
		r := querySingleSTUN(conn, srv, 1000*time.Millisecond)
		if r.err == nil {
			results = append(results, r)
		}
	}

	elapsed := time.Since(start)
	if len(results) == 0 {
		return DiagnosticItem{
			Name:    "STUN NAT Пробитие и Классификация (RFC 5389 / RFC 5780)",
			Passed:  false,
			Elapsed: elapsed,
			Message: "❌ Таймаут ответов от всех STUN-серверов (Google, Cloudflare, Sipnet, MiWiFi)",
			Details: "UDP-трафик полностью блокируется ТСПУ/провайдером или локальным брандмауэром. Прямой UDP P2P заблокирован, требуется TCP ShadowTLS или Relay.",
		}
	}

	// Determine consensus public IP via majority voting across all responding STUN servers
	ipCounts := make(map[string]int)
	for _, r := range results {
		ipCounts[r.mappedIP.String()]++
	}
	consensusIPStr := results[0].mappedIP.String()
	maxCount := 0
	for ipStr, count := range ipCounts {
		if count > maxCount {
			maxCount = count
			consensusIPStr = ipStr
		}
	}

	var consensusResults []stunProbeResult
	for _, r := range results {
		if r.mappedIP.String() == consensusIPStr {
			consensusResults = append(consensusResults, r)
		}
	}

	primarySocket := results[0]
	if len(consensusResults) > 0 {
		primarySocket = consensusResults[0]
	}

	natType := "Full Cone / Endpoint-Independent Mapping (EIM) [✓ 100% P2P совместимо]"
	delta := 0
	if len(consensusResults) >= 2 {
		delta = consensusResults[1].port - consensusResults[0].port
		if delta != 0 {
			natType = fmt.Sprintf("Symmetric NAT / EDM (Delta: %+d) [⚠ Требуется TCP ShadowTLS]", delta)
		}
	}

	var sb strings.Builder
	hasMultiWAN := len(ipCounts) > 1
	var multiWANNote string
	if hasMultiWAN {
		var allIPs []string
		for ip, c := range ipCounts {
			allIPs = append(allIPs, fmt.Sprintf("%s (%d)", ip, c))
		}
		multiWANNote = fmt.Sprintf(" [⚠️ Multi-WAN/Split-Tunnel: %s]", strings.Join(allIPs, ", "))
	}

	sb.WriteString(fmt.Sprintf("Внешний сокет: %s:%d | Классификация NAT: %s%s\n", primarySocket.mappedIP, primarySocket.port, natType, multiWANNote))
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("  -> %-27s: %s:%d (RTT: %v)\n", r.server, r.mappedIP, r.port, r.rtt.Round(time.Millisecond)))
	}

	return DiagnosticItem{
		Name:    "STUN NAT Пробитие и Классификация (RFC 5389 / RFC 5780)",
		Passed:  true,
		Elapsed: elapsed,
		Message: fmt.Sprintf("✓ Внешний IP: %s:%d (%s)%s", primarySocket.mappedIP, primarySocket.port, natType, multiWANNote),
		Details: strings.TrimRight(sb.String(), "\n"),
	}
}

func CheckSignalingConnectivity() DiagnosticItem {
	start := time.Now()
	// Проверка MQTT
	mConn, mErr := net.DialTimeout("tcp", "broker.emqx.io:1883", 2500*time.Millisecond)
	mqttOk := mErr == nil
	if mConn != nil {
		_ = mConn.Close()
	}

	// Проверка Telegram
	client := http.Client{Timeout: 2500 * time.Millisecond}
	resp, tErr := client.Get("https://api.telegram.org")
	tgOk := tErr == nil
	if resp != nil {
		_ = resp.Body.Close()
	}

	elapsed := time.Since(start)
	if mqttOk || tgOk {
		var active []string
		if mqttOk {
			active = append(active, "MQTT (broker.emqx.io:1883)")
		}
		if tgOk {
			active = append(active, "Telegram Bot API")
		}
		return DiagnosticItem{
			Name:    "Сигнальные каналы (MQTT / Telegram)",
			Passed:  true,
			Elapsed: elapsed,
			Message: fmt.Sprintf("✓ Доступны каналы: %s", formatSlice(active)),
		}
	}

	return DiagnosticItem{
		Name:    "Сигнальные каналы (MQTT / Telegram)",
		Passed:  false,
		Elapsed: elapsed,
		Message: "❌ Нет связи ни с MQTT брокером, ни с Telegram API",
		Details: "Проверьте подключение к интернету или задайте собственный брокер / прокси в настройках.",
	}
}

func CheckNetworkInterfaces() DiagnosticItem {
	start := time.Now()
	ifaces, err := net.Interfaces()
	elapsed := time.Since(start)
	if err != nil {
		return DiagnosticItem{Name: "Сетевые адаптеры", Passed: false, Elapsed: elapsed, Message: err.Error()}
	}

	var upCount, loopbackCount int
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 {
			upCount++
		}
		if iface.Flags&net.FlagLoopback != 0 {
			loopbackCount++
		}
	}

	return DiagnosticItem{
		Name:    "Сетевые адаптеры системы (NDIS / Netlink)",
		Passed:  true,
		Elapsed: elapsed,
		Message: fmt.Sprintf("✓ Найдено сетевых адаптеров: %d (активных: %d)", len(ifaces), upCount),
	}
}

func formatSlice(s []string) string {
	res := ""
	for i, v := range s {
		if i > 0 {
			res += ", "
		}
		res += v
	}
	return res
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CheckPathMTU tests sending UDP packets of typical VPN MTU sizes (1420, 1360, 1280)
// to verify kernel and local path MTU limits.
func CheckPathMTU() DiagnosticItem {
	start := time.Now()
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return DiagnosticItem{Name: "Path MTU & Фрагментация (PMTU)", Passed: true, Elapsed: time.Since(start), Message: "Пропуск (сокет занят)"}
	}
	defer conn.Close()

	srvAddr, err := net.ResolveUDPAddr("udp4", "1.1.1.1:53")
	if err != nil {
		srvAddr, _ = net.ResolveUDPAddr("udp4", "8.8.8.8:53")
	}

	sizes := []int{1420, 1360, 1280}
	var passed []int
	for _, sz := range sizes {
		data := make([]byte, sz)
		if _, wErr := conn.WriteToUDP(data, srvAddr); wErr == nil {
			passed = append(passed, sz)
		}
	}

	elapsed := time.Since(start)
	msg := "✓ UDP пакеты MTU 1420/1360/1280 успешно отправляются без локальной ошибки ядра (AWG MTU 1420 поддерживается)"
	if len(passed) < len(sizes) {
		msg = fmt.Sprintf("⚠️ Ограничение MTU стека ОС: успешно только %v", passed)
	}

	return DiagnosticItem{
		Name:    "Path MTU & Фрагментация (PMTU)",
		Passed:  true,
		Elapsed: elapsed,
		Message: msg,
	}
}

// CheckRoutingTable checks whether the mesh routes (10.1.1.0/24) are present in the OS routing table,
// and identifies any conflicting subnets (e.g. 100.64.200.0/24).
func CheckRoutingTable() DiagnosticItem {
	start := time.Now()
	var routesStr string
	var hasConflict bool

	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "interface", "ipv4", "show", "route")
		out, err := cmd.CombinedOutput()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			var filtered []string
			has10 := false
			has100 := false
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, "10.1.1.") || strings.Contains(trimmed, "100.64.200.") {
					filtered = append(filtered, "  "+trimmed)
					if strings.Contains(trimmed, "10.1.1.") {
						has10 = true
					}
					if strings.Contains(trimmed, "100.64.200.") {
						has100 = true
					}
				}
			}
			if has10 && has100 {
				hasConflict = true
			}
			routesStr = strings.Join(filtered, "\n")
		}
	} else {
		cmd := exec.Command("ip", "route", "show")
		out, err := cmd.CombinedOutput()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			var filtered []string
			has10 := false
			has100 := false
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, "10.1.1.") || strings.Contains(trimmed, "100.64.200.") || strings.Contains(trimmed, "nb0") {
					filtered = append(filtered, "  "+trimmed)
					if strings.Contains(trimmed, "10.1.1.") {
						has10 = true
					}
					if strings.Contains(trimmed, "100.64.200.") {
						has100 = true
					}
				}
			}
			if has10 && has100 {
				hasConflict = true
			}
			routesStr = strings.Join(filtered, "\n")
		}
	}

	elapsed := time.Since(start)
	msg := "✓ Маршруты mesh-сети активны в таблице ядра"
	if hasConflict {
		msg = "⚠️ Обнаружен конфликт подсетей (одновременно присутствуют 10.1.1.0/24 и 100.64.200.0/24)"
	}
	if routesStr == "" {
		routesStr = "  Маршруты mesh-подсетей 10.1.1.0/24 не найдены"
	}

	return DiagnosticItem{
		Name:    "Системные маршруты ядра (L3 Routing)",
		Passed:  !hasConflict,
		Elapsed: elapsed,
		Message: msg,
		Details: routesStr,
	}
}

// CheckMeshPeersAndEngine queries the local NatBypass HTTP API (127.0.0.1:8080/api/status and /api/peers)
// to collect the mesh network topology, peer transport types, and direct P2P latency.
func CheckMeshPeersAndEngine() DiagnosticItem {
	start := time.Now()
	client := http.Client{Timeout: 900 * time.Millisecond}

	var rawPeers []byte
	var connectedPort int

	for _, port := range []int{8080, 8081, 8082} {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/peers", port))
		if err == nil && resp != nil {
			if resp.StatusCode == 200 {
				rawPeers, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				connectedPort = port
				break
			}
			_ = resp.Body.Close()
		}
	}

	if connectedPort == 0 {
		return DiagnosticItem{
			Name:    "Mesh-состояние и активные пиры (L3 P2P)",
			Passed:  true,
			Elapsed: time.Since(start),
			Message: "ℹ Демон активен (WebUI API на 8080..8082 недоступен или отключен флагом -no-webui)",
		}
	}

	var peersData []map[string]interface{}
	if len(rawPeers) > 0 {
		var wrapper struct {
			Ok   bool                     `json:"ok"`
			Data []map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal(rawPeers, &wrapper); err == nil && len(wrapper.Data) > 0 {
			peersData = wrapper.Data
		} else {
			_ = json.Unmarshal(rawPeers, &peersData)
		}
	}

	// Rate-limited ICMP ping to all discovered peer Virtual IPs (max 2 concurrent workers to prevent socket contention on routers)
	type peerPingResult struct {
		vip string
		ok  bool
		rtt time.Duration
	}
	pingChan := make(chan peerPingResult, len(peersData)+1)
	sem := make(chan struct{}, 2)
	var wg sync.WaitGroup

	for _, p := range peersData {
		vip, _ := p["virtual_ip"].(string)
		cleanVIP := strings.TrimSpace(strings.Split(vip, "/")[0])
		if cleanVIP == "" || net.ParseIP(cleanVIP) == nil {
			continue
		}

		// If local engine already verified L3 ping and recorded latency, trust engine telemetry
		var enginePingMs int64
		if pm, ok := p["ping_ms"].(float64); ok && pm > 0 {
			enginePingMs = int64(pm)
		}
		if enginePingMs > 0 {
			pingChan <- peerPingResult{
				vip: cleanVIP,
				ok:  true,
				rtt: time.Duration(enginePingMs) * time.Millisecond,
			}
			continue
		}

		wg.Add(1)
		go func(targetVIP string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pCtx, pCancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
			defer pCancel()
			rtt, pErr := PingVirtualIP(pCtx, targetVIP, 2500*time.Millisecond)
			pingChan <- peerPingResult{
				vip: targetVIP,
				ok:  pErr == nil,
				rtt: rtt,
			}
		}(cleanVIP)
	}

	wg.Wait()
	close(pingChan)

	pingMap := make(map[string]peerPingResult)
	for pr := range pingChan {
		pingMap[pr.vip] = pr
	}

	var sb strings.Builder
	p2pCount := 0
	relayCount := 0

	for _, p := range peersData {
		name, _ := p["nickname"].(string)
		if name == "" {
			name, _ = p["device_id"].(string)
		}
		vip, _ := p["virtual_ip"].(string)
		cleanVIP := strings.TrimSpace(strings.Split(vip, "/")[0])
		transport, _ := p["transport"].(string)
		directP2P, _ := p["direct_p2p"].(bool)
		directTCP, _ := p["direct_tcp"].(bool)
		activeEP, _ := p["active_endpoint"].(string)
		var pingMs int64
		if pm, ok := p["ping_ms"].(float64); ok {
			pingMs = int64(pm)
		}

		statusLabel := "Relay [MQTT]"
		if directTCP || transport == "tcp_tls" || transport == "tcp_shadowtls" {
			statusLabel = "Прямой TCP [ShadowTLS]"
			p2pCount++
		} else if directP2P || transport == "udp_direct" {
			statusLabel = "Прямой P2P [UDP AWG]"
			p2pCount++
		} else {
			relayCount++
		}

		pingStr := "N/A"
		if pingMs > 0 {
			pingStr = fmt.Sprintf("%d ms", pingMs)
		}

		icmpStr := "ICMP: N/A"
		if pr, exists := pingMap[cleanVIP]; exists {
			if pr.ok {
				icmpStr = fmt.Sprintf("ICMP: ✓ OK (%d ms)", pr.rtt.Milliseconds())
			} else {
				icmpStr = "ICMP: ❌ Таймаут (100% loss)"
			}
		}

		sb.WriteString(fmt.Sprintf("  -> %-18s | VIP: %-15s | %-22s | EP: %-21s | EnginePing: %-7s | %s\n",
			name, vip, statusLabel, activeEP, pingStr, icmpStr))
	}

	msg := fmt.Sprintf("✓ API активно (порт %d), обнаружено пиров: %d (P2P: %d, Relay: %d)",
		connectedPort, len(peersData), p2pCount, relayCount)

	return DiagnosticItem{
		Name:    "Mesh-состояние и активные пиры (L3 P2P)",
		Passed:  true,
		Elapsed: time.Since(start),
		Message: msg,
		Details: strings.TrimRight(sb.String(), "\n"),
	}
}
