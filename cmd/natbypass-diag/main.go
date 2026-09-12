// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/diagnostic"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/updater"
)

var (
	flagTopic   = flag.String("topic", "", "Signaling topic, URL, or natbypass://profile link")
	flagBroker  = flag.String("broker", "", "MQTT broker URL (defaults to profile or ssl://broker.emqx.io:8883)")
	flagKey     = flag.String("key", "", "NetworkKey for room encryption/decryption")
	flagTarget  = flag.String("target", "", "Target DeviceID to diagnose or update (empty = all beta nodes)")
	flagUpdate  = flag.Bool("update", false, "Trigger remote beta update across target/all nodes")
	flagBatch   = flag.Bool("batch", false, "Run non-interactively in batch mode (execute and exit)")
	flagTimeout = flag.Duration("timeout", 45*time.Second, "Response collection timeout")
	flagOutput  = flag.String("output", "", "Output filename for consolidated cluster report")
	flagLocal   = flag.Bool("local", false, "Include local host diagnostic report in the consolidated output")
	flagConfig  = flag.String("config", "config.yaml", "Path to config.yaml (used for defaults)")
)

const (
	colorReset         = "\033[0m"
	colorBold          = "\033[1m"
	colorDim           = "\033[2m"
	colorItalic        = "\033[3m"
	colorUnderline     = "\033[4m"

	// High-Contrast Vivid Bright ANSI Colors
	colorBrightRed     = "\033[91m"
	colorBrightGreen   = "\033[92m"
	colorBrightYellow  = "\033[93m"
	colorBrightBlue    = "\033[94m"
	colorBrightMagenta = "\033[95m"
	colorBrightCyan    = "\033[96m"
	colorBrightWhite   = "\033[97m"

	// Vibrant Aliases with maximum readability on dark terminal backgrounds
	colorRed           = "\033[91m"
	colorGreen         = "\033[92m"
	colorYellow        = "\033[93m"
	colorBlue          = "\033[94m"
	colorCyan          = "\033[96m"
	colorWhite         = "\033[97m"
	colorGray          = "\033[90m"
)

type NodeResponse struct {
	DeviceID    string
	OS          string
	Platform    string
	Arch        string
	Version     string
	Status      string
	TotalChunks int
	Chunks      map[int]string
	FullReport  string
	Completed   bool
	LastUpdate  time.Time
}

type DiscoveredNodeInfo struct {
	DeviceID  string
	Nickname  string
	OS        string
	Platform  string
	Arch      string
	Version   string
	VirtualIP string
	PublicIP  string
	STUNAddr  string
	LastSeen  time.Time
}

type PeerLinkInfo struct {
	FromNode  string
	FromGeo   string
	ToNode    string
	ToVIP     string
	Transport string
	Endpoint  string
	Ping      string
	ICMP      string
	DPIStatus string
}

func parseShareLink(raw string) (broker, topic, key string) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "natbypass://profile?") {
		u, err := url.Parse(raw)
		if err == nil {
			q := u.Query()
			broker = q.Get("broker")
			topic = q.Get("topic")
			key = q.Get("network_key")
			if key == "" {
				key = q.Get("key")
			}
			return
		}
	}
	if strings.HasPrefix(raw, "mqtt://") || strings.HasPrefix(raw, "tcp://") ||
		strings.HasPrefix(raw, "ssl://") || strings.HasPrefix(raw, "tls://") ||
		strings.HasPrefix(raw, "wss://") || strings.HasPrefix(raw, "ws://") {
		u, err := url.Parse(raw)
		if err == nil {
			broker = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
			pathTopic := strings.TrimPrefix(u.Path, "/")
			if pathTopic != "" {
				topic = pathTopic
			}
			q := u.Query()
			if k := q.Get("key"); k != "" {
				key = k
			} else if k := q.Get("network_key"); k != "" {
				key = k
			}
			return
		}
	}
	topic = raw
	return
}

func printBanner() {
	fmt.Print(colorBrightCyan + colorBold + `
╔══════════════════════════════════════════════════════════════════════════════╗
║               NATBYPASS CLUSTER DIAGNOSTIC & CONTROL CENTER                  ║
║                  (v1.9.226-beta16 | Local Engineering)                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
` + colorReset)
}

func guessGeo(ip, name string) string {
	lowerName := strings.ToLower(name)
	if strings.Contains(lowerName, "marnet") || strings.Contains(lowerName, "mord") ||
		strings.Contains(lowerName, "by") || strings.Contains(lowerName, "mac") ||
		strings.Contains(lowerName, "9r8") {
		return "BY (Беларусь)"
	}
	if strings.Contains(lowerName, "msk") || strings.Contains(lowerName, "krsda") ||
		strings.Contains(lowerName, "ustug") || strings.Contains(lowerName, "nextcloud") ||
		strings.Contains(lowerName, "nc") {
		return "RU (Россия)"
	}
	if strings.HasPrefix(ip, "37.212.") || strings.HasPrefix(ip, "37.214.") ||
		strings.HasPrefix(ip, "178.120.") || strings.HasPrefix(ip, "178.121.") {
		return "BY (Беларусь)"
	}
	if strings.HasPrefix(ip, "91.214.") || strings.HasPrefix(ip, "77.37.") ||
		strings.HasPrefix(ip, "212.22.") || strings.HasPrefix(ip, "109.252.") {
		return "RU (Россия)"
	}
	if strings.HasPrefix(ip, "144.172.") || strings.HasPrefix(ip, "194.59.") {
		return "EU (VPS)"
	}
	return "Global"
}

func isBeta7OrNewer(ver string) bool {
	vLower := strings.ToLower(ver)
	if !strings.Contains(vLower, "beta") {
		return false
	}
	// Any 1.9.225+ or newer version supports RemoteDiag
	if strings.Contains(vLower, "1.9.225") || strings.Contains(vLower, "1.9.226") || strings.Contains(vLower, "1.10.") || strings.Contains(vLower, "2.0.") {
		return true
	}
	// In 1.9.224 series, RemoteDiag was introduced in beta7
	if strings.Contains(vLower, "1.9.224") {
		for _, old := range []string{"beta1", "beta2", "beta3", "beta4", "beta5", "beta6"} {
			if strings.Contains(vLower, old) {
				return false
			}
		}
		return true
	}
	return false
}

func waitForEnter(reader *bufio.Reader) {
	fmt.Print(colorBrightYellow + colorBold + "\n  [ Нажмите ENTER для возврата в главное меню... ] " + colorReset)
	_, _ = reader.ReadString('\n')
}

func truncateStr(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

func runCollection(
	ch signaling.SignalingChannel,
	rx <-chan *signaling.Payload,
	topic, broker, networkKey, collectorID string,
	targetID string,
	isUpdate bool,
	timeout time.Duration,
	includeLocal bool,
) (map[string]*DiscoveredNodeInfo, map[string]*NodeResponse, string) {

	randBytes := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		h := sha256.Sum256([]byte(fmt.Sprintf("diag-session-%d", time.Now().UnixNano())))
		copy(randBytes, h[:4])
	}
	sessionID := fmt.Sprintf("diag-sess-%x", randBytes)

	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	action := "request_diag"
	if isUpdate {
		action = "request_update"
	}

	reqSig := &signaling.RemoteDiagSignal{
		Action:    action,
		TargetID:  targetID,
		SenderID:  collectorID,
		SessionID: sessionID,
		Timestamp: time.Now().Unix(),
	}

	reqPayload := &signaling.Payload{
		DeviceID:   collectorID,
		Nickname:   "DiagCollector",
		RemoteDiag: reqSig,
		Timestamp:  time.Now(),
	}

	toSend := reqPayload
	if networkKey != "" {
		if enc, err := signaling.EncryptPayloadWithKey(reqPayload, networkKey); err == nil && enc != nil {
			toSend = enc
		}
	}

	// Send request signal with retry
	var sendErr error
	for attempt := 1; attempt <= 4; attempt++ {
		sendErr = ch.Send(ctx, toSend)
		if sendErr == nil {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if sendErr != nil {
		fmt.Printf(colorYellow+"[!] Предупреждение: ошибка отправки команды в топик: %v\n"+colorReset, sendErr)
	} else {
		if isUpdate {
			fmt.Println(colorYellow + colorBold + "⚡ Команда принудительного OTA-обновления разослана. Ожидание статусов от узлов..." + colorReset)
		} else {
			fmt.Println(colorGreen + "✓ Запрос диагностики разослан в сеть. Ожидание ответов от узлов..." + colorReset)
		}
	}
	fmt.Println(colorBold + "─────────────────────────────────────────────────────────────────────────" + colorReset)

	// Burst repeat after 2s (ONLY for diagnostics, NEVER for OTA updates to prevent race conditions)
	if !isUpdate {
		go func() {
			time.Sleep(2 * time.Second)
			_ = ch.Send(ctx, toSend)
		}()
	}

	nodes := make(map[string]*NodeResponse)
	discoveredPeers := make(map[string]*DiscoveredNodeInfo)
	var mu sync.Mutex

	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

collectLoop:
	for {
		select {
		case <-timeoutTimer.C:
			fmt.Println(colorYellow + "\n[⏰] Время ожидания ответов завершено." + colorReset)
			break collectLoop

		case p, ok := <-rx:
			if !ok || p == nil {
				break collectLoop
			}

			if len(p.Encrypted) > 0 && networkKey != "" {
				if dec, decErr := signaling.DecryptPayloadWithKey(p, networkKey); decErr == nil && dec != nil {
					p = dec
				}
			}

			if p.DeviceID == "" || p.DeviceID == collectorID {
				continue
			}

			mu.Lock()
			if _, seen := discoveredPeers[p.DeviceID]; !seen {
				ver := p.Version
				if ver == "" {
					ver = "не указана"
				}
				discoveredPeers[p.DeviceID] = &DiscoveredNodeInfo{
					DeviceID:  p.DeviceID,
					Nickname:  p.Nickname,
					OS:        p.OS,
					Platform:  p.Platform,
					Arch:      p.Arch,
					Version:   ver,
					VirtualIP: p.VirtualIP,
					PublicIP:  p.PublicIP,
					STUNAddr:  p.STUNAddr,
					LastSeen:  time.Now(),
				}
				if p.RemoteDiag == nil {
					nick := p.Nickname
					if nick == "" {
						nick = "-"
					}
					fmt.Printf(colorCyan+"  [i] Обнаружен узел в сети: %-22s (%s) [ОС: %s, VIP: %s, Версия: %s]\n"+colorReset,
						p.DeviceID, nick, p.OS, p.VirtualIP, ver)
				}
			}

			if p.RemoteDiag != nil && p.RemoteDiag.SessionID == sessionID {
				r := p.RemoteDiag

				// Ensure discoveredPeers has full OS/Arch/Version metadata from the response signal
				if dp, ok := discoveredPeers[r.SenderID]; ok {
					if dp.OS == "" && r.OS != "" {
						dp.OS = r.OS
					}
					if dp.Platform == "" && r.Platform != "" {
						dp.Platform = r.Platform
					}
					if dp.Arch == "" && r.Arch != "" {
						dp.Arch = r.Arch
					}
					if (dp.Version == "" || dp.Version == "не указана") && r.Version != "" {
						dp.Version = r.Version
					}
				} else {
					discoveredPeers[r.SenderID] = &DiscoveredNodeInfo{
						DeviceID: r.SenderID,
						OS:       r.OS,
						Platform: r.Platform,
						Arch:     r.Arch,
						Version:  r.Version,
						LastSeen: time.Now(),
					}
				}

				node, exists := nodes[r.SenderID]
				if !exists {
					node = &NodeResponse{
						DeviceID:    r.SenderID,
						OS:          r.OS,
						Platform:    r.Platform,
						Arch:        r.Arch,
						Version:     r.Version,
						Status:      r.Status,
						TotalChunks: r.TotalChunks,
						Chunks:      make(map[int]string),
					}
					nodes[r.SenderID] = node
				}

				node.Chunks[r.ChunkIndex] = r.Payload
				node.Status = r.Status
				node.LastUpdate = time.Now()

				if r.Action == "response_update" {
					if r.Status == "updating" {
						if !exists {
							vStr := r.Version
							if !strings.HasPrefix(vStr, "v") {
								vStr = "v" + vStr
							}
							fmt.Printf(colorYellow+"  [⚡] Узел %s (%s/%s %s): %s\n"+colorReset,
								r.SenderID, r.OS, r.Arch, vStr, r.Payload)
						}
					} else {
						fmt.Printf(colorGreen+"  [✓] Узел %s: Обновление завершено (%s)! Результат: %s\n"+colorReset,
							r.SenderID, r.Status, r.Payload)
						node.Completed = true
						node.FullReport = r.Payload
					}
				} else {
					if r.TotalChunks > 1 {
						fmt.Printf(colorCyan+"  [📦] Узел %s: чанк %d/%d (%d байт)\n"+colorReset,
							r.SenderID, r.ChunkIndex+1, r.TotalChunks, len(r.Payload))
					}
					if len(node.Chunks) >= node.TotalChunks {
						node.Completed = true
						var sb strings.Builder
						for i := 0; i < node.TotalChunks; i++ {
							sb.WriteString(node.Chunks[i])
						}
						node.FullReport = sb.String()
						fmt.Printf(colorGreen+colorBold+"  [✓] Узел %-20s (%s/%s v%s): Диагностический отчет ПОЛНОСТЬЮ получен (%d байт)\n"+colorReset,
							r.SenderID, r.OS, r.Arch, strings.TrimPrefix(r.Version, "v"), len(node.FullReport))
					}
				}

				// Fast exit if all discovered nodes have responded
				if targetID != "" && node.Completed {
					mu.Unlock()
					break collectLoop
				}
				if targetID == "" && len(discoveredPeers) > 0 && len(nodes) == len(discoveredPeers) {
					allDone := true
					for _, n := range nodes {
						if !n.Completed {
							allDone = false
							break
						}
					}
					if allDone {
						mu.Unlock()
						fmt.Println(colorGreen + colorBold + "\n[⚡] Все обнаруженные узлы кластера успешно передали отчеты!" + colorReset)
						break collectLoop
					}
				}
			}
			mu.Unlock()
		}
	}

	var localReport string
	if includeLocal {
		fmt.Println(colorCyan + "\n[ℹ] Запуск локальной диагностики управляющей машины..." + colorReset)
		rep := diagnostic.RunFullDiagnostics()
		localReport = diagnostic.FormatGoDiagnosticsReport(rep)
	}

	return discoveredPeers, nodes, localReport
}

func printSummaryTable(discoveredPeers map[string]*DiscoveredNodeInfo, nodes map[string]*NodeResponse) {
	peerSet := make(map[string]bool)
	for id := range discoveredPeers {
		peerSet[id] = true
	}
	for id := range nodes {
		peerSet[id] = true
	}
	var allPeerIDs []string
	for id := range peerSet {
		allPeerIDs = append(allPeerIDs, id)
	}
	sort.Strings(allPeerIDs)

	fmt.Println("\n" + colorBrightCyan + colorBold + "═══════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBrightWhite + colorBold + " 📊 СВОДНАЯ ТАБЛИЦА УЗЛОВ КЛАСТЕРА" + colorReset)
	fmt.Println(colorBrightCyan + colorBold + "═══════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Printf(colorBrightCyan+colorBold+"%-24s │ %-15s │ %-14s │ %-24s │ %-10s\n"+colorReset, "DEVICE ID", "ПЛАТФОРМА", "ВЕРСИЯ", "СТАТУС", "РАЗМЕР")
	fmt.Println(colorGray + "─────────────────────────┼─────────────────┼────────────────┼──────────────────────────┼───────────" + colorReset)
	for _, id := range allPeerIDs {
		dp := discoveredPeers[id]
		osStr := ""
		archStr := ""
		verStr := "не указана"
		if dp != nil {
			osStr = dp.OS
			archStr = dp.Arch
			if dp.Version != "" {
				verStr = dp.Version
			}
		}
		if n, ok := nodes[id]; ok {
			if osStr == "" && n.OS != "" {
				osStr = n.OS
			}
			if archStr == "" && n.Arch != "" {
				archStr = n.Arch
			}
			if (verStr == "" || verStr == "не указана") && n.Version != "" {
				verStr = n.Version
			}
		}
		plat := fmt.Sprintf("%s/%s", osStr, archStr)
		if archStr == "" {
			plat = osStr
		}
		if plat == "/" || plat == "" {
			plat = "-"
		}
		st := "Старая beta (нет RemoteDiag)"
		stColor := colorBrightRed
		if isBeta7OrNewer(verStr) {
			st = "⌛ Таймаут / Занят"
			stColor = colorBrightYellow
		}
		szStr := "-"
		if n, ok := nodes[id]; ok {
			st = n.Status
			if n.Completed {
				st = "✓ Получен"
				stColor = colorBrightGreen
			}
			if len(n.FullReport) > 1024 {
				szStr = fmt.Sprintf("%.1f КБ", float64(len(n.FullReport))/1024.0)
			} else if len(n.FullReport) > 0 {
				szStr = fmt.Sprintf("%d Б", len(n.FullReport))
			}
		}
		fmt.Printf("%s%-24s%s │ %s%-15s%s │ %s%-14s%s │ %s%-24s%s │ %s%-10s%s\n",
			colorBrightWhite+colorBold, truncateStr(id, 24), colorReset,
			colorBrightCyan, truncateStr(plat, 15), colorReset,
			colorBrightYellow, truncateStr(verStr, 14), colorReset,
			stColor+colorBold, truncateStr(st, 24), colorReset,
			colorBrightWhite, szStr, colorReset)
	}
	if len(allPeerIDs) == 0 {
		fmt.Println(colorBrightYellow + " (Узлов в сети не обнаружено. Проверьте активность маяков и топик)" + colorReset)
	}
	fmt.Println(colorBrightCyan + colorBold + "═══════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
}

func printDpiMeshMatrix(discoveredPeers map[string]*DiscoveredNodeInfo, nodes map[string]*NodeResponse) {
	fmt.Println("\n" + colorBold + "══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " 🌐 МЕЖГЕОГРАФИЧЕСКАЯ P2P / DPI МАТРИЦА СВЯЗНОСТИ КЛАСТЕРА (CROSS-BORDER MESH MATRIX)" + colorReset)
	fmt.Println(colorBold + "══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)

	// Support both beta9 (EnginePing + ICMP) and beta8 (Ping only) peer line formats
	regexBeta9 := regexp.MustCompile(`->\s*([^|]+)\|\s*VIP:\s*([^|]+)\|\s*([^|]+)\|\s*EP:\s*([^|]+)\|\s*EnginePing:\s*([^|]+)\|\s*(.+)`)
	regexBeta8 := regexp.MustCompile(`->\s*([^|]+)\|\s*VIP:\s*([^|]+)\|\s*([^|]+)\|\s*EP:\s*([^|]+)\|\s*Ping:\s*(.+)`)

	var allLinks []PeerLinkInfo
	totalUDP := 0
	totalTCP := 0
	totalRelay := 0
	totalICMPOk := 0
	totalICMPFail := 0

	for id, node := range nodes {
		dp := discoveredPeers[id]
		fromName := id
		fromGeo := "Global"
		if dp != nil {
			if dp.Nickname != "" {
				fromName = dp.Nickname
			}
			fromGeo = guessGeo(dp.PublicIP, dp.Nickname+" "+dp.DeviceID)
		}

		lines := strings.Split(node.FullReport, "\n")
		for _, line := range lines {
			trimmedLine := strings.TrimSpace(line)
			var toNode, toVIP, transport, endpoint, ping, icmp string

			if m := regexBeta9.FindStringSubmatch(trimmedLine); len(m) >= 7 {
				toNode = strings.TrimSpace(m[1])
				toVIP = strings.TrimSpace(m[2])
				transport = strings.TrimSpace(m[3])
				endpoint = strings.TrimSpace(m[4])
				ping = strings.TrimSpace(m[5])
				icmp = strings.TrimSpace(m[6])
			} else if m := regexBeta8.FindStringSubmatch(trimmedLine); len(m) >= 6 {
				toNode = strings.TrimSpace(m[1])
				toVIP = strings.TrimSpace(m[2])
				transport = strings.TrimSpace(m[3])
				endpoint = strings.TrimSpace(m[4])
				ping = strings.TrimSpace(m[5])
				icmp = "N/A (beta8)"
			}

			if toNode != "" {

				dpiStatus := "✓ Пропуск (P2P OK)"
				if strings.Contains(transport, "ShadowTLS") || strings.Contains(transport, "TCP") {
					dpiStatus = "🛡️ Обход ТСПУ через TCP"
					totalTCP++
				} else if strings.Contains(transport, "AWG") || strings.Contains(transport, "UDP") {
					totalUDP++
				} else {
					dpiStatus = "❌ Заблокирован ТСПУ / Relay"
					totalRelay++
				}

				if strings.Contains(icmp, "✓") {
					totalICMPOk++
				} else {
					totalICMPFail++
				}

				allLinks = append(allLinks, PeerLinkInfo{
					FromNode:  fromName,
					FromGeo:   fromGeo,
					ToNode:    toNode,
					ToVIP:     toVIP,
					Transport: transport,
					Endpoint:  endpoint,
					Ping:      ping,
					ICMP:      icmp,
					DPIStatus: dpiStatus,
				})
			}
		}
	}

	if len(allLinks) == 0 {
		fmt.Println(" (Детальные списки пиров не найдены в отчетах. Убедитесь, что демоны узлов запущены с WebUI-эндпоинтом :8080)")
		fmt.Println(colorBold + "══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
		return
	}

	fmt.Printf(colorBrightCyan+colorBold+"%-22s │ %-18s │ %-24s │ %-21s │ %-10s │ %-16s │ %-24s\n"+colorReset,
		"ИСТОЧНИК (FROM)", "НАЗНАЧЕНИЕ (TO)", "РЕЖИМ ТРАНСПОРТА", "ENDPOINT", "PING", "ICMP L3", "DPI СТАТУС")
	fmt.Println(colorGray + "───────────────────────┼────────────────────┼──────────────────────────┼───────────────────────┼────────────┼──────────────────┼─────────────────────────" + colorReset)

	for _, link := range allLinks {
		fromStr := fmt.Sprintf("%s (%s)", truncateStr(link.FromNode, 14), truncateStr(link.FromGeo, 6))

		// Colorize transport
		transColor := colorBrightGreen
		if strings.Contains(link.Transport, "ShadowTLS") || strings.Contains(link.Transport, "TCP") {
			transColor = colorBrightCyan
		} else if strings.Contains(link.Transport, "Relay") || strings.Contains(link.Transport, "MQTT") {
			transColor = colorBrightYellow
		}

		// Colorize ping
		pingColor := colorBrightWhite
		if strings.Contains(link.Ping, "N/A") || link.Ping == "" {
			pingColor = colorGray
		} else if strings.Contains(link.Ping, "ms") {
			var msVal int
			if _, err := fmt.Sscanf(link.Ping, "%d", &msVal); err == nil {
				if msVal < 50 {
					pingColor = colorBrightGreen
				} else if msVal < 150 {
					pingColor = colorBrightCyan
				} else {
					pingColor = colorBrightYellow
				}
			}
		}

		// Colorize ICMP
		icmpColor := colorBrightRed
		if strings.Contains(link.ICMP, "✓") || strings.Contains(link.ICMP, "OK") {
			icmpColor = colorBrightGreen
		}

		// Colorize DPI
		dpiColor := colorBrightGreen
		if strings.Contains(link.DPIStatus, "🛡️") {
			dpiColor = colorBrightCyan
		} else if strings.Contains(link.DPIStatus, "❌") {
			dpiColor = colorBrightRed
		}

		fmt.Printf("%s%-22s%s │ %s%-18s%s │ %s%-24s%s │ %s%-21s%s │ %s%-10s%s │ %s%-16s%s │ %s%-24s%s\n",
			colorBrightWhite, truncateStr(fromStr, 22), colorReset,
			colorBrightWhite, truncateStr(link.ToNode, 18), colorReset,
			transColor, truncateStr(link.Transport, 24), colorReset,
			colorBrightWhite, truncateStr(link.Endpoint, 21), colorReset,
			pingColor, truncateStr(link.Ping, 10), colorReset,
			icmpColor+colorBold, truncateStr(link.ICMP, 16), colorReset,
			dpiColor, truncateStr(link.DPIStatus, 24), colorReset,
		)
	}

	totalLinks := len(allLinks)
	fmt.Println(colorBrightCyan + colorBold + "══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBrightWhite + colorBold + " 📊 СВОДНАЯ СТАТИСТИКА P2P / DPI КЛАСТЕРА:" + colorReset)
	fmt.Printf(colorBrightWhite+"  • Всего обнаруженных каналов между узлами:  %s%d%s\n", colorBrightCyan+colorBold, totalLinks, colorReset)
	if totalLinks > 0 {
		fmt.Printf(colorBrightWhite+"  • Прямой P2P через UDP AWG:                 %s%d (%.1f%%)%s — Высокая скорость, низкий пинг\n",
			colorBrightGreen+colorBold, totalUDP, float64(totalUDP)*100.0/float64(totalLinks), colorReset)
		fmt.Printf(colorBrightWhite+"  • Защищенный P2P через TCP ShadowTLS:       %s%d (%.1f%%)%s — Успешный обход DPI/ТСПУ\n",
			colorBrightCyan+colorBold, totalTCP, float64(totalTCP)*100.0/float64(totalLinks), colorReset)
		fmt.Printf(colorBrightWhite+"  • Резервный Relay через MQTT брокер:        %s%d (%.1f%%)%s — Требуется диагностика\n",
			colorBrightYellow+colorBold, totalRelay, float64(totalRelay)*100.0/float64(totalLinks), colorReset)
		fmt.Printf(colorBrightWhite+"  • Доставка ICMP L3 пакетов (Ping):          %s%d успешно%s / %s%d потерь%s\n",
			colorBrightGreen+colorBold, totalICMPOk, colorReset,
			colorBrightRed+colorBold, totalICMPFail, colorReset)
	}
	fmt.Println(colorBrightCyan + colorBold + "══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
}

func saveConsolidatedReport(
	outFileName, topic string,
	networkKey, localReport string,
	discoveredPeers map[string]*DiscoveredNodeInfo,
	nodes map[string]*NodeResponse,
) {
	peerSet := make(map[string]bool)
	for id := range discoveredPeers {
		peerSet[id] = true
	}
	for id := range nodes {
		peerSet[id] = true
	}
	var allPeerIDs []string
	for id := range peerSet {
		allPeerIDs = append(allPeerIDs, id)
	}
	sort.Strings(allPeerIDs)

	var fileSb strings.Builder
	fileSb.WriteString("================================================================================\n")
	fileSb.WriteString("                  NATBYPASS CLUSTER DIAGNOSTIC REPORT                           \n")
	fileSb.WriteString("================================================================================\n")
	fileSb.WriteString(fmt.Sprintf("Timestamp:      %s\n", time.Now().UTC().Format(time.RFC3339)))
	fileSb.WriteString(fmt.Sprintf("Topic:          %s\n", topic))
	fileSb.WriteString(fmt.Sprintf("Encrypted:      %t\n", networkKey != ""))
	fileSb.WriteString(fmt.Sprintf("Discovered:     %d nodes\n", len(allPeerIDs)))
	fileSb.WriteString(fmt.Sprintf("Responded Beta: %d nodes\n", len(nodes)))
	fileSb.WriteString("================================================================================\n\n")

	fileSb.WriteString("================================================================================\n")
	fileSb.WriteString(fmt.Sprintf(" СПИСОК ОБНАРУЖЕННЫХ УЗЛОВ В СЕТИ (ОНЛАЙН В ТОПИКЕ: %d)\n", len(allPeerIDs)))
	fileSb.WriteString("================================================================================\n\n")
	for _, id := range allPeerIDs {
		dp := discoveredPeers[id]
		osStr := ""
		archStr := ""
		verStr := "не указана"
		nickStr := "-"
		vipStr := "-"
		pubIPStr := "-"
		if dp != nil {
			osStr = dp.OS
			archStr = dp.Arch
			if dp.Version != "" {
				verStr = dp.Version
			}
			if dp.Nickname != "" {
				nickStr = dp.Nickname
			}
			if dp.VirtualIP != "" {
				vipStr = dp.VirtualIP
			}
			if dp.PublicIP != "" {
				pubIPStr = dp.PublicIP
			}
		}
		if n, ok := nodes[id]; ok {
			if osStr == "" && n.OS != "" {
				osStr = n.OS
			}
			if archStr == "" && n.Arch != "" {
				archStr = n.Arch
			}
			if (verStr == "" || verStr == "не указана") && n.Version != "" {
				verStr = n.Version
			}
		}
		hasDiag := false
		if n, ok := nodes[id]; ok && n.Completed {
			hasDiag = true
		}
		statusText := fmt.Sprintf("Требуется обновить бинарник до актуальной beta (на узле: %s, RemoteDiag с v1.9.224-beta7+)", verStr)
		if hasDiag {
			statusText = "OK (Диагностический отчет получен)"
		} else if isBeta7OrNewer(verStr) {
			statusText = "Таймаут сбора отчета (узел на актуальной beta, но не успел передать отчет за отведенное время)"
		}
		fileSb.WriteString(fmt.Sprintf("Узел:        %s (%s)\n", id, nickStr))
		fileSb.WriteString(fmt.Sprintf("ОС/Арх:      %s/%s | Версия: %s\n", osStr, archStr, verStr))
		fileSb.WriteString(fmt.Sprintf("Virtual IP:  %s | Публичный IP: %s\n", vipStr, pubIPStr))
		fileSb.WriteString(fmt.Sprintf("Статус:      %s\n", statusText))
		fileSb.WriteString("--------------------------------------------------------------------------------\n")
	}
	fileSb.WriteString("\n\n")

	if localReport != "" {
		fileSb.WriteString("################################################################################\n")
		fileSb.WriteString(" LOCAL CONTROLLER HOST DIAGNOSTICS\n")
		fileSb.WriteString("################################################################################\n\n")
		fileSb.WriteString(localReport)
		fileSb.WriteString("\n\n")
	}

	var respondingIDs []string
	for id := range nodes {
		respondingIDs = append(respondingIDs, id)
	}
	sort.Strings(respondingIDs)

	for _, id := range respondingIDs {
		n := nodes[id]
		fileSb.WriteString("################################################################################\n")
		fileSb.WriteString(fmt.Sprintf(" ПОЛНЫЙ ДИАГНОСТИЧЕСКИЙ ОТЧЕТ УЗЛА: %s\n", n.DeviceID))
		fileSb.WriteString(fmt.Sprintf(" Platform: %s/%s | Version: %s | Status: %s\n", n.OS, n.Arch, n.Version, n.Status))
		fileSb.WriteString(fmt.Sprintf(" Completed: %t | Total Chunks: %d\n", n.Completed, n.TotalChunks))
		fileSb.WriteString("################################################################################\n\n")

		if n.FullReport != "" {
			fileSb.WriteString(n.FullReport)
		} else {
			for i := 0; i < n.TotalChunks; i++ {
				if chunk, ok := n.Chunks[i]; ok {
					fileSb.WriteString(chunk)
				} else {
					fileSb.WriteString(fmt.Sprintf("\n[ПРОПУЩЕН ЧАНК %d]\n", i))
				}
			}
		}
		fileSb.WriteString("\n\n")
	}

	if err := os.WriteFile(outFileName, []byte(fileSb.String()), 0644); err != nil {
		fmt.Printf(colorRed+"[✗] Ошибка сохранения файла отчета: %v\n"+colorReset, err)
	} else {
		absPath, _ := filepath.Abs(outFileName)
		fmt.Printf(colorGreen+colorBold+"\n💾 Объединенный диагностический отчет успешно сохранен:\n   %s\n"+colorReset, absPath)
	}
}

func createSignalingChannel(ctx context.Context, broker, topic, collectorID, networkKey string) (signaling.SignalingChannel, <-chan *signaling.Payload, error) {
	var sigChannels []signaling.SignalingChannel
	sigChannels = append(sigChannels, signaling.NewMQTTChannelNamed("mqtt:primary", broker, topic, collectorID, "", ""))
	for _, b := range config.DefaultPublicMQTTBrokers {
		if b != broker {
			sigChannels = append(sigChannels, signaling.NewMQTTChannelNamed("mqtt:backup:"+b, b, topic, collectorID, "", ""))
		}
	}
	fm := signaling.NewFallbackManager(sigChannels)
	if networkKey != "" {
		fm.SetNetworkKey(networkKey)
	}
	rx, err := fm.Receive(ctx)
	return fm, rx, err
}

func main() {
	initConsole()
	os.Args = reorderArgs(os.Args)
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	isInteractive := !*flagBatch && !*flagUpdate
	// 1. Resolve room parameters: CLI flags > share link in flag > local config.yaml > WebUI API
	rawInput := *flagTopic
	var parsedBroker, parsedTopic, parsedKey string
	if rawInput != "" {
		parsedBroker, parsedTopic, parsedKey = parseShareLink(rawInput)
	}

	if rawInput == "" {
		candidatePaths := []string{*flagConfig}
		if exePath, err := os.Executable(); err == nil {
			candidatePaths = append(candidatePaths, filepath.Join(filepath.Dir(exePath), "config.yaml"))
		}
		if wd, err := os.Getwd(); err == nil {
			candidatePaths = append(candidatePaths, filepath.Join(wd, "config.yaml"))
		}
		for _, candPath := range candidatePaths {
			if candPath == "" {
				continue
			}
			if cfg, err := config.Load(candPath); err == nil && cfg != nil {
				activeProf := cfg.EnsureActiveProfile()
				if activeProf != nil && activeProf.MQTTTopic != "" {
					parsedTopic = activeProf.MQTTTopic
					parsedBroker = activeProf.MQTTBroker
					parsedKey = activeProf.NetworkKey
					break
				}
			}
		}
		if parsedTopic == "" {
			client := &http.Client{Timeout: 800 * time.Millisecond}
			for _, port := range []string{"8080", "8081", "8082"} {
				resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/api/config", port))
				if err == nil && resp.StatusCode == http.StatusOK {
					var apiResp struct {
						Data *config.Config `json:"data"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&apiResp); err == nil && apiResp.Data != nil {
						if prof := apiResp.Data.EnsureActiveProfile(); prof != nil && prof.MQTTTopic != "" {
							parsedTopic = prof.MQTTTopic
							parsedBroker = prof.MQTTBroker
							parsedKey = prof.NetworkKey
						}
					}
					_ = resp.Body.Close()
				}
				if parsedTopic != "" {
					break
				}
			}
		}
	}

	if parsedTopic == "" && *flagTopic == "" {
		printBanner()
		fmt.Print(colorYellow + "Вставьте natbypass:// ссылку или нажмите Enter для ручного ввода: " + colorReset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			b, t, k := parseShareLink(input)
			if t != "" {
				parsedTopic = t
			}
			if b != "" {
				parsedBroker = b
			}
			if k != "" {
				parsedKey = k
			}
		}
	}

	broker := *flagBroker
	if broker == "" {
		broker = parsedBroker
	}
	topic := parsedTopic
	networkKey := *flagKey
	if networkKey == "" {
		networkKey = parsedKey
	}

	if topic == "" {
		fmt.Println(colorRed + "[✗] Ошибка: не указан топик сигнальной комнаты (-topic)!" + colorReset)
		os.Exit(1)
	}

	if broker == "" {
		broker = "tcp://broker.hivemq.com:1883"
	}

	randBytes := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		h := sha256.Sum256([]byte(fmt.Sprintf("diag-collector-%d", time.Now().UnixNano())))
		copy(randBytes, h[:4])
	}
	collectorID := fmt.Sprintf("natbypass-diag-%x", randBytes)

	// Connect to signaling channel once with multi-broker fallback
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, rx, err := createSignalingChannel(ctx, broker, topic, collectorID, networkKey)
	if err != nil {
		fmt.Printf(colorRed+"[✗] Ошибка подключения к сигнальным брокерам: %v\n"+colorReset, err)
		os.Exit(1)
	}
	defer ch.Close()

	fmt.Print(colorCyan + "⏳ Подключение к сигнальным брокерам (основной + резерв)..." + colorReset)
	connStart := time.Now()
	for time.Since(connStart) < 7*time.Second {
		if ch.IsAvailable(ctx) {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	fmt.Println(colorGreen + " Готово!" + colorReset)

	// Main Menu Loop
	for {
		printBanner()
		fmt.Printf(colorCyan+"[ℹ] Брокер:     %s\n"+colorReset, broker)
		fmt.Printf(colorCyan+"[ℹ] Топик:      %s\n"+colorReset, topic)
		if networkKey != "" {
			fmt.Printf(colorGreen+"[✓] Шифрование: Включено (NetworkKey: %s***)\n"+colorReset, networkKey[:min(4, len(networkKey))])
		} else {
			fmt.Printf(colorYellow+"[!] Шифрование: Отключено (открытый канал)\n"+colorReset)
		}
		fmt.Println(colorBold + "─────────────────────────────────────────────────────────────────────────" + colorReset)

		var choice string
		if !isInteractive {
			if *flagUpdate {
				choice = "4"
			} else if *flagTarget != "" {
				choice = "3"
			} else {
				choice = "1"
			}
		} else {
			fmt.Println(colorBrightCyan + colorBold + " 📋 ГЛАВНОЕ МЕНЮ ДИАГНОСТИКИ И УПРАВЛЕНИЯ КЛАСТЕРОМ:" + colorReset)
			fmt.Println(colorBrightYellow + "  [ 1 ] " + colorBrightWhite + "Собрать полную диагностику со всех узлов в файл" + colorReset + colorGray + " (Diag Collect)" + colorReset)
			fmt.Println(colorBrightYellow + "  [ 2 ] " + colorBrightWhite + "Межгеографическая P2P/DPI матрица связности" + colorReset + colorGray + " (Mesh Matrix)" + colorReset)
			fmt.Println(colorBrightYellow + "  [ 3 ] " + colorBrightWhite + "Диагностика одного конкретного узла по DeviceID" + colorReset)
			fmt.Println(colorBrightYellow + "  [ 4 ] " + colorBrightWhite + "Принудительно обновить все beta-узлы сети" + colorReset + colorGray + " (OTA Beta Update)" + colorReset)
			fmt.Println(colorBrightYellow + "  [ 5 ] " + colorBrightWhite + "Сменить профиль / топик / брокер" + colorReset)
			fmt.Println(colorBrightYellow + "  [ 0 ] " + colorBrightWhite + "Выход из утилиты" + colorReset)
			fmt.Println(colorGray + "─────────────────────────────────────────────────────────────────────────" + colorReset)
			fmt.Print(colorBrightGreen + colorBold + "► Введите номер команды [1-5, 0]: " + colorReset)
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				if readErr == io.EOF && len(line) == 0 {
					fmt.Println("\nВыход из утилиты.")
					return
				}
			}
			choice = strings.TrimSpace(line)
			if choice == "" {
				fmt.Println(colorBrightYellow + "  [!] Команда не указана. Пожалуйста, введите цифру от 0 до 5.\n" + colorReset)
				continue
			}
			menuNames := map[string]string{
				"1": "Сбор полной диагностики со всех узлов",
				"2": "Межгеографическая P2P/DPI матрица связности",
				"3": "Диагностика целевого узла",
				"4": "OTA-обновление всех beta-узлов",
				"5": "Смена комнаты / топика / брокера",
				"0": "Выход",
			}
			if name, ok := menuNames[choice]; ok {
				fmt.Printf(colorBrightCyan+"  >> Выбрано: [ %s ] %s\n\n"+colorReset, choice, name)
			} else {
				fmt.Printf(colorBrightRed+"  [!] Некорректный выбор '%s'. Введите цифру от 0 до 5.\n\n"+colorReset, choice)
				continue
			}
		}

		switch choice {
		case "1":
			discov, nodes, localRep := runCollection(ch, rx, topic, broker, networkKey, collectorID, "", false, *flagTimeout, *flagLocal)
			outFileName := *flagOutput
			if outFileName == "" {
				safeTopic := strings.ReplaceAll(topic, "/", "_")
				outFileName = fmt.Sprintf("cluster_diag_%s_%s.txt", safeTopic, time.Now().Format("20060102_150405"))
			}
			saveConsolidatedReport(outFileName, topic, networkKey, localRep, discov, nodes)
			printSummaryTable(discov, nodes)
			printDpiMeshMatrix(discov, nodes)

		case "2":
			discov, nodes, _ := runCollection(ch, rx, topic, broker, networkKey, collectorID, "", false, *flagTimeout, false)
			printDpiMeshMatrix(discov, nodes)

		case "3":
			fmt.Print(colorYellow + "Введите DeviceID целевого узла: " + colorReset)
			tID, _ := reader.ReadString('\n')
			tID = strings.TrimSpace(tID)
			if tID == "" {
				fmt.Println(colorRed + "[!] Узел не указан." + colorReset)
				break
			}
			_, nodes, _ := runCollection(ch, rx, topic, broker, networkKey, collectorID, tID, false, *flagTimeout, false)
			if n, ok := nodes[tID]; ok && n.Completed {
				fmt.Println(colorGreen + colorBold + "\n═════════════════════════════════════════════════════════════════════════" + colorReset)
				fmt.Printf(colorBold+" ДИАГНОСТИЧЕСКИЙ ОТЧЕТ УЗЛА: %s (%s/%s v%s)\n"+colorReset, n.DeviceID, n.OS, n.Arch, strings.TrimPrefix(n.Version, "v"))
				fmt.Println(colorBold + "═════════════════════════════════════════════════════════════════════════" + colorReset)
				fmt.Println(n.FullReport)
			} else {
				fmt.Printf(colorRed+"\n[✗] Отчет от узла '%s' не получен за отведенное время.\n"+colorReset, tID)
			}

		case "4":
			fmt.Println(colorCyan + "🔎 Проверка последней доступной beta-версии в репозитории..." + colorReset)
			checkCtx, checkCancel := context.WithTimeout(ctx, 6*time.Second)
			latestInfo, checkErr := updater.CheckUpdateWithOptions(checkCtx, "v1.9.224-beta0", updater.CheckOptions{Channel: "beta", IncludePrerelease: true})
			checkCancel()
			if checkErr == nil && latestInfo != nil {
				fmt.Printf(colorGreen+"[✓] Актуальная beta-версия в репозитории: %s\n"+colorReset, latestInfo.LatestVersion)
			} else {
				fmt.Printf(colorYellow+"[!] Проверка репозитория: %v\n"+colorReset, checkErr)
			}
			var conf string
			if !isInteractive {
				conf = "y"
			} else {
				fmt.Print("Подтверждаете отправку команды обновления? [y/N]: ")
				conf, _ = reader.ReadString('\n')
				conf = strings.TrimSpace(strings.ToLower(conf))
			}
			if conf == "y" || conf == "yes" || conf == "д" || conf == "да" {
				_, nodes, _ := runCollection(ch, rx, topic, broker, networkKey, collectorID, "", true, *flagTimeout, false)
				fmt.Println(colorBold + "\nРезультаты обновления:" + colorReset)
				for id, n := range nodes {
					fmt.Printf("  • %-22s: %s (%s)\n", id, n.Status, n.FullReport)
				}
			} else {
				fmt.Println("Отменено.")
			}

		case "5":
			fmt.Print(colorYellow + "Вставьте новую ссылку сети (natbypass://profile?...) или название топика: " + colorReset)
			newLink, _ := reader.ReadString('\n')
			newLink = strings.TrimSpace(newLink)
			if newLink != "" {
				nb, nt, nk := parseShareLink(newLink)
				if nt != "" {
					topic = nt
				}
				if nb != "" {
					broker = nb
				}
				if nk != "" {
					networkKey = nk
				}
				fmt.Println(colorGreen + "Параметры обновлены. Переподключение..." + colorReset)
				_ = ch.Close()
				ch, rx, _ = createSignalingChannel(ctx, broker, topic, collectorID, networkKey)
			}

		case "0":
			fmt.Println(colorCyan + "Выход из утилиты диагностики. До свидания!" + colorReset)
			return

		default:
			fmt.Println(colorRed + "Неизвестный пункт меню." + colorReset)
		}

		if !isInteractive {
			// Non-interactive run finishes immediately
			return
		}

		waitForEnter(reader)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func reorderArgs(args []string) []string {
	if len(args) <= 1 {
		return args
	}
	var flags []string
	var pos []string
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				lower := strings.ToLower(arg)
				if lower != "-update" && lower != "-local" && lower != "--update" && lower != "--local" && lower != "-batch" && lower != "--batch" {
					i++
					flags = append(flags, args[i])
				}
			}
		} else {
			pos = append(pos, arg)
		}
	}
	res := []string{args[0]}
	res = append(res, flags...)
	res = append(res, pos...)
	return res
}
