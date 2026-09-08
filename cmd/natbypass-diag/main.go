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
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/diagnostic"
	"github.com/natbypass/natbypass/internal/signaling"
)

var (
	flagTopic   = flag.String("topic", "", "Signaling topic, URL, or natbypass://profile link")
	flagBroker  = flag.String("broker", "", "MQTT broker URL (defaults to profile or ssl://broker.emqx.io:8883)")
	flagKey     = flag.String("key", "", "NetworkKey for room encryption/decryption")
	flagTarget  = flag.String("target", "", "Target DeviceID to diagnose or update (empty = all beta nodes)")
	flagUpdate  = flag.Bool("update", false, "Trigger remote beta update across target/all nodes")
	flagTimeout = flag.Duration("timeout", 45*time.Second, "Response collection timeout")
	flagOutput  = flag.String("output", "", "Output filename for consolidated cluster report")
	flagLocal   = flag.Bool("local", false, "Include local host diagnostic report in the consolidated output")
	flagConfig  = flag.String("config", "config.yaml", "Path to config.yaml (used for defaults)")
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

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

func main() {
	os.Args = reorderArgs(os.Args)
	flag.Parse()
	printBanner()

	reader := bufio.NewReader(os.Stdin)
	isInteractive := false

	// 1. Resolve configuration defaults
	cfg := loadOptionalConfig(*flagConfig)
	topic := *flagTopic
	broker := *flagBroker
	networkKey := *flagKey

	// If a link / topic was passed as first positional arg
	if topic == "" && flag.NArg() > 0 {
		topic = flag.Arg(0)
	}

	// Parse input if it's a natbypass:// link, MQTT URL, or JSON
	if topic != "" {
		b, t, k, err := parseNetworkInput(topic)
		if err == nil && t != "" {
			topic = t
			if broker == "" {
				broker = b
			}
			if networkKey == "" && k != "" {
				networkKey = k
			}
		}
	}

	// If topic is still empty, check local config profile or prompt interactively
	if topic == "" {
		isInteractive = true
		if cfg != nil {
			if prof := cfg.EnsureActiveProfile(); prof != nil && prof.MQTTTopic != "" {
				fmt.Printf(colorCyan+"[i] Найден локальный профиль NatBypass: '%s'\n"+colorReset, prof.Name)
				keyPreview := "(открытый)"
				if prof.NetworkKey != "" {
					keyPreview = prof.NetworkKey[:min(4, len(prof.NetworkKey))] + "***"
				}
				fmt.Printf(colorCyan+"    Топик: %s | Ключ: %s\n"+colorReset, prof.MQTTTopic, keyPreview)
				fmt.Print(colorYellow + "Использовать его? [Enter = Да, или вставьте ссылку natbypass://profile?...]: " + colorReset)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input == "" || strings.EqualFold(input, "y") || strings.EqualFold(input, "yes") || strings.EqualFold(input, "д") {
					topic = prof.MQTTTopic
					if broker == "" {
						broker = prof.MQTTBroker
					}
					if networkKey == "" {
						networkKey = prof.NetworkKey
					}
				} else {
					b, t, k, err := parseNetworkInput(input)
					if err == nil && t != "" {
						topic = t
						if broker == "" {
							broker = b
						}
						if networkKey == "" {
							networkKey = k
						}
					}
				}
			}
		}

		// If still empty, ask user to paste network link
		for topic == "" {
			fmt.Println(colorYellow + "\nВставьте ссылку сети (natbypass://profile?...), топик или URL брокера:" + colorReset)
			fmt.Print("> ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "" {
				continue
			}
			b, t, k, err := parseNetworkInput(input)
			if err == nil && t != "" {
				topic = t
				if broker == "" {
					broker = b
				}
				if networkKey == "" {
					networkKey = k
				}
				break
			}
			fmt.Printf(colorRed+"[✗] Ошибка распознавания ссылки: %v\n"+colorReset, err)
		}
	}

	// Default broker if not set
	if broker == "" {
		broker = "ssl://broker.emqx.io:8883"
	}

	// Interactive Mode Menu (if run interactively and -update wasn't explicitly flagged)
	if isInteractive && !*flagUpdate {
		fmt.Println(colorCyan + "\nВыберите действие:" + colorReset)
		fmt.Println("  [1] 📋 Собрать диагностические логи со всех узлов в единый файл (по умолчанию)")
		fmt.Println("  [2] 🚀 Принудительно обновить все beta-узлы сети (OTA Beta Update)")
		fmt.Println("  [3] 🎯 Диагностика одного конкретного узла")
		fmt.Print(colorYellow + "Ваш выбор [1]: " + colorReset)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		switch choice {
		case "2":
			*flagUpdate = true
		case "3":
			fmt.Print(colorYellow + "Введите DeviceID целевого узла: " + colorReset)
			tID, _ := reader.ReadString('\n')
			*flagTarget = strings.TrimSpace(tID)
		default:
			// [1] default
		}
	}

	// 2. Generate unique collector session ID and device ID
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	sessionID := fmt.Sprintf("diag-sess-%x", randBytes)
	collectorID := fmt.Sprintf("natbypass-diag-%x", randBytes)

	fmt.Println()
	fmt.Printf(colorCyan+"[ℹ] Брокер сигнализации: %s\n"+colorReset, broker)
	fmt.Printf(colorCyan+"[ℹ] Топик комнаты:       %s\n"+colorReset, topic)
	if networkKey != "" {
		fmt.Printf(colorGreen+"[✓] Шифрование комнаты:  Включено (NetworkKey: %s***)\n"+colorReset, networkKey[:min(4, len(networkKey))])
	} else {
		fmt.Printf(colorYellow+"[!] Шифрование комнаты:  Отключено (открытый канал)\n"+colorReset)
	}
	if *flagTarget != "" {
		fmt.Printf(colorCyan+"[ℹ] Целевой узел:        %s\n"+colorReset, *flagTarget)
	} else {
		fmt.Printf(colorCyan+"[ℹ] Целевой узел:        Все beta-узлы сети (Broadcast)\n"+colorReset)
	}
	if *flagUpdate {
		fmt.Printf(colorYellow+colorBold+"[⚠] РЕЖИМ:               ПРИНУДИТЕЛЬНОЕ ОБНОВЛЕНИЕ КЛИЕНТОВ (OTA Beta Update)\n"+colorReset)
	} else {
		fmt.Printf(colorCyan+"[ℹ] РЕЖИМ:               Сбор диагностических логов (Diag Collect)\n"+colorReset)
	}
	fmt.Printf(colorCyan+"[ℹ] Таймаут ожидания:    %v\n\n"+colorReset, *flagTimeout)

	// 3. Connect to signaling channel
	ctx, cancel := context.WithTimeout(context.Background(), *flagTimeout+10*time.Second)
	defer cancel()

	ch := signaling.NewMQTTChannel(broker, topic, collectorID, "", "")
	defer ch.Close()

	rx, err := ch.Receive(ctx)
	if err != nil {
		fmt.Printf(colorRed+"[✗] Ошибка подключения к брокеру: %v\n"+colorReset, err)
		if isInteractive {
			fmt.Print(colorCyan + "\nНажмите Enter для завершения..." + colorReset)
			_, _ = reader.ReadString('\n')
		}
		os.Exit(1)
	}

	// Wait for MQTT connection to establish
	fmt.Print(colorCyan + "⏳ Подключение к брокеру..." + colorReset)
	connStart := time.Now()
	for time.Since(connStart) < 7*time.Second {
		if ch.IsAvailable(ctx) {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	fmt.Println(colorGreen + " Готово!" + colorReset)

	// 4. Prepare request signal
	action := "request_diag"
	if *flagUpdate {
		action = "request_update"
	}

	reqSig := &signaling.RemoteDiagSignal{
		Action:    action,
		TargetID:  *flagTarget,
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
		time.Sleep(500 * time.Millisecond)
	}
	if sendErr != nil {
		fmt.Printf(colorYellow+"[!] Предупреждение: ошибка отправки запроса в топик: %v\n"+colorReset, sendErr)
	} else {
		fmt.Println(colorGreen + "✓ Управляющий сигнал разослан в сеть. Ожидание ответов от узлов..." + colorReset)
	}
	fmt.Println(colorBold + "─────────────────────────────────────────────────────────────────────────" + colorReset)

	// 5. Collect responses
	nodes := make(map[string]*NodeResponse)
	discoveredPeers := make(map[string]*DiscoveredNodeInfo)
	var mu sync.Mutex

	timeoutTimer := time.NewTimer(*flagTimeout)
	defer timeoutTimer.Stop()

	// Burst repeat after 2s
	go func() {
		time.Sleep(2 * time.Second)
		_ = ch.Send(ctx, toSend)
	}()

collectLoop:
	for {
		select {
		case <-timeoutTimer.C:
			fmt.Println(colorYellow + "\n[⏰] Время ожидания ответов истекло." + colorReset)
			break collectLoop

		case p, ok := <-rx:
			if !ok || p == nil {
				break collectLoop
			}

			// Decrypt if needed
			if len(p.Encrypted) > 0 && networkKey != "" {
				if dec, decErr := signaling.DecryptPayloadWithKey(p, networkKey); decErr == nil && dec != nil {
					p = dec
				}
			}

			if p.DeviceID == "" || p.DeviceID == collectorID {
				continue
			}

			mu.Lock()
			// Track discovered node
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
					fmt.Printf(colorCyan+"  [i] Обнаружен узел: %-22s (%s) [ОС: %s, VIP: %s, Версия: %s]\n"+colorReset,
						p.DeviceID, nick, p.OS, p.VirtualIP, ver)
				}
			}

			// Check for RemoteDiag response
			if p.RemoteDiag != nil && p.RemoteDiag.SessionID == sessionID {
				r := p.RemoteDiag
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
						fmt.Printf(colorYellow+"  [⚡] Узел %s (%s/%s v%s): %s\n"+colorReset,
							r.SenderID, r.OS, r.Arch, r.Version, r.Payload)
					} else {
						fmt.Printf(colorGreen+"  [✓] Узел %s: Обновление завершено (%s)! Результат: %s\n"+colorReset,
							r.SenderID, r.Status, r.Payload)
						node.Completed = true
						node.FullReport = r.Payload
					}
				} else {
					// response_diag
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
						fmt.Printf(colorGreen+colorBold+"  [✓] Узел %s (%s/%s v%s): Диагностический отчет ПОЛНОСТЬЮ получен (%d байт)\n"+colorReset,
							r.SenderID, r.OS, r.Arch, r.Version, len(node.FullReport))
					}
				}
			}
			mu.Unlock()
		}
	}

	// 6. If local flag was set, gather local diagnostic report
	var localReport string
	if *flagLocal {
		fmt.Println(colorCyan + "\n[🖥️] Выполнение локальной диагностики хоста..." + colorReset)
		localReport = diagnostic.ExecuteLocalDiagScript(ctx)
		fmt.Println(colorGreen + "✓ Локальная диагностика хоста завершена!" + colorReset)
	}

	// 7. Format unified cluster report
	timestampStr := time.Now().Format("20060102_150405")
	cleanTopic := strings.ReplaceAll(strings.ReplaceAll(topic, "/", "_"), "\\", "_")
	outFileName := *flagOutput
	if outFileName == "" {
		outFileName = fmt.Sprintf("cluster_diag_%s_%s.txt", cleanTopic, timestampStr)
	}

	var fileSb strings.Builder
	fileSb.WriteString("================================================================================\n")
	fileSb.WriteString("                  NATBYPASS CLUSTER DIAGNOSTIC REPORT                           \n")
	fileSb.WriteString("================================================================================\n")
	fileSb.WriteString(fmt.Sprintf("Timestamp:      %s\n", time.Now().UTC().Format(time.RFC3339)))
	fileSb.WriteString(fmt.Sprintf("MQTT Broker:    %s\n", broker))
	fileSb.WriteString(fmt.Sprintf("Topic:          %s\n", topic))
	fileSb.WriteString(fmt.Sprintf("Encrypted:      %t\n", networkKey != ""))
	fileSb.WriteString(fmt.Sprintf("Discovered:     %d nodes\n", len(discoveredPeers)))
	fileSb.WriteString(fmt.Sprintf("Responded Beta: %d nodes\n", len(nodes)))
	fileSb.WriteString("================================================================================\n\n")

	// Summary of all discovered nodes
	var allPeerIDs []string
	for id := range discoveredPeers {
		allPeerIDs = append(allPeerIDs, id)
	}
	sort.Strings(allPeerIDs)

	fileSb.WriteString("================================================================================\n")
	fileSb.WriteString(fmt.Sprintf(" СПИСОК ОБНАРУЖЕННЫХ УЗЛОВ В СЕТИ (ОНЛАЙН В ТОПИКЕ: %d)\n", len(discoveredPeers)))
	fileSb.WriteString("================================================================================\n\n")
	for _, id := range allPeerIDs {
		dp := discoveredPeers[id]
		hasDiag := false
		if n, ok := nodes[id]; ok && n.Completed {
			hasDiag = true
		}
		statusText := fmt.Sprintf("Требуется обновить бинарник до актуальной beta (на узле: %s, RemoteDiag с v1.9.224-beta7+)", dp.Version)
		if hasDiag {
			statusText = "OK (Диагностический отчет получен)"
		} else if isBeta7OrNewer(dp.Version) {
			statusText = "Таймаут сбора отчета (узел на актуальной beta, но не успел передать отчет за отведенное время)"
		}
		fileSb.WriteString(fmt.Sprintf("Узел:        %s (%s)\n", dp.DeviceID, dp.Nickname))
		fileSb.WriteString(fmt.Sprintf("ОС/Арх:      %s/%s | Версия: %s\n", dp.OS, dp.Arch, dp.Version))
		fileSb.WriteString(fmt.Sprintf("Virtual IP:  %s | Публичный IP: %s\n", dp.VirtualIP, dp.PublicIP))
		fileSb.WriteString(fmt.Sprintf("Статус:      %s\n", statusText))
		fileSb.WriteString("--------------------------------------------------------------------------------\n")
	}
	fileSb.WriteString("\n\n")

	if *flagLocal && localReport != "" {
		fileSb.WriteString("################################################################################\n")
		fileSb.WriteString(" LOCAL CONTROLLER HOST DIAGNOSTICS\n")
		fileSb.WriteString("################################################################################\n\n")
		fileSb.WriteString(localReport)
		fileSb.WriteString("\n\n")
	}

	// Full diagnostic logs from responding beta nodes
	var nodeIDs []string
	for id := range nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	for _, id := range nodeIDs {
		n := nodes[id]
		fileSb.WriteString("################################################################################\n")
		fileSb.WriteString(fmt.Sprintf(" ПОЛНЫЙ ДИАГНОСТИЧЕСКИЙ ОТЧЕТ УЗЛА: %s\n", n.DeviceID))
		fileSb.WriteString(fmt.Sprintf(" Platform: %s/%s | Version: %s | Status: %s\n", n.OS, n.Arch, n.Version, n.Status))
		fileSb.WriteString(fmt.Sprintf(" Completed: %t | Total Chunks: %d\n", n.Completed, n.TotalChunks))
		fileSb.WriteString("################################################################################\n\n")
		if n.FullReport != "" {
			fileSb.WriteString(n.FullReport)
		} else {
			fileSb.WriteString("(Внимание: отчет получен не полностью или поврежден)\n")
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

	// 8. Print Summary Table
	fmt.Println("\n" + colorBold + "═══════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " 📊 СВОДНАЯ ТАБЛИЦА УЗЛОВ КЛАСТЕРА" + colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Printf("%-24s │ %-15s │ %-14s │ %-24s │ %-10s\n", "DEVICE ID", "ПЛАТФОРМА", "ВЕРСИЯ", "СТАТУС", "РАЗМЕР")
	fmt.Println("─────────────────────────┼─────────────────┼────────────────┼──────────────────────────┼───────────")
	for _, id := range allPeerIDs {
		dp := discoveredPeers[id]
		plat := fmt.Sprintf("%s/%s", dp.OS, dp.Arch)
		if dp.Arch == "" {
			plat = dp.OS
		}
		st := "Старая beta (нет RemoteDiag)"
		if isBeta7OrNewer(dp.Version) {
			st = "⌛ Таймаут / Занят"
		}
		szStr := "-"
		if n, ok := nodes[id]; ok {
			st = n.Status
			if n.Completed {
				st = "✓ Получен"
			}
			if len(n.FullReport) > 1024 {
				szStr = fmt.Sprintf("%.1f КБ", float64(len(n.FullReport))/1024.0)
			} else if len(n.FullReport) > 0 {
				szStr = fmt.Sprintf("%d Б", len(n.FullReport))
			}
		}
		fmt.Printf("%-24s │ %-15s │ %-14s │ %-24s │ %-10s\n",
			truncateStr(dp.DeviceID, 24), truncateStr(plat, 15), truncateStr(dp.Version, 14), truncateStr(st, 24), szStr)
	}
	if len(allPeerIDs) == 0 {
		fmt.Println(" (Узлов в сети не обнаружено. Проверьте активность маяков и топик)")
	}
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)

	if isInteractive {
		fmt.Print(colorCyan + "\nНажмите Enter для завершения..." + colorReset)
		_, _ = reader.ReadString('\n')
	}
}

// parseNetworkInput extracts broker, topic, and networkKey from any format:
// - natbypass://profile?... (the standard share link)
// - mqtt://..., ssl://..., tcp://... URL
// - plain topic name (e.g. natbypass/mesh/...)
func parseNetworkInput(raw string) (broker, topic, key string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", fmt.Errorf("empty input")
	}

	// 1. Try standard natbypass://profile or JSON via config.ImportProfileURI
	if prof, pErr := config.ImportProfileURI(raw); pErr == nil && prof != nil {
		b := prof.MQTTBroker
		if b == "" {
			b = "ssl://broker.emqx.io:8883"
		}
		return b, prof.MQTTTopic, prof.NetworkKey, nil
	}

	// 2. Try URL with mqtt://, ssl://, tcp://, wss://
	if strings.Contains(raw, "://") {
		if parsedURL, pErr := url.Parse(raw); pErr == nil {
			q := parsedURL.Query()
			b := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
			t := strings.TrimPrefix(parsedURL.Path, "/")
			k := q.Get("key")
			if t != "" {
				return b, t, k, nil
			}
		}
	}

	// 3. Plain topic name (e.g. natbypass/mesh/12345 or myroom)
	return "ssl://broker.emqx.io:8883", raw, "", nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func loadOptionalConfig(path string) *config.Config {
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		cfg, err := config.Load(path)
		if err == nil {
			return cfg
		}
	}
	if fi, err := os.Stat("dist/config.yaml"); err == nil && !fi.IsDir() {
		cfg, err := config.Load("dist/config.yaml")
		if err == nil {
			return cfg
		}
	}
	return nil
}

func printBanner() {
	fmt.Println(colorCyan + colorBold + `
  ███╗   ██╗ █████╗ ████████╗██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
  ████╗  ██║██╔══██╗╚══██╔══╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██╔██╗ ██║███████║   ██║   ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
  ██║╚██╗██║██╔══██║   ██║   ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
  ██║ ╚████║██║  ██║   ██║   ██████╔╝   ██║   ██║     ██║  ██║███████║███████║
  ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
        Cluster Remote Diagnostic & Update Tool (Beta / Engineering Only)
` + colorReset)
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
				if lower != "-update" && lower != "-local" && lower != "--update" && lower != "--local" {
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

func isBeta7OrNewer(ver string) bool {
	vLower := strings.ToLower(ver)
	if !strings.Contains(vLower, "beta") {
		return false
	}
	for _, old := range []string{"beta1", "beta2", "beta3", "beta4", "beta5", "beta6"} {
		if strings.Contains(vLower, old) {
			return false
		}
	}
	return true
}
