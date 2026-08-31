package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/natbypass/natbypass/internal/diagnostic"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/spf13/cobra"
)

func newDiagCmd() *cobra.Command {
	var targetIP string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "diag",
		Short: "Run deep network, P2P, firewall, routing and L3 diagnostics",
		Long: `Run comprehensive diagnostic analysis on the local node:
- Verifies virtual network interface (nb0 / NatBypass)
- Checks kernel routing table, policy routing (ip rule), and sysctl parameters
- Probes STUN servers and classifies NAT mapping & filtering
- Queries local NatBypass daemon and lists all discovered peers
- Tests active UDP reachability and end-to-end ICMP ping delivery`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiagnostics(configFile, targetIP, jsonOutput)
		},
	}

	cmd.Flags().StringVar(&targetIP, "target", "", "Target Virtual IP or DeviceID to specifically diagnose")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output diagnostic report in JSON format")

	return cmd
}

func runDiagnostics(cfgPath, targetIP string, jsonOut bool) error {
	fmt.Println("\033[1;36m======================================================================")
	fmt.Printf("   🔍 NatBypass Universal Network & L3 Diagnostic Tool (v%s)\n", Version)
	fmt.Println("======================================================================\033[0m")

	report := diagnostic.RunFullDiagnostics()

	// 1. System & Admin
	fmt.Printf("\n\033[1;34m▶ 1. СИСТЕМНОЕ ОКРУЖЕНИЕ И ПЛАТФОРМА\033[0m\n")
	fmt.Printf("  [i] Хост: %s | ОС: %s | Архитектура: %s\n", report.Hostname, report.OS, report.Arch)
	if report.IsAdmin {
		fmt.Println("  \033[1;32m[✓]\033[0m Права: Администратор / Root")
	} else {
		fmt.Println("  \033[1;33m[!]\033[0m Права: Обычный пользователь (рекомендуется запуск под root / Administrator)")
	}

	// 2. NAT & STUN
	fmt.Printf("\n\033[1;34m▶ 2. КЛАССИФИКАЦИЯ NAT И STUN ЭНДПОИНТ\033[0m\n")
	natInfo, err := diagnostic.ClassifyNATBehavior()
	if err == nil && natInfo != nil {
		fmt.Printf("  \033[1;32m[✓]\033[0m Публичный IP: %s (Порт STUN: %d)\n", natInfo.PublicIP, natInfo.MappedPort1)
		fmt.Printf("  [i] Тип NAT: %s\n", natInfo.NATType)
		fmt.Printf("  [i] P2P совместимость: %s\n", natInfo.P2PFeasibility)
	} else {
		fmt.Printf("  \033[1;33m[!]\033[0m STUN проба: %v\n", err)
	}

	// 3. Local Daemon Query
	fmt.Printf("\n\033[1;34m▶ 3. ЛОКАЛЬНЫЙ ДЕМОН NATBYPASS (HTTP 127.0.0.1:8080)\033[0m\n")
	daemonRunning := false
	var peers []*peer.Peer
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8080/api/status")
	if err == nil && resp.StatusCode == 200 {
		daemonRunning = true
		var st struct {
			DeviceID  string `json:"device_id"`
			VirtualIP string `json:"virtual_ip"`
			WGPort    int    `json:"wg_port"`
			PublicIP  string `json:"public_ip"`
			DirectP2P int    `json:"direct_p2p_count"`
			Peers     int    `json:"peer_count"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&st)
		_ = resp.Body.Close()
		fmt.Printf("  \033[1;32m[✓]\033[0m Демон активен: DeviceID=%s | VirtualIP=%s | Port=%d | Peers=%d (Direct=%d)\n",
			st.DeviceID, st.VirtualIP, st.WGPort, st.Peers, st.DirectP2P)

		pResp, pErr := client.Get("http://127.0.0.1:8080/api/peers")
		if pErr == nil && pResp.StatusCode == 200 {
			var pData struct {
				Data []*peer.Peer `json:"data"`
			}
			_ = json.NewDecoder(pResp.Body).Decode(&pData)
			_ = pResp.Body.Close()
			peers = pData.Data
		}
	} else {
		fmt.Println("  \033[1;33m[!]\033[0m Локальный API http://127.0.0.1:8080 не отвечает (демон не запущен)")
	}

	// 4. Peers Table
	fmt.Printf("\n\033[1;34m▶ 4. СПИСОК ПИРОВ И АКТИВНЫХ МАРШРУТОВ\033[0m\n")
	if len(peers) > 0 {
		for _, p := range peers {
			p2pStatus := "📡 Relay"
			if p.DirectP2P {
				p2pStatus = "🟢 Прямой P2P"
			}
			fmt.Printf("  • %s (%s) | VIP: %s | %s | EP: %s | Ping: %v\n",
				p.DeviceName, p.DeviceID, p.VirtualIP, p2pStatus, p.ActiveEndpoint, p.Latency)
			if len(p.Candidates) > 0 {
				fmt.Printf("    Кандидаты: %s\n", strings.Join(p.Candidates, ", "))
			}
		}
	} else if daemonRunning {
		fmt.Println("  [i] В сети пока нет других пиров (ожидание сигнальных сообщений).")
	}

	// 5. ICMP Ping Test
	fmt.Printf("\n\033[1;34m▶ 5. СКВОЗНОЙ ТЕСТ ICMP PING ДО ВСЕХ ОБНАРУЖЕННЫХ ПИРОВ\033[0m\n")
	type pingTarget struct {
		name string
		ip   string
	}
	var targets []pingTarget
	cleanLocalVIP := strings.TrimSpace(strings.Split(st.VirtualIP, "/")[0])
	if targetIP != "" {
		targets = append(targets, pingTarget{name: "Указанный IP", ip: targetIP})
	} else {
		if cleanLocalVIP != "" && cleanLocalVIP != "0.0.0.0" {
			targets = append(targets, pingTarget{name: "Локальный узел (Self)", ip: cleanLocalVIP})
		}
		for _, p := range peers {
			cleanIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
			if cleanIP != "" && cleanIP != "0.0.0.0" && cleanIP != cleanLocalVIP {
				pName := p.DeviceName
				if pName == "" {
					pName = p.DeviceID
				}
				targets = append(targets, pingTarget{name: pName, ip: cleanIP})
			}
		}
		if len(targets) == 0 || (len(targets) == 1 && cleanLocalVIP != "") {
			for _, fb := range []string{"10.123.111.1", "10.123.111.2", "10.123.111.110", "100.64.200.1"} {
				if fb != cleanLocalVIP {
					targets = append(targets, pingTarget{name: "Mesh узел (Fallback)", ip: fb})
				}
			}
		}
	}
	for _, t := range targets {
		cleanIP := strings.TrimSpace(strings.Split(t.ip, "/")[0])
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("ping", cleanIP, "-n", "2", "-w", "1500")
		} else {
			cmd = exec.Command("ping", "-c", "2", "-W", "2", cleanIP)
		}
		out, pErr := cmd.CombinedOutput()
		if pErr == nil && !strings.Contains(string(out), "100%") && (strings.Contains(string(out), "TTL=") || strings.Contains(string(out), "ttl=")) {
			fmt.Printf("  \033[1;32m[✓]\033[0m Ping до %s (%s): УСПЕШНО!\n", t.name, cleanIP)
		} else {
			fmt.Printf("  \033[1;31m[✗]\033[0m Ping до %s (%s): ПРЕВЫШЕН ИНТЕРВАЛ ОЖИДАНИЯ (100%% потерь)\n", t.name, cleanIP)
		}
	}

	fmt.Println("\n\033[1;32m======================================================================")
	fmt.Println("✓ Диагностика завершена!")
	fmt.Println("======================================================================\033[0m")
	return nil
}