//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/network"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/pion/stun/v2"
	"golang.org/x/sys/windows"
)

var (
	flagConfig = flag.String("config", "dist/config.yaml", "Path to config.yaml")
	flagTarget = flag.String("target", "", "Target Peer Virtual IP or DeviceID to diagnose specifically")
	flagSniff  = flag.Bool("sniff", false, "Run live real-time packet sniffer on Wintun tunnel")
	flagLaunch = flag.Bool("launch", false, "Launch NatBypass.exe and attach diagnostic monitor")
	flagFull   = flag.Bool("full", true, "Run full comprehensive network and packet analysis")
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

func main() {
	flag.Parse()

	printBanner()

	if *flagLaunch {
		launchAndDiagnose()
		return
	}

	cfg := loadConfig(*flagConfig)

	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " [1/6] 🖥️ ДИАГНОСТИКА СИСТЕМНОГО ОКРУЖЕНИЯ WINDOWS" + colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	checkWindowsEnvironment()

	fmt.Println("\n" + colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " [2/6] 🌐 ДИАГНОСТИКА NAT, STUN И ВНЕШНЕГО IP" + colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	checkNATAndSTUN(cfg)

	fmt.Println("\n" + colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " [3/6] 🚪 ПРОВЕРКА UPnP / РОУТЕРА" + colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	checkUPnP(cfg)

	fmt.Println("\n" + colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " [4/6] 📡 ПРОВЕРКА СИГНАЛЬНЫХ КАНАЛОВ (MQTT & TELEGRAM)" + colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	checkSignaling(cfg)

	fmt.Println("\n" + colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " [5/6] 👥 СОСТОЯНИЕ СЕТИ И АКТИВНЫХ ПИРОВ" + colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	checkPeersAndRouting(cfg)

	fmt.Println("\n" + colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " [6/6] 📦 СКВОЗНОЙ ТЕСТ L3 DATA-PLANE И MTU ПАКЕТОВ" + colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	checkDataPlaneAndMTU(cfg)

	if *flagSniff {
		runLivePacketSniffer(cfg)
	}

	fmt.Println("\n" + colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorGreen + colorBold + "✓ Диагностика завершена!" + colorReset)
}

func printBanner() {
	fmt.Println(colorCyan + colorBold + `
  ███╗   ██╗ █████╗ ████████╗██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
  ████╗  ██║██╔══██╗╚══██╔══╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██╔██╗ ██║███████║   ██║   ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
  ██║╚██╗██║██╔══██║   ██║   ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
  ██║ ╚████║██║  ██║   ██║   ██████╔╝   ██║   ██║     ██║  ██║███████║███████║
  ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
      NatBypass Network Diagnostic & Packet Analysis Tool v1.9.29
` + colorReset)
}

func loadConfig(path string) *config.Config {
	if _, err := os.Stat(path); err != nil {
		if _, err2 := os.Stat("config.yaml"); err2 == nil {
			path = "config.yaml"
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Printf(colorYellow+"⚠ Ошибка загрузки конфига %s, используются параметры по умолчанию: %v\n"+colorReset, path, err)
		return &config.Config{}
	}
	fmt.Printf(colorGreen+"✓ Загружен конфиг: %s\n"+colorReset, path)
	return cfg
}



func checkWindowsEnvironment() {
	// 1. Проверка прав Администратора
	isAdmin := checkIsAdmin()
	if isAdmin {
		fmt.Println(colorGreen + " [✓] Права Администратора: ДА (Elevated)" + colorReset)
	} else {
		fmt.Println(colorRed + " [✗] Права Администратора: НЕТ (Требуется запуск от имени Администратора для Wintun!)" + colorReset)
	}

	// 2. Проверка wintun.dll
	wintunFound := false
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	pathsToCheck := []string{"wintun.dll", filepath.Join(exeDir, "wintun.dll"), "dist/wintun.dll"}
	for _, p := range pathsToCheck {
		if _, err := os.Stat(p); err == nil {
			wintunFound = true
			fmt.Printf(colorGreen+" [✓] Драйвер Wintun.dll найден: %s\n"+colorReset, p)
			break
		}
	}
	if !wintunFound {
		fmt.Println(colorRed + " [✗] wintun.dll НЕ найден рядом с программой! Туннель не сможет запуститься." + colorReset)
	}

	// 3. Проверка сетевого интерфейса NatBypass
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "subinterfaces").CombinedOutput()
	if err == nil && strings.Contains(string(out), "NatBypass") {
		fmt.Println(colorGreen + " [✓] Сетевой адаптер NatBypass зарегистрирован в Windows NDIS" + colorReset)
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			if strings.Contains(l, "NatBypass") {
				fmt.Printf(colorCyan+"     Параметры интерфейса: %s\n"+colorReset, strings.TrimSpace(l))
			}
		}
	} else {
		fmt.Println(colorYellow + " [ℹ] Сетевой адаптер NatBypass не активен в данный момент (запустите NatBypass.exe)" + colorReset)
	}

	// 4. Проверка правил Брандмауэра Windows
	fwOut, _ := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=NatBypass ICMP In").CombinedOutput()
	if strings.Contains(string(fwOut), "NatBypass") {
		fmt.Println(colorGreen + " [✓] Правило брандмауэра Windows 'NatBypass ICMP In': АКТИВНО (ICMP Ping разрешен)" + colorReset)
	} else {
		fmt.Println(colorYellow + " [ℹ] Правило 'NatBypass ICMP In' не найдено в брандмауэре (будет создано при старте)" + colorReset)
	}
}

func checkIsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

func checkNATAndSTUN(cfg *config.Config) {
	stunServers := cfg.Network.StunServers
	if len(stunServers) == 0 {
		stunServers = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		fmt.Printf(colorRed+" [✗] Ошибка открытия локального UDP сокета: %v\n"+colorReset, err)
		return
	}
	defer conn.Close()

	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf(colorCyan+" [ℹ] Локальный UDP порт для зондирования: :%d\n"+colorReset, localPort)

	for _, srv := range stunServers {
		srvAddr, err := net.ResolveUDPAddr("udp", srv)
		if err != nil {
			fmt.Printf(colorYellow+" [!] STUN сервер %s не резолвится: %v\n"+colorReset, srv, err)
			continue
		}

		msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		start := time.Now()
		if _, err := conn.WriteToUDP(msg.Raw, srvAddr); err != nil {
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(buf)
		rtt := time.Since(start)

		if err == nil && stun.IsMessage(buf[:n]) {
			var resp stun.Message
			resp.Raw = buf[:n]
			_ = resp.Decode()
			var mappedAddr stun.XORMappedAddress
			if err := mappedAddr.GetFrom(&resp); err == nil {
				fmt.Printf(colorGreen+" [✓] STUN %-28s -> Внешний адрес: %s:%d (RTT: %dмс)\n"+colorReset,
					srv, mappedAddr.IP.String(), mappedAddr.Port, rtt.Milliseconds())
			}
		} else {
			fmt.Printf(colorRed+" [✗] STUN %-28s -> Таймаут ответа (фильтрация UDP/DPI)\n"+colorReset, srv)
		}
	}

	// Определение типа NAT
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	natType, err := network.DetectNATType(ctx, conn, stunServers)
	if err == nil {
		switch natType {
		case network.NATTypeFullCone:
			fmt.Printf(colorGreen+colorBold+" [✓] Тип NAT: %s — Прямое P2P соединение поддерживается идеально!\n"+colorReset, natType.String())
		case network.NATTypeRestricted, network.NATTypePortRestricted:
			fmt.Printf(colorGreen+" [✓] Тип NAT: %s — P2P доступно через стандартный Hole Punching.\n"+colorReset, natType.String())
		case network.NATTypeSymmetric:
			fmt.Printf(colorYellow+colorBold+" [!] Тип NAT: %s — Требуется Multi-Port Spray / UPnP / IPv6.\n"+colorReset, natType.String())
		default:
			fmt.Printf(colorCyan+" [ℹ] Тип NAT: %s\n"+colorReset, natType.String())
		}

	}
}

func checkUPnP(cfg *config.Config) {
	upnp := network.NewUPnPClient()
	err := upnp.AddPortMapping(context.Background(), 51820, 51820, "UDP", "NatBypass Diag", 300)
	if err == nil {
		fmt.Println(colorGreen + " [✓] UPnP / IGD шлюз доступен! Порт 51820 успешно проброшен на роутере (Full Cone активирован)." + colorReset)
		_ = upnp.DeletePortMapping(context.Background(), 51820, "UDP")
	} else {
		fmt.Printf(colorYellow+" [ℹ] UPnP не ответил: %v (это нормально для мобильных сетей или если UPnP выключен на роутере)\n"+colorReset, err)
	}
}

func checkSignaling(cfg *config.Config) {
	activeProf := cfg.EnsureActiveProfile()
	broker := "tcp://broker.emqx.io:1883"
	topic := "natbypass/mesh/diagnostic"
	if activeProf != nil && activeProf.MQTTBroker != "" {
		broker = activeProf.MQTTBroker
	}
	if activeProf != nil && activeProf.MQTTTopic != "" {
		topic = activeProf.MQTTTopic
	}

	fmt.Printf(colorCyan+" [ℹ] Проверка MQTT брокера: %s (Топик: %s)\n"+colorReset, broker, topic)

	ch := signaling.NewMQTTChannel(broker, topic, "DiagTester", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	rx, err := ch.Receive(ctx)
	if err != nil {
		fmt.Printf(colorRed+" [✗] Ошибка подписки на MQTT брокер: %v\n"+colorReset, err)
		return
	}

	testPayload := &signaling.Payload{
		DeviceID:  "DiagTester",
		PublicIP:  "127.0.0.1",
		Timestamp: time.Now(),
	}

	start := time.Now()
	if err := ch.Send(ctx, testPayload); err != nil {
		fmt.Printf(colorRed+" [✗] Ошибка отправки в MQTT топик: %v\n"+colorReset, err)
		return
	}

	select {
	case p := <-rx:
		rtt := time.Since(start)
		if p != nil {
			fmt.Printf(colorGreen+" [✓] Сигнальный канал MQTT работает! Задержка брокера: %dмс\n"+colorReset, rtt.Milliseconds())
		}
	case <-time.After(3 * time.Second):
		fmt.Println(colorYellow + " [!] Эхо-маяк MQTT не получен за 3с (возможна задержка публичного брокера)" + colorReset)
	}
	_ = ch.Close()
}

func checkPeersAndRouting(cfg *config.Config) {
	// Опрос локального API работающего узла
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/peers", cfg.WebUI.Port))
	if err != nil {
		fmt.Printf(colorYellow+" [ℹ] Локальный процесс NatBypass на порту %d не запущен (API недоступно)\n"+colorReset, cfg.WebUI.Port)
		return
	}
	defer resp.Body.Close()

	fmt.Println(colorGreen + " [✓] Локальный процесс NatBypass активен и отвечает по HTTP API" + colorReset)
}

func checkDataPlaneAndMTU(cfg *config.Config) {
	myVIP := "100.64.200.10"
	if cfg.Network.Address != "" {
		myVIP = strings.Split(cfg.Network.Address, "/")[0]
	}

	fmt.Printf(colorCyan+" [ℹ] Тестирование собственного Virtual IP: %s\n"+colorReset, myVIP)
	_, err := exec.Command("ping", "-n", "2", "-w", "1000", myVIP).CombinedOutput()
	if err == nil {
		fmt.Println(colorGreen + " [✓] Локальный стек Wintun отвечает на ICMP Ping (0% потерь)" + colorReset)
	} else {
		fmt.Println(colorYellow + " [!] Пинг собственного адреса не прошел (адаптер еще не привязан или служба остановлена)" + colorReset)
	}


	if *flagTarget != "" {
		fmt.Printf(colorBold+"\n [ℹ] Тестирование целевого узла %s:\n"+colorReset, *flagTarget)
		
		// 1. Стандартный пинг
		pOut, pErr := exec.Command("ping", "-n", "3", "-w", "1500", *flagTarget).CombinedOutput()
		if pErr == nil {
			fmt.Printf(colorGreen+" [✓] Пинг до %s УСПЕШЕН:\n%s\n"+colorReset, *flagTarget, string(pOut))
		} else {
			fmt.Printf(colorRed+" [✗] Узел %s не отвечает на пинг:\n%s\n"+colorReset, *flagTarget, string(pOut))
		}

		// 2. Тест MTU без фрагментации (1420 vs 1500)
		fmt.Printf(colorCyan + " [ℹ] Проверка MTU пути (Don't Fragment test):\n" + colorReset)
		mtu1420, _ := exec.Command("ping", "-n", "1", "-f", "-l", "1392", "-w", "1000", *flagTarget).CombinedOutput()
		if strings.Contains(string(mtu1420), "TTL=") {
			fmt.Println(colorGreen + " [✓] Пакеты MTU 1420 проходят без фрагментации!" + colorReset)
		} else {
			fmt.Println(colorYellow + " [!] Пакеты MTU 1420 требуют фрагментации или блокируются фильтрами" + colorReset)
		}
	}
}

func runLivePacketSniffer(cfg *config.Config) {
	fmt.Println("\n" + colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println(colorBold + " 🕵️ РЕЖИМ СНИФФЕРА ПАКЕТОВ В РЕАЛЬНОМ ВРЕМЕНИ (WINTUN / TUNNEL DATA)" + colorReset)
	fmt.Println(colorBold + " Нажмите Ctrl+C для выхода" + colorReset)
	fmt.Println(colorBold + "═══════════════════════════════════════════════════════════════════════" + colorReset)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 51820})
	if err != nil {
		fmt.Printf(colorYellow+" [!] Порт 51820 занят основным процессом (запуск в режиме прослушивания)\n"+colorReset)
		return
	}
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 20 {
			continue
		}

		nowStr := time.Now().Format("15:04:05.000")
		if strings.HasPrefix(string(buf[:n]), "NATBYPASS:TUN:") {
			ipPkt := buf[14:n]
			if len(ipPkt) >= 20 {
				srcIP := net.IPv4(ipPkt[12], ipPkt[13], ipPkt[14], ipPkt[15])
				dstIP := net.IPv4(ipPkt[16], ipPkt[17], ipPkt[18], ipPkt[19])
				proto := ipPkt[9]
				protoName := "IP"
				switch proto {
				case 1:
					protoName = "ICMP"
				case 6:
					protoName = "TCP"
				case 17:
					protoName = "UDP"
				}
				fmt.Printf(colorCyan+"[%s] 📦 INBOUND TUNNEL: %s -> %s [%s] Size=%d байт (от %s)\n"+colorReset,
					nowStr, srcIP, dstIP, protoName, len(ipPkt), remoteAddr)
			}
		} else if strings.HasPrefix(string(buf[:n]), "NATBYPASS:PING:") {
			fmt.Printf(colorGreen+"[%s] ⚡ P2P PROBE PING: от %s (%s)\n"+colorReset, nowStr, remoteAddr, string(buf[:n]))
		}
	}
}

func launchAndDiagnose() {
	exeDir, _ := os.Executable()
	mainExe := filepath.Join(filepath.Dir(exeDir), "NatBypass.exe")
	if _, err := os.Stat(mainExe); err != nil {
		mainExe = "dist/NatBypass.exe"
	}
	fmt.Printf(colorCyan+"Запуск основного процесса %s...\n"+colorReset, mainExe)
	cmd := exec.Command(mainExe, "--ui", "browser")
	if err := cmd.Start(); err != nil {
		fmt.Printf(colorRed+"Ошибка запуска: %v\n"+colorReset, err)
		return
	}
	fmt.Printf(colorGreen+"Процесс запущен (PID %d). Запуск диагностики через 3 секунды...\n"+colorReset, cmd.Process.Pid)
	time.Sleep(3 * time.Second)
	*flagLaunch = false
	main()
}
