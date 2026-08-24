package diagnostic

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/pion/stun/v2"
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

	// 7. Проверка среды WebView2 (Edge Runtime)
	report.Items = append(report.Items, CheckWebView2Runtime())

	// 8. Перечисление локальных сетевых адаптеров
	report.Items = append(report.Items, CheckNetworkInterfaces())

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

func CheckSTUNDiscovery() DiagnosticItem {
	start := time.Now()
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return DiagnosticItem{Name: "STUN NAT Пробитие", Passed: false, Elapsed: time.Since(start), Message: err.Error()}
	}
	defer conn.Close()

	srvAddr, err := net.ResolveUDPAddr("udp4", "stun.l.google.com:19302")
	if err != nil {
		return DiagnosticItem{Name: "STUN NAT Пробитие", Passed: false, Elapsed: time.Since(start), Message: "Не удалось разрешить DNS stun.l.google.com"}
	}

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	_, _ = conn.WriteToUDP(msg.Raw, srvAddr)

	_ = conn.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	elapsed := time.Since(start)

	if err != nil {
		return DiagnosticItem{
			Name:    "STUN NAT Пробитие (RFC 5389)",
			Passed:  false,
			Elapsed: elapsed,
			Message: "❌ Таймаут ответа от STUN-сервера Google (порт 19302 UDP)",
			Details: "UDP-трафик блокируется провайдером, роутером или локальным брандмауэром. Прямой P2P может потребовать релея.",
		}
	}

	var resp stun.Message
	resp.Raw = buf[:n]
	var xorAddr stun.XORMappedAddress
	if err := resp.Decode(); err == nil && xorAddr.GetFrom(&resp) == nil {
		return DiagnosticItem{
			Name:    "STUN NAT Пробитие (RFC 5389)",
			Passed:  true,
			Elapsed: elapsed,
			Message: fmt.Sprintf("✓ Внешний сокет успешно определен: %s:%d (задержка %d ms)", xorAddr.IP.String(), xorAddr.Port, elapsed.Milliseconds()),
		}
	}

	return DiagnosticItem{
		Name:    "STUN NAT Пробитие (RFC 5389)",
		Passed:  true,
		Elapsed: elapsed,
		Message: "✓ STUN пакет получен",
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
