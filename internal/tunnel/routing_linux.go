//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/network"
)

func runLinuxCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// isKeeneticDevice checks if running on KeeneticOS.
func isKeeneticDevice() bool {
	for _, p := range []string{"/bin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// findIptablesBinary finds the preferred iptables executable.
func findIptablesBinary() string {
	for _, p := range []string{"/usr/sbin/iptables", "/sbin/iptables", "iptables", "/opt/sbin/iptables"} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	return "iptables"
}

// ensureIptablesRule checks if a rule exists in iptables; if not, appends it.
func ensureIptablesRule(ipt string, table string, chain string, args ...string) {
	checkArgs := []string{"-w", "2"}
	if table != "" {
		checkArgs = append(checkArgs, "-t", table)
	}
	checkArgs = append(checkArgs, "-C", chain)
	checkArgs = append(checkArgs, args...)
	if exec.Command(ipt, checkArgs...).Run() == nil {
		return // Rule already exists, do not duplicate!
	}
	insertArgs := []string{"-w", "2"}
	if table != "" {
		insertArgs = append(insertArgs, "-t", table)
	}
	insertArgs = append(insertArgs, "-A", chain)
	insertArgs = append(insertArgs, args...)
	_ = exec.Command(ipt, insertArgs...).Run()
}

// insertIptablesRule inserts a rule at the TOP of a chain (-I), ensuring it takes priority
// over any existing rules (e.g. Docker's DROP policies). Idempotent via -C check.
func insertIptablesRule(ipt, table, chain string, args ...string) {
	checkArgs := []string{"-w", "2"}
	if table != "" {
		checkArgs = append(checkArgs, "-t", table)
	}
	checkArgs = append(checkArgs, "-C", chain)
	checkArgs = append(checkArgs, args...)
	if exec.Command(ipt, checkArgs...).Run() == nil {
		return // already exists
	}
	insertArgs := []string{"-w", "2"}
	if table != "" {
		insertArgs = append(insertArgs, "-t", table)
	}
	insertArgs = append(insertArgs, "-I", chain, "1")
	insertArgs = append(insertArgs, args...)
	_ = exec.Command(ipt, insertArgs...).Run()
}

// EnableHostIPForwardingSubnet enables kernel IPv4 forwarding and adds iptables NAT masquerading for mesh subnet.
func EnableHostIPForwardingSubnet(subnet string) error {
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	if subnet == "" {
		subnet = "100.64.200.0/24"
	}
	cleanSubnet := subnet
	// F5: Нормализуем через ParseCIDR — получаем сетевой адрес (10.11.12.0/24 из 10.11.12.1/24)
	if _, ipNet, err := net.ParseCIDR(subnet); err == nil {
		cleanSubnet = ipNet.String()
	} else if !strings.Contains(cleanSubnet, "/") {
		parts := strings.Split(cleanSubnet, ".")
		if len(parts) >= 3 {
			cleanSubnet = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		} else {
			cleanSubnet = "100.64.200.0/24"
		}
	}

	ipt := findIptablesBinary()

	// 1. NAT Masquerading for mesh subnet ONLY when not exiting back to nb0
	ensureIptablesRule(ipt, "nat", "POSTROUTING", "-s", cleanSubnet, "!", "-o", "nb0", "-j", "MASQUERADE")

	// 2. Forwarding rules for nb0
	// FIX-N2: Use -I (insert at top) for FORWARD rules so they take priority over Docker's DROP policies
	insertIptablesRule(ipt, "", "FORWARD", "-i", "nb0", "-j", "ACCEPT")
	insertIptablesRule(ipt, "", "FORWARD", "-o", "nb0", "-j", "ACCEPT")
	// Try conntrack module first; fall back to 'state' module if conntrack not available (MIPS routers)
	if exec.Command(ipt, "-w", "2", "-C", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run() != nil {
		if err2 := exec.Command(ipt, "-w", "2", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run(); err2 != nil {
			// conntrack module not available — use legacy 'state' module
			_ = exec.Command(ipt, "-w", "2", "-A", "FORWARD", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
		}
	}

	// Keenetic NDM chains if present
	if isKeeneticDevice() {
		ensureIptablesRule(ipt, "", "_NDM_FORWARD", "-i", "nb0", "-j", "ACCEPT")
		ensureIptablesRule(ipt, "", "_NDM_FORWARD", "-o", "nb0", "-j", "ACCEPT")
		// S5: Keenetic NDM блокирует ICMP по умолчанию — добавляем правило для пинга
		ensureIptablesRule(ipt, "", "INPUT", "-i", "nb0", "-p", "icmp", "-j", "ACCEPT")
	}

	// 3. Bi-directional TCP MSS Clamping
	ensureIptablesRule(ipt, "mangle", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")

	// Keenetic / OpenWrt: ensure forwarded traffic from mesh subnet can lookup default WAN table
	if isKeeneticDevice() {
		_ = runLinuxCmd("ip", "rule", "del", "from", cleanSubnet, "lookup", "default")
		_ = runLinuxCmd("ip", "rule", "add", "from", cleanSubnet, "lookup", "default", "priority", "60")
		StartLinuxNATWatchdog(context.Background(), cleanSubnet)
	}

	return nil
}

var (
	natWatchdogCancel context.CancelFunc
	natWatchdogMu     sync.Mutex
)

// StartLinuxNATWatchdog запускает фоновый сторож целостности правил iptables ТОЛЬКО на KeeneticOS (каждые 60 сек).
// S5: Расширен — проверяет и восстанавливает FORWARD, INPUT (ICMP) и MASQUERADE правила при сбросе цепочек NDM.
func StartLinuxNATWatchdog(ctx context.Context, subnet string) {
	if !isKeeneticDevice() {
		return
	}
	natWatchdogMu.Lock()
	if natWatchdogCancel != nil {
		natWatchdogCancel()
	}
	wCtx, cancel := context.WithCancel(ctx)
	natWatchdogCancel = cancel
	natWatchdogMu.Unlock()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		ipt := findIptablesBinary()
		for {
			select {
			case <-wCtx.Done():
				return
			case <-ticker.C:
				needRestore := false

				// Проверяем MASQUERADE в nat POSTROUTING
				if err := exec.Command(ipt, "-w", "2", "-t", "nat", "-C", "POSTROUTING",
					"-s", subnet, "!", "-o", "nb0", "-j", "MASQUERADE").Run(); err != nil {
					needRestore = true
				}

				// S5: Проверяем FORWARD правила для nb0
				if err := exec.Command(ipt, "-w", "2", "-C", "FORWARD",
					"-i", "nb0", "-j", "ACCEPT").Run(); err != nil {
					needRestore = true
				}

				// S5: Проверяем INPUT ICMP через nb0 (Keenetic NDM блокирует ICMP без этого)
				if err := exec.Command(ipt, "-w", "2", "-C", "INPUT",
					"-i", "nb0", "-p", "icmp", "-j", "ACCEPT").Run(); err != nil {
					// Восстанавливаем ICMP без полного сброса
					_ = exec.Command(ipt, "-w", "2", "-I", "INPUT",
						"-i", "nb0", "-p", "icmp", "-j", "ACCEPT").Run()
				}

				if needRestore {
					// Полное восстановление через EnableHostIPForwardingSubnet
					_ = EnableHostIPForwardingSubnet(subnet)
				}
			}
		}
	}()
}

// EnableHostIPForwarding enables kernel IPv4 forwarding and adds iptables NAT masquerading for default mesh subnet.
func EnableHostIPForwarding() error {
	return EnableHostIPForwardingSubnet("100.64.200.0/24")
}

// DisableHostIPForwarding removes iptables NAT masquerading rule.
func DisableHostIPForwarding() error {
	natWatchdogMu.Lock()
	if natWatchdogCancel != nil {
		natWatchdogCancel()
		natWatchdogCancel = nil
	}
	natWatchdogMu.Unlock()

	iptablesPaths := []string{"iptables", "/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables"}
	for _, ipt := range iptablesPaths {
		_ = runLinuxCmd(ipt, "-t", "nat", "-D", "POSTROUTING", "-s", "100.64.200.0/24", "-j", "MASQUERADE")
	}
	return nil
}

var (
	linuxBypassedMu             sync.Mutex
	lastBypassedEndpointIPs []string
)

// getPhysicalGatewayLinux finds the physical default gateway IP
func getPhysicalGatewayLinux() string {
	cmd := exec.Command("sh", "-c", "ip route show default | grep -v 'nb0' | head -n1 | awk '{print $3}'")
	out, err := cmd.Output()
	if err == nil {
		gw := strings.TrimSpace(string(out))
		if ip := net.ParseIP(gw); ip != nil && !ip.IsUnspecified() {
			return gw
		}
	}
	return ""
}

func extractHostIPs(endpoint string) []string {
	if endpoint == "" {
		return nil
	}
	s := strings.TrimSpace(endpoint)
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() && !ip.IsUnspecified() {
			return []string{ip.String()}
		}
		return nil
	}

	// Resolve domain names (e.g. broker.emqx.io, stun servers)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	var res []string
	for _, ip := range ips {
		if !ip.IsLoopback() && !ip.IsUnspecified() {
			res = append(res, ip.String())
		}
	}
	return res
}

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1),
// with automatic routing-loop prevention by adding a bypass route to the remote endpoints and signaling servers.
func EnableExitNodeRouting(gatewayVIP string, remoteEndpoints ...string) error {
	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])

	// 1. Bypass remote endpoint IPs via physical default gateway to prevent routing loop
	physGW := getPhysicalGatewayLinux()
	if physGW != "" {
		linuxBypassedMu.Lock()
		for _, ep := range remoteEndpoints {
			for _, hostIP := range extractHostIPs(ep) {
				alreadyAdded := false
				for _, prev := range lastBypassedEndpointIPs {
					if prev == hostIP {
						alreadyAdded = true
						break
					}
				}
				if !alreadyAdded {
					_ = runLinuxCmd("ip", "route", "add", hostIP+"/32", "via", physGW)
					lastBypassedEndpointIPs = append(lastBypassedEndpointIPs, hostIP)
				}
			}
		}
		linuxBypassedMu.Unlock()
	}

	// 2. Add def1 routes
	err1 := runLinuxCmd("ip", "route", "add", "0.0.0.0/1", "via", cleanVIP, "dev", "nb0", "onlink")
	if err1 != nil {
		_ = runLinuxCmd("ip", "route", "add", "0.0.0.0/1", "via", cleanVIP)
	}
	err2 := runLinuxCmd("ip", "route", "add", "128.0.0.0/1", "via", cleanVIP, "dev", "nb0", "onlink")
	if err2 != nil {
		_ = runLinuxCmd("ip", "route", "add", "128.0.0.0/1", "via", cleanVIP)
	}

	// 3. Ensure DNS servers (1.1.1.1, 8.8.8.8) are routed via exit node
	_ = runLinuxCmd("ip", "route", "add", "1.1.1.1/32", "via", cleanVIP, "dev", "nb0", "onlink")
	_ = runLinuxCmd("ip", "route", "add", "8.8.8.8/32", "via", cleanVIP, "dev", "nb0", "onlink")

	// R2: Настраиваем DNS через exit node чтобы не было DNS-утечек
	// Пробуем resolvectl (systemd-resolved), затем прямую запись в resolv.conf
	setLinuxExitNodeDNS()

	return nil
}

// setLinuxExitNodeDNS настраивает DNS серверы при активации exit node на Linux.
// R2: Без этого DNS запросы могут идти мимо VPN-тоннеля (DNS leak).
func setLinuxExitNodeDNS() {
	// Метод 1: systemd-resolved через resolvectl
	if err := exec.Command("resolvectl", "dns", "nb0", "1.1.1.1", "8.8.8.8").Run(); err == nil {
		_ = exec.Command("resolvectl", "domain", "nb0", "~.").Run()
		return
	}
	// Метод 2: через nmcli (NetworkManager)
	if err := exec.Command("nmcli", "dev", "mod", "nb0", "ipv4.dns", "1.1.1.1 8.8.8.8").Run(); err == nil {
		return
	}
	// Метод 3: Прямая правка /etc/resolv.conf (fallback для OpenWrt/Keenetic)
	const dnsContent = "# NatBypass exit node DNS\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	if err := os.WriteFile("/etc/resolv.conf", []byte(dnsContent), 0644); err != nil {
		// /etc/resolv.conf может быть симлинком — игнорируем
		_ = err
	}
}

// restoreLinuxDNS восстанавливает DNS после отключения exit node.
func restoreLinuxDNS() {
	// Метод 1: resolvectl revert
	if err := exec.Command("resolvectl", "revert", "nb0").Run(); err == nil {
		return
	}
	// Метод 2: nmcli сброс
	_ = exec.Command("nmcli", "dev", "mod", "nb0", "ipv4.dns", "").Run()
}

// DisableExitNodeRouting removes def1 routes and bypass routes.
func DisableExitNodeRouting(gatewayVIP string) error {
	if gatewayVIP != "" {
		cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])
		_ = runLinuxCmd("ip", "route", "del", "0.0.0.0/1", "via", cleanVIP)
		_ = runLinuxCmd("ip", "route", "del", "128.0.0.0/1", "via", cleanVIP)
		_ = runLinuxCmd("ip", "route", "del", "1.1.1.1/32", "via", cleanVIP)
		_ = runLinuxCmd("ip", "route", "del", "8.8.8.8/32", "via", cleanVIP)
	}
	_ = runLinuxCmd("ip", "route", "del", "0.0.0.0/1")
	_ = runLinuxCmd("ip", "route", "del", "128.0.0.0/1")
	_ = runLinuxCmd("ip", "route", "del", "1.1.1.1/32")
	_ = runLinuxCmd("ip", "route", "del", "8.8.8.8/32")

	linuxBypassedMu.Lock()
	for _, hostIP := range lastBypassedEndpointIPs {
		_ = runLinuxCmd("ip", "route", "del", hostIP+"/32")
	}
	lastBypassedEndpointIPs = nil
	linuxBypassedMu.Unlock()

	// R2: Восстанавливаем DNS при отключении exit node
	restoreLinuxDNS()

	return nil
}

// AddSubnetRoute adds a route for a subnet CIDR via gatewayVIP with dev nb0 onlink.
func AddSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])
	err := runLinuxCmd("ip", "route", "add", subnetCIDR, "via", cleanVIP, "dev", "nb0", "onlink")
	if err != nil {
		return runLinuxCmd("ip", "route", "add", subnetCIDR, "via", cleanVIP)
	}
	return nil
}

// RemoveSubnetRoute removes a route for a subnet CIDR via gatewayVIP.
func RemoveSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	return runLinuxCmd("ip", "route", "del", subnetCIDR, "via", gatewayVIP)
}

// FlushAllRouting cleans up any active routes.
func FlushAllRouting(gatewayVIP string, subnets []string) {
	_ = DisableExitNodeRouting(gatewayVIP)
	for _, s := range subnets {
		_ = RemoveSubnetRoute(s, gatewayVIP)
	}
}

// EnsurePeerHostRoute adds a /32 host route for a peer's VirtualIP via the nb0 TUN interface.
// Required on Linux routers (Keenetic/OpenWrt/mipsle) so the kernel routes ICMP replies and
// forwarded return traffic back through nb0 instead of escaping via the WAN interface.
// Idempotent — "file exists" errors (route already present) are silently ignored.
func EnsurePeerHostRoute(peerVIP string) {
	if peerVIP == "" {
		return
	}
	cleanVIP := strings.TrimSpace(strings.Split(peerVIP, "/")[0])
	if net.ParseIP(cleanVIP) == nil {
		return
	}
	_ = runLinuxCmd("ip", "route", "add", cleanVIP+"/32", "dev", "nb0", "onlink")
}

// EnableMSSClamping принудительно снижает MSS для TCP-соединений через TUN.
// Предотвращает MTU Blackhole при инкапсуляции пакетов.
func EnableMSSClamping(tunInterface string, mtu int) error {
	if tunInterface == "" {
		return fmt.Errorf("tun interface name is required")
	}
	if mtu < 576 || mtu > 1500 {
		mtu = 1420 // Default WireGuard MTU
	}
	mss := mtu - 60 // IP header (20) + TCP header (20) + overhead (20)

	// Удаляем старое правило если есть (идемпотентность)
	_ = runLinuxCmd("iptables", "-t", "mangle", "-D", "POSTROUTING",
		"-o", tunInterface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss))

	// Добавляем новое
	return runLinuxCmd("iptables", "-t", "mangle", "-A", "POSTROUTING",
		"-o", tunInterface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss))
}

// DisableMSSClamping удаляет правило MSS clamping.
func DisableMSSClamping(tunInterface string) error {
	if tunInterface == "" {
		tunInterface = "nb0"
	}
	return runLinuxCmd("iptables", "-t", "mangle", "-D", "POSTROUTING",
		"-o", tunInterface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS")
}


// GetLocalSubnets returns a unique list of local IPv4 subnet CIDRs.
func GetLocalSubnets() []string {
	return network.GetLocalSubnets()
}
