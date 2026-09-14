//go:build linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

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

var (
	isKeeneticOnce   sync.Once
	isKeeneticCached bool

	// peerHostRoutes tracks the last time a /32 host route was installed per VIP.
	// Value type: int64 (Unix timestamp of last installation).
	// Routes are re-installed by the watchdog every peerRouteRefreshInterval seconds
	// so that NDM / kernel routing flushes on Keenetic are automatically healed.
	peerHostRoutes sync.Map

	peerRouteWatchdogOnce sync.Once
)

const peerRouteRefreshInterval = 25 * time.Second

// startPeerRouteWatchdog launches a single background goroutine that re-installs
// all known peer host routes on a fixed interval. This ensures Keenetic NDM
// routing-table flushes are healed within peerRouteRefreshInterval seconds.
func startPeerRouteWatchdog() {
	peerRouteWatchdogOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(peerRouteRefreshInterval)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now().Unix()
				peerHostRoutes.Range(func(key, value any) bool {
					vip, ok := key.(string)
					if !ok {
						return true
					}
					lastTs, ok := value.(int64)
					if !ok || now-lastTs >= int64(peerRouteRefreshInterval.Seconds()) {
						peerHostRoutes.Store(vip, now)
						go func(targetVIP string) {
							_ = runLinuxCmd("ip", "route", "replace", targetVIP+"/32", "dev", "nb0", "table", "main", "onlink")
							_ = runLinuxCmd("ip", "route", "replace", targetVIP+"/32", "dev", "nb0", "onlink")
							if isKeeneticDevice() {
								_ = runLinuxCmd("ip", "rule", "del", "pref", "40", "to", targetVIP+"/32", "lookup", "main")
								_ = runLinuxCmd("ip", "rule", "add", "pref", "40", "to", targetVIP+"/32", "lookup", "main")
							}
						}(vip)
					}
					return true
				})
			}
		}()
	})
}

// isKeeneticDevice checks if running on KeeneticOS.
func isKeeneticDevice() bool {
	isKeeneticOnce.Do(func() {
		for _, p := range []string{"/bin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq"} {
			if _, err := os.Stat(p); err == nil {
				isKeeneticCached = true
				return
			}
		}
	})
	return isKeeneticCached
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

// forceInsertIptablesRule ensures a rule is at the very top (rule 1) of a chain.
// If the rule already exists anywhere in the chain, it is removed first to avoid duplicates.
func forceInsertIptablesRule(ipt, table, chain string, args ...string) {
	checkArgs := []string{"-w", "2"}
	if table != "" {
		checkArgs = append(checkArgs, "-t", table)
	}
	checkArgs = append(checkArgs, "-C", chain)
	checkArgs = append(checkArgs, args...)
	if exec.Command(ipt, checkArgs...).Run() == nil {
		// Rule exists. Remove it so we can re-insert at top
		delArgs := []string{"-w", "2"}
		if table != "" {
			delArgs = append(delArgs, "-t", table)
		}
		delArgs = append(delArgs, "-D", chain)
		delArgs = append(delArgs, args...)
		_ = exec.Command(ipt, delArgs...).Run()
	}
	insertArgs := []string{"-w", "2"}
	if table != "" {
		insertArgs = append(insertArgs, "-t", table)
	}
	insertArgs = append(insertArgs, "-I", chain, "1")
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
	// 1. Kernel sysctl forwarding and rp_filter
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.conf.all.forwarding=1")
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.conf.default.forwarding=1")
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.conf.nb0.forwarding=1")
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.conf.nb0.rp_filter=0")

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

	// 2. MANGLE PREROUTING: Mark ANY packet entering nb0 interface with fwmark 0x4e
	// This enables universal NAT masquerading regardless of client IP / subnet!
	ensureIptablesRule(ipt, "mangle", "PREROUTING", "-i", "nb0", "-j", "MARK", "--set-mark", "0x4e")

	// 3. NAT MASQUERADE in POSTROUTING:
	// a) By packet mark 0x4e (any packet that entered via nb0 exiting to WAN)
	ensureIptablesRule(ipt, "nat", "POSTROUTING", "-m", "mark", "--mark", "0x4e", "!", "-o", "nb0", "-j", "MASQUERADE")
	// b) Fallback for all standard private & CGNAT ranges used by mesh clients
	meshSubnets := []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12"}
	if cleanSubnet != "" && cleanSubnet != "10.0.0.0/8" && cleanSubnet != "100.64.0.0/10" && cleanSubnet != "172.16.0.0/12" {
		meshSubnets = append(meshSubnets, cleanSubnet)
	}
	for _, s := range meshSubnets {
		ensureIptablesRule(ipt, "nat", "POSTROUTING", "-s", s, "!", "-o", "nb0", "-j", "MASQUERADE")
	}

	// 4. Forwarding and Input rules for nb0
	// FIX-N2: Use forceInsertIptablesRule to place rules at TOP of chain (position 1), bypassing Docker/UFW drop policies
	forceInsertIptablesRule(ipt, "", "FORWARD", "-i", "nb0", "-j", "ACCEPT")
	forceInsertIptablesRule(ipt, "", "FORWARD", "-o", "nb0", "-j", "ACCEPT")
	ensureIptablesRule(ipt, "", "INPUT", "-i", "nb0", "-j", "ACCEPT")
	ensureIptablesRule(ipt, "", "INPUT", "-p", "icmp", "-j", "ACCEPT")
	ensureIptablesRule(ipt, "", "INPUT", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT")
	ensureIptablesRule(ipt, "", "INPUT", "-p", "udp", "--dport", "47832", "-j", "ACCEPT")

	// Docker compatibility: if DOCKER-USER chain exists, ensure nb0 traffic is accepted
	if exec.Command(ipt, "-w", "2", "-C", "DOCKER-USER", "-i", "nb0", "-j", "ACCEPT").Run() != nil {
		if exec.Command(ipt, "-w", "2", "-L", "DOCKER-USER").Run() == nil {
			_ = exec.Command(ipt, "-w", "2", "-I", "DOCKER-USER", "1", "-i", "nb0", "-j", "ACCEPT").Run()
			_ = exec.Command(ipt, "-w", "2", "-I", "DOCKER-USER", "1", "-o", "nb0", "-j", "ACCEPT").Run()
		}
	}

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
		ensureIptablesRule(ipt, "", "_NDM_INPUT", "-i", "nb0", "-j", "ACCEPT")
		ensureIptablesRule(ipt, "", "_NDM_INPUT", "-p", "icmp", "-j", "ACCEPT")
		ensureIptablesRule(ipt, "", "_NDM_INPUT", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT")
		ensureIptablesRule(ipt, "", "INPUT", "-i", "nb0", "-p", "icmp", "-j", "ACCEPT")
	}

	// 5. Bi-directional TCP MSS Clamping
	ensureIptablesRule(ipt, "mangle", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	ensureIptablesRule(ipt, "mangle", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")

	// 6. nftables fallback (Ubuntu 22.04+, Debian 12+)
	if nft, err := exec.LookPath("nft"); err == nil {
		_ = exec.Command(nft, "add", "rule", "inet", "filter", "forward", "iifname", "nb0", "accept").Run()
		_ = exec.Command(nft, "add", "rule", "inet", "filter", "forward", "oifname", "nb0", "accept").Run()
	}

	// 7. Ensure direct routes for standard mesh subnets exist on nb0 in table main
	_ = runLinuxCmd("ip", "route", "replace", "10.1.1.0/24", "dev", "nb0", "table", "main", "onlink")
	_ = runLinuxCmd("ip", "route", "replace", "100.64.200.0/24", "dev", "nb0", "table", "main", "onlink")
	if cleanSubnet != "" && cleanSubnet != "10.1.1.0/24" && cleanSubnet != "100.64.200.0/24" {
		_ = runLinuxCmd("ip", "route", "replace", cleanSubnet, "dev", "nb0", "table", "main", "onlink")
	}

	// 8. Keenetic / OpenWrt: ensure forwarded traffic from mesh subnet can lookup default WAN table
	if isKeeneticDevice() {
		// Priority 40: return traffic to mesh subnets always looks up table main
		for _, s := range []string{"10.1.1.0/24", "100.64.200.0/24", cleanSubnet} {
			if s != "" {
				_ = runLinuxCmd("ip", "rule", "del", "pref", "40", "to", s, "lookup", "main")
				_ = runLinuxCmd("ip", "rule", "add", "pref", "40", "to", s, "lookup", "main")
			}
		}

		// Priority 55: preserve local LAN and mesh destinations before falling through to WAN
		for _, s := range []string{"192.168.0.0/16", "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12"} {
			_ = runLinuxCmd("ip", "rule", "del", "pref", "55", "to", s, "lookup", "main")
			_ = runLinuxCmd("ip", "rule", "add", "pref", "55", "to", s, "lookup", "main")
		}

		// Priority 60: forward mesh internet traffic to WAN default table
		_ = runLinuxCmd("ip", "rule", "del", "pref", "60", "fwmark", "0x4e", "lookup", "default")
		_ = runLinuxCmd("ip", "rule", "add", "pref", "60", "fwmark", "0x4e", "lookup", "default")
		_ = runLinuxCmd("ip", "rule", "del", "pref", "60", "iif", "nb0", "lookup", "default")
		_ = runLinuxCmd("ip", "rule", "add", "pref", "60", "iif", "nb0", "lookup", "default")
		for _, s := range []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", cleanSubnet} {
			if s != "" {
				_ = runLinuxCmd("ip", "rule", "del", "pref", "60", "from", s, "lookup", "default")
				_ = runLinuxCmd("ip", "rule", "add", "pref", "60", "from", s, "lookup", "default")
			}
		}

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

				// Проверяем маркировку и MASQUERADE
				if err := exec.Command(ipt, "-w", "2", "-t", "mangle", "-C", "PREROUTING",
					"-i", "nb0", "-j", "MARK", "--set-mark", "0x4e").Run(); err != nil {
					needRestore = true
				}
				if err := exec.Command(ipt, "-w", "2", "-t", "nat", "-C", "POSTROUTING",
					"-m", "mark", "--mark", "0x4e", "!", "-o", "nb0", "-j", "MASQUERADE").Run(); err != nil {
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
func DisableHostIPForwarding(subnets ...string) error {
	natWatchdogMu.Lock()
	if natWatchdogCancel != nil {
		natWatchdogCancel()
		natWatchdogCancel = nil
	}
	natWatchdogMu.Unlock()

	targetSubnet := "100.64.200.0/24"
	if len(subnets) > 0 && subnets[0] != "" {
		targetSubnet = subnets[0]
	}

	iptablesPaths := []string{"iptables", "/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables"}
	for _, ipt := range iptablesPaths {
		_ = runLinuxCmd(ipt, "-t", "nat", "-D", "POSTROUTING", "-s", targetSubnet, "-j", "MASQUERADE")
		if targetSubnet != "100.64.200.0/24" {
			_ = runLinuxCmd(ipt, "-t", "nat", "-D", "POSTROUTING", "-s", "100.64.200.0/24", "-j", "MASQUERADE")
		}
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

// BypassEndpoint dynamically adds a /32 route via the physical default gateway for an endpoint IP/host
// to prevent routing loops when Exit Node routing is active.
func BypassEndpoint(endpoint string) error {
	physGW := getPhysicalGatewayLinux()
	if physGW == "" || endpoint == "" {
		return nil
	}
	hostIPs := extractHostIPs(endpoint)
	linuxBypassedMu.Lock()
	defer linuxBypassedMu.Unlock()
	for _, hostIP := range hostIPs {
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
	return nil
}

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1),
// with automatic routing-loop prevention by adding a bypass route to the remote endpoints and signaling servers.
func EnableExitNodeRouting(gatewayVIP string, remoteEndpoints ...string) error {
	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])

	// 1. Bypass remote endpoint IPs via physical default gateway to prevent routing loop
	for _, ep := range remoteEndpoints {
		_ = BypassEndpoint(ep)
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
	// Метод 1: systemd-resolved через resolvectl (127.0.0.1 DoH, 1.1.1.1 fallback)
	if err := exec.Command("resolvectl", "dns", "nb0", "127.0.0.1", "1.1.1.1").Run(); err == nil {
		_ = exec.Command("resolvectl", "domain", "nb0", "~.").Run()
		return
	}
	// Метод 2: через nmcli (NetworkManager)
	if err := exec.Command("nmcli", "dev", "mod", "nb0", "ipv4.dns", "127.0.0.1 1.1.1.1").Run(); err == nil {
		return
	}
	// Метод 3: Прямая правка /etc/resolv.conf (fallback для OpenWrt/Keenetic)
	const dnsContent = "# NatBypass exit node DoH DNS\nnameserver 127.0.0.1\nnameserver 1.1.1.1\n"
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
	peerHostRoutes.Range(func(key, value any) bool {
		peerHostRoutes.Delete(key)
		return true
	})
}

// EnsurePeerHostRoute adds a /32 host route for a peer's VirtualIP via the nb0 TUN interface.
// Required on Linux routers (Keenetic/OpenWrt/mipsle) so the kernel routes ICMP replies and
// forwarded return traffic back through nb0 instead of escaping via the WAN interface.
//
// Fast path: thread-safe, keyed by cleanVIP. If the route was installed within the last
// peerRouteRefreshInterval, the call returns immediately with zero syscalls.
// The background watchdog goroutine (started once) re-installs all routes every
// peerRouteRefreshInterval so NDM / kernel routing flushes on Keenetic are auto-healed.
func EnsurePeerHostRoute(peerVIP string) {
	if peerVIP == "" {
		return
	}
	cleanVIP := strings.TrimSpace(strings.Split(peerVIP, "/")[0])
	if net.ParseIP(cleanVIP) == nil {
		return
	}

	now := time.Now().Unix()
	cutoff := now - int64(peerRouteRefreshInterval.Seconds())
	if prev, loaded := peerHostRoutes.LoadOrStore(cleanVIP, now); loaded {
		if ts, ok := prev.(int64); ok && ts > cutoff {
			return // route installed recently — no need to reinstall
		}
		peerHostRoutes.Store(cleanVIP, now)
	}

	// Ensure watchdog is running so NDM flushes are healed automatically
	startPeerRouteWatchdog()

	// Install immediately and synchronously so initial return packets have a valid kernel route
	_ = runLinuxCmd("ip", "route", "replace", cleanVIP+"/32", "dev", "nb0", "table", "main", "onlink")
	_ = runLinuxCmd("ip", "route", "replace", cleanVIP+"/32", "dev", "nb0", "onlink")
	if isKeeneticDevice() {
		_ = runLinuxCmd("ip", "rule", "del", "pref", "40", "to", cleanVIP+"/32", "lookup", "main")
		_ = runLinuxCmd("ip", "rule", "add", "pref", "40", "to", cleanVIP+"/32", "lookup", "main")
	}
}

// EnableMSSClamping принудительно снижает MSS для TCP-соединений через TUN.
// Предотвращает MTU Blackhole при инкапсуляции пакетов.
func EnableMSSClamping(tunInterface string, mtu int) error {
	if tunInterface == "" {
		return fmt.Errorf("tun interface name is required")
	}
	if mtu < 576 || mtu > 1500 {
		mtu = 1280 // Default Mesh MTU
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
