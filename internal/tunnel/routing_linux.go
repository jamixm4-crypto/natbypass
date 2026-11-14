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
	"path/filepath"
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

// IsKeeneticDevice returns true if the host system is running KeeneticOS.
func IsKeeneticDevice() bool {
	return isKeeneticDevice()
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

// buildMeshSubnetList возвращает уникальный набор подсетей для iptables/ip-route: подсеть из конфига + 100.64.200.0/24.
func buildMeshSubnetList(configSubnet string) []string {
	seen := map[string]bool{}
	var result []string
	add := func(s string) {
		if s != "" && s != "10.0.0.0/8" && s != "172.16.0.0/12" && s != "100.64.0.0/10" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	if configSubnet != "" {
		add(configSubnet)
	}
	add("100.64.200.0/24")
	return result
}

// isMeshIPLinux проверяет, является ли IP адресом из mesh-подсети (динамически по VIP текущего TUN).
func isMeshIPLinux(hostIP string) bool {
	ip := net.ParseIP(hostIP)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 10.0.0.0/8 (Default mesh subnet family)
	if ip4[0] == 10 {
		return true
	}
	// 100.64.0.0/10 (CGNAT / fallback mesh)
	if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
		return true
	}
	// Проверяем по текущей подсети активного TUN
	tunStat := GetTUNStatus()
	if tunStat.Active && tunStat.VirtualIP != "" {
		vipParts := strings.SplitN(strings.Split(tunStat.VirtualIP, "/")[0], ".", 4)
		candParts := strings.SplitN(hostIP, ".", 4)
		if len(vipParts) >= 3 && len(candParts) >= 3 {
			if vipParts[0] == candParts[0] && vipParts[1] == candParts[1] && vipParts[2] == candParts[2] {
				return true
			}
		}
	}
	return false
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

	// F6: Ensure rp_filter=0 and forwarding=1 across all available interface procfs nodes
	if confDirs, err := os.ReadDir("/proc/sys/net/ipv4/conf"); err == nil {
		for _, d := range confDirs {
			_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", d.Name()), []byte("0\n"), 0644)
			_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", d.Name()), []byte("1\n"), 0644)
		}
	}

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
	forceInsertIptablesRule(ipt, "mangle", "PREROUTING", "-i", "nb0", "-j", "MARK", "--set-mark", "0x4e")

	// 3. NAT MASQUERADE in POSTROUTING:
	// Inserted at TOP of POSTROUTING (position 1) so it precedes any Docker/UFW/Keenetic NDM chains!
	forceInsertIptablesRule(ipt, "nat", "POSTROUTING", "-m", "mark", "--mark", "0x4e", "!", "-o", "nb0", "-j", "MASQUERADE")

	// Clean up any old broad 10.0.0.0/8 MASQUERADE rules that intercepted the local LAN (e.g. 10.11.219.0/24)
	_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "POSTROUTING", "-s", "10.0.0.0/8", "!", "-o", "nb0", "-j", "MASQUERADE").Run()
	_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "POSTROUTING", "-s", "172.16.0.0/12", "!", "-o", "nb0", "-j", "MASQUERADE").Run()

	meshSubnets := buildMeshSubnetList(cleanSubnet)
	for _, s := range meshSubnets {
		forceInsertIptablesRule(ipt, "nat", "POSTROUTING", "-s", s, "!", "-o", "nb0", "-j", "MASQUERADE")
	}

	// 4. Forwarding and Input rules for nb0
	// Use forceInsertIptablesRule to place rules at TOP of chain (position 1), bypassing Docker/UFW drop policies
	forceInsertIptablesRule(ipt, "", "FORWARD", "-i", "nb0", "-j", "ACCEPT")
	forceInsertIptablesRule(ipt, "", "FORWARD", "-o", "nb0", "-j", "ACCEPT")
	forceInsertIptablesRule(ipt, "", "FORWARD", "-i", "nb0", "-o", "br0", "-j", "ACCEPT")
	forceInsertIptablesRule(ipt, "", "FORWARD", "-i", "br0", "-o", "nb0", "-j", "ACCEPT")
	forceInsertIptablesRule(ipt, "", "INPUT", "-i", "nb0", "-j", "ACCEPT")
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

	// Keenetic NDM chains if present: MUST be inserted at position 1 to precede default DROP/REJECT!
	if isKeeneticDevice() {
		forceInsertIptablesRule(ipt, "", "_NDM_FORWARD", "-i", "nb0", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_FORWARD", "-o", "nb0", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_FORWARD", "-i", "nb0", "-o", "br0", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_FORWARD", "-i", "br0", "-o", "nb0", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_INPUT", "-i", "nb0", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_INPUT", "-p", "icmp", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_INPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_INPUT", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "_NDM_INPUT", "-p", "udp", "--dport", "47832", "-j", "ACCEPT")
		forceInsertIptablesRule(ipt, "", "INPUT", "-i", "nb0", "-p", "icmp", "-j", "ACCEPT")

		// Clean up any legacy broad REDIRECT rules on nb0 that hijacked internet traffic (ports 80, 443, 53)
		_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "PREROUTING", "-i", "nb0", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "80").Run()
		_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "PREROUTING", "-i", "nb0", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "443").Run()
		_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "PREROUTING", "-i", "nb0", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53").Run()
		_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "PREROUTING", "-i", "nb0", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53").Run()

		// Remove legacy pref 40/50 iif nb0 and pref 50 from rules that intercepted internet transit packets before WAN lookup!
		for i := 0; i < 5; i++ {
			_ = runLinuxCmd("ip", "rule", "del", "pref", "50", "iif", "nb0")
			_ = runLinuxCmd("ip", "rule", "del", "pref", "50", "from", cleanSubnet)
			_ = runLinuxCmd("ip", "rule", "del", "pref", "40", "iif", "nb0")
		}
		_ = runLinuxCmd("ip", "rule", "del", "pref", "40", "to", cleanSubnet, "lookup", "main")
		_ = runLinuxCmd("ip", "rule", "add", "pref", "40", "to", cleanSubnet, "lookup", "main")
	}

	// 5. Bi-directional TCP MSS Clamping to 1220 bytes (prevents PMTU Blackhole under tunnel encapsulation)
	forceInsertIptablesRule(ipt, "mangle", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1220")
	forceInsertIptablesRule(ipt, "mangle", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1220")
	ensureIptablesRule(ipt, "mangle", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")

	// 6. nftables fallback (Ubuntu 22.04+, Debian 12+)
	if nft, err := exec.LookPath("nft"); err == nil {
		_ = exec.Command(nft, "add", "rule", "inet", "filter", "forward", "iifname", "nb0", "accept").Run()
		_ = exec.Command(nft, "add", "rule", "inet", "filter", "forward", "oifname", "nb0", "accept").Run()
	}

	// 7. Ensure direct routes for standard mesh subnets exist on nb0 in table main
	for _, s := range buildMeshSubnetList(cleanSubnet) {
		if s != "" {
			_ = runLinuxCmd("ip", "route", "replace", s, "dev", "nb0", "table", "main", "onlink")
			_ = runLinuxCmd("ip", "route", "replace", s, "dev", "nb0", "onlink")
		}
	}

	// 8. Keenetic / OpenWrt: ensure forwarded traffic from mesh subnet looks up the actual WAN table
	if isKeeneticDevice() {
		wanTable := findLinuxWANTable()
		if wanTable == "" || wanTable == "default" {
			wanTable = "main"
		}

		// Priority 40: return traffic to mesh subnets always looks up table main
		for _, s := range buildMeshSubnetList(cleanSubnet) {
			if s != "" {
				_ = runLinuxCmd("ip", "rule", "del", "pref", "40", "to", s, "lookup", "main")
				_ = runLinuxCmd("ip", "rule", "add", "pref", "40", "to", s, "lookup", "main")
			}
		}

		// Clean up overly broad rules from earlier versions that hijacked local LAN (e.g. 10.11.219.0/24)
		_ = runLinuxCmd("ip", "rule", "del", "from", "10.0.0.0/8")
		_ = runLinuxCmd("ip", "rule", "del", "to", "10.0.0.0/8", "lookup", "main")
		_ = runLinuxCmd("ip", "rule", "del", "from", "172.16.0.0/12")

		// Priority 55: preserve local LAN and mesh destinations before falling through to WAN
		for _, s := range append([]string{"192.168.0.0/16"}, buildMeshSubnetList(cleanSubnet)...) {
			if s != "" && s != "10.0.0.0/8" {
				_ = runLinuxCmd("ip", "rule", "del", "pref", "55", "to", s, "lookup", "main")
				_ = runLinuxCmd("ip", "rule", "add", "pref", "55", "to", s, "lookup", "main")
			}
		}

		// Priority 60: forward mesh internet traffic to real WAN routing table
		// Packets from mesh enter via nb0 or carry fwmark 0x4e
		for i := 0; i < 5; i++ {
			_ = runLinuxCmd("ip", "rule", "del", "pref", "60")
		}
		_ = runLinuxCmd("ip", "rule", "add", "pref", "60", "fwmark", "0x4e", "lookup", wanTable)
		_ = runLinuxCmd("ip", "rule", "add", "pref", "60", "iif", "nb0", "lookup", wanTable)
		for _, s := range buildMeshSubnetList(cleanSubnet) {
			if s != "" && s != "10.0.0.0/8" && s != "172.16.0.0/12" {
				_ = runLinuxCmd("ip", "rule", "add", "pref", "60", "from", s, "lookup", wanTable)
			}
		}

		// On KeeneticOS, table main MUST NOT contain a default route, because NDM isolates WAN to table 1000+.
		// Having an injected default route in table main breaks Keenetic NDM/LAN management and web UI.
		_ = runLinuxCmd("ip", "route", "del", "default", "table", "main")

		// Ensure persistent KeeneticOS netfilter hook is installed and valid
		ensureKeeneticNetfilterHook(cleanSubnet)

		StartLinuxNATWatchdog(context.Background(), cleanSubnet)
	}

	return nil
}

// ensureKeeneticNetfilterHook ensures /opt/etc/ndm/netfilter.d/010-natbypass.sh is present and updated on KeeneticOS.
func ensureKeeneticNetfilterHook(subnet string) {
	hookDir := "/opt/etc/ndm/netfilter.d"
	if fi, err := os.Stat(hookDir); err != nil || !fi.IsDir() {
		return
	}
	hookPath := filepath.Join(hookDir, "010-natbypass.sh")
	script := `#!/bin/sh
[ "$type" = "ip6tables" ] && exit 0

if [ "$table" = "filter" ]; then
    iptables -C INPUT -i nb0 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i nb0 -j ACCEPT
    iptables -C FORWARD -i nb0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i nb0 -j ACCEPT
    iptables -C FORWARD -o nb0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o nb0 -j ACCEPT
    iptables -C OUTPUT -o nb0 -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o nb0 -j ACCEPT
    iptables -C _NDM_INPUT -i nb0 -j ACCEPT 2>/dev/null || iptables -I _NDM_INPUT 1 -i nb0 -j ACCEPT 2>/dev/null || true
    iptables -C _NDM_FORWARD -i nb0 -j ACCEPT 2>/dev/null || iptables -I _NDM_FORWARD 1 -i nb0 -j ACCEPT 2>/dev/null || true
    iptables -C _NDM_FORWARD -o nb0 -j ACCEPT 2>/dev/null || iptables -I _NDM_FORWARD 1 -o nb0 -j ACCEPT 2>/dev/null || true
    iptables -C _NDM_OUTPUT -o nb0 -j ACCEPT 2>/dev/null || iptables -I _NDM_OUTPUT 1 -o nb0 -j ACCEPT 2>/dev/null || true
fi

if [ "$table" = "mangle" ]; then
    iptables -t mangle -C PREROUTING -i nb0 -j MARK --set-mark 0x4e 2>/dev/null || iptables -t mangle -I PREROUTING 1 -i nb0 -j MARK --set-mark 0x4e 2>/dev/null || true
    iptables -t mangle -C OUTPUT -o nb0 -j ACCEPT 2>/dev/null || iptables -t mangle -I OUTPUT 1 -o nb0 -j ACCEPT 2>/dev/null || true
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -I POSTROUTING 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
fi

if [ "$table" = "nat" ]; then
    iptables -t nat -D PREROUTING -i nb0 -p tcp --dport 80 -j REDIRECT --to-ports 80 2>/dev/null || true
    iptables -t nat -D PREROUTING -i nb0 -p tcp --dport 443 -j REDIRECT --to-ports 443 2>/dev/null || true
    iptables -t nat -D PREROUTING -i nb0 -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true
    iptables -t nat -D PREROUTING -i nb0 -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true
    iptables -t nat -C POSTROUTING -m mark --mark 0x4e ! -o nb0 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -m mark --mark 0x4e ! -o nb0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 10.0.0.0/8 ! -o nb0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 172.16.0.0/12 ! -o nb0 -j MASQUERADE 2>/dev/null || true
    NB_SUBNET=$(ip -4 addr show nb0 2>/dev/null | awk '/inet /{print $2}' | sed -E 's/\.[0-9]+\//.0\//')
    if [ -n "$NB_SUBNET" ]; then
        iptables -t nat -C POSTROUTING -s "$NB_SUBNET" ! -o nb0 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s "$NB_SUBNET" ! -o nb0 -j MASQUERADE 2>/dev/null || true
    fi
    iptables -t nat -C POSTROUTING -s 100.64.200.0/24 ! -o nb0 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 100.64.200.0/24 ! -o nb0 -j MASQUERADE 2>/dev/null || true
fi

ip rule del from 10.0.0.0/8 2>/dev/null || true
ip rule del to 10.0.0.0/8 2>/dev/null || true
NB_SUBNET=$(ip -4 addr show nb0 2>/dev/null | awk '/inet /{print $2}' | sed -E 's/\.[0-9]+\//.0\//')
if [ -n "$NB_SUBNET" ]; then
    ip rule add to "$NB_SUBNET" lookup main priority 40 2>/dev/null || true
fi
ip rule add to 100.64.200.0/24 lookup main priority 40 2>/dev/null || true

WAN_TABLE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="table") print $(i+1)}')
if [ -z "$WAN_TABLE" ] || [ "$WAN_TABLE" = "main" ]; then
    for tbl in $(ip route show table all default 2>/dev/null | grep -v 'nb0' | awk '{for(i=1;i<=NF;i++) if($i=="table") print $(i+1)}'); do
        if [ "$tbl" != "main" ] && [ "$tbl" != "local" ] && [ "$tbl" != "default" ]; then
            WAN_TABLE="$tbl"
            break
        fi
    done
fi
if [ -z "$WAN_TABLE" ] || [ "$WAN_TABLE" = "main" ]; then
    for tbl in 1000 1001 1002 1003 1004 1005 1008 100 200 default; do
        if ip route show table "$tbl" default 2>/dev/null | grep -q 'default'; then
            WAN_TABLE="$tbl"
            break
        fi
    done
fi
[ -z "$WAN_TABLE" ] && WAN_TABLE="main"

ip rule add fwmark 0x4e lookup $WAN_TABLE priority 60 2>/dev/null || true
ip rule add iif nb0 lookup $WAN_TABLE priority 60 2>/dev/null || true
if [ -n "$NB_SUBNET" ]; then
    ip rule add from "$NB_SUBNET" lookup $WAN_TABLE priority 60 2>/dev/null || true
fi
ip rule add from 100.64.200.0/24 lookup $WAN_TABLE priority 60 2>/dev/null || true

WAN_DEF=$(ip route show table all default 2>/dev/null | grep -v 'nb0' | head -n1 | sed -E 's/table [0-9a-zA-Z_]+//g')
if [ -n "$WAN_DEF" ]; then
    ip route replace $WAN_DEF table main 2>/dev/null || true
fi
`
	_ = os.WriteFile(hookPath, []byte(script), 0755)
}

var (
	natWatchdogCancel context.CancelFunc
	natWatchdogMu     sync.Mutex
)

// StartLinuxNATWatchdog запускает фоновый сторож целостности правил iptables ТОЛЬКО на KeeneticOS (каждые 60 сек).
// Проверяет и восстанавливает FORWARD, INPUT (ICMP) и MASQUERADE правила при сбросе цепочек NDM.
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

				// Проверяем FORWARD правила для nb0
				if err := exec.Command(ipt, "-w", "2", "-C", "FORWARD",
					"-i", "nb0", "-j", "ACCEPT").Run(); err != nil {
					needRestore = true
				}

				// Проверяем INPUT ICMP через nb0 (Keenetic NDM блокирует ICMP без этого)
				if err := exec.Command(ipt, "-w", "2", "-C", "INPUT",
					"-i", "nb0", "-p", "icmp", "-j", "ACCEPT").Run(); err != nil {
					_ = exec.Command(ipt, "-w", "2", "-I", "INPUT", "1",
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

// DisableHostIPForwarding removes iptables NAT masquerading rule and policy routes.
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

	ipt := findIptablesBinary()
	// Clean up all masquerade and mark rules
	_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "POSTROUTING", "-m", "mark", "--mark", "0x4e", "!", "-o", "nb0", "-j", "MASQUERADE").Run()
	_ = exec.Command(ipt, "-w", "2", "-t", "mangle", "-D", "PREROUTING", "-i", "nb0", "-j", "MARK", "--set-mark", "0x4e").Run()
	_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "POSTROUTING", "-s", "10.0.0.0/8", "!", "-o", "nb0", "-j", "MASQUERADE").Run()
	_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "POSTROUTING", "-s", "172.16.0.0/12", "!", "-o", "nb0", "-j", "MASQUERADE").Run()

	for _, s := range buildMeshSubnetList(targetSubnet) {
		if s != "" {
			_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "POSTROUTING", "-s", s, "!", "-o", "nb0", "-j", "MASQUERADE").Run()
			_ = exec.Command(ipt, "-w", "2", "-t", "nat", "-D", "POSTROUTING", "-s", s, "-j", "MASQUERADE").Run()
		}
	}

	// Clean up ip rules
	_ = runLinuxCmd("ip", "rule", "del", "pref", "60")
	_ = runLinuxCmd("ip", "rule", "del", "fwmark", "0x4e")
	_ = runLinuxCmd("ip", "rule", "del", "iif", "nb0")
	_ = runLinuxCmd("ip", "rule", "del", "from", "10.0.0.0/8")
	_ = runLinuxCmd("ip", "rule", "del", "to", "10.0.0.0/8", "lookup", "main")
	return nil
}

var (
	linuxBypassedMu             sync.Mutex
	lastBypassedEndpointIPs []string
)

// findLinuxWANTable determines the routing table used for the physical WAN gateway.
// On KeeneticOS, NDM places WAN routes in dedicated ISP tables (e.g. 1000, 1001, 1004, 1005, 1008), while table main has no default route.
func findLinuxWANTable() string {
	// 1. Check known Keenetic NDM / OpenWrt / Linux ISP candidate routing tables directly without GNU flags.
	// This works universally across BusyBox (KeeneticOS, OpenWrt, Alpine) and full iproute2.
	candidateTables := []string{"1000", "1001", "1002", "1003", "1004", "1005", "1006", "1007", "1008", "100", "200"}
	for _, tbl := range candidateTables {
		cmdStr := fmt.Sprintf("ip route show table %s 2>/dev/null | grep '^default' | grep -v 'nb0' | head -n1", tbl)
		if out, err := exec.Command("sh", "-c", cmdStr).Output(); err == nil {
			line := strings.TrimSpace(string(out))
			if strings.HasPrefix(line, "default") {
				return tbl
			}
		}
	}

	// 2. Parse ip rule show for table lookups (NDM creates: "1000: from all ... lookup 1000")
	if out, err := exec.Command("sh", "-c", "ip rule show 2>/dev/null").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "lookup") {
				fields := strings.Fields(line)
				for i, f := range fields {
					if f == "lookup" && i+1 < len(fields) {
						tbl := fields[i+1]
						if tbl != "main" && tbl != "local" && tbl != "default" && tbl != "254" && tbl != "255" {
							c := fmt.Sprintf("ip route show table %s 2>/dev/null | grep '^default' | grep -v 'nb0' | head -n1", tbl)
							if o, e := exec.Command("sh", "-c", c).Output(); e == nil && strings.HasPrefix(strings.TrimSpace(string(o)), "default") {
								return tbl
							}
						}
					}
				}
			}
		}
	}

	// 3. Try ip route get 8.8.8.8 (standard kernel FIB query)
	if out, err := exec.Command("sh", "-c", "ip route get 8.8.8.8 2>/dev/null | head -n1").Output(); err == nil {
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "table" && i+1 < len(fields) {
				tbl := fields[i+1]
				if tbl != "main" && tbl != "local" && tbl != "default" {
					return tbl
				}
			}
		}
	}

	// 4. Query ip route across all tables for full iproute2
	cmdStr := "ip route show table all 2>/dev/null | grep '^default' | grep -v 'nb0'"
	if out, err := exec.Command("sh", "-c", cmdStr).Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "default") {
				continue
			}
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "table" && i+1 < len(fields) {
					tbl := fields[i+1]
					if tbl != "main" && tbl != "local" && tbl != "default" && tbl != "254" && tbl != "255" {
						return tbl
					}
				}
			}
		}
	}

	// 5. Fallback: check table main
	if out, err := exec.Command("sh", "-c", "ip route show 2>/dev/null | grep '^default' | grep -v 'nb0' | head -n1").Output(); err == nil {
		if strings.HasPrefix(strings.TrimSpace(string(out)), "default") {
			return "main"
		}
	}

	return "main"
}

// ensureDefaultRouteInMain copies the default route from WAN routing table into table main if missing.
func ensureDefaultRouteInMain(wanTable string) {
	out, err := exec.Command("sh", "-c", "ip route show table main default 2>/dev/null | grep -v 'nb0'").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return // Table main already has a valid physical default route
	}

	// Attempt 1: Copy from detected WAN table
	if wanTable != "" && wanTable != "main" {
		defOut, defErr := exec.Command("sh", "-c", fmt.Sprintf("ip route show table %s default 2>/dev/null | grep -v 'nb0' | head -n1", wanTable)).Output()
		if defErr == nil && strings.HasPrefix(strings.TrimSpace(string(defOut)), "default") {
			parts := strings.Fields(strings.TrimSpace(string(defOut)))
			var cleanParts []string
			for i := 0; i < len(parts); i++ {
				if parts[i] == "table" {
					i++ // skip table name
					continue
				}
				cleanParts = append(cleanParts, parts[i])
			}
			args := append([]string{"route", "replace"}, cleanParts...)
			args = append(args, "table", "main")
			_ = runLinuxCmd("ip", args...)
			return
		}
	}

	// Attempt 2: Query across all tables
	defOut, defErr := exec.Command("sh", "-c", "ip -4 route show table all default 2>/dev/null | grep -v 'nb0' | head -n1").Output()
	if defErr == nil && strings.HasPrefix(strings.TrimSpace(string(defOut)), "default") {
		parts := strings.Fields(strings.TrimSpace(string(defOut)))
		var cleanParts []string
		for i := 0; i < len(parts); i++ {
			if parts[i] == "table" {
				i++
				continue
			}
			cleanParts = append(cleanParts, parts[i])
		}
		args := append([]string{"route", "replace"}, cleanParts...)
		args = append(args, "table", "main")
		_ = runLinuxCmd("ip", args...)
		return
	}

	// Attempt 3: Candidate tables fallback
	tablesToTry := []string{"1000", "1001", "1002", "1003", "1004", "1005", "1008", "100", "200", "default"}
	for _, tbl := range tablesToTry {
		defOut, defErr := exec.Command("sh", "-c", fmt.Sprintf("ip route show table %s default 2>/dev/null | grep -v 'nb0' | head -n1", tbl)).Output()
		if defErr == nil && strings.HasPrefix(strings.TrimSpace(string(defOut)), "default") {
			parts := strings.Fields(strings.TrimSpace(string(defOut)))
			var cleanParts []string
			for i := 0; i < len(parts); i++ {
				if parts[i] == "table" {
					i++
					continue
				}
				cleanParts = append(cleanParts, parts[i])
			}
			args := append([]string{"route", "replace"}, cleanParts...)
			args = append(args, "table", "main")
			_ = runLinuxCmd("ip", args...)
			break
		}
	}
}

// getPhysicalGatewayLinux finds the physical default gateway IP
func getPhysicalGatewayLinux() string {
	// 1. Try ip route get 8.8.8.8 (most accurate query across all Linux/Keenetic/OpenWrt kernels)
	if out, err := exec.Command("sh", "-c", "ip route get 8.8.8.8 2>/dev/null | head -n1").Output(); err == nil {
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				gw := fields[i+1]
				if ip := net.ParseIP(gw); ip != nil && !ip.IsUnspecified() {
					return gw
				}
			}
		}
	}
	// 2. Try known ISP tables on Keenetic/OpenWrt
	for _, tbl := range []string{"1000", "1001", "1002", "100", "200", "default", "main"} {
		cmdStr := fmt.Sprintf("ip route show table %s default 2>/dev/null | grep -v 'nb0' | head -n1", tbl)
		if out, err := exec.Command("sh", "-c", cmdStr).Output(); err == nil {
			fields := strings.Fields(string(out))
			for i, f := range fields {
				if f == "via" && i+1 < len(fields) {
					gw := fields[i+1]
					if ip := net.ParseIP(gw); ip != nil && !ip.IsUnspecified() {
						return gw
					}
				}
			}
		}
	}
	// 3. Fallback to standard table main
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
		if hostIP == physGW {
			continue
		}
		if ip := net.ParseIP(hostIP); ip != nil {
			// Do NOT bypass private, loopback, link-local or mesh IPs to physical gateway
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || isMeshIPLinux(hostIP) {
				continue
			}
		}
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
	dohActive := false
	if conn, err := net.DialTimeout("udp", "127.0.0.1:53", 100*time.Millisecond); err == nil {
		_ = conn.Close()
		dohActive = true
	}

	primaryDNS := "1.1.1.1"
	secDNS := "8.8.8.8"
	if dohActive {
		primaryDNS = "127.0.0.1"
		secDNS = "1.1.1.1"
	}

	// Метод 1: systemd-resolved через resolvectl
	if err := exec.Command("resolvectl", "dns", "nb0", primaryDNS, secDNS).Run(); err == nil {
		_ = exec.Command("resolvectl", "domain", "nb0", "~.").Run()
		return
	}
	// Метод 2: через nmcli (NetworkManager)
	if err := exec.Command("nmcli", "dev", "mod", "nb0", "ipv4.dns", primaryDNS+" "+secDNS).Run(); err == nil {
		return
	}
	// Метод 3: Прямая правка /etc/resolv.conf (fallback для OpenWrt/Keenetic с бэкапом!)
	if _, err := os.Stat("/etc/resolv.conf.natbypass.bak"); os.IsNotExist(err) {
		if origData, readErr := os.ReadFile("/etc/resolv.conf"); readErr == nil {
			_ = os.WriteFile("/etc/resolv.conf.natbypass.bak", origData, 0644)
		}
	}
	dnsContent := fmt.Sprintf("# NatBypass exit node DNS\nnameserver %s\nnameserver %s\n", primaryDNS, secDNS)
	if err := os.WriteFile("/etc/resolv.conf", []byte(dnsContent), 0644); err != nil {
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

	// Метод 3: Восстановление исходного /etc/resolv.conf из бэкапа
	if bakData, err := os.ReadFile("/etc/resolv.conf.natbypass.bak"); err == nil {
		_ = os.WriteFile("/etc/resolv.conf", bakData, 0644)
		_ = os.Remove("/etc/resolv.conf.natbypass.bak")
	}
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
	_ = runLinuxCmd("ip", "route", "replace", subnetCIDR, "dev", "nb0", "table", "main", "onlink")
	err := runLinuxCmd("ip", "route", "replace", subnetCIDR, "dev", "nb0", "onlink")
	if err != nil && cleanVIP != "" {
		return runLinuxCmd("ip", "route", "replace", subnetCIDR, "via", cleanVIP, "dev", "nb0", "onlink")
	}
	return err
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
	// Strictly restrict host routes to mesh overlay IPs, never arbitrary internet destinations
	if !isMeshIPLinux(cleanVIP) {
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
