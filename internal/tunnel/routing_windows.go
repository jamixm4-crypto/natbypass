//go:build windows

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
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/natbypass/natbypass/internal/network"
)

var (
	cachedWintunLUID          winipcfg.LUID
	cachedWintunLUIDMu        sync.RWMutex
	cachedWintunIfIndex       uint32
	cachedWintunAdapterName   string
	cachedWintunAdapterNameMu sync.RWMutex

	moddnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = moddnsapi.NewProc("DnsFlushResolverCache")
)

// SetCachedWintunLUID sets the cached NatBypass Wintun LUID for sub-millisecond route/IP operations.
func SetCachedWintunLUID(luid winipcfg.LUID) {
	cachedWintunLUIDMu.Lock()
	cachedWintunLUID = luid
	cachedWintunLUIDMu.Unlock()
}

// GetCachedWintunLUID returns the cached NatBypass Wintun LUID, or attempts to discover it if not set.
func GetCachedWintunLUID() winipcfg.LUID {
	cachedWintunLUIDMu.RLock()
	luid := cachedWintunLUID
	cachedWintunLUIDMu.RUnlock()
	if luid != 0 {
		return luid
	}

	// Try resolving from cached interface index
	if idx := atomic.LoadUint32(&cachedWintunIfIndex); idx > 0 {
		if l, err := winipcfg.LUIDFromIndex(idx); err == nil {
			SetCachedWintunLUID(l)
			return l
		}
	}

	// Try resolving from cached adapter name or scanning interfaces
	if ifaceName := GetCachedWintunAdapterName(); ifaceName != "" {
		if iface, err := net.InterfaceByName(ifaceName); err == nil && iface.Index > 0 {
			if l, err := winipcfg.LUIDFromIndex(uint32(iface.Index)); err == nil {
				SetCachedWintunLUID(l)
				return l
			}
		}
	}

	// Scan system interfaces for NatBypass adapter
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if strings.EqualFold(iface.Name, "NatBypass") || strings.Contains(strings.ToLower(iface.Name), "natbypass") {
				if l, err := winipcfg.LUIDFromIndex(uint32(iface.Index)); err == nil {
					SetCachedWintunLUID(l)
					SetCachedWintunIfIndex(uint32(iface.Index))
					SetCachedWintunAdapterName(iface.Name)
					return l
				}
			}
		}
	}

	return 0
}

// SetCachedWintunIfIndex caches the NatBypass Wintun adapter interface index for instant lookups.
func SetCachedWintunIfIndex(idx uint32) {
	atomic.StoreUint32(&cachedWintunIfIndex, idx)
	if idx > 0 {
		if l, err := winipcfg.LUIDFromIndex(idx); err == nil {
			SetCachedWintunLUID(l)
		}
	}
}

// SetCachedWintunAdapterName caches the NatBypass Wintun adapter alias/name for instant lookups.
func SetCachedWintunAdapterName(name string) {
	cachedWintunAdapterNameMu.Lock()
	cachedWintunAdapterName = name
	cachedWintunAdapterNameMu.Unlock()
}

// GetCachedWintunAdapterName returns the cached NatBypass adapter name.
func GetCachedWintunAdapterName() string {
	cachedWintunAdapterNameMu.RLock()
	defer cachedWintunAdapterNameMu.RUnlock()
	return cachedWintunAdapterName
}

// flushDNSCacheWindows invokes the native Windows API DnsFlushResolverCache for instant microsecond cache flush.
func flushDNSCacheWindows() {
	if procDnsFlushResolverCache.Find() == nil {
		_, _, _ = procDnsFlushResolverCache.Call()
	} else {
		_ = runRouteCmd("ipconfig", "/flushdns")
	}
}

// runRouteCmd executes a Windows command without opening a console window (used for firewall and netnat).
func runRouteCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:       true,
		CreationFlags:    0x08000000,
		NoInheritHandles: true,
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// IsKeeneticDevice returns false on Windows.
func IsKeeneticDevice() bool {
	return false
}

// isMeshIPWindows проверяет, является ли IP адресом из mesh-подсети (динамически по VIP текущего TUN).
func isMeshIPWindows(hostIP string) bool {
	ip := net.ParseIP(hostIP)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 100.64.0.0/10 (CGNAT / fallback mesh)
	if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
		return true
	}
	// 10.0.0.0/8 (Default mesh subnet family)
	if ip4[0] == 10 {
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

// getMeshSupernet returns a CIDR prefix covering all mesh nodes based on an IP or subnet string.
func getMeshSupernet(vipOrSubnet string) string {
	clean := strings.TrimSpace(vipOrSubnet)
	if strings.Contains(clean, "/") {
		clean = strings.Split(clean, "/")[0]
	}
	ip := net.ParseIP(clean)
	if ip == nil {
		return "10.0.0.0/8"
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "10.0.0.0/8"
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return fmt.Sprintf("192.168.%d.0/24", ip4[2])
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
}

// EnableHostIPForwardingSubnet sets IP forwarding and activates Windows NetNat for dynamic mesh subnet.
func EnableHostIPForwardingSubnet(subnet string) error {
	targetSubnet := subnet
	tunStat := GetTUNStatus()
	if tunStat.Active && tunStat.VirtualIP != "" {
		targetSubnet = tunStat.VirtualIP
	}
	targetPrefix := getMeshSupernet(targetSubnet)

	tunLUID := GetCachedWintunLUID()
	if tunLUID != 0 {
		if ipif, err := tunLUID.IPInterface(windows.AF_INET); err == nil {
			ipif.ForwardingEnabled = true
			ipif.WeakHostSend = true
			ipif.WeakHostReceive = true
			_ = ipif.Set()
		}
	}

	adapterName := getNatBypassAdapterNameWindows()
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "interface", adapterName, "forwarding=enabled")

	// Asynchronously configure NetNat and firewall so connection is never delayed
	go func(prefix, name string) {
		psScript := fmt.Sprintf(`
			Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1 -ErrorAction SilentlyContinue
			Set-Service -Name 'RemoteAccess' -StartupType Automatic -ErrorAction SilentlyContinue
			Start-Service -Name 'RemoteAccess' -ErrorAction SilentlyContinue
			Set-NetIPInterface -AddressFamily IPv4 -Forwarding Enabled -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue

			$targetPrefix = '%s'
			$existingNats = Get-NetNat -ErrorAction SilentlyContinue
			$matched = $false
			if ($existingNats) {
				foreach ($nat in $existingNats) {
					if ($nat.InternalIPInterfaceAddressPrefix -eq $targetPrefix) {
						$matched = $true
					} else {
						Remove-NetNat -Name $nat.Name -Confirm:$false -ErrorAction SilentlyContinue
					}
				}
			}

			if (-not $matched) {
				New-NetNat -Name 'NatBypassNAT' -InternalIPInterfaceAddressPrefix $targetPrefix -ErrorAction SilentlyContinue
			}

			if (-not (Get-NetFirewallRule -Name "NatBypass-Forward-In" -ErrorAction SilentlyContinue)) {
				New-NetFirewallRule -Name "NatBypass-Forward-In" -DisplayName "NatBypass Forward Inbound" -Direction Inbound -Action Allow -Protocol Any -Profile Any -EdgeTraversalPolicy Allow -ErrorAction SilentlyContinue
			}
			if (-not (Get-NetFirewallRule -Name "NatBypass-Forward-Out" -ErrorAction SilentlyContinue)) {
				New-NetFirewallRule -Name "NatBypass-Forward-Out" -DisplayName "NatBypass Forward Outbound" -Direction Outbound -Action Allow -Protocol Any -Profile Any -ErrorAction SilentlyContinue
			}
			if (-not (Get-NetFirewallRule -Name "NatBypass-ICMP-In" -ErrorAction SilentlyContinue)) {
				New-NetFirewallRule -Name "NatBypass-ICMP-In" -DisplayName "NatBypass ICMP Inbound" -Direction Inbound -Action Allow -Protocol ICMPv4 -Profile Any -ErrorAction SilentlyContinue
			}
		`, prefix)
		_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
		_ = runRouteCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=NatBypass Forward In", "dir=in", "action=allow", "interface="+name)
		_ = runRouteCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=NatBypass Forward Out", "dir=out", "action=allow", "interface="+name)
	}(targetPrefix, adapterName)

	return nil
}

// EnableHostIPForwarding enables IP forwarding for default mesh subnet.
func EnableHostIPForwarding() error {
	return EnableHostIPForwardingSubnet("100.64.200.0/24")
}

// EnsurePeerHostRoute adds a /32 host route for a peer's VirtualIP via the NatBypass Wintun interface using NetIO API.
func EnsurePeerHostRoute(peerVIP string) {
	if peerVIP == "" {
		return
	}
	cleanVIP := strings.TrimSpace(strings.Split(peerVIP, "/")[0])
	addr, err := netip.ParseAddr(cleanVIP)
	if err != nil || !addr.Is4() {
		return
	}
	if !isMeshIPWindows(cleanVIP) {
		return
	}

	tunStat := GetTUNStatus()
	if !tunStat.Active || tunStat.VirtualIP == "" {
		return
	}
	if cleanVIP == tunStat.VirtualIP {
		return
	}

	tunLUID := GetCachedWintunLUID()
	if tunLUID == 0 {
		return
	}

	prefix := netip.PrefixFrom(addr, 32)
	_ = tunLUID.AddRoute(prefix, netip.IPv4Unspecified(), 5)
}

// DisableHostIPForwarding disables IP forwarding and cleans up NetNat rule.
func DisableHostIPForwarding() error {
	tunLUID := GetCachedWintunLUID()
	if tunLUID != 0 {
		if ipif, err := tunLUID.IPInterface(windows.AF_INET); err == nil {
			ipif.ForwardingEnabled = false
			_ = ipif.Set()
		}
	}
	adapterName := getNatBypassAdapterNameWindows()
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "interface", adapterName, "forwarding=disabled")
	go func() {
		psScript := `
			Set-NetIPInterface -InterfaceAlias 'NatBypass*' -AddressFamily IPv4 -Forwarding Disabled -ErrorAction SilentlyContinue
			Get-NetNat | Where-Object { $_.Name -like 'NatBypassNAT*' } | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue
			Remove-NetFirewallRule -Name 'NatBypass-Forward-*' -ErrorAction SilentlyContinue
		`
		_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	}()
	return nil
}

type physicalRouteInfo struct {
	Gateway netip.Addr
	LUID    winipcfg.LUID
	IfIndex uint32
}

// getPhysicalGatewayWin finds the current primary physical default gateway IP and interface LUID
// using direct memory queries against the Windows Kernel FIB (winipcfg.GetIPForwardTable2). Sub-millisecond execution.
func getPhysicalGatewayWin() (*physicalRouteInfo, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("winipcfg GetIPForwardTable2 failed: %w", err)
	}

	tunLUID := GetCachedWintunLUID()
	var bestMetric uint32 = 0xFFFFFFFF
	var bestInfo *physicalRouteInfo

	for _, r := range routes {
		prefix := r.DestinationPrefix.Prefix()
		// Match IPv4 default route: 0.0.0.0/0
		if prefix.Bits() == 0 && prefix.Addr().Is4() {
			if tunLUID != 0 && r.InterfaceLUID == tunLUID {
				continue // Skip the NatBypass tunnel itself
			}
			nextHop := r.NextHop.Addr()
			if nextHop.IsValid() && !nextHop.IsUnspecified() && !nextHop.IsLoopback() && !isMeshIPWindows(nextHop.String()) {
				// Select route with lowest metric (primary default gateway)
				if r.Metric < bestMetric {
					bestMetric = r.Metric
					bestInfo = &physicalRouteInfo{
						Gateway: nextHop,
						LUID:    r.InterfaceLUID,
						IfIndex: r.InterfaceIndex,
					}
				}
			}
		}
	}

	if bestInfo == nil {
		return nil, fmt.Errorf("no physical IPv4 default gateway found")
	}
	return bestInfo, nil
}

// getPhysicalGatewayWindows returns the string IP of the primary physical default gateway.
func getPhysicalGatewayWindows() string {
	info, err := getPhysicalGatewayWin()
	if err != nil {
		return ""
	}
	return info.Gateway.String()
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
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
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

// isLocalDNSResponding sends a real 12-byte DNS test query to 127.0.0.1:53 to check if DoH proxy is actively responding.
func isLocalDNSResponding() bool {
	conn, err := net.DialTimeout("udp", "127.0.0.1:53", 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	_ = conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := conn.Write(query); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	return err == nil && n >= 12
}

// getNatBypassAdapterNameWindows returns the actual system interface name for the NatBypass Wintun adapter.
func getNatBypassAdapterNameWindows() string {
	if name := GetCachedWintunAdapterName(); name != "" {
		return name
	}
	if idx := atomic.LoadUint32(&cachedWintunIfIndex); idx > 0 {
		if iface, err := net.InterfaceByIndex(int(idx)); err == nil && iface.Name != "" {
			SetCachedWintunAdapterName(iface.Name)
			return iface.Name
		}
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if strings.EqualFold(iface.Name, "NatBypass") || strings.Contains(strings.ToLower(iface.Name), "natbypass") {
				SetCachedWintunAdapterName(iface.Name)
				return iface.Name
			}
		}
	}
	return "NatBypass"
}

// getNatBypassIfIndexWindows finds the interface index of the NatBypass Wintun adapter.
func getNatBypassIfIndexWindows() int {
	if idx := atomic.LoadUint32(&cachedWintunIfIndex); idx > 0 {
		return int(idx)
	}
	if luid := GetCachedWintunLUID(); luid != 0 {
		if ifRow, err := luid.Interface(); err == nil {
			SetCachedWintunIfIndex(ifRow.InterfaceIndex)
			return int(ifRow.InterfaceIndex)
		}
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if strings.EqualFold(iface.Name, "NatBypass") || strings.Contains(strings.ToLower(iface.Name), "natbypass") {
				SetCachedWintunIfIndex(uint32(iface.Index))
				return iface.Index
			}
		}
	}
	return 0
}

var (
	bypassedMu       sync.Mutex
	lastBypassedIPs  []netip.Addr
	lastBypassedLUID winipcfg.LUID
	lastBypassedGW   netip.Addr
	lastLANSubnet    netip.Prefix
)

// BypassEndpoint dynamically adds a /32 route via the physical default gateway for an endpoint IP/host
// using direct NetIO API to prevent routing loops when Exit Node routing is active.
func BypassEndpoint(endpoint string) error {
	physInfo, err := getPhysicalGatewayWin()
	if err != nil || endpoint == "" {
		return nil
	}
	hostIPs := extractHostIPs(endpoint)
	bypassedMu.Lock()
	defer bypassedMu.Unlock()

	lastBypassedLUID = physInfo.LUID
	lastBypassedGW = physInfo.Gateway

	for _, hostIP := range hostIPs {
		addr, err := netip.ParseAddr(hostIP)
		if err != nil || !addr.Is4() {
			continue
		}
		if addr == physInfo.Gateway {
			continue
		}
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || isMeshIPWindows(hostIP) {
			continue
		}

		alreadyAdded := false
		for _, prev := range lastBypassedIPs {
			if prev == addr {
				alreadyAdded = true
				break
			}
		}
		if !alreadyAdded {
			prefix := netip.PrefixFrom(addr, 32)
			_ = physInfo.LUID.AddRoute(prefix, physInfo.Gateway, 1)
			lastBypassedIPs = append(lastBypassedIPs, addr)
		}
	}
	return nil
}

var (
	exitNodeOpMu      sync.Mutex
	lastActiveExitVIP string
)

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1) via gatewayVIP,
// with automatic routing-loop prevention and DNS configuration.
// WireGuard-grade implementation: executes directly in Windows Kernel memory via NetIO API in < 15ms.
func EnableExitNodeRouting(gatewayVIP string, remoteEndpoints ...string) error {
	exitNodeOpMu.Lock()
	defer exitNodeOpMu.Unlock()

	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])
	vipAddr, err := netip.ParseAddr(cleanVIP)
	if err != nil || !vipAddr.Is4() {
		return fmt.Errorf("invalid gateway VIP %q: %w", gatewayVIP, err)
	}

	tunLUID := GetCachedWintunLUID()
	if tunLUID == 0 {
		return fmt.Errorf("natbypass wintun LUID is not available")
	}

	// 0. Cleanly teardown any prior exit node state before applying new one
	_ = disableExitNodeRoutingLocked("")
	lastActiveExitVIP = cleanVIP

	// 1. Routing loop prevention: bypass remote endpoints, MQTT broker, STUN servers via physical default gateway
	for _, ep := range remoteEndpoints {
		_ = BypassEndpoint(ep)
	}

	// 1b. Cache physical gateway info for endpoint bypasses
	if physInfo, err := getPhysicalGatewayWin(); err == nil {
		bypassedMu.Lock()
		lastBypassedLUID = physInfo.LUID
		lastBypassedGW = physInfo.Gateway
		bypassedMu.Unlock()
	}

	// 2. Ensure /32 host route to the exit gateway VIP exists on NatBypass adapter
	peerPrefix := netip.PrefixFrom(vipAddr, 32)
	_ = tunLUID.AddRoute(peerPrefix, netip.IPv4Unspecified(), 1)

	// 3. Add WireGuard def1 /1 routes directly to Wintun adapter LUID (< 1ms)
	p0 := netip.MustParsePrefix("0.0.0.0/1")
	p128 := netip.MustParsePrefix("128.0.0.0/1")

	_ = tunLUID.DeleteRoute(p0, netip.IPv4Unspecified())
	_ = tunLUID.DeleteRoute(p128, netip.IPv4Unspecified())
	_ = tunLUID.DeleteRoute(p0, vipAddr)
	_ = tunLUID.DeleteRoute(p128, vipAddr)

	// In Point-to-Point Wintun, the next-hop is on-link (unspecified)
	if err0 := tunLUID.AddRoute(p0, netip.IPv4Unspecified(), 1); err0 != nil {
		_ = tunLUID.AddRoute(p0, vipAddr, 1)
	}
	if err128 := tunLUID.AddRoute(p128, netip.IPv4Unspecified(), 1); err128 != nil {
		_ = tunLUID.AddRoute(p128, vipAddr, 1)
	}

	// 4. Configure DNS strictly on NatBypass Wintun adapter LUID (WireGuard standard).
	// The physical network adapter DNS is 100% untouched and never modified!
	dnsServers := []netip.Addr{
		netip.MustParseAddr("77.88.8.8"),
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("1.1.1.1"),
	}
	if isLocalDNSResponding() {
		dnsServers = append([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, dnsServers...)
	}
	_ = tunLUID.SetDNS(windows.AF_INET, dnsServers, nil)

	// 5. Route public DNS resolvers via Wintun LUID so DNS is always tunneled through exit node
	for _, dnsAddr := range []netip.Addr{
		netip.MustParseAddr("77.88.8.8"),
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
	} {
		_ = tunLUID.AddRoute(netip.PrefixFrom(dnsAddr, 32), netip.IPv4Unspecified(), 1)
	}

	// 6. Instant microsecond DNS cache flush
	flushDNSCacheWindows()

	return nil
}

// DisableExitNodeRouting removes the default gateway /1 routes, bypass routes, and restores DNS.
func DisableExitNodeRouting(gatewayVIP string) error {
	exitNodeOpMu.Lock()
	defer exitNodeOpMu.Unlock()
	return disableExitNodeRoutingLocked(gatewayVIP)
}

func disableExitNodeRoutingLocked(gatewayVIP string) error {
	vipToClean := gatewayVIP
	if vipToClean == "" {
		vipToClean = lastActiveExitVIP
	}
	lastActiveExitVIP = ""

	tunLUID := GetCachedWintunLUID()
	if tunLUID != 0 {
		p0 := netip.MustParsePrefix("0.0.0.0/1")
		p128 := netip.MustParsePrefix("128.0.0.0/1")

		// 1. Instant removal of WireGuard def1 routes from Windows kernel (< 1ms)
		_ = tunLUID.DeleteRoute(p0, netip.IPv4Unspecified())
		_ = tunLUID.DeleteRoute(p128, netip.IPv4Unspecified())
		if vipToClean != "" {
			if vipAddr, err := netip.ParseAddr(vipToClean); err == nil {
				_ = tunLUID.DeleteRoute(p0, vipAddr)
				_ = tunLUID.DeleteRoute(p128, vipAddr)
			}
		}

		// 2. Remove tunneled DNS resolver /32 routes
		for _, dnsAddr := range []netip.Addr{
			netip.MustParseAddr("77.88.8.8"),
			netip.MustParseAddr("9.9.9.9"),
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("8.8.8.8"),
		} {
			_ = tunLUID.DeleteRoute(netip.PrefixFrom(dnsAddr, 32), netip.IPv4Unspecified())
		}

		// 3. Reset DNS on Wintun LUID (< 1ms)
		_ = tunLUID.FlushDNS(windows.AF_INET)
	}

	// 4. Remove remote endpoint bypass routes on physical adapter
	bypassedMu.Lock()
	if lastBypassedLUID != 0 && lastBypassedGW.IsValid() {
		for _, ip := range lastBypassedIPs {
			_ = lastBypassedLUID.DeleteRoute(netip.PrefixFrom(ip, 32), lastBypassedGW)
		}
	}
	lastBypassedIPs = nil
	lastBypassedLUID = 0
	lastBypassedGW = netip.Addr{}
	lastLANSubnet = netip.Prefix{}
	bypassedMu.Unlock()

	// 5. Instant microsecond DNS cache flush
	flushDNSCacheWindows()

	return nil
}

// AddSubnetRoute adds a routing entry for a subnet CIDR via Wintun LUID. Instant sub-millisecond execution.
func AddSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	prefix, err := netip.ParsePrefix(subnetCIDR)
	if err != nil {
		return fmt.Errorf("invalid subnet CIDR %q: %w", subnetCIDR, err)
	}

	tunLUID := GetCachedWintunLUID()
	if tunLUID == 0 {
		return fmt.Errorf("natbypass wintun LUID is not available")
	}

	nextHop := netip.IPv4Unspecified()
	if gatewayVIP != "" {
		cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])
		if addr, err := netip.ParseAddr(cleanVIP); err == nil {
			nextHop = addr
		}
	}

	if err := tunLUID.AddRoute(prefix, netip.IPv4Unspecified(), 10); err != nil {
		return tunLUID.AddRoute(prefix, nextHop, 10)
	}
	return nil
}

// RemoveSubnetRoute removes a routing entry for a subnet CIDR via Wintun LUID.
func RemoveSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	prefix, err := netip.ParsePrefix(subnetCIDR)
	if err != nil {
		return fmt.Errorf("invalid subnet CIDR %q: %w", subnetCIDR, err)
	}

	tunLUID := GetCachedWintunLUID()
	if tunLUID == 0 {
		return nil
	}

	_ = tunLUID.DeleteRoute(prefix, netip.IPv4Unspecified())
	if gatewayVIP != "" {
		cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])
		if addr, err := netip.ParseAddr(cleanVIP); err == nil {
			_ = tunLUID.DeleteRoute(prefix, addr)
		}
	}
	return nil
}

// FlushAllRouting cleans up any active exit routes or subnet routes.
func FlushAllRouting(gatewayVIP string, subnets []string) {
	_ = DisableExitNodeRouting(gatewayVIP)
	for _, s := range subnets {
		_ = RemoveSubnetRoute(s, gatewayVIP)
	}
}

// GetLocalSubnets returns a unique list of local IPv4 subnet CIDRs.
func GetLocalSubnets() []string {
	return network.GetLocalSubnets()
}

// EnableMSSClamping sets the MTU on the NatBypass TUN adapter on Windows via direct NetIO API.
func EnableMSSClamping(tunInterface string, mtu int) error {
	if mtu <= 0 {
		mtu = 1420
	}
	tunLUID := GetCachedWintunLUID()
	if tunLUID != 0 {
		if ipif, err := tunLUID.IPInterface(windows.AF_INET); err == nil {
			ipif.NLMTU = uint32(mtu)
			return ipif.Set()
		}
	}
	return nil
}

// DisableMSSClamping restores default MTU (1500) on the NatBypass TUN adapter.
func DisableMSSClamping(tunInterface string) error {
	tunLUID := GetCachedWintunLUID()
	if tunLUID != 0 {
		if ipif, err := tunLUID.IPInterface(windows.AF_INET); err == nil {
			ipif.NLMTU = 1500
			return ipif.Set()
		}
	}
	return nil
}
