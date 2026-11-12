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
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/natbypass/natbypass/internal/network"
)

var cachedWintunIfIndex uint32

// SetCachedWintunIfIndex caches the NatBypass Wintun adapter interface index for instant lookups.
func SetCachedWintunIfIndex(idx uint32) {
	atomic.StoreUint32(&cachedWintunIfIndex, idx)
}

// runRouteCmd executes a Windows command without opening a console window.
func runRouteCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:        true,
		CreationFlags:     0x08000000,
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
	if ip4[0] == 10 {
		return "10.0.0.0/8"
	}
	if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
		return "100.64.0.0/10"
	}
	if ip4[0] == 172 && (ip4[1] >= 16 && ip4[1] <= 31) {
		return "172.16.0.0/12"
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return "192.168.0.0/16"
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

	adapterName := getNatBypassAdapterNameWindows()

	// 1. Enable forwarding on NatBypass adapter
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "interface", adapterName, "forwarding=enabled")

	// 2. Enable IP routing in Windows Registry & NetNat & enable forwarding on all active network adapters
	// Note: Windows supports only ONE active NetNat instance system-wide.
	psScript := fmt.Sprintf(`
		Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1 -ErrorAction SilentlyContinue
		Set-NetIPInterface -AddressFamily IPv4 -Forwarding Enabled -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue

		$targetPrefix = '%s'
		$existingNats = Get-NetNat -ErrorAction SilentlyContinue

		$matched = $false
		if ($existingNats) {
			foreach ($nat in $existingNats) {
				if ($nat.InternalIPInterfaceAddressPrefix -eq $targetPrefix) {
					$matched = $true
				} elseif ($nat.Name -like 'NatBypassNAT*') {
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
	`, targetPrefix)
	_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)

	// 3. Add Windows firewall rules for interface forwarding
	_ = runRouteCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=NatBypass Forward In", "dir=in", "action=allow", "interface="+adapterName)
	_ = runRouteCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=NatBypass Forward Out", "dir=out", "action=allow", "interface="+adapterName)

	return nil
}

// EnableHostIPForwarding enables IP forwarding for default mesh subnet.
func EnableHostIPForwarding() error {
	return EnableHostIPForwardingSubnet("100.64.200.0/24")
}

var winPeerRoutes sync.Map

// EnsurePeerHostRoute adds a /32 host route for a peer's VirtualIP via the NatBypass Wintun interface on Windows.
// This is critical when peers belong to different subnets (e.g. Android on 10.1.1.x, Windows on 10.1.2.x).
func EnsurePeerHostRoute(peerVIP string) {
	if peerVIP == "" {
		return
	}
	cleanVIP := strings.TrimSpace(strings.Split(peerVIP, "/")[0])
	if net.ParseIP(cleanVIP) == nil {
		return
	}

	tunStat := GetTUNStatus()
	if !tunStat.Active || tunStat.VirtualIP == "" {
		return
	}
	myVIP := tunStat.VirtualIP
	if cleanVIP == myVIP {
		return
	}

	now := time.Now().Unix()
	if prev, loaded := winPeerRoutes.LoadOrStore(cleanVIP, now); loaded {
		if ts, ok := prev.(int64); ok && now-ts < 60 {
			return
		}
		winPeerRoutes.Store(cleanVIP, now)
	}

	ifIdx := getNatBypassIfIndexWindows()
	args := []string{"add", cleanVIP, "mask", "255.255.255.255", "0.0.0.0", "metric", "5"}
	if ifIdx > 0 {
		args = append(args, "IF", fmt.Sprintf("%d", ifIdx))
	}
	_ = runRouteCmd("route", args...)
	if ifIdx > 0 {
		psHostRoute := fmt.Sprintf(`
			Get-NetRoute -InterfaceIndex %d -DestinationPrefix '%s/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
			New-NetRoute -InterfaceIndex %d -DestinationPrefix '%s/32' -NextHop '0.0.0.0' -RouteMetric 5 -ErrorAction SilentlyContinue
		`, ifIdx, cleanVIP, ifIdx, cleanVIP)
		_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psHostRoute)
	}
}

// DisableHostIPForwarding disables IP forwarding and cleans up NetNat rule.
func DisableHostIPForwarding() error {
	adapterName := getNatBypassAdapterNameWindows()
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "interface", adapterName, "forwarding=disabled")
	psScript := `
		Set-NetIPInterface -InterfaceAlias 'NatBypass*' -AddressFamily IPv4 -Forwarding Disabled -ErrorAction SilentlyContinue
		Get-NetNat | Where-Object { $_.Name -like 'NatBypassNAT*' } | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue
		Remove-NetFirewallRule -Name 'NatBypass-Forward-*' -ErrorAction SilentlyContinue
	`
	_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	return nil
}

var (
	bypassedMu              sync.Mutex
	lastBypassedEndpointIPs []string
	cachedPhysGW            string
	cachedPhysGWTime        time.Time
)

// getPhysicalGatewayWindows finds the current primary physical default gateway IP
func getPhysicalGatewayWindows() string {
	bypassedMu.Lock()
	if cachedPhysGW != "" && time.Since(cachedPhysGWTime) < 10*time.Second {
		gw := cachedPhysGW
		bypassedMu.Unlock()
		return gw
	}
	bypassedMu.Unlock()

	// 1. Fast path: "route print 0.0.0.0" via cmd.exe (~70ms vs 1500ms powershell)
	cmd := exec.Command("cmd", "/c", "route print 0.0.0.0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if out, err := cmd.Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				gw := fields[2]
				if ip := net.ParseIP(gw); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !isMeshIPWindows(gw) {
					bypassedMu.Lock()
					cachedPhysGW = gw
					cachedPhysGWTime = time.Now()
					bypassedMu.Unlock()
					return gw
				}
			}
		}
	}

	// 2. Fallback: PowerShell Get-NetRoute
	psScript := `(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.InterfaceAlias -notlike '*NatBypass*' } | Sort-Object RouteMetric | Select-Object -First 1).NextHop`
	psCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	psCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if out, err := psCmd.Output(); err == nil {
		gw := strings.TrimSpace(string(out))
		if ip := net.ParseIP(gw); ip != nil && !ip.IsUnspecified() && !isMeshIPWindows(gw) {
			bypassedMu.Lock()
			cachedPhysGW = gw
			cachedPhysGWTime = time.Now()
			bypassedMu.Unlock()
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

// isLocalDNSResponding sends a real 12-byte DNS test query to 127.0.0.1:53 to check if DoH proxy is actively responding.
func isLocalDNSResponding() bool {
	conn, err := net.DialTimeout("udp", "127.0.0.1:53", 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	// Standard DNS query header for localhost: Type A, Class IN
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
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if strings.EqualFold(iface.Name, "NatBypass") || strings.Contains(strings.ToLower(iface.Name), "natbypass") {
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
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if strings.EqualFold(iface.Name, "NatBypass") || strings.Contains(strings.ToLower(iface.Name), "natbypass") {
				return iface.Index
			}
		}
	}
	return 0
}

// BypassEndpoint dynamically adds a /32 route via the physical default gateway for an endpoint IP/host
// to prevent routing loops when Exit Node routing is active.
func BypassEndpoint(endpoint string) error {
	physGW := getPhysicalGatewayWindows()
	if physGW == "" || endpoint == "" {
		return nil
	}
	hostIPs := extractHostIPs(endpoint)
	bypassedMu.Lock()
	defer bypassedMu.Unlock()
	for _, hostIP := range hostIPs {
		if hostIP == physGW {
			continue
		}
		if ip := net.ParseIP(hostIP); ip != nil {
			// Do NOT bypass mesh IPs to physical gateway — check dynamically against active TUN subnet
			if isMeshIPWindows(hostIP) {
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
			_ = runRouteCmd("route", "add", hostIP, "mask", "255.255.255.255", physGW, "metric", "1")
			lastBypassedEndpointIPs = append(lastBypassedEndpointIPs, hostIP)
		}
	}
	return nil
}

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1) via gatewayVIP,
// with automatic routing-loop prevention and DNS configuration.
func EnableExitNodeRouting(gatewayVIP string, remoteEndpoints ...string) error {
	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])

	// 1. Routing loop prevention: bypass remote endpoints, MQTT broker, STUN servers via physical default gateway
	for _, ep := range remoteEndpoints {
		_ = BypassEndpoint(ep)
	}

	// 2. Ensure /32 host route to the exit gateway VIP exists on NatBypass adapter
	EnsurePeerHostRoute(cleanVIP)

	// 3. Add WireGuard def1 /1 routes with NatBypass adapter IF index to avoid interface ambiguity
	ifIdx := getNatBypassIfIndexWindows()

	// Clear existing def1 routes first to avoid duplicate route errors
	_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_ = runRouteCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")

	// On Windows Point-to-Point Wintun, the next hop for the def1 routes is 0.0.0.0 (On-link),
	// binding all default transit traffic unconditionally to the NatBypass Wintun interface.
	args0 := []string{"add", "0.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "metric", "1"}
	args128 := []string{"add", "128.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "metric", "1"}
	if ifIdx > 0 {
		args0 = append(args0, "IF", fmt.Sprintf("%d", ifIdx))
		args128 = append(args128, "IF", fmt.Sprintf("%d", ifIdx))
	}

	_ = runRouteCmd("route", args0...)
	_ = runRouteCmd("route", args128...)

	if ifIdx > 0 {
		psRoutes := fmt.Sprintf(`
			Get-NetRoute -InterfaceIndex %d -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
			Get-NetRoute -InterfaceIndex %d -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
			New-NetRoute -InterfaceIndex %d -DestinationPrefix '0.0.0.0/1' -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction SilentlyContinue
			New-NetRoute -InterfaceIndex %d -DestinationPrefix '128.0.0.0/1' -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction SilentlyContinue
		`, ifIdx, ifIdx, ifIdx, ifIdx)
		_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psRoutes)
	}

	// 4. Configure DNS on NatBypass adapter: use local DoH (127.0.0.1) ONLY if port 53 is responsive,
	// otherwise fall back directly to public resolvers (1.1.1.1, 8.8.8.8) routed via tunnel.
	adapterName := getNatBypassAdapterNameWindows()
	dohActive := isLocalDNSResponding()

	if dohActive {
		_ = runRouteCmd("netsh", "interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", adapterName), "static", "127.0.0.1", "register=primary", "validate=no")
		_ = runRouteCmd("netsh", "interface", "ipv4", "add", "dnsservers", fmt.Sprintf("name=%s", adapterName), "address=1.1.1.1", "index=2", "validate=no")
		_ = runRouteCmd("netsh", "interface", "ipv4", "add", "dnsservers", fmt.Sprintf("name=%s", adapterName), "address=8.8.8.8", "index=3", "validate=no")
	} else {
		_ = runRouteCmd("netsh", "interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", adapterName), "static", "1.1.1.1", "register=primary", "validate=no")
		_ = runRouteCmd("netsh", "interface", "ipv4", "add", "dnsservers", fmt.Sprintf("name=%s", adapterName), "address=8.8.8.8", "index=2", "validate=no")
	}

	if ifIdx > 0 {
		var psDNS string
		if dohActive {
			psDNS = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses @('127.0.0.1', '1.1.1.1', '8.8.8.8') -ErrorAction SilentlyContinue", ifIdx)
		} else {
			psDNS = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses @('1.1.1.1', '8.8.8.8') -ErrorAction SilentlyContinue", ifIdx)
		}
		_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psDNS)
	}

	return nil
}

// DisableExitNodeRouting removes the default gateway /1 routes, bypass routes, and restores DNS.
func DisableExitNodeRouting(gatewayVIP string) error {
	var errs []string
	if gatewayVIP != "" {
		_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0", gatewayVIP)
		_ = runRouteCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0", gatewayVIP)
	}
	_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_ = runRouteCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	if ifIdx := getNatBypassIfIndexWindows(); ifIdx > 0 {
		psClean := fmt.Sprintf(`
			Get-NetRoute -InterfaceIndex %d -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
			Get-NetRoute -InterfaceIndex %d -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
		`, ifIdx, ifIdx)
		_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psClean)
	}

	// Remove all bypass routes
	bypassedMu.Lock()
	for _, hostIP := range lastBypassedEndpointIPs {
		_ = runRouteCmd("route", "delete", hostIP, "mask", "255.255.255.255")
	}
	lastBypassedEndpointIPs = nil
	bypassedMu.Unlock()

	// Reset DNS on adapter
	adapterName := getNatBypassAdapterNameWindows()
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", adapterName), "source=dhcp")
	if ifIdx := getNatBypassIfIndexWindows(); ifIdx > 0 {
		psScript := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses -ErrorAction SilentlyContinue", ifIdx)
		_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors disabling exit node routing: %s", strings.Join(errs, "; "))
	}
	return nil
}

// AddSubnetRoute adds a routing entry for a subnet CIDR via gatewayVIP.
func AddSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	ipStr, maskStr, err := parseSubnetCIDR(subnetCIDR)
	if err != nil {
		return err
	}
	if err := runRouteCmd("route", "add", ipStr, "mask", maskStr, gatewayVIP, "metric", "10"); err != nil {
		return fmt.Errorf("failed to add subnet route %s via %s: %w", subnetCIDR, gatewayVIP, err)
	}
	return nil
}

// RemoveSubnetRoute removes a routing entry for a subnet CIDR via gatewayVIP.
func RemoveSubnetRoute(subnetCIDR string, gatewayVIP string) error {
	ipStr, maskStr, err := parseSubnetCIDR(subnetCIDR)
	if err != nil {
		return err
	}
	if err := runRouteCmd("route", "delete", ipStr, "mask", maskStr, gatewayVIP); err != nil {
		return fmt.Errorf("failed to remove subnet route %s via %s: %w", subnetCIDR, gatewayVIP, err)
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

// EnableMSSClamping sets the MTU on the NatBypass TUN adapter on Windows.
// R1: Windows does not support iptables MSS clamping, so we set a reduced MTU (1420)
// on the TUN adapter so the OS derives a correct MSS (MTU - 40 = 1380) automatically.
// This prevents TCP connection stalls over the VPN tunnel.
func EnableMSSClamping(tunInterface string, mtu int) error {
	if tunInterface == "" || strings.EqualFold(tunInterface, "NatBypass") {
		tunInterface = getNatBypassAdapterNameWindows()
	}
	if mtu <= 0 {
		mtu = 1420
	}
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "subinterface",
		tunInterface, fmt.Sprintf("mtu=%d", mtu), "store=persistent")
	return nil
}

// DisableMSSClamping restores default MTU (1500) on the NatBypass TUN adapter.
func DisableMSSClamping(tunInterface string) error {
	if tunInterface == "" || strings.EqualFold(tunInterface, "NatBypass") {
		tunInterface = getNatBypassAdapterNameWindows()
	}
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "subinterface",
		tunInterface, "mtu=1500", "store=persistent")
	return nil
}
