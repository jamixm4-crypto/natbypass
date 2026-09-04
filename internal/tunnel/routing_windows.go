//go:build windows

package tunnel

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/natbypass/natbypass/internal/network"
)

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

// EnableHostIPForwardingSubnet sets IP forwarding and activates Windows NetNat for dynamic mesh subnet.
func EnableHostIPForwardingSubnet(subnet string) error {
	if subnet == "" {
		subnet = "100.64.200.0/24"
	}
	cleanSubnet := subnet
	if !strings.Contains(cleanSubnet, "/") {
		parts := strings.Split(cleanSubnet, ".")
		if len(parts) >= 3 {
			cleanSubnet = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		} else {
			cleanSubnet = "100.64.200.0/24"
		}
	}

	// 1. Enable forwarding on NatBypass adapter
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "interface", "NatBypass", "forwarding=enabled")

	// 2. Enable IP routing in Windows Registry & NetNat & enable forwarding on all active network adapters
	psScript := fmt.Sprintf(`
		Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1 -ErrorAction SilentlyContinue
		Set-Service -Name RemoteAccess -StartupType Automatic -ErrorAction SilentlyContinue
		Start-Service -Name RemoteAccess -ErrorAction SilentlyContinue
		netsh interface ipv4 set interface "NatBypass" forwarding=enabled
		Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
			netsh interface ipv4 set interface $_.InterfaceAlias forwarding=enabled
		}
		$existing = Get-NetNat -ErrorAction SilentlyContinue
		$matched = $false
		if ($existing) {
			foreach ($nat in $existing) {
				if ($nat.InternalIPInterfaceAddressPrefix -eq '%s') {
					$matched = $true
					break
				}
			}
		}
		if (-not $matched) {
			Remove-NetNat -Name 'NatBypassNAT' -Confirm:$false -ErrorAction SilentlyContinue
			New-NetNat -Name 'NatBypassNAT' -InternalIPInterfaceAddressPrefix '%s' -ErrorAction SilentlyContinue
		}
	`, cleanSubnet, cleanSubnet)
	_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)

	// 3. Add Windows firewall rules for interface forwarding
	_ = runRouteCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=NatBypass Forward In", "dir=in", "action=allow", "interface=NatBypass")
	_ = runRouteCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=NatBypass Forward Out", "dir=out", "action=allow", "interface=NatBypass")

	return nil
}

// EnableHostIPForwarding enables IP forwarding for default mesh subnet.
func EnableHostIPForwarding() error {
	return EnableHostIPForwardingSubnet("100.64.200.0/24")
}

// DisableHostIPForwarding disables IP forwarding and cleans up NetNat rule.
func DisableHostIPForwarding() error {
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "interface", "NatBypass", "forwarding=disabled")
	psScript := `Remove-NetNat -Name 'NatBypassNAT' -Confirm:$false -ErrorAction SilentlyContinue`
	_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	return nil
}

var (
	bypassedMu             sync.Mutex
	lastBypassedEndpointIPs []string
)

// getPhysicalGatewayWindows finds the current primary physical default gateway IP
func getPhysicalGatewayWindows() string {
	psScript := `(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.InterfaceAlias -notlike '*NatBypass*' } | Sort-Object RouteMetric | Select-Object -First 1).NextHop`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
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

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1) via gatewayVIP,
// with automatic routing-loop prevention and DNS configuration.
func EnableExitNodeRouting(gatewayVIP string, remoteEndpoints ...string) error {
	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])

	// 1. Routing loop prevention: bypass remote endpoints, MQTT broker, STUN servers via physical default gateway
	physGW := getPhysicalGatewayWindows()
	if physGW != "" {
		bypassedMu.Lock()
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
					_ = runRouteCmd("route", "add", hostIP, "mask", "255.255.255.255", physGW, "metric", "1")
					lastBypassedEndpointIPs = append(lastBypassedEndpointIPs, hostIP)
				}
			}
		}
		bypassedMu.Unlock()
	}

	// 2. Add WireGuard def1 /1 routes
	if err := runRouteCmd("route", "add", "0.0.0.0", "mask", "128.0.0.0", cleanVIP, "metric", "5"); err != nil {
		return fmt.Errorf("failed to add default route 0.0.0.0/1 via %s: %w", cleanVIP, err)
	}
	if err := runRouteCmd("route", "add", "128.0.0.0", "mask", "128.0.0.0", cleanVIP, "metric", "5"); err != nil {
		_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0", cleanVIP)
		return fmt.Errorf("failed to add default route 128.0.0.0/1 via %s: %w", cleanVIP, err)
	}

	// 3. Configure public DNS on NatBypass adapter to prevent DNS failure / leaks
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "dnsservers", "name=NatBypass", "static", "1.1.1.1", "register=primary", "validate=no")
	_ = runRouteCmd("netsh", "interface", "ipv4", "add", "dnsservers", "name=NatBypass", "address=8.8.8.8", "index=2", "validate=no")

	return nil
}

// DisableExitNodeRouting removes the default gateway /1 routes, bypass routes, and restores DNS.
func DisableExitNodeRouting(gatewayVIP string) error {
	var errs []string
	if gatewayVIP != "" {
		_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0", gatewayVIP)
		_ = runRouteCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0", gatewayVIP)
	} else {
		_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
		_ = runRouteCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	}

	// Remove all bypass routes
	bypassedMu.Lock()
	for _, hostIP := range lastBypassedEndpointIPs {
		_ = runRouteCmd("route", "delete", hostIP, "mask", "255.255.255.255")
	}
	lastBypassedEndpointIPs = nil
	bypassedMu.Unlock()

	// Reset DNS on adapter
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "dnsservers", "name=NatBypass", "source=dhcp")

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

// EnableMSSClamping is a cross-platform stub on Windows.
func EnableMSSClamping(tunInterface string, mtu int) error {
	return nil
}

// DisableMSSClamping is a cross-platform stub on Windows.
func DisableMSSClamping(tunInterface string) error {
	return nil
}
