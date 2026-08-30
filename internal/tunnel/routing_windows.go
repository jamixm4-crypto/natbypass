//go:build windows

package tunnel

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

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

// EnableHostIPForwarding sets IP forwarding on interface "NatBypass", enables IP routing in Windows registry,
// and activates Windows NetNat (kernel NAT masquerading) for the mesh subnet.
func EnableHostIPForwarding() error {
	// 1. Enable forwarding on NatBypass adapter
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "interface", "NatBypass", "forwarding=enabled")

	// 2. Enable IP routing in Windows Registry & NetNat & enable forwarding on all active network adapters
	psScript := `
		Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1 -ErrorAction SilentlyContinue
		Set-Service -Name RemoteAccess -StartupType Automatic -ErrorAction SilentlyContinue
		Start-Service -Name RemoteAccess -ErrorAction SilentlyContinue
		netsh interface ipv4 set interface "NatBypass" forwarding=enabled
		Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
			netsh interface ipv4 set interface $_.InterfaceAlias forwarding=enabled
		}
		if (-not (Get-NetNat -Name 'NatBypassNAT' -ErrorAction SilentlyContinue)) {
			New-NetNat -Name 'NatBypassNAT' -InternalIPInterfaceAddressPrefix '100.64.200.0/24' -ErrorAction SilentlyContinue
		}
	`
	_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)

	// 3. Add Windows firewall rules for interface forwarding
	_ = runRouteCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=NatBypass Forward In", "dir=in", "action=allow", "interface=NatBypass")
	_ = runRouteCmd("netsh", "advfirewall", "firewall", "add", "rule", "name=NatBypass Forward Out", "dir=out", "action=allow", "interface=NatBypass")

	return nil
}

// DisableHostIPForwarding disables IP forwarding and cleans up NetNat rule.
func DisableHostIPForwarding() error {
	_ = runRouteCmd("netsh", "interface", "ipv4", "set", "interface", "NatBypass", "forwarding=disabled")
	psScript := `Remove-NetNat -Name 'NatBypassNAT' -Confirm:$false -ErrorAction SilentlyContinue`
	_ = runRouteCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	return nil
}

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1) via gatewayVIP.
func EnableExitNodeRouting(gatewayVIP string) error {
	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	if err := runRouteCmd("route", "add", "0.0.0.0", "mask", "128.0.0.0", gatewayVIP, "metric", "5"); err != nil {
		return fmt.Errorf("failed to add default route 0.0.0.0/1 via %s: %w", gatewayVIP, err)
	}
	if err := runRouteCmd("route", "add", "128.0.0.0", "mask", "128.0.0.0", gatewayVIP, "metric", "5"); err != nil {
		_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0", gatewayVIP)
		return fmt.Errorf("failed to add default route 128.0.0.0/1 via %s: %w", gatewayVIP, err)
	}
	return nil
}

// DisableExitNodeRouting removes the default gateway /1 routes via gatewayVIP.
func DisableExitNodeRouting(gatewayVIP string) error {
	var errs []string
	if gatewayVIP != "" {
		_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0", gatewayVIP)
		_ = runRouteCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0", gatewayVIP)
	} else {
		_ = runRouteCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
		_ = runRouteCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
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

// EnableMSSClamping is a cross-platform stub on Windows.
func EnableMSSClamping(tunInterface string, mtu int) error {
	return nil
}

// DisableMSSClamping is a cross-platform stub on Windows.
func DisableMSSClamping(tunInterface string) error {
	return nil
}
