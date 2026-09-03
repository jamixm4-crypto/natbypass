//go:build linux

package tunnel

import (
	"fmt"
	"os/exec"
	"strings"

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

// EnableHostIPForwardingSubnet enables kernel IPv4 forwarding and adds iptables NAT masquerading for mesh subnet.
func EnableHostIPForwardingSubnet(subnet string) error {
	_ = runLinuxCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	if subnet == "" {
		subnet = "10.11.12.0/24"
	}
	cleanSubnet := subnet
	if !strings.Contains(cleanSubnet, "/") {
		parts := strings.Split(cleanSubnet, ".")
		if len(parts) >= 3 {
			cleanSubnet = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		} else {
			cleanSubnet = "10.11.12.0/24"
		}
	}
	iptablesPaths := []string{"iptables", "/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables"}
	for _, ipt := range iptablesPaths {
		_ = runLinuxCmd(ipt, "-t", "nat", "-D", "POSTROUTING", "-s", cleanSubnet, "-j", "MASQUERADE")
		_ = runLinuxCmd(ipt, "-t", "nat", "-A", "POSTROUTING", "-s", cleanSubnet, "-j", "MASQUERADE")
		_ = runLinuxCmd(ipt, "-t", "nat", "-D", "POSTROUTING", "-s", "10.0.0.0/8", "-j", "MASQUERADE")
		_ = runLinuxCmd(ipt, "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/8", "-j", "MASQUERADE")
		_ = runLinuxCmd(ipt, "-t", "nat", "-D", "POSTROUTING", "-s", "100.64.0.0/10", "-j", "MASQUERADE")
		_ = runLinuxCmd(ipt, "-t", "nat", "-A", "POSTROUTING", "-s", "100.64.0.0/10", "-j", "MASQUERADE")

		// Forwarding rules for nb0
		_ = runLinuxCmd(ipt, "-C", "FORWARD", "-i", "nb0", "-j", "ACCEPT")
		_ = runLinuxCmd(ipt, "-I", "FORWARD", "1", "-i", "nb0", "-j", "ACCEPT")
		_ = runLinuxCmd(ipt, "-C", "FORWARD", "-o", "nb0", "-j", "ACCEPT")
		_ = runLinuxCmd(ipt, "-I", "FORWARD", "1", "-o", "nb0", "-j", "ACCEPT")
		_ = runLinuxCmd(ipt, "-I", "_NDM_FORWARD", "1", "-i", "nb0", "-j", "ACCEPT")
		_ = runLinuxCmd(ipt, "-I", "_NDM_FORWARD", "1", "-o", "nb0", "-j", "ACCEPT")
	}
	return nil
}

// EnableHostIPForwarding enables kernel IPv4 forwarding and adds iptables NAT masquerading for default mesh subnet.
func EnableHostIPForwarding() error {
	return EnableHostIPForwardingSubnet("100.64.200.0/24")
}

// DisableHostIPForwarding removes iptables NAT masquerading rule.
func DisableHostIPForwarding() error {
	iptablesPaths := []string{"iptables", "/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables"}
	for _, ipt := range iptablesPaths {
		_ = runLinuxCmd(ipt, "-t", "nat", "-D", "POSTROUTING", "-s", "100.64.200.0/24", "-j", "MASQUERADE")
	}
	return nil
}

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1).
func EnableExitNodeRouting(gatewayVIP string) error {
	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])
	err1 := runLinuxCmd("ip", "route", "add", "0.0.0.0/1", "via", cleanVIP, "dev", "nb0", "onlink")
	if err1 != nil {
		_ = runLinuxCmd("ip", "route", "add", "0.0.0.0/1", "via", cleanVIP)
	}
	err2 := runLinuxCmd("ip", "route", "add", "128.0.0.0/1", "via", cleanVIP, "dev", "nb0", "onlink")
	if err2 != nil {
		_ = runLinuxCmd("ip", "route", "add", "128.0.0.0/1", "via", cleanVIP)
	}
	return nil
}

// DisableExitNodeRouting removes def1 routes.
func DisableExitNodeRouting(gatewayVIP string) error {
	if gatewayVIP != "" {
		cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])
		_ = runLinuxCmd("ip", "route", "del", "0.0.0.0/1", "via", cleanVIP)
		_ = runLinuxCmd("ip", "route", "del", "128.0.0.0/1", "via", cleanVIP)
	}
	_ = runLinuxCmd("ip", "route", "del", "0.0.0.0/1")
	_ = runLinuxCmd("ip", "route", "del", "128.0.0.0/1")
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
