//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"net"
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
		_ = runLinuxCmd(ipt, "-t", "nat", "-D", "POSTROUTING", "-s", cleanSubnet, "!", "-o", "nb0", "-j", "MASQUERADE")
		_ = runLinuxCmd(ipt, "-t", "nat", "-A", "POSTROUTING", "-s", cleanSubnet, "!", "-o", "nb0", "-j", "MASQUERADE")
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

		// Bi-directional TCP MSS Clamping to prevent MTU Blackhole on 4G/PPPoE
		_ = runLinuxCmd(ipt, "-t", "mangle", "-D", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
		_ = runLinuxCmd(ipt, "-t", "mangle", "-I", "FORWARD", "1", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	}

	// Keenetic / OpenWrt: ensure forwarded traffic from mesh subnet can lookup default WAN table
	_ = runLinuxCmd("ip", "rule", "del", "from", cleanSubnet, "lookup", "default")
	_ = runLinuxCmd("ip", "rule", "add", "from", cleanSubnet, "lookup", "default", "priority", "60")

	StartLinuxNATWatchdog(context.Background(), cleanSubnet)
	return nil
}

var (
	natWatchdogCancel context.CancelFunc
	natWatchdogMu     sync.Mutex
)

// StartLinuxNATWatchdog запускает фоновый сторож целостности правил iptables на Keenetic/Linux (каждые 25 сек).
func StartLinuxNATWatchdog(ctx context.Context, subnet string) {
	natWatchdogMu.Lock()
	if natWatchdogCancel != nil {
		natWatchdogCancel()
	}
	wCtx, cancel := context.WithCancel(ctx)
	natWatchdogCancel = cancel
	natWatchdogMu.Unlock()

	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-wCtx.Done():
				return
			case <-ticker.C:
				cmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
				if err := cmd.Run(); err != nil {
					// Правило исчезло (сброс цепочек NDM при смене WAN) -> восстанавливаем
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
	lastBypassedEndpointIP string
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

func extractHostIP(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	host = strings.TrimSpace(host)
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() {
		return host
	}
	return ""
}

// EnableExitNodeRouting sets up default gateway routing using WireGuard def1 pattern (0.0.0.0/1 and 128.0.0.0/1),
// with automatic routing-loop prevention by adding a bypass route to the remote endpoint.
func EnableExitNodeRouting(gatewayVIP string, remoteEndpoints ...string) error {
	if gatewayVIP == "" {
		return fmt.Errorf("gateway VIP is required")
	}
	cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])

	// 1. Bypass remote endpoint IP via physical default gateway to prevent routing loop
	for _, ep := range remoteEndpoints {
		if hostIP := extractHostIP(ep); hostIP != "" {
			if physGW := getPhysicalGatewayLinux(); physGW != "" {
				_ = runLinuxCmd("ip", "route", "add", hostIP+"/32", "via", physGW)
				lastBypassedEndpointIP = hostIP
				break
			}
		}
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
	return nil
}

// DisableExitNodeRouting removes def1 routes and bypass route.
func DisableExitNodeRouting(gatewayVIP string) error {
	if gatewayVIP != "" {
		cleanVIP := strings.TrimSpace(strings.Split(gatewayVIP, "/")[0])
		_ = runLinuxCmd("ip", "route", "del", "0.0.0.0/1", "via", cleanVIP)
		_ = runLinuxCmd("ip", "route", "del", "128.0.0.0/1", "via", cleanVIP)
	}
	_ = runLinuxCmd("ip", "route", "del", "0.0.0.0/1")
	_ = runLinuxCmd("ip", "route", "del", "128.0.0.0/1")

	if lastBypassedEndpointIP != "" {
		_ = runLinuxCmd("ip", "route", "del", lastBypassedEndpointIP+"/32")
		lastBypassedEndpointIP = ""
	}
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
