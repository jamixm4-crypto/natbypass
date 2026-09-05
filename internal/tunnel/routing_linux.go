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
	ensureIptablesRule(ipt, "", "FORWARD", "-i", "nb0", "-j", "ACCEPT")
	ensureIptablesRule(ipt, "", "FORWARD", "-o", "nb0", "-j", "ACCEPT")
	ensureIptablesRule(ipt, "", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	// Keenetic NDM chains if present
	if isKeeneticDevice() {
		ensureIptablesRule(ipt, "", "_NDM_FORWARD", "-i", "nb0", "-j", "ACCEPT")
		ensureIptablesRule(ipt, "", "_NDM_FORWARD", "-o", "nb0", "-j", "ACCEPT")
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
				cmd := exec.Command(ipt, "-w", "2", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "!", "-o", "nb0", "-j", "MASQUERADE")
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

	return nil
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
