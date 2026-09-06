package network

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v2"
	"github.com/rs/zerolog/log"
)

// EgressInfo represents information about the primary physical network interface
// used by the host operating system to route traffic out to the public Internet.
type EgressInfo struct {
	InterfaceName  string        `json:"interface_name"`  // e.g. "Wi-Fi", "eth0", "wlan0", "rmnet0"
	InterfaceAlias string        `json:"interface_alias"` // Human-readable friendly name
	InterfaceIndex int           `json:"interface_index"` // OS interface index (ifIndex)
	LocalIP        net.IP        `json:"local_ip"`        // Primary egress local IPv4 address
	GatewayIP      net.IP        `json:"gateway_ip"`      // Physical default gateway IPv4 address
	MTU            int           `json:"mtu"`             // Adapter MTU
	HardwareType   string        `json:"hardware_type"`   // "Wi-Fi", "Cellular", "Ethernet", "Network Adapter"
	InternetLive   bool          `json:"internet_live"`   // True if 1-RTT canary STUN check succeeded
	CanaryLatency  time.Duration `json:"canary_latency"`  // Round-trip latency to canary STUN server
	Signature      string        `json:"signature"`       // Hash/key string to detect network changes
}

// Canary STUN servers used for fast 1-RTT reachability testing.
var canarySTUNServers = []string{
	"stun.sipnet.ru:3478",
	"stun.cloudflare.com:3478",
	"stun.miwifi.com:3478",
}

// DetectEgress determines the active physical Internet interface, default gateway, and reachability.
// Uses Zero-RTT OS routing queries (0 packets over wire) followed by a 1-RTT STUN canary test.
func DetectEgress(ctx context.Context) (*EgressInfo, error) {
	info := &EgressInfo{
		HardwareType: "Network Adapter",
	}

	// 1. Zero-RTT Kernel Route Query: asks kernel routing table which local IP would reach a public canary
	targets := []string{"1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53"}
	var localIP net.IP

	for _, target := range targets {
		conn, err := net.Dial("udp4", target)
		if err == nil {
			if lAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && lAddr != nil && lAddr.IP != nil {
				ip4 := lAddr.IP.To4()
				if ip4 != nil && !ip4.IsLoopback() && !ip4.IsUnspecified() {
					localIP = ip4
					_ = conn.Close()
					break
				}
			}
			_ = conn.Close()
		}
	}

	if localIP == nil {
		// Fallback to GetLocalLANIP
		lanIP := GetLocalLANIP()
		if lanIP != "" {
			localIP = net.ParseIP(lanIP).To4()
		}
	}

	info.LocalIP = localIP

	// 2. Identify the network interface that holds localIP
	ifaces, err := net.Interfaces()
	if err == nil && localIP != nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			nameLower := strings.ToLower(iface.Name)
			// Skip virtual mesh and container interfaces
			if isVirtualInterface(nameLower) {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && ip.Equal(localIP) {
					info.InterfaceName = iface.Name
					info.InterfaceAlias = iface.Name
					info.InterfaceIndex = iface.Index
					info.MTU = iface.MTU
					info.HardwareType = classifyHardwareType(iface.Name)
					break
				}
			}
			if info.InterfaceName != "" {
				break
			}
		}
	}

	// 3. Find Default Gateway IP
	info.GatewayIP = detectDefaultGateway(info.InterfaceName)

	// Build a unique signature for this network attachment
	info.Signature = fmt.Sprintf("%d:%s:%s", info.InterfaceIndex, ipToString(info.LocalIP), ipToString(info.GatewayIP))

	// 4. 1-RTT Canary STUN Probe to confirm bidirectional Internet access
	canaryCtx, cancel := context.WithTimeout(ctx, 850*time.Millisecond)
	defer cancel()

	start := time.Now()
	if checkInternetCanary(canaryCtx) {
		info.InternetLive = true
		info.CanaryLatency = time.Since(start)
	}

	return info, nil
}

func ipToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func isVirtualInterface(name string) bool {
	// Only filter our own tunnel/VPN adapters so we never mistake the VPN tunnel for the physical network
	return strings.HasPrefix(name, "nb") ||
		strings.Contains(name, "natbypass") ||
		strings.Contains(name, "wintun") ||
		strings.HasPrefix(name, "tun") ||
		strings.HasPrefix(name, "tap") ||
		strings.HasPrefix(name, "nwg") ||
		strings.HasPrefix(name, "wg")
}

func classifyHardwareType(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "wi-fi") || strings.Contains(n, "wlan") || strings.Contains(n, "wireless") || strings.Contains(n, "802.11") || strings.Contains(n, "ra0") || strings.Contains(n, "ath") || strings.Contains(n, "беспроводн"):
		return "Wi-Fi"
	case strings.Contains(n, "rmnet") || strings.Contains(n, "cellular") || strings.Contains(n, "pdp") || strings.Contains(n, "lte") || strings.Contains(n, "mobile") || strings.Contains(n, "ccmni") || strings.Contains(n, "wwan") || strings.Contains(n, "мобильн"):
		return "Cellular"
	case strings.Contains(n, "eth") || strings.Contains(n, "ethernet") || strings.Contains(n, "vethernet") || strings.Contains(n, "enp") || strings.Contains(n, "eno") || strings.Contains(n, "lan") || strings.Contains(n, "wan") || strings.Contains(n, "локальн"):
		return "Ethernet"
	case strings.Contains(n, "bluetooth"):
		return "Bluetooth"
	default:
		return "Network Adapter"
	}
}

// detectDefaultGateway returns the primary gateway IP for the active default route.
func detectDefaultGateway(ifaceName string) net.IP {
	if runtime.GOOS == "linux" {
		if gw := getGatewayFromProcNetRoute(ifaceName); gw != nil {
			return gw
		}
		// Fallback via ip route command
		cmd := exec.Command("sh", "-c", "ip route show default 2>/dev/null | grep -v 'nb0' | head -n1 | awk '{print $3}'")
		if out, err := cmd.Output(); err == nil {
			str := strings.TrimSpace(string(out))
			if ip := net.ParseIP(str); ip != nil && !ip.IsUnspecified() {
				return ip.To4()
			}
		}
	} else if runtime.GOOS == "windows" {
		return getWindowsDefaultGateway()
	}
	return nil
}

// getGatewayFromProcNetRoute reads /proc/net/route in pure Go without forking processes.
func getGatewayFromProcNetRoute(ifaceName string) net.IP {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			if fields[1] == "00000000" { // Destination 0.0.0.0
				if ifaceName == "" || fields[0] == ifaceName {
					gwHex := fields[2]
					if len(gwHex) == 8 {
						d, err := hex.DecodeString(gwHex)
						if err == nil && len(d) == 4 {
							// /proc/net/route IP is in little-endian byte order
							ip := net.IPv4(d[3], d[2], d[1], d[0]).To4()
							if ip != nil && !ip.IsUnspecified() {
								return ip
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// checkInternetCanary performs a 1-RTT STUN binding request to verify active bidirectional Internet.
func checkInternetCanary(ctx context.Context) bool {
	done := make(chan bool, 1)

	go func() {
		conn, err := net.ListenUDP("udp4", nil)
		if err != nil {
			done <- false
			return
		}
		defer conn.Close()

		msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

		// Send probe to top canary servers in parallel
		for _, srv := range canarySTUNServers {
			go func(server string) {
				rAddr, err := net.ResolveUDPAddr("udp4", server)
				if err == nil && rAddr != nil {
					_, _ = conn.WriteToUDP(msg.Raw, rAddr)
				}
			}(srv)
		}

		_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		buf := make([]byte, 1024)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			if n > 0 && stun.IsMessage(buf[:n]) {
				done <- true
				return
			}
		}
		done <- false
	}()

	select {
	case ok := <-done:
		return ok
	case <-ctx.Done():
		return false
	}
}

// NetworkChangeCallback is invoked when a network interface change or roaming event occurs.
type NetworkChangeCallback func(oldInfo, newInfo *EgressInfo)

// NetworkWatchdog continuously monitors the system's primary egress interface for changes.
type NetworkWatchdog struct {
	ctx      context.Context
	cancel   context.CancelFunc
	current  *EgressInfo
	mu       sync.RWMutex
	onChange NetworkChangeCallback
	interval time.Duration
}

// NewNetworkWatchdog creates and starts a background network watchdog.
func NewNetworkWatchdog(ctx context.Context, interval time.Duration, onChange NetworkChangeCallback) *NetworkWatchdog {
	if interval < 1*time.Second {
		interval = 2 * time.Second
	}
	wCtx, cancel := context.WithCancel(ctx)

	w := &NetworkWatchdog{
		ctx:      wCtx,
		cancel:   cancel,
		onChange: onChange,
		interval: interval,
	}

	// Initial detection
	initial, _ := DetectEgress(wCtx)
	w.current = initial

	go w.run()
	return w
}

func (w *NetworkWatchdog) run() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.check()
		}
	}
}

func (w *NetworkWatchdog) check() {
	ctx, cancel := context.WithTimeout(w.ctx, 1500*time.Millisecond)
	newInfo, err := DetectEgress(ctx)
	cancel()
	if err != nil || newInfo == nil || newInfo.LocalIP == nil {
		return
	}

	w.mu.Lock()
	oldInfo := w.current
	if oldInfo == nil {
		w.current = newInfo
		w.mu.Unlock()
		return
	}

	// Compare signatures: has ifIndex, LocalIP, or GatewayIP changed?
	hasChanged := oldInfo.Signature != newInfo.Signature
	if hasChanged {
		w.current = newInfo
		w.mu.Unlock()

		log.Warn().
			Str("old_iface", oldInfo.InterfaceName).
			Str("old_ip", ipToString(oldInfo.LocalIP)).
			Str("new_iface", newInfo.InterfaceName).
			Str("new_ip", ipToString(newInfo.LocalIP)).
			Str("new_gateway", ipToString(newInfo.GatewayIP)).
			Str("hardware", newInfo.HardwareType).
			Msg("🔄 Network interface change detected by Watchdog")

		if w.onChange != nil {
			w.onChange(oldInfo, newInfo)
		}
	} else {
		w.mu.Unlock()
	}
}

// Stop terminates the watchdog loop.
func (w *NetworkWatchdog) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
}

// GetCurrent returns the most recently observed EgressInfo.
func (w *NetworkWatchdog) GetCurrent() *EgressInfo {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.current
}
