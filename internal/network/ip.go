package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var defaultIPAPIs = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
	"https://checkip.amazonaws.com",
	"https://ipinfo.io/ip",
	"https://ipecho.net/plain",
}

type Discoverer struct {
	apis   []string
	client *http.Client

	mu         sync.Mutex
	cachedIP   net.IP
	cachedTime time.Time
}

func NewDiscoverer(apis []string, timeout time.Duration) *Discoverer {
	if len(apis) == 0 {
		apis = defaultIPAPIs
	}

	return &Discoverer{
		apis: apis,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (d *Discoverer) GetPublicIP(ctx context.Context) (net.IP, error) {
	var lastErr error

	for _, api := range d.apis {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := d.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		ipStr := strings.TrimSpace(string(body))
		ip := net.ParseIP(ipStr)
		if ip != nil {
			return ip, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("failed to discover public IP")
}

func (d *Discoverer) GetPublicIPCached(ctx context.Context, maxAge time.Duration) (net.IP, error) {
	d.mu.Lock()
	if d.cachedIP != nil && time.Since(d.cachedTime) < maxAge {
		ip := d.cachedIP
		d.mu.Unlock()
		return ip, nil
	}
	d.mu.Unlock()

	ip, err := d.GetPublicIP(ctx)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.cachedIP = ip
	d.cachedTime = time.Now()
	d.mu.Unlock()

	return ip, nil
}

// GetLocalSubnets iterates interface addresses, finds active IPv4 addresses on
// non-loopback and non-Wintun interfaces, calculates each network address (e.g. 192.168.1.0/24),
// and returns a unique list of local subnets.
func GetLocalSubnets() []string {
	var subnets []string
	seen := make(map[string]bool)

	// Check interfaces to filter by flags (Up, non-loopback) and name (non-Wintun/virtual)
	ifaces, err := net.Interfaces()
	if err == nil && len(ifaces) > 0 {
		for _, iface := range ifaces {
			// Skip inactive interfaces and loopback interfaces
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			name := strings.ToLower(iface.Name)
			// Skip Wintun, WireGuard, TUN/TAP, or NatBypass virtual adapters
			if strings.Contains(name, "wintun") ||
				strings.Contains(name, "natbypass") ||
				strings.Contains(name, "wireguard") ||
				strings.Contains(name, "wg0") ||
				strings.Contains(name, "tap") ||
				strings.Contains(name, "tun") ||
				strings.Contains(name, "loopback") {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				subnet := extractIPv4Subnet(addr)
				if subnet != "" && !seen[subnet] {
					seen[subnet] = true
					subnets = append(subnets, subnet)
				}
			}
		}
		if len(subnets) > 0 {
			return subnets
		}
	}

	// Fallback to net.InterfaceAddrs() directly
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return subnets
	}

	for _, addr := range addrs {
		subnet := extractIPv4Subnet(addr)
		if subnet != "" && !seen[subnet] {
			seen[subnet] = true
			subnets = append(subnets, subnet)
		}
	}

	return subnets
}

// extractIPv4Subnet parses an address and calculates the network CIDR (e.g. "192.168.1.0/24").
func extractIPv4Subnet(addr net.Addr) string {
	ipNet, ok := addr.(*net.IPNet)
	if !ok {
		var err error
		_, ipNet, err = net.ParseCIDR(addr.String())
		if err != nil {
			return ""
		}
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() || ip4.IsLinkLocalUnicast() {
		return ""
	}

	// Filter out typical virtual mesh 10.200.x.x addresses
	if strings.HasPrefix(ip4.String(), "10.200.") {
		return ""
	}

	mask := ipNet.Mask
	if len(mask) == 16 {
		mask = mask[12:16]
	}
	if len(mask) != 4 {
		return ""
	}

	networkIP := ip4.Mask(mask)
	ones, _ := ipNet.Mask.Size()
	if ones <= 0 || ones > 32 {
		return ""
	}

	return fmt.Sprintf("%s/%d", networkIP.String(), ones)
}

// GetLocalLANIP возвращает основной локальный IPv4-адрес устройства
func GetLocalLANIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				ipStr := ip4.String()
				if strings.HasPrefix(ipStr, "10.200.") {
					continue
				}
				if strings.HasPrefix(ipStr, "192.168.") || strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "172.") {
					return ipStr
				}
			}
		}
	}
	return ""
}

var defaultIPv6APIs = []string{
	"https://api6.ipify.org",
	"https://ifconfig.co/ip",
	"https://icanhazip.com",
	"https://ident.me",
}

// GetPublicIPv6 возвращает глобальный IPv6-адрес устройства (без NAT, 100% прямой P2P на мобильных сетях LTE/5G)
func GetPublicIPv6(ctx context.Context) string {
	// Сначала проверяем глобальные одноадресные IPv6-адреса на интерфейсах (без обращения к внешним API)
	if ip := GetLocalIPv6(); ip != "" {
		return ip
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for _, api := range defaultIPv6APIs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ipStr := strings.TrimSpace(string(body))
		parsed := net.ParseIP(ipStr)
		if parsed != nil && parsed.To4() == nil && !parsed.IsLoopback() && !parsed.IsLinkLocalUnicast() && !parsed.IsPrivate() {
			return parsed.String()
		}
	}
	return ""
}

// GetLocalIPv6 возвращает глобальный IPv6-адрес из сетевых адаптеров устройства
func GetLocalIPv6() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			ip := ipNet.IP
			if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsPrivate() {
				return ip.String()
			}
		}
	}
	return ""
}
