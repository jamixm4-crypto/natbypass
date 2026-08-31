//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)


const (
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
	TUNSETIFF = 0x400454ca
)

type ifreq struct {
	ifrName  [16]byte
	ifrFlags uint16
	_        [22]byte
}

// Device представляет созданный виртуальный сетевой интерфейс Linux (TUN)
type Device struct {
	AdapterName string
	VirtualIP   string
	file        *os.File
	isClosed    int32
	mu          sync.Mutex
}

// CreateAdapter создает виртуальный TUN интерфейс nb0 в Linux / Keenetic / OpenWrt
func CreateAdapter(adapterName, virtualIP string) (*Device, error) {
	if adapterName == "" {
		adapterName = "nb0"
	}

	// 1. Поиск и открытие /dev/net/tun или /dev/tun
	var file *os.File
	var err error
	tunPaths := []string{"/dev/net/tun", "/dev/tun", "/opt/dev/net/tun"}
	for _, p := range tunPaths {
		file, err = os.OpenFile(p, os.O_RDWR, 0)
		if err == nil {
			break
		}
	}

	if file == nil {
		// Попытка загрузить модуль tun и создать ноду устройства
		_ = exec.Command("modprobe", "tun").Run()
		_ = exec.Command("insmod", "/lib/modules/tun.ko").Run()
		_ = exec.Command("mkdir", "-p", "/dev/net").Run()
		_ = exec.Command("mknod", "/dev/net/tun", "c", "10", "200").Run()

		for _, p := range tunPaths {
			file, err = os.OpenFile(p, os.O_RDWR, 0)
			if err == nil {
				break
			}
		}
	}

	if file == nil {
		return nil, fmt.Errorf("не удалось открыть /dev/net/tun: %w (требуется modprobe tun или права root)", err)
	}

	// 2. Регистрация TUN устройства через ioctl с поддержкой x86_64, arm64, mips, mipsle
	var req ifreq
	copy(req.ifrName[:], adapterName)
	req.ifrFlags = IFF_TUN | IFF_NO_PI

	tunIoctls := []uintptr{
		0x400454ca, // Standard Linux (x86_64, arm, arm64)
		0x800454ca, // Linux MIPS / MIPSLE (_IOW('T', 202, int) on MIPS where _IOC_WRITE has bit 31 set)
		0x000054ca, // Raw TUNSETIFF constant (0x54ca)
	}

	var errno syscall.Errno
	ioctlSuccess := false
	for _, ioctlCmd := range tunIoctls {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), ioctlCmd, uintptr(unsafe.Pointer(&req)))
		if errno == 0 {
			ioctlSuccess = true
			break
		}
	}

	if !ioctlSuccess {
		file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF error: %v", errno)
	}


	dev := &Device{
		AdapterName: adapterName,
		VirtualIP:   virtualIP,
		file:        file,
	}

	// 3. Назначение IP-адреса и включение интерфейса
	if virtualIP != "" {
		_ = dev.SetVirtualIP(virtualIP)
	}

	// 4. Включение маршрутизации ядра Linux (IP Forwarding)
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	return dev, nil
}

func (d *Device) ReadPacket() ([]byte, error) {
	if atomic.LoadInt32(&d.isClosed) == 1 {
		return nil, fmt.Errorf("интерфейс закрыт")
	}
	buf := make([]byte, 2048)
	n, err := d.file.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (d *Device) WritePacket(packet []byte) error {
	if atomic.LoadInt32(&d.isClosed) == 1 {
		return fmt.Errorf("интерфейс закрыт")
	}
	_, err := d.file.Write(packet)
	return err
}

func (d *Device) SetVirtualIP(virtualIP string) error {
	d.mu.Lock()
	d.VirtualIP = virtualIP
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cleanVIP := strings.TrimSpace(strings.Split(virtualIP, "/")[0])

	// 1. Попытка через утилиту ip
	_ = exec.CommandContext(ctx, "ip", "addr", "flush", "dev", d.AdapterName).Run()
	cmd := exec.CommandContext(ctx, "ip", "addr", "add", cleanVIP+"/24", "dev", d.AdapterName)
	if err := cmd.Run(); err != nil {
		// 2. Fallback через ifconfig
		_ = exec.CommandContext(ctx, "ifconfig", d.AdapterName, cleanVIP, "netmask", "255.255.255.0", "up").Run()
	} else {
		_ = exec.CommandContext(ctx, "ip", "link", "set", d.AdapterName, "up").Run()
	}

	// 3. Установка MTU 1420 и MSS Clamping
	_ = exec.CommandContext(ctx, "ip", "link", "set", "dev", d.AdapterName, "mtu", "1420").Run()
	_ = exec.CommandContext(ctx, "ifconfig", d.AdapterName, "mtu", "1420").Run()
	_ = EnableMSSClamping(d.AdapterName, 1420)

	// 4. Маршрутизация подсети через адаптер
	prefix := "100.64.200"
	parts := strings.Split(cleanVIP, ".")
	if len(parts) >= 3 {
		prefix = fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	}
	_ = exec.CommandContext(ctx, "ip", "route", "add", prefix+".0/24", "dev", d.AdapterName).Run()
	_ = exec.CommandContext(ctx, "ip", "route", "add", "100.64.200.0/24", "dev", d.AdapterName).Run()

	// 5. Прямая запись в /proc/sys/net/ipv4 (100% совместимо со всеми Linux/Keenetic даже без утилиты sysctl)
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("0\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", d.AdapterName), []byte("0\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/accept_local", []byte("1\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("0\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", []byte("0\n"), 0644)

	// Также дублируем через sysctl если доступен
	sysctlPaths := []string{"sysctl", "/sbin/sysctl", "/usr/sbin/sysctl", "/opt/sbin/sysctl"}
	for _, sc := range sysctlPaths {
		_ = exec.CommandContext(ctx, sc, "-w", "net.ipv4.ip_forward=1").Run()
		_ = exec.CommandContext(ctx, sc, "-w", "net.ipv4.conf.all.rp_filter=0").Run()
		_ = exec.CommandContext(ctx, sc, "-w", "net.ipv4.conf.default.rp_filter=0").Run()
		_ = exec.CommandContext(ctx, sc, "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", d.AdapterName)).Run()
		_ = exec.CommandContext(ctx, sc, "-w", "net.ipv4.icmp_echo_ignore_all=0").Run()
	}

	// 6. Разрешение входящего и транзитного трафика в iptables (Keenetic NDM / OpenWrt / Linux / Entware)
	applyFirewallRules := func() {
		iptablesPaths := []string{"iptables", "/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables"}
		for _, ipt := range iptablesPaths {
			_ = exec.Command(ipt, "-I", "INPUT", "1", "-i", d.AdapterName, "-j", "ACCEPT").Run()
			_ = exec.Command(ipt, "-I", "INPUT", "1", "-p", "icmp", "-j", "ACCEPT").Run()
			_ = exec.Command(ipt, "-I", "INPUT", "1", "-p", "udp", "--dport", "47832", "-j", "ACCEPT").Run()
			_ = exec.Command(ipt, "-I", "FORWARD", "1", "-i", d.AdapterName, "-j", "ACCEPT").Run()
			_ = exec.Command(ipt, "-I", "FORWARD", "1", "-o", d.AdapterName, "-j", "ACCEPT").Run()

			// Специальные цепочки KeeneticOS (NDM)
			_ = exec.Command(ipt, "-I", "_NDM_INPUT", "1", "-i", d.AdapterName, "-j", "ACCEPT").Run()
			_ = exec.Command(ipt, "-I", "_NDM_INPUT", "1", "-p", "icmp", "-j", "ACCEPT").Run()
			_ = exec.Command(ipt, "-I", "_NDM_INPUT", "1", "-p", "udp", "--dport", "47832", "-j", "ACCEPT").Run()
			_ = exec.Command(ipt, "_NDM_FORWARD", "1", "-i", d.AdapterName, "-j", "ACCEPT").Run()
		}
	}
	applyFirewallRules()

	// Фоновый сторожевой таймер: Keenetic ndm периодически пересоздает цепочки правил при смене сети.
	// Поддерживаем правила в актуальном состоянии каждые 8 секунд.
	go func() {
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()
		for {
			if atomic.LoadInt32(&d.isClosed) == 1 {
				return
			}
			<-ticker.C
			applyFirewallRules()
		}
	}()

	return nil

}

// SetMTU динамически обновляет MTU на интерфейсе Linux/Keenetic
func (d *Device) SetMTU(mtu int) error {
	if mtu < 1280 || mtu > 1500 {
		return fmt.Errorf("недопустимый MTU: %d (допустимо 1280..1500)", mtu)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "ip", "link", "set", "dev", d.AdapterName, "mtu", fmt.Sprintf("%d", mtu)).Run()
	_ = exec.CommandContext(ctx, "ifconfig", d.AdapterName, "mtu", fmt.Sprintf("%d", mtu)).Run()
	return nil
}

func (d *Device) Close() error {

	if atomic.CompareAndSwapInt32(&d.isClosed, 0, 1) {
		if d.file != nil {
			return d.file.Close()
		}
	}
	return nil
}