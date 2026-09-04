//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
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
	AdapterName  string
	VirtualIP    string
	MTU          int
	file         *os.File
	isClosed     int32
	mu           sync.Mutex
	stopCh       chan struct{}
	stopOnce     sync.Once
	watchdogOnce sync.Once
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

	// Ensure pure blocking I/O so file.Read() blocks in kernel queue without spinning CPU on Linux/MIPS
	_ = syscall.SetNonblock(int(file.Fd()), false)

	dev := &Device{
		AdapterName: adapterName,
		VirtualIP:   virtualIP,
		file:        file,
		stopCh:      make(chan struct{}),
	}


	// 3. Назначение IP-адреса и включение интерфейса
	if virtualIP != "" {
		_ = dev.SetVirtualIP(virtualIP)
	}

	// 4. Включение маршрутизации ядра Linux (IP Forwarding)
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	return dev, nil
}

var packetPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 65536)
		return &buf
	},
}

func (d *Device) ReadPacket() ([]byte, error) {
	if atomic.LoadInt32(&d.isClosed) == 1 {
		return nil, fmt.Errorf("интерфейс закрыт")
	}
	bufPtr := packetPool.Get().(*[]byte)
	buf := *bufPtr
	n, err := d.file.Read(buf)
	if err != nil {
		packetPool.Put(bufPtr)
		return nil, err
	}
	res := make([]byte, n)
	copy(res, buf[:n])
	packetPool.Put(bufPtr)
	return res, nil
}

func (d *Device) ReadPacketPooled() ([]byte, func(), error) {
	if atomic.LoadInt32(&d.isClosed) == 1 {
		return nil, nil, fmt.Errorf("интерфейс закрыт")
	}
	bufPtr := packetPool.Get().(*[]byte)
	buf := *bufPtr
	n, err := d.file.Read(buf)
	if err != nil {
		packetPool.Put(bufPtr)
		return nil, nil, err
	}
	release := func() {
		packetPool.Put(bufPtr)
	}
	return buf[:n], release, nil
}

func (d *Device) WritePacket(packet []byte) error {
	if atomic.LoadInt32(&d.isClosed) == 1 {
		return fmt.Errorf("интерфейс закрыт")
	}
	_, err := d.file.Write(packet)
	return err
}

func findIPBinary() string {
	for _, p := range []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip", "ip"} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	return "ip"
}

func (d *Device) SetVirtualIP(virtualIP string) error {
	d.mu.Lock()
	d.VirtualIP = virtualIP
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cleanVIP := strings.TrimSpace(strings.Split(virtualIP, "/")[0])
	if cleanVIP == "" {
		return nil
	}

	ipBin := findIPBinary()

	// 1. Установка MTU
	mtu := 1420
	d.mu.Lock()
	if d.MTU > 0 {
		mtu = d.MTU
	}
	d.mu.Unlock()
	mtuStr := strconv.Itoa(mtu)

	// 2. ГАРАНТИРОВАННО поднимаем интерфейс первым делом (LINK UP + MTU)
	_ = exec.CommandContext(ctx, ipBin, "link", "set", "dev", d.AdapterName, "mtu", mtuStr).Run()
	_ = exec.CommandContext(ctx, ipBin, "link", "set", d.AdapterName, "up").Run()

	// 3. Очистка старых IP-адресов на интерфейсе
	_ = exec.CommandContext(ctx, ipBin, "addr", "flush", "dev", d.AdapterName).Run()

	// 4. Многоступенчатое назначение IP-адреса на интерфейс
	addrAssigned := false

	// Шаг 4a: Стандартный /24 CIDR
	if err := exec.CommandContext(ctx, ipBin, "addr", "add", cleanVIP+"/24", "dev", d.AdapterName).Run(); err == nil {
		addrAssigned = true
	}

	// Шаг 4b: Point-to-Point TUN с указанием peer
	if !addrAssigned {
		if err := exec.CommandContext(ctx, ipBin, "addr", "add", cleanVIP+"/24", "peer", cleanVIP, "dev", d.AdapterName).Run(); err == nil {
			addrAssigned = true
		}
	}

	// Шаг 4c: С вычисленным broadcast адресом
	if !addrAssigned {
		parts := strings.Split(cleanVIP, ".")
		if len(parts) == 4 {
			brd := fmt.Sprintf("%s.%s.%s.255", parts[0], parts[1], parts[2])
			if err := exec.CommandContext(ctx, ipBin, "addr", "add", cleanVIP+"/24", "broadcast", brd, "dev", d.AdapterName).Run(); err == nil {
				addrAssigned = true
			}
		}
	}

	// Шаг 4d: Назначение как /32 хост
	if !addrAssigned {
		if err := exec.CommandContext(ctx, ipBin, "addr", "add", cleanVIP+"/32", "dev", d.AdapterName).Run(); err == nil {
			addrAssigned = true
		}
	}

	// Шаг 4e: Fallback через ifconfig (если ip недоступен или вернул ошибку)
	if !addrAssigned {
		ifconfigBin := "ifconfig"
		for _, icp := range []string{"/sbin/ifconfig", "/usr/sbin/ifconfig", "/bin/ifconfig", "ifconfig"} {
			if path, err := exec.LookPath(icp); err == nil {
				ifconfigBin = path
				break
			}
		}
		_ = exec.CommandContext(ctx, ifconfigBin, d.AdapterName, cleanVIP, "netmask", "255.255.255.0", "up").Run()
	}

	// Финальное подтверждение статуса UP
	_ = exec.CommandContext(ctx, ipBin, "link", "set", d.AdapterName, "up").Run()
	_ = EnableMSSClamping(d.AdapterName, mtu)

	// 5. Маршрутизация подсети через адаптер (используем replace, чтобы маршрут не падал с File exists)
	prefix := "100.64.200"
	parts := strings.Split(cleanVIP, ".")
	if len(parts) >= 3 {
		prefix = fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	}
	_ = exec.CommandContext(ctx, ipBin, "route", "replace", prefix+".0/24", "dev", d.AdapterName).Run()
	_ = exec.CommandContext(ctx, ipBin, "route", "replace", prefix+".0/24", "dev", d.AdapterName, "table", "main").Run()
	_ = exec.CommandContext(ctx, ipBin, "route", "replace", "100.64.200.0/24", "dev", d.AdapterName).Run()
	_ = exec.CommandContext(ctx, ipBin, "route", "replace", "100.64.200.0/24", "dev", d.AdapterName, "table", "main").Run()

	// Приоритетные правила маршрутизации для KeeneticOS (обход blackhole таблиц 4096-4101)
	_ = exec.CommandContext(ctx, ipBin, "rule", "del", "pref", "50", "to", prefix+".0/24", "lookup", "main").Run()
	_ = exec.CommandContext(ctx, ipBin, "rule", "del", "pref", "50", "from", prefix+".0/24", "lookup", "main").Run()
	_ = exec.CommandContext(ctx, ipBin, "rule", "del", "pref", "50", "iif", d.AdapterName, "lookup", "main").Run()
	_ = exec.CommandContext(ctx, ipBin, "rule", "add", "pref", "50", "to", prefix+".0/24", "lookup", "main").Run()
	_ = exec.CommandContext(ctx, ipBin, "rule", "add", "pref", "50", "from", prefix+".0/24", "lookup", "main").Run()
	_ = exec.CommandContext(ctx, ipBin, "rule", "add", "pref", "50", "iif", d.AdapterName, "lookup", "main").Run()

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

	// 6. Разрешение входящего и транзитного трафика в iptables / nftables / ufw
	applyFirewallRules := func() {
		// Поиск доступных бинарников iptables
		var iptCandidates []string
		for _, p := range []string{"/usr/sbin/iptables", "/sbin/iptables", "iptables", "/opt/sbin/iptables"} {
			if path, err := exec.LookPath(p); err == nil {
				// Avoid duplicate paths
				found := false
				for _, existing := range iptCandidates {
					if existing == path {
						found = true
						break
					}
				}
				if !found {
					iptCandidates = append(iptCandidates, path)
				}
			}
		}
		if len(iptCandidates) == 0 {
			iptCandidates = []string{"/usr/sbin/iptables", "/sbin/iptables", "iptables"}
		}

		for _, ipt := range iptCandidates {
			// Проверяем, поддерживает ли данная сборка iptables ключ -w (wait lock)
			hasWait := exec.Command(ipt, "-w", "1", "-L", "INPUT", "-n").Run() == nil

			runIpt := func(args ...string) {
				var checkArgs, insertArgs []string
				if hasWait {
					checkArgs = append([]string{"-w", "2", "-C"}, args...)
					insertArgs = append([]string{"-w", "2", "-I"}, append([]string{args[0], "1"}, args[1:]...)...)
				} else {
					checkArgs = append([]string{"-C"}, args...)
					insertArgs = append([]string{"-I"}, append([]string{args[0], "1"}, args[1:]...)...)
				}

				if err := exec.Command(ipt, checkArgs...).Run(); err == nil {
					return // Правило уже существует
				}
				_ = exec.Command(ipt, insertArgs...).Run()
			}

			// 1. Стандартные цепочки ядра Linux
			runIpt("INPUT", "-i", d.AdapterName, "-j", "ACCEPT")
			runIpt("INPUT", "-p", "icmp", "-j", "ACCEPT")
			runIpt("FORWARD", "-i", d.AdapterName, "-j", "ACCEPT")
			runIpt("FORWARD", "-o", d.AdapterName, "-j", "ACCEPT")
			runIpt("OUTPUT", "-o", d.AdapterName, "-j", "ACCEPT")

			// 2. Специальные цепочки KeeneticOS (NDM Framework)
			runIpt("_NDM_INPUT", "-i", d.AdapterName, "-j", "ACCEPT")
			runIpt("_NDM_INPUT", "-p", "icmp", "-j", "ACCEPT")
			runIpt("_NDM_FORWARD", "-i", d.AdapterName, "-j", "ACCEPT")
			runIpt("_NDM_FORWARD", "-o", d.AdapterName, "-j", "ACCEPT")
			runIpt("_NDM_OUTPUT", "-o", d.AdapterName, "-j", "ACCEPT")

			// 3. Таблица mangle: отключение blackhole-маркировки для пакетов mesh
			if hasWait {
				_ = exec.Command(ipt, "-w", "2", "-t", "mangle", "-I", "PREROUTING", "1", "-i", d.AdapterName, "-j", "ACCEPT").Run()
				_ = exec.Command(ipt, "-w", "2", "-t", "mangle", "-I", "OUTPUT", "1", "-o", d.AdapterName, "-j", "ACCEPT").Run()
			} else {
				_ = exec.Command(ipt, "-t", "mangle", "-I", "PREROUTING", "1", "-i", d.AdapterName, "-j", "ACCEPT").Run()
				_ = exec.Command(ipt, "-t", "mangle", "-I", "OUTPUT", "1", "-o", d.AdapterName, "-j", "ACCEPT").Run()
			}

			// 4. Разрешение входящих UDP-пакетов
			runIpt("INPUT", "-p", "udp", "--dport", "47832", "-j", "ACCEPT")
			runIpt("_NDM_INPUT", "-p", "udp", "--dport", "47832", "-j", "ACCEPT")
		}

		// Прямой вызов через sh -c (на случай ограниченного окружения Entware на KeeneticOS)
		shCmd := fmt.Sprintf(`iptables -I INPUT 1 -i %s -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I INPUT 1 -i %s -j ACCEPT 2>/dev/null; iptables -I FORWARD 1 -i %s -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I FORWARD 1 -i %s -j ACCEPT 2>/dev/null; iptables -I OUTPUT 1 -o %s -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I OUTPUT 1 -o %s -j ACCEPT 2>/dev/null; iptables -I _NDM_INPUT 1 -i %s -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I _NDM_INPUT 1 -i %s -j ACCEPT 2>/dev/null; iptables -I _NDM_FORWARD 1 -i %s -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I _NDM_FORWARD 1 -i %s -j ACCEPT 2>/dev/null; iptables -I _NDM_OUTPUT 1 -o %s -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I _NDM_OUTPUT 1 -o %s -j ACCEPT 2>/dev/null`, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName)
		_ = exec.Command("sh", "-c", shCmd).Run()

		// 5. nftables (Ubuntu 22.04+, Debian 12+): добавляем разрешение для nb0 через nft напрямую
		if nft, err := exec.LookPath("nft"); err == nil {
			// Разрешаем весь трафик через TUN интерфейс в nftables (если таблица inet filter существует)
			_ = exec.Command(nft, "add", "rule", "inet", "filter", "input", "iifname", d.AdapterName, "accept").Run()
			_ = exec.Command(nft, "add", "rule", "inet", "filter", "forward", "iifname", d.AdapterName, "accept").Run()
			_ = exec.Command(nft, "add", "rule", "inet", "filter", "forward", "oifname", d.AdapterName, "accept").Run()
			_ = exec.Command(nft, "add", "rule", "inet", "filter", "output", "oifname", d.AdapterName, "accept").Run()
			// Разрешение ICMP глобально
			_ = exec.Command(nft, "add", "rule", "inet", "filter", "input", "ip", "protocol", "icmp", "accept").Run()
		}


		// 6. ufw (Ubuntu): разрешение через профиль ufw если доступен
		if ufw, err := exec.LookPath("ufw"); err == nil {
			_ = exec.Command(ufw, "allow", "in", "on", d.AdapterName).Run()
			_ = exec.Command(ufw, "allow", "out", "on", d.AdapterName).Run()
		}
	}
	applyFirewallRules()

	// Автоматическое создание/обновление системного хука брандмауэра KeeneticOS
	// NDM автоматически вызывает скрипты из /opt/etc/ndm/netfilter.d/ при любых сетевых изменениях
	isKeenetic := false
	if _, err := os.Stat("/bin/ndmq"); err == nil {
		isKeenetic = true
	} else if _, err := os.Stat("/usr/bin/ndmq"); err == nil {
		isKeenetic = true
	} else if _, err := os.Stat("/etc/ndm"); err == nil {
		isKeenetic = true
	}

	if isKeenetic {
		if _, err := os.Stat("/opt/etc"); err == nil {
			_ = os.MkdirAll("/opt/etc/ndm/netfilter.d", 0755)
			hookContent := fmt.Sprintf(`#!/bin/sh
[ "$type" = "ip6tables" ] && exit 0

if [ "$table" = "filter" ]; then
    iptables -C INPUT -i %s -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i %s -j ACCEPT
    iptables -C FORWARD -i %s -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i %s -j ACCEPT
    iptables -C OUTPUT -o %s -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o %s -j ACCEPT
    iptables -C _NDM_INPUT -i %s -j ACCEPT 2>/dev/null || iptables -I _NDM_INPUT 1 -i %s -j ACCEPT 2>/dev/null || true
    iptables -C _NDM_FORWARD -i %s -j ACCEPT 2>/dev/null || iptables -I _NDM_FORWARD 1 -i %s -j ACCEPT 2>/dev/null || true
    iptables -C _NDM_OUTPUT -o %s -j ACCEPT 2>/dev/null || iptables -I _NDM_OUTPUT 1 -o %s -j ACCEPT 2>/dev/null || true
fi

if [ "$table" = "mangle" ]; then
    iptables -t mangle -C PREROUTING -i %s -j ACCEPT 2>/dev/null || iptables -t mangle -I PREROUTING 1 -i %s -j ACCEPT 2>/dev/null || true
    iptables -t mangle -C OUTPUT -o %s -j ACCEPT 2>/dev/null || iptables -t mangle -I OUTPUT 1 -o %s -j ACCEPT 2>/dev/null || true
fi
`, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName, d.AdapterName)
			hookPath := "/opt/etc/ndm/netfilter.d/010-natbypass.sh"
			if cur, rErr := os.ReadFile(hookPath); rErr != nil || string(cur) != hookContent {
				_ = os.WriteFile(hookPath, []byte(hookContent), 0755)
				_ = exec.Command("chmod", "+x", hookPath).Run()
			}
		}
	}

	// Фоновый сторожевой таймер: проверяет статус интерфейса, IP-адрес и правила брандмауэра (раз в 30 сек)
	d.watchdogOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-d.stopCh:
					return
				case <-ticker.C:
					if atomic.LoadInt32(&d.isClosed) == 1 {
						return
					}
					// 1. Проверка статуса интерфейса и IP адреса
					ipPath := findIPBinary()
					out, _ := exec.Command(ipPath, "addr", "show", "dev", d.AdapterName).Output()
					outStr := string(out)
					if !strings.Contains(outStr, "UP") || !strings.Contains(outStr, "inet ") {
						d.mu.Lock()
						vip := d.VirtualIP
						d.mu.Unlock()
						if vip != "" {
							_ = d.SetVirtualIP(vip)
						}
					}
					// 2. Быстрая проверка правил iptables
					chk := exec.Command("iptables", "-C", "INPUT", "-i", d.AdapterName, "-j", "ACCEPT")
					if chk.Run() != nil {
						applyFirewallRules()
					}
				}
			}
		}()
	})

	return nil
}


// SetMTU динамически обновляет MTU на интерфейсе Linux/Keenetic
func (d *Device) SetMTU(mtu int) error {
	if mtu < 1280 || mtu > 1500 {
		return fmt.Errorf("недопустимый MTU: %d (допустимо 1280..1500)", mtu)
	}
	d.mu.Lock()
	d.MTU = mtu
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mtuStr := strconv.Itoa(mtu)
	_ = exec.CommandContext(ctx, "ip", "link", "set", "dev", d.AdapterName, "mtu", mtuStr).Run()
	_ = exec.CommandContext(ctx, "ifconfig", d.AdapterName, "mtu", mtuStr).Run()
	return nil
}

func (d *Device) Close() error {

	if atomic.CompareAndSwapInt32(&d.isClosed, 0, 1) {
		d.stopOnce.Do(func() {
			if d.stopCh != nil {
				close(d.stopCh)
			}
		})
		if d.file != nil {
			return d.file.Close()
		}
	}
	return nil
}