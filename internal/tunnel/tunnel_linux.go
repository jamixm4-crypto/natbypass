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

	// 1. Открытие /dev/net/tun
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		// Попытка загрузить модуль tun
		_ = exec.Command("modprobe", "tun").Run()
		file, err = os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("не удалось открыть /dev/net/tun: %w (требуется modprobe tun или права root)", err)
		}
	}

	// 2. Регистрация TUN устройства через ioctl
	var req ifreq
	copy(req.ifrName[:], adapterName)
	req.ifrFlags = IFF_TUN | IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
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

	// 3. Установка MTU 1420
	_ = exec.CommandContext(ctx, "ip", "link", "set", "dev", d.AdapterName, "mtu", "1420").Run()
	_ = exec.CommandContext(ctx, "ifconfig", d.AdapterName, "mtu", "1420").Run()

	// 4. Маршрутизация 100.64.200.0/24 через адаптер
	_ = exec.CommandContext(ctx, "ip", "route", "add", "100.64.200.0/24", "dev", d.AdapterName).Run()

	// 5. Разрешение входящего и транзитного трафика в iptables (Keenetic / OpenWrt / Linux)
	_ = exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-i", d.AdapterName, "-j", "ACCEPT").Run()
	_ = exec.CommandContext(ctx, "iptables", "-I", "FORWARD", "-i", d.AdapterName, "-j", "ACCEPT").Run()
	_ = exec.CommandContext(ctx, "iptables", "-I", "FORWARD", "-o", d.AdapterName, "-j", "ACCEPT").Run()


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