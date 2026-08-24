//go:build windows

package tunnel

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed wintun.dll
var embeddedWintunDLL []byte

var (
	modkernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procRtlMoveMemory              = modkernel32.NewProc("RtlMoveMemory")
	wintunDLL                      *windows.LazyDLL
	procWintunCreateAdapter        *windows.LazyProc
	procWintunOpenAdapter          *windows.LazyProc
	procWintunCloseAdapter         *windows.LazyProc
	procWintunDeleteDriver         *windows.LazyProc
	procWintunStartSession         *windows.LazyProc
	procWintunEndSession           *windows.LazyProc
	procWintunGetReadWaitEvent     *windows.LazyProc
	procWintunReceivePacket        *windows.LazyProc
	procWintunReleaseReceivePacket *windows.LazyProc
	procWintunAllocateSendPacket   *windows.LazyProc
	procWintunSendPacket           *windows.LazyProc
	procWintunGetAdapterLUID       *windows.LazyProc
	wintunInitOnce                 sync.Once
)

func initWintun() error {
	var initErr error
	wintunInitOnce.Do(func() {
		dllPath := "wintun.dll"
		if _, err := os.Stat(dllPath); err != nil {
			if len(embeddedWintunDLL) > 0 {
				_ = os.WriteFile(dllPath, embeddedWintunDLL, 0755)
			} else {
				tempDll := filepath.Join(os.TempDir(), "wintun.dll")
				if _, err := os.Stat(tempDll); err == nil {
					dllPath = tempDll
				}
			}
		}

		wintunDLL = windows.NewLazyDLL(dllPath)
		procWintunCreateAdapter = wintunDLL.NewProc("WintunCreateAdapter")
		procWintunOpenAdapter = wintunDLL.NewProc("WintunOpenAdapter")
		procWintunCloseAdapter = wintunDLL.NewProc("WintunCloseAdapter")
		procWintunDeleteDriver = wintunDLL.NewProc("WintunDeleteDriver")
		procWintunStartSession = wintunDLL.NewProc("WintunStartSession")
		procWintunEndSession = wintunDLL.NewProc("WintunEndSession")
		procWintunGetReadWaitEvent = wintunDLL.NewProc("WintunGetReadWaitEvent")
		procWintunReceivePacket = wintunDLL.NewProc("WintunReceivePacket")
		procWintunReleaseReceivePacket = wintunDLL.NewProc("WintunReleaseReceivePacket")
		procWintunAllocateSendPacket = wintunDLL.NewProc("WintunAllocateSendPacket")
		procWintunSendPacket = wintunDLL.NewProc("WintunSendPacket")
		procWintunGetAdapterLUID = wintunDLL.NewProc("WintunGetAdapterLUID")
	})
	return initErr
}

// Device представляет созданный виртуальный сетевой адаптер Windows
type Device struct {
	AdapterName string
	VirtualIP   string
	hAdapter    uintptr
	hSession    uintptr
	hReadEvent  windows.Handle
	isClosed    int32
	mu          sync.Mutex
}

// CreateAdapter создает адаптер Wintun и настраивает IP адрес в Windows
func CreateAdapter(adapterName, virtualIP string) (*Device, error) {
	if err := initWintun(); err != nil {
		return nil, fmt.Errorf("ошибка инициализации wintun: %w", err)
	}

	poolName, _ := windows.UTF16PtrFromString(adapterName)
	adapterType, _ := windows.UTF16PtrFromString("NatBypass")

	// 1. Попытка открыть уже существующий или создать новый
	hAdapter, _, _ := procWintunOpenAdapter.Call(uintptr(unsafe.Pointer(poolName)), uintptr(unsafe.Pointer(poolName)))
	if hAdapter == 0 {
		hAdapter, _, _ = procWintunCreateAdapter.Call(
			uintptr(unsafe.Pointer(poolName)),
			uintptr(unsafe.Pointer(adapterType)),
			0,
		)
	}

	if hAdapter == 0 {
		return nil, fmt.Errorf("не удалось создать виртуальный Wintun адаптер (требуются права Администратора)")
	}

	// 2. Настройка статического IP адреса интерфейса через netsh (совместимо с Win7 - Win11)
	// 2. Запуск сессии Wintun с кольцевым буфером 4 MB
	hSession, _, _ := procWintunStartSession.Call(hAdapter, 0x400000)
	if hSession == 0 {
		procWintunCloseAdapter.Call(hAdapter)
		return nil, fmt.Errorf("не удалось запустить сессию Wintun (StartSession вернул 0)")
	}

	hEvent, _, _ := procWintunGetReadWaitEvent.Call(hSession)

	dev := &Device{
		AdapterName: adapterName,
		VirtualIP:   virtualIP,
		hAdapter:    hAdapter,
		hSession:    hSession,
		hReadEvent:  windows.Handle(hEvent),
	}

	// 3. Асинхронная настройка IP-адреса и правил брандмауэра в фоне (никогда не блокирует GUI!)
	go func() {
		runNetsh := func(args ...string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, "netsh", args...)
			c.SysProcAttr = &syscall.SysProcAttr{
				HideWindow:    true,
				CreationFlags: 0x08000000,
			}
			return c.Run()
		}

		// Ожидаем готовности интерфейса в NDIS и устанавливаем статический IP
		for i := 0; i < 6; i++ {
			time.Sleep(200 * time.Millisecond)
			err := runNetsh("interface", "ipv4", "set", "address",
				fmt.Sprintf("name=%s", adapterName),
				"source=static",
				fmt.Sprintf("address=%s", virtualIP),
				"mask=255.255.255.0",
			)
			if err == nil {
				break
			}
		}

		// Разрешаем входящий ICMP ping и пакеты в Брандмауэре Windows
		_ = runNetsh("advfirewall", "firewall", "add", "rule", "name=NatBypass ICMP", "dir=in", "action=allow", "protocol=icmpv4:8,any", "interface=NatBypass")
		_ = runNetsh("advfirewall", "firewall", "add", "rule", "name=NatBypass Allow All", "dir=in", "action=allow", "interface=NatBypass")
		_ = runNetsh("advfirewall", "firewall", "add", "rule",
			"name=NatBypass-Inbound",
			"dir=in",
			"action=allow",
			fmt.Sprintf("interface=%s", adapterName),
			"enable=yes",
		)
	}()

	return dev, nil
}

// ReadPacket считывает один IPv4 пакет из сетевого стека Windows
func (d *Device) ReadPacket() ([]byte, error) {
	if atomic.LoadInt32(&d.isClosed) == 1 {
		return nil, fmt.Errorf("адаптер закрыт")
	}

	for {
		var size uint32
		ptr, _, _ := procWintunReceivePacket.Call(d.hSession, uintptr(unsafe.Pointer(&size)))
		if ptr != 0 && size > 0 {
			packet := make([]byte, size)
			procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&packet[0])), ptr, uintptr(size))
			procWintunReleaseReceivePacket.Call(d.hSession, ptr)
			return packet, nil
		}

		// Ожидание события появления новых пакетов в очереди драйвера
		if d.hReadEvent != 0 {
			event, _ := windows.WaitForSingleObject(d.hReadEvent, 100)
			if event == windows.WAIT_OBJECT_0 {
				continue
			}
		} else {
			time.Sleep(10 * time.Millisecond)
		}

		if atomic.LoadInt32(&d.isClosed) == 1 {
			return nil, fmt.Errorf("адаптер закрыт")
		}
	}
}

// WritePacket отправляет входящий расшифрованный IPv4 пакет в сетевой стек Windows
func (d *Device) WritePacket(packet []byte) error {
	if atomic.LoadInt32(&d.isClosed) == 1 || len(packet) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ptr, _, _ := procWintunAllocateSendPacket.Call(d.hSession, uintptr(len(packet)))
	if ptr == 0 {
		return fmt.Errorf("wintun: переполнение буфера отправки")
	}

	procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)))
	procWintunSendPacket.Call(d.hSession, ptr)
	return nil
}

// SetVirtualIP обновляет IP адрес интерфейса
func (d *Device) SetVirtualIP(virtualIP string) error {
	d.VirtualIP = virtualIP
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", d.AdapterName),
		"source=static",
		fmt.Sprintf("address=%s", virtualIP),
		"mask=255.255.255.0",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	return cmd.Run()
}

// Close корректно завершает работу адаптера
func (d *Device) Close() error {
	if !atomic.CompareAndSwapInt32(&d.isClosed, 0, 1) {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.hSession != 0 {
		procWintunEndSession.Call(d.hSession)
		d.hSession = 0
	}
	if d.hAdapter != 0 {
		procWintunCloseAdapter.Call(d.hAdapter)
		d.hAdapter = 0
	}

	return nil
}


