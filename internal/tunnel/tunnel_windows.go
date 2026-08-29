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
			tempDll := filepath.Join(os.TempDir(), "wintun.dll")
			if _, tErr := os.Stat(tempDll); tErr == nil {
				dllPath = tempDll
			} else if len(embeddedWintunDLL) > 0 {
				if wErr := os.WriteFile(dllPath, embeddedWintunDLL, 0755); wErr == nil {
					// written locally
				} else if twErr := os.WriteFile(tempDll, embeddedWintunDLL, 0755); twErr == nil {
					dllPath = tempDll
				} else {
					initErr = fmt.Errorf("не удалось извлечь wintun.dll: %v", twErr)
					return
				}
			} else {
				initErr = fmt.Errorf("wintun.dll не найден и не встроен")
				return
			}
		}

		wintunDLL = windows.NewLazyDLL(dllPath)
		if err := wintunDLL.Load(); err != nil {
			initErr = fmt.Errorf("ошибка загрузки wintun.dll: %w", err)
			return
		}
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

		// 1. Ожидаем готовности интерфейса в NDIS и устанавливаем статический IP через netsh
		ipAssigned := false
		for i := 0; i < 10; i++ {
			err := runNetsh("interface", "ipv4", "set", "address",
				fmt.Sprintf("name=%s", adapterName),
				"source=static",
				fmt.Sprintf("address=%s", virtualIP),
				"mask=255.255.255.0",
			)
			if err == nil {
				ipAssigned = true
				break
			}
			time.Sleep(250 * time.Millisecond)
		}

		// PowerShell fallback if netsh was blocked
		if !ipAssigned {
			psCmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress "%s" -PrefixLength 24 -SkipAsSource $false -ErrorAction SilentlyContinue; Set-NetIPAddress -InterfaceAlias "%s" -IPAddress "%s" -PrefixLength 24 -ErrorAction SilentlyContinue`, adapterName, virtualIP, adapterName, virtualIP)
			_ = runHiddenPS(psCmd)
		}

		// 2. Переводим профиль сети адаптера в Private (критично для разрешения ICMP Ping на Windows 10/11 и Windows Server)
		psProfile := fmt.Sprintf(`Set-NetConnectionProfile -InterfaceAlias "%s" -NetworkCategory Private -ErrorAction SilentlyContinue`, adapterName)
		_ = runHiddenPS(psProfile)

		// 3. Выставляем метрику и MTU 1420 для защиты от фрагментации пакетов
		_ = runNetsh("interface", "ipv4", "set", "interface",
			fmt.Sprintf("name=%s", adapterName),
			"metric=100",
		)
		_ = runNetsh("interface", "ipv4", "set", "subinterface",
			fmt.Sprintf("name=%s", adapterName),
			"mtu=1420",
			"store=persistent",
		)


		// 4. Правила брандмауэра Windows для интерфейса NatBypass (ICMP, TCP, UDP)
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name=NatBypass ICMP In")
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name=NatBypass All In")
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name=NatBypass Mesh Inbound")

		_ = runNetsh("advfirewall", "firewall", "add", "rule",
			"name=NatBypass ICMP In",
			"dir=in", "action=allow",
			"protocol=icmpv4:any,any",
			fmt.Sprintf("interface=%s", adapterName),
		)
		_ = runNetsh("advfirewall", "firewall", "add", "rule",
			"name=NatBypass All In",
			"dir=in", "action=allow",
			fmt.Sprintf("interface=%s", adapterName),
		)
		_ = runNetsh("advfirewall", "firewall", "add", "rule",
			"name=NatBypass Mesh Inbound",
			"dir=in", "action=allow",
			"remoteip=100.64.200.0/24",
		)

		// 5. Явный маршрут 100.64.200.0/24 через адаптер
		for i := 0; i < 3; i++ {
			err := runNetsh("interface", "ipv4", "add", "route",
				"100.64.200.0/24",
				fmt.Sprintf("name=%s", adapterName),
				"0.0.0.0",
				"metric=1",
			)
			if err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
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

// SetMTU динамически обновляет MTU на интерфейсе Windows
func (d *Device) SetMTU(mtu int) error {
	if mtu < 1280 || mtu > 1500 {
		return fmt.Errorf("недопустимый MTU: %d (допустимо 1280..1500)", mtu)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("name=%s", d.AdapterName),
		fmt.Sprintf("mtu=%d", mtu),
		"store=persistent",
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



func runHiddenPS(cmdStr string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmdStr)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	return cmd.Run()
}
