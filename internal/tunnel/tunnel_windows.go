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
	"strings"
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
	modiphlpapi                    = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceLuidToIndex = modiphlpapi.NewProc("ConvertInterfaceLuidToIndex")
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

	// 1. Попытка открыть уже существующий или создать новый с гарантированным запуском сессии
	var hAdapter uintptr
	var hSession uintptr

	hAdapter, _, _ = procWintunOpenAdapter.Call(uintptr(unsafe.Pointer(poolName)), uintptr(unsafe.Pointer(poolName)))
	if hAdapter != 0 {
		hSession, _, _ = procWintunStartSession.Call(hAdapter, 0x400000)
		if hSession == 0 {
			// Предыдущая сессия адаптера зависла. Закрываем и пересоздаем адаптер заново
			procWintunCloseAdapter.Call(hAdapter)
			hAdapter = 0
		}
	}

	if hAdapter == 0 {
		hAdapter, _, _ = procWintunCreateAdapter.Call(
			uintptr(unsafe.Pointer(poolName)),
			uintptr(unsafe.Pointer(adapterType)),
			0,
		)
		if hAdapter != 0 {
			hSession, _, _ = procWintunStartSession.Call(hAdapter, 0x400000)
		}
	}

	if hAdapter == 0 || hSession == 0 {
		if hAdapter != 0 {
			procWintunCloseAdapter.Call(hAdapter)
		}
		return nil, fmt.Errorf("не удалось инициализировать Wintun адаптер и сессию (требуются права Администратора)")
	}

	hEvent, _, _ := procWintunGetReadWaitEvent.Call(hSession)

	dev := &Device{
		AdapterName: adapterName,
		VirtualIP:   virtualIP,
		hAdapter:    hAdapter,
		hSession:    hSession,
		hReadEvent:  windows.Handle(hEvent),
	}

	// 3. Мгновенная прямая привязка IP и маршрутов к InterfaceIndex
	var luid uint64
	var ifIndex uint32
	procWintunGetAdapterLUID.Call(hAdapter, uintptr(unsafe.Pointer(&luid)))
	procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&ifIndex)))

	cleanVIP := strings.TrimSpace(strings.Split(virtualIP, "/")[0])
	prefix := "100.64.200"
	parts := strings.Split(cleanVIP, ".")
	if len(parts) >= 3 {
		prefix = fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	}

	psSetup := fmt.Sprintf(`Get-NetIPAddress | Where-Object { $_.IPAddress -eq "%s" -and $_.InterfaceIndex -ne %d } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; $cur = Get-NetIPAddress | Where-Object { $_.IPAddress -eq "%s" -and $_.InterfaceIndex -eq %d }; if (-not $cur) { New-NetIPAddress -InterfaceIndex %d -IPAddress "%s" -PrefixLength 24 -SkipAsSource $false -ErrorAction SilentlyContinue }; Set-NetIPInterface -InterfaceIndex %d -DadTransmits 0 -InterfaceMetric 1 -RouterDiscovery Disabled -ErrorAction SilentlyContinue; New-NetRoute -InterfaceIndex %d -DestinationPrefix "%s.0/24" -NextHop 0.0.0.0 -RouteMetric 1 -ErrorAction SilentlyContinue; New-NetRoute -InterfaceIndex %d -DestinationPrefix "100.64.200.0/24" -NextHop 0.0.0.0 -RouteMetric 1 -ErrorAction SilentlyContinue; Set-NetConnectionProfile -InterfaceIndex %d -NetworkCategory Private -ErrorAction SilentlyContinue`, cleanVIP, ifIndex, cleanVIP, ifIndex, ifIndex, cleanVIP, ifIndex, ifIndex, prefix, ifIndex, ifIndex)
	_ = runHiddenPS(psSetup)

	// Фоновое добавление правил брандмауэра
	go func() {
		psFw := `netsh advfirewall firewall add rule name="NatBypass ICMPv4 In" dir=in action=allow protocol=ICMPv4 enable=yes; Enable-NetFirewallRule -DisplayGroup "Core Networking Diagnostics" -ErrorAction SilentlyContinue; Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue`
		_ = runHiddenPS(psFw)
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

// SetVirtualIP обновляет IP адрес интерфейса и маршрут подсети
func (d *Device) SetVirtualIP(virtualIP string) error {
	cleanVIP := strings.TrimSpace(strings.Split(virtualIP, "/")[0])
	d.VirtualIP = cleanVIP
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", d.AdapterName),
		"source=static",
		fmt.Sprintf("address=%s", cleanVIP),
		"mask=255.255.255.0",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	err := cmd.Run()

	// Extract subnet prefix and install subnet route
	prefix := "100.64.200"
	parts := strings.Split(cleanVIP, ".")
	if len(parts) >= 3 {
		prefix = fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	}
	_ = exec.CommandContext(ctx, "route", "add", prefix+".0", "mask", "255.255.255.0", cleanVIP, "metric", "10").Run()

	return err
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
