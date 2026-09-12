//go:build windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// Official Wintun release zip URL
	officialWintunZipURL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
	minWintunDLLSize     = 50000 // Wintun DLL is ~400KB
)

// FindExistingWintunDLL returns the file path of a valid wintun.dll on the system, or empty string.
func FindExistingWintunDLL() string {
	candidates := make([]string, 0, 6)

	// 1. Next to the current running executable
	if exePath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), "wintun.dll"))
	}
	// 2. Current working directory
	candidates = append(candidates, "wintun.dll")
	// 3. User LocalAppData
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		candidates = append(candidates, filepath.Join(localAppData, "NatBypass", "wintun.dll"))
	}
	// 4. System temp directory
	if tempDir := os.TempDir(); tempDir != "" {
		candidates = append(candidates, filepath.Join(tempDir, "wintun.dll"))
	}
	// 5. System32 directory
	if sysRoot := os.Getenv("SystemRoot"); sysRoot != "" {
		candidates = append(candidates, filepath.Join(sysRoot, "System32", "wintun.dll"))
	}

	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Size() >= minWintunDLLSize {
			return p
		}
	}
	return ""
}

// downloadOfficialWintunDLL downloads and extracts the official signed wintun.dll from wintun.net
// matching the current CPU architecture.
func downloadOfficialWintunDLL() ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", officialWintunZipURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("User-Agent", "NatBypass-Wintun-Downloader/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network request failed (%s): %w", officialWintunZipURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %s from %s", resp.Status, officialWintunZipURL)
	}

	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read zip content: %w", err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse zip archive: %w", err)
	}

	var targetSubpath string
	switch runtime.GOARCH {
	case "amd64":
		targetSubpath = "wintun/bin/amd64/wintun.dll"
	case "arm64":
		targetSubpath = "wintun/bin/arm64/wintun.dll"
	case "386":
		targetSubpath = "wintun/bin/x86/wintun.dll"
	case "arm":
		targetSubpath = "wintun/bin/arm/wintun.dll"
	default:
		targetSubpath = "wintun/bin/amd64/wintun.dll"
	}

	for _, f := range zipReader.File {
		if filepath.ToSlash(f.Name) == targetSubpath {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open %s from archive: %w", f.Name, err)
			}
			defer rc.Close()

			dllBytes, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("failed to read %s from archive: %w", f.Name, err)
			}
			if len(dllBytes) < minWintunDLLSize {
				return nil, fmt.Errorf("extracted %s is suspiciously small (%d bytes)", f.Name, len(dllBytes))
			}
			return dllBytes, nil
		}
	}

	return nil, fmt.Errorf("architecture binary %s not found in official wintun zip", targetSubpath)
}

// EnsureWintunDLL ensures that wintun.dll is available on the local machine.
// If not found locally, it automatically downloads and extracts the official
// driver from https://www.wintun.net. Returns the absolute or relative path to wintun.dll.
func EnsureWintunDLL() (string, error) {
	if existing := FindExistingWintunDLL(); existing != "" {
		return existing, nil
	}

	dllBytes, err := downloadOfficialWintunDLL()
	if err != nil {
		return "", fmt.Errorf("драйвер Wintun (wintun.dll) не найден, и автозагрузка с %s не удалась: %w\nПожалуйста, скачайте официальный архив с https://www.wintun.net/builds/wintun-0.14.1.zip и поместите wintun.dll рядом с программой", officialWintunZipURL, err)
	}

	// Try saving in order:
	// 1. Alongside executable (best for portability)
	// 2. LocalAppData\NatBypass (best for non-admin installs)
	// 3. TempDir
	destCandidates := make([]string, 0, 3)
	if exePath, err := os.Executable(); err == nil {
		destCandidates = append(destCandidates, filepath.Join(filepath.Dir(exePath), "wintun.dll"))
	}
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		destCandidates = append(destCandidates, filepath.Join(localAppData, "NatBypass", "wintun.dll"))
	}
	if tempDir := os.TempDir(); tempDir != "" {
		destCandidates = append(destCandidates, filepath.Join(tempDir, "wintun.dll"))
	}

	var writeErr error
	for _, dest := range destCandidates {
		dir := filepath.Dir(dest)
		if dir != "" {
			_ = os.MkdirAll(dir, 0755)
		}
		if err := os.WriteFile(dest, dllBytes, 0755); err == nil {
			return dest, nil
		} else {
			writeErr = err
		}
	}

	return "", fmt.Errorf("не удалось сохранить скачанный wintun.dll: %w", writeErr)
}

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
		dllPath, err := EnsureWintunDLL()
		if err != nil {
			initErr = err
			return
		}

		wintunDLL = windows.NewLazyDLL(dllPath)
		if err := wintunDLL.Load(); err != nil {
			initErr = fmt.Errorf("ошибка загрузки %s: %w", dllPath, err)
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

	extraRouteClean := ""
	if prefix != "100.64.200" {
		extraRouteClean = fmt.Sprintf(`Get-NetRoute | Where-Object { $_.DestinationPrefix -like "100.64.200*" -and $_.InterfaceIndex -eq %d } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; `, ifIndex)
	}

	psSetup := fmt.Sprintf(`Get-NetRoute | Where-Object { ($_.DestinationPrefix -like "%s*" -or $_.DestinationPrefix -like "100.64.200*") -and $_.InterfaceIndex -ne %d } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; Get-NetIPAddress | Where-Object { ($_.IPAddress -like "%s*" -or $_.IPAddress -like "100.64.200*") -and $_.InterfaceIndex -ne %d } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; %s$cur = Get-NetIPAddress | Where-Object { $_.IPAddress -eq "%s" -and $_.InterfaceIndex -eq %d }; if (-not $cur) { New-NetIPAddress -InterfaceIndex %d -IPAddress "%s" -PrefixLength 24 -SkipAsSource $false -ErrorAction SilentlyContinue }; Set-NetIPInterface -InterfaceIndex %d -NlMtu 1280 -DadTransmits 0 -InterfaceMetric 1 -RouterDiscovery Disabled -ErrorAction SilentlyContinue; New-NetRoute -InterfaceIndex %d -DestinationPrefix "%s.0/24" -NextHop 0.0.0.0 -RouteMetric 1 -ErrorAction SilentlyContinue; Set-NetConnectionProfile -InterfaceIndex %d -NetworkCategory Private -ErrorAction SilentlyContinue`, prefix, ifIndex, prefix, ifIndex, extraRouteClean, cleanVIP, ifIndex, ifIndex, cleanVIP, ifIndex, ifIndex, prefix, ifIndex)
	_ = runHiddenPS(psSetup)

	// Фоновое добавление правил брандмауэра Windows (поддержка Windows 10/11 и Windows Server 2016-2025)
	go func() {
		exePath, _ := os.Executable()
		psExeFw := ""
		if exePath != "" {
			escapedExe := strings.ReplaceAll(exePath, "'", "''")
			psExeFw = fmt.Sprintf(`$exe = '%s'; if (-not (Get-NetFirewallRule -Name "NatBypass-App-UDP-In" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name "NatBypass-App-UDP-In" -DisplayName "NatBypass Core UDP Inbound" -Direction Inbound -Program $exe -Action Allow -Protocol UDP -Profile Any -ErrorAction SilentlyContinue }; if (-not (Get-NetFirewallRule -Name "NatBypass-App-TCP-In" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name "NatBypass-App-TCP-In" -DisplayName "NatBypass Core TCP Inbound" -Direction Inbound -Program $exe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue }; `, escapedExe)
		}
		psFw := psExeFw + `if (-not (Get-NetFirewallRule -Name "NatBypass-In-All" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name "NatBypass-In-All" -DisplayName "NatBypass Mesh Inbound All" -Direction Inbound -Action Allow -Profile Any -InterfaceAlias "NatBypass" -ErrorAction SilentlyContinue }; if (-not (Get-NetFirewallRule -Name "NatBypass-ICMP-In" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name "NatBypass-ICMP-In" -DisplayName "NatBypass ICMPv4 Inbound" -Direction Inbound -Action Allow -Protocol ICMPv4 -Profile Any -InterfaceAlias "NatBypass" -ErrorAction SilentlyContinue }; if (-not (Get-NetFirewallRule -DisplayName "NatBypass ICMPv4 In" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "NatBypass ICMPv4 In" -Name "NatBypass ICMPv4 In" -Direction Inbound -Action Allow -Protocol ICMPv4 -Profile Any -ErrorAction SilentlyContinue }; Set-NetFirewallRule -DisplayName "NatBypass ICMPv4 In" -Profile Any -Enabled True -ErrorAction SilentlyContinue; Enable-NetFirewallRule -DisplayGroup "Core Networking Diagnostics" -ErrorAction SilentlyContinue; Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue; Enable-NetFirewallRule -DisplayName "*ICMPv4*" -ErrorAction SilentlyContinue`
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
		if atomic.LoadInt32(&d.isClosed) == 1 {
			return nil, fmt.Errorf("адаптер закрыт")
		}

		d.mu.Lock()
		hSession := d.hSession
		d.mu.Unlock()

		if hSession == 0 {
			return nil, fmt.Errorf("адаптер закрыт")
		}

		var size uint32
		ptr, _, _ := procWintunReceivePacket.Call(hSession, uintptr(unsafe.Pointer(&size)))
		if ptr != 0 && size > 0 {
			packet := make([]byte, size)
			procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&packet[0])), ptr, uintptr(size))
			procWintunReleaseReceivePacket.Call(hSession, ptr)
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
	hSession := d.hSession
	d.mu.Unlock()

	if hSession == 0 {
		return fmt.Errorf("адаптер закрыт")
	}

	ptr, _, _ := procWintunAllocateSendPacket.Call(hSession, uintptr(len(packet)))
	if ptr == 0 {
		return fmt.Errorf("wintun: переполнение буфера отправки")
	}

	procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)))
	procWintunSendPacket.Call(hSession, ptr)
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
	hSession := d.hSession
	hAdapter := d.hAdapter
	d.hSession = 0
	d.hAdapter = 0
	d.mu.Unlock()

	// ✅ КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Пробуждаем ждущий ReadPacket
	if d.hReadEvent != 0 {
		_ = windows.SetEvent(d.hReadEvent)
	}

	// Дать ReadPacket выйти
	time.Sleep(5 * time.Millisecond)

	if hSession != 0 {
		procWintunEndSession.Call(hSession)
	}
	if hAdapter != 0 {
		procWintunCloseAdapter.Call(hAdapter)
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
