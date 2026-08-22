//go:build windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazyDLL("user32.dll")
	kernel32 = windows.NewLazyDLL("kernel32.dll")
	psapi    = windows.NewLazyDLL("psapi.dll")

	procIsHungAppWindow          = user32.NewProc("IsHungAppWindow")
	procSendMessageTimeoutW      = user32.NewProc("SendMessageTimeoutW")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procIsWindow                 = user32.NewProc("IsWindow")
	procGetWindow                = user32.NewProc("GetWindow")
	procGetParent                = user32.NewProc("GetParent")
	procGetWindowRect            = user32.NewProc("GetWindowRect")
	procGetClassNameW            = user32.NewProc("GetClassNameW")
	procGetAsyncKeyState          = user32.NewProc("GetAsyncKeyState")

	procGetProcessTimes       = kernel32.NewProc("GetProcessTimes")
	procGetProcessIoCounters  = kernel32.NewProc("GetProcessIoCounters")
	procGetProcessHandleCount = kernel32.NewProc("GetProcessHandleCount")
	procThread32First         = kernel32.NewProc("Thread32First")
	procThread32Next          = kernel32.NewProc("Thread32Next")
	procModule32FirstW        = kernel32.NewProc("Module32FirstW")
	procModule32NextW         = kernel32.NewProc("Module32NextW")

	procGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

const (
	WM_NULL          = 0x0000
	SMTO_BLOCK       = 0x0001
	SMTO_ABORTIFHUNG = 0x0002
	GW_OWNER         = 4
)

type RECT struct {
	Left, Top, Right, Bottom int32
}

type PROCESS_MEMORY_COUNTERS struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

type IO_COUNTERS struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type THREADENTRY32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

type MODULEENTRY32W struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	HModule      uintptr
	Module       [256]uint16
	ExePath      [260]uint16
}

type Snapshot struct {
	PID           uint32
	HWND          uintptr
	IsAlive       bool
	ExitCode      uint32
	UIResponding  bool
	UILatency     time.Duration
	CPUPercent    float64
	RAMMB         float64
	PrivateMB     float64
	HandleCount   uint32
	ThreadCount   int
	ReadKBPerSec  float64
	WriteKBPerSec float64
	LastLogs      []string
	ProbeTime     time.Time
	ProbeDuration time.Duration
}

type DiagnosticNotification struct {
	Message     string
	ExpireAfter time.Time
}

func enableVirtualTerminal() {
	stdout := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(stdout, &mode); err == nil {
		mode |= 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
		_ = windows.SetConsoleMode(stdout, mode)
	}
}

func findNatBypassPID() (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, err
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, "NatBypass.exe") || strings.EqualFold(name, "natbypass-gui.exe") {
			return entry.ProcessID, nil
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return 0, fmt.Errorf("процесс NatBypass.exe не найден")
}

type candidateWindow struct {
	hwnd      uintptr
	visible   bool
	className string
	width     int32
	height    int32
}

// findMainWindow safely discovers the top-level HWND belonging to targetPID.
// It checks that the window is top-level (GetWindow(hwnd, GW_OWNER) == 0 && GetParent(hwnd) == 0).
// If targetPID owns multiple HWNDs, it selects the best window based on class name and non-zero size.
// It NEVER calls GetWindowTextW to avoid hangs when the target process is deadlocked.
func findMainWindow(targetPID uint32) uintptr {
	var candidates []candidateWindow
	cb := syscall.NewCallback(func(hwnd, lParam uintptr) uintptr {
		var pid uint32
		procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid == targetPID {
			owner, _, _ := procGetWindow.Call(hwnd, GW_OWNER)
			parent, _, _ := procGetParent.Call(hwnd)
			if owner == 0 && parent == 0 {
				vis, _, _ := procIsWindowVisible.Call(hwnd)
				var rc RECT
				procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
				w := rc.Right - rc.Left
				h := rc.Bottom - rc.Top

				var clsBuf [256]uint16
				n, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&clsBuf[0])), 256)
				clsName := ""
				if n > 0 {
					clsName = windows.UTF16ToString(clsBuf[:n])
				}

				candidates = append(candidates, candidateWindow{
					hwnd:      hwnd,
					visible:   vis != 0,
					className: clsName,
					width:     w,
					height:    h,
				})
			}
		}
		return 1 // continue enumeration
	})
	procEnumWindows.Call(cb, 0)

	if len(candidates) == 0 {
		return 0
	}
	if len(candidates) == 1 {
		return candidates[0].hwnd
	}

	// Priority 1: Window class name contains "NatBypass"
	for _, c := range candidates {
		if strings.Contains(strings.ToLower(c.className), "natbypass") {
			return c.hwnd
		}
	}

	// Priority 2: Visible window with non-zero size (largest area)
	var bestHWND uintptr
	var maxArea int32 = -1
	for _, c := range candidates {
		if c.visible && c.width > 0 && c.height > 0 {
			area := c.width * c.height
			if area > maxArea {
				maxArea = area
				bestHWND = c.hwnd
			}
		}
	}
	if bestHWND != 0 {
		return bestHWND
	}

	// Priority 3: Any top-level window with non-zero size
	for _, c := range candidates {
		if c.width > 0 && c.height > 0 {
			area := c.width * c.height
			if area > maxArea {
				maxArea = area
				bestHWND = c.hwnd
			}
		}
	}
	if bestHWND != 0 {
		return bestHWND
	}

	return candidates[0].hwnd
}

// checkUIResponsiveness probes the window message queue with a strict 200ms timeout
// and SMTO_ABORTIFHUNG | SMTO_BLOCK. If the target is hung or deadlocked, it returns immediately.
func checkUIResponsiveness(hwnd uintptr) (bool, time.Duration) {
	if hwnd == 0 {
		return false, 0
	}
	isWin, _, _ := procIsWindow.Call(hwnd)
	if isWin == 0 {
		return false, 0
	}

	hung, _, _ := procIsHungAppWindow.Call(hwnd)
	if hung != 0 {
		return false, 0
	}

	start := time.Now()
	var result uintptr
	ret, _, _ := procSendMessageTimeoutW.Call(
		hwnd,
		WM_NULL,
		0,
		0,
		uintptr(SMTO_ABORTIFHUNG|SMTO_BLOCK),
		200,
		uintptr(unsafe.Pointer(&result)),
	)
	rtt := time.Since(start)

	if ret == 0 {
		return false, rtt
	}
	return true, rtt
}

func countProcessThreads(pid uint32) int {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procThread32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0
	}

	count := 0
	for {
		if entry.OwnerProcessID == pid {
			count++
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procThread32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return count
}

func readRecentLogs(filePath string, maxLines int) []string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	content := strings.TrimSpace(string(data))
	if len(content) == 0 {
		return nil
	}
	lines := strings.Split(content, "\n")
	startIdx := len(lines) - maxLines
	if startIdx < 0 {
		startIdx = 0
	}
	var res []string
	for _, l := range lines[startIdx:] {
		l = strings.TrimRight(l, "\r\n")
		if len(l) > 71 {
			l = l[:68] + "..."
		}
		res = append(res, l)
	}
	return res
}

func dumpDiagnostics(pid uint32, hProc windows.Handle, hwnd uintptr) (string, error) {
	timestamp := time.Now()
	fileName := fmt.Sprintf("natbypass_diagnostic_%s.txt", timestamp.Format("20060102_150405"))

	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("              NATBYPASS FULL PROCESS FORENSIC DIAGNOSTIC DUMP                 \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("Timestamp       : %s\n", timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Target PID      : %d\n", pid))
	sb.WriteString(fmt.Sprintf("Window HWND     : 0x%X\n", hwnd))

	if hwnd != 0 {
		var classNameBuf [256]uint16
		procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&classNameBuf[0])), 256)
		className := windows.UTF16ToString(classNameBuf[:])
		vis, _, _ := procIsWindowVisible.Call(hwnd)
		hung, _, _ := procIsHungAppWindow.Call(hwnd)
		responding, latency := checkUIResponsiveness(hwnd)

		sb.WriteString(fmt.Sprintf("Window Class    : %s\n", className))
		sb.WriteString(fmt.Sprintf("Window Visible  : %v\n", vis != 0))
		sb.WriteString(fmt.Sprintf("IsHungAppWindow : %v\n", hung != 0))
		sb.WriteString(fmt.Sprintf("UI Responding   : %v (Probe Latency: %v)\n", responding, latency))
	} else {
		sb.WriteString("Window HWND     : NONE / NOT FOUND\n")
	}

	var memCounters PROCESS_MEMORY_COUNTERS
	memCounters.CB = uint32(unsafe.Sizeof(memCounters))
	procGetProcessMemoryInfo.Call(uintptr(hProc), uintptr(unsafe.Pointer(&memCounters)), uintptr(memCounters.CB))
	sb.WriteString("\n--------------------------------------------------------------------------------\n")
	sb.WriteString(" MEMORY & RESOURCE COUNTERS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf(" Working Set (RAM)   : %.2f MB (Peak: %.2f MB)\n",
		float64(memCounters.WorkingSetSize)/(1024*1024), float64(memCounters.PeakWorkingSetSize)/(1024*1024)))
	sb.WriteString(fmt.Sprintf(" Pagefile (Private)  : %.2f MB (Peak: %.2f MB)\n",
		float64(memCounters.PagefileUsage)/(1024*1024), float64(memCounters.PeakPagefileUsage)/(1024*1024)))
	sb.WriteString(fmt.Sprintf(" Paged Pool Usage    : %.2f KB\n", float64(memCounters.QuotaPagedPoolUsage)/1024))
	sb.WriteString(fmt.Sprintf(" Non-Paged Pool      : %.2f KB\n", float64(memCounters.QuotaNonPagedPoolUsage)/1024))

	var handleCount uint32
	procGetProcessHandleCount.Call(uintptr(hProc), uintptr(unsafe.Pointer(&handleCount)))
	sb.WriteString(fmt.Sprintf(" Handle Count        : %d\n", handleCount))

	var ioCounters IO_COUNTERS
	procGetProcessIoCounters.Call(uintptr(hProc), uintptr(unsafe.Pointer(&ioCounters)))
	sb.WriteString(fmt.Sprintf(" Total Read Transfer : %.2f MB (%d ops)\n", float64(ioCounters.ReadTransferCount)/(1024*1024), ioCounters.ReadOperationCount))
	sb.WriteString(fmt.Sprintf(" Total Write Transfer: %.2f MB (%d ops)\n", float64(ioCounters.WriteTransferCount)/(1024*1024), ioCounters.WriteOperationCount))

	sb.WriteString("\n--------------------------------------------------------------------------------\n")
	sb.WriteString(" THREADS LIST\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	snapThread, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	threadCount := 0
	if err == nil {
		defer windows.CloseHandle(snapThread)
		var tEntry THREADENTRY32
		tEntry.Size = uint32(unsafe.Sizeof(tEntry))
		ret, _, _ := procThread32First.Call(uintptr(snapThread), uintptr(unsafe.Pointer(&tEntry)))
		if ret != 0 {
			sb.WriteString("  TID        BasePriority  DeltaPriority\n")
			for {
				if tEntry.OwnerProcessID == pid {
					threadCount++
					sb.WriteString(fmt.Sprintf("  %-10d %-13d %-13d\n", tEntry.ThreadID, tEntry.BasePri, tEntry.DeltaPri))
				}
				tEntry.Size = uint32(unsafe.Sizeof(tEntry))
				ret, _, _ = procThread32Next.Call(uintptr(snapThread), uintptr(unsafe.Pointer(&tEntry)))
				if ret == 0 {
					break
				}
			}
		}
	}
	sb.WriteString(fmt.Sprintf(" Total Threads: %d\n", threadCount))

	sb.WriteString("\n--------------------------------------------------------------------------------\n")
	sb.WriteString(" LOADED MODULES\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	snapMod, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err == nil {
		defer windows.CloseHandle(snapMod)
		var mEntry MODULEENTRY32W
		mEntry.Size = uint32(unsafe.Sizeof(mEntry))
		ret, _, _ := procModule32FirstW.Call(uintptr(snapMod), uintptr(unsafe.Pointer(&mEntry)))
		if ret != 0 {
			sb.WriteString("  Base Address         Size (KB)   Module Name\n")
			for {
				modName := windows.UTF16ToString(mEntry.Module[:])
				sb.WriteString(fmt.Sprintf("  0x%016X   %-10d  %s\n", mEntry.ModBaseAddr, mEntry.ModBaseSize/1024, modName))
				mEntry.Size = uint32(unsafe.Sizeof(mEntry))
				ret, _, _ = procModule32NextW.Call(uintptr(snapMod), uintptr(unsafe.Pointer(&mEntry)))
				if ret == 0 {
					break
				}
			}
		}
	}

	sb.WriteString("\n--------------------------------------------------------------------------------\n")
	sb.WriteString(" RECENT LOGS (natbypass_debug.log)\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	if logData, err := os.ReadFile("natbypass_debug.log"); err == nil {
		lines := strings.Split(strings.TrimSpace(string(logData)), "\n")
		startIdx := len(lines) - 50
		if startIdx < 0 {
			startIdx = 0
		}
		for _, l := range lines[startIdx:] {
			sb.WriteString("  " + strings.TrimRight(l, "\r\n") + "\n")
		}
	} else {
		sb.WriteString("  (Лог-файл natbypass_debug.log не найден)\n")
	}

	sb.WriteString("================================================================================\n")
	sb.WriteString(" END OF DIAGNOSTIC DUMP\n")
	sb.WriteString("================================================================================\n")

	content := sb.String()
	if err := os.WriteFile(fileName, []byte(content), 0644); err != nil {
		return "", err
	}
	_ = os.WriteFile("natbypass_diagnostic_latest.txt", []byte(content), 0644)

	return fileName, nil
}

// targetProbeWorker runs in an isolated background goroutine.
// It probes target metrics without ever blocking the UI rendering loop.
func targetProbeWorker(ctx context.Context, targetPID uint32, hProc windows.Handle, snapshotHolder *atomic.Pointer[Snapshot]) {
	var lastKernelTime, lastUserTime windows.Filetime
	var lastCheckTime time.Time
	var lastIO IO_COUNTERS
	var cachedHWND uintptr

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		probeStart := time.Now()

		var exitCode uint32
		if err := windows.GetExitCodeProcess(hProc, &exitCode); err != nil || exitCode != 259 {
			snapshotHolder.Store(&Snapshot{
				PID:       targetPID,
				IsAlive:   false,
				ExitCode:  exitCode,
				ProbeTime: time.Now(),
			})
			return
		}

		// Discover or validate cached HWND (without GetWindowTextW)
		isW, _, _ := procIsWindow.Call(cachedHWND)
		if cachedHWND == 0 || isW == 0 {
			cachedHWND = findMainWindow(targetPID)
		}

		// Responsive probe (SMTO_ABORTIFHUNG | SMTO_BLOCK, 200ms timeout)
		uiResponding, uiLatency := checkUIResponsiveness(cachedHWND)

		// CPU times
		var creationTime, exitTime, kernelTime, userTime windows.Filetime
		procGetProcessTimes.Call(
			uintptr(hProc),
			uintptr(unsafe.Pointer(&creationTime)),
			uintptr(unsafe.Pointer(&exitTime)),
			uintptr(unsafe.Pointer(&kernelTime)),
			uintptr(unsafe.Pointer(&userTime)),
		)

		now := time.Now()
		elapsed := now.Sub(lastCheckTime).Seconds()
		cpuPercent := 0.0
		if elapsed > 0 && !lastCheckTime.IsZero() {
			kDiff := (int64(kernelTime.HighDateTime)<<32 + int64(kernelTime.LowDateTime)) - (int64(lastKernelTime.HighDateTime)<<32 + int64(lastKernelTime.LowDateTime))
			uDiff := (int64(userTime.HighDateTime)<<32 + int64(userTime.LowDateTime)) - (int64(lastUserTime.HighDateTime)<<32 + int64(lastUserTime.LowDateTime))
			totalDiffSec := float64(kDiff+uDiff) / 10000000.0
			cpuPercent = (totalDiffSec / elapsed) * 100.0
		}
		lastKernelTime = kernelTime
		lastUserTime = userTime
		lastCheckTime = now

		// Memory
		var memCounters PROCESS_MEMORY_COUNTERS
		memCounters.CB = uint32(unsafe.Sizeof(memCounters))
		procGetProcessMemoryInfo.Call(uintptr(hProc), uintptr(unsafe.Pointer(&memCounters)), uintptr(memCounters.CB))
		ramMB := float64(memCounters.WorkingSetSize) / (1024 * 1024)
		privateMB := float64(memCounters.PagefileUsage) / (1024 * 1024)

		// Handles & Threads
		var handleCount uint32
		procGetProcessHandleCount.Call(uintptr(hProc), uintptr(unsafe.Pointer(&handleCount)))
		threadCount := countProcessThreads(targetPID)

		// Disk IO
		var currentIO IO_COUNTERS
		procGetProcessIoCounters.Call(uintptr(hProc), uintptr(unsafe.Pointer(&currentIO)))
		var readKBPerSec, writeKBPerSec float64
		if elapsed > 0 {
			readKBPerSec = float64(currentIO.ReadTransferCount-lastIO.ReadTransferCount) / 1024.0 / elapsed
			writeKBPerSec = float64(currentIO.WriteTransferCount-lastIO.WriteTransferCount) / 1024.0 / elapsed
		}
		lastIO = currentIO

		// Logs
		logs := readRecentLogs("natbypass_debug.log", 8)

		snapshotHolder.Store(&Snapshot{
			PID:           targetPID,
			HWND:          cachedHWND,
			IsAlive:       true,
			ExitCode:      exitCode,
			UIResponding:  uiResponding,
			UILatency:     uiLatency,
			CPUPercent:    cpuPercent,
			RAMMB:         ramMB,
			PrivateMB:     privateMB,
			HandleCount:   handleCount,
			ThreadCount:   threadCount,
			ReadKBPerSec:  readKBPerSec,
			WriteKBPerSec: writeKBPerSec,
			LastLogs:      logs,
			ProbeTime:     now,
			ProbeDuration: time.Since(probeStart),
		})
	}
}

// keyListener listens for keyboard shortcuts ('S', Space, 'Q', Esc) without blocking.
func keyListener(ctx context.Context, triggerDump chan<- struct{}, cancel context.CancelFunc) {
	var lastSpaceState, lastSState, lastQState int16

	ticker := time.NewTicker(35 * time.Millisecond)
	defer ticker.Stop()

	// Also support line input fallback
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := strings.TrimSpace(strings.ToUpper(scanner.Text()))
			if text == "S" || text == "DUMP" || text == "" {
				select {
				case triggerDump <- struct{}{}:
				default:
				}
			} else if text == "Q" || text == "QUIT" || text == "EXIT" {
				cancel()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Space key (VK_SPACE = 0x20)
		spaceState, _, _ := procGetAsyncKeyState.Call(0x20)
		if (uint32(spaceState)&0x8000 != 0) && (uint32(lastSpaceState)&0x8000 == 0) {
			select {
			case triggerDump <- struct{}{}:
			default:
			}
		}
		lastSpaceState = int16(spaceState)

		// 'S' key (0x53)
		sState, _, _ := procGetAsyncKeyState.Call(0x53)
		if (uint32(sState)&0x8000 != 0) && (uint32(lastSState)&0x8000 == 0) {
			select {
			case triggerDump <- struct{}{}:
			default:
			}
		}
		lastSState = int16(sState)

		// 'Q' key (0x51) or ESC (0x1B)
		qState, _, _ := procGetAsyncKeyState.Call(0x51)
		escState, _, _ := procGetAsyncKeyState.Call(0x1B)
		if (uint32(qState)&0x8000 != 0 && uint32(lastQState)&0x8000 == 0) || (uint32(escState)&0x8000 != 0) {
			cancel()
			return
		}
		lastQState = int16(qState)
	}
}

func main() {
	enableVirtualTerminal()
	fmt.Print("\033[2J\033[H")
	fmt.Println("═════════════════════════════════════════════════════════════════════════")
	fmt.Println("             🛸 NATBYPASS РЕАЛЬНО-ВРЕМЕННОЙ МОНИТОР И ДЕБАГГЕР           ")
	fmt.Println("═════════════════════════════════════════════════════════════════════════")
	fmt.Println("🔍 Поиск активного процесса NatBypass.exe...")

	var pid uint32
	for {
		var err error
		pid, err = findNatBypassPID()
		if err == nil {
			break
		}
		fmt.Print("\r⏳ Ожидание запуска NatBypass.exe...     ")
		time.Sleep(1 * time.Second)
	}

	fmt.Printf("\n✅ Процесс NatBypass.exe найден! PID: %d\n", pid)

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		fmt.Printf("❌ Не удалось открыть дескриптор процесса: %v\n", err)
		return
	}
	defer windows.CloseHandle(hProc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var snapshotHolder atomic.Pointer[Snapshot]
	var notifHolder atomic.Pointer[DiagnosticNotification]

	triggerDump := make(chan struct{}, 5)

	// Launch isolated background probe goroutine
	go targetProbeWorker(ctx, pid, hProc, &snapshotHolder)

	// Launch non-blocking keyboard listener
	go keyListener(ctx, triggerDump, cancel)

	// Launch background diagnostic dump handler
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-triggerDump:
				snap := snapshotHolder.Load()
				var curHWND uintptr
				if snap != nil {
					curHWND = snap.HWND
				}
				fileName, err := dumpDiagnostics(pid, hProc, curHWND)
				if err != nil {
					notifHolder.Store(&DiagnosticNotification{
						Message:     fmt.Sprintf("❌ Ошибка дампа: %v", err),
						ExpireAfter: time.Now().Add(5 * time.Second),
					})
				} else {
					notifHolder.Store(&DiagnosticNotification{
						Message:     fmt.Sprintf("⚡ [DIAGNOSTIC] Дамп сохранен в %s", fileName),
						ExpireAfter: time.Now().Add(6 * time.Second),
					})
				}
			}
		}
	}()

	// UI Rendering Loop: 100% decoupled from target process responsiveness
	renderTicker := time.NewTicker(500 * time.Millisecond)
	defer renderTicker.Stop()

	fmt.Print("\033[2J") // Clear screen once before loop

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n👋 Монитор завершил работу.")
			return
		case <-renderTicker.C:
		}

		snap := snapshotHolder.Load()
		if snap == nil {
			continue
		}

		if !snap.IsAlive {
			fmt.Print("\033[H")
			fmt.Println("═════════════════════════════════════════════════════════════════════════")
			fmt.Println("             🛸 NATBYPASS РЕАЛЬНО-ВРЕМЕННОЙ МОНИТОР И ДЕБАГГЕР           ")
			fmt.Println("═════════════════════════════════════════════════════════════════════════")
			fmt.Printf("\n🛑 Процесс NatBypass.exe (PID %d) завершил работу (ExitCode: %d).\n\n", snap.PID, snap.ExitCode)
			fmt.Println(" Нажмите 'Q' или Esc для выхода.")
			break
		}

		fmt.Print("\033[H")
		fmt.Println("═════════════════════════════════════════════════════════════════════════")
		fmt.Println("             🛸 NATBYPASS РЕАЛЬНО-ВРЕМЕННОЙ МОНИТОР И ДЕБАГГЕР           ")
		fmt.Println("═════════════════════════════════════════════════════════════════════════")

		uiStatus := "🟢 ОТВЕЧАЕТ МГНОВЕННО"
		if snap.HWND == 0 {
			uiStatus = "⚪ ОКНО НЕ НАЙДЕНО / ФОНОВЫЙ РЕЖИМ"
		} else if !snap.UIResponding {
			uiStatus = "🔴 ДЕДЛОК / НЕ ОТВЕЧАЕТ (>200ms)!"
		} else if snap.UILatency > 50*time.Millisecond {
			uiStatus = fmt.Sprintf("🟡 ПОДВИСАЕТ (%v)", snap.UILatency.Round(time.Millisecond))
		}

		fmt.Printf(" [ 🎯 ПРОЦЕСС ] PID: %-7d | Окно HWND: 0x%-8X | Потоков: %d\n", snap.PID, snap.HWND, snap.ThreadCount)
		fmt.Printf(" [ ⚡ СТАТУС UI ] %s (Задержка: %v)\n", uiStatus, snap.UILatency.Round(time.Millisecond))
		fmt.Printf(" [ 📊 РЕСУРСЫ  ] CPU: %5.1f%% | RAM: %5.1f MB (Private: %5.1f MB) | Handles: %d\n", snap.CPUPercent, snap.RAMMB, snap.PrivateMB, snap.HandleCount)
		fmt.Printf(" [ 💾 ДИСК I/O ] Чтение: %6.1f KB/s | Запись: %6.1f KB/s | Probe RTT: %v\n", snap.ReadKBPerSec, snap.WriteKBPerSec, snap.ProbeDuration.Round(time.Microsecond))

		notif := notifHolder.Load()
		if notif != nil && time.Now().Before(notif.ExpireAfter) {
			fmt.Println("─────────────────────────────────────────────────────────────────────────")
			fmt.Printf(" %s\n", notif.Message)
		}

		fmt.Println("─────────────────────────────────────────────────────────────────────────")
		fmt.Println(" 📋 ПОСЛЕДНИЕ СОБЫТИЯ ИЗ ЛОГА natbypass_debug.log:")

		if len(snap.LastLogs) > 0 {
			for _, l := range snap.LastLogs {
				fmt.Printf("  %s\n", l)
			}
		} else {
			fmt.Println("  (Лог-файл еще не создан или пуст)")
		}

		fmt.Println("═════════════════════════════════════════════════════════════════════════")
		fmt.Print(" [Space / S] Сделать Diagnostic Dump • [Q / Esc] Выход • Refresh: 500ms\r")
	}
}
