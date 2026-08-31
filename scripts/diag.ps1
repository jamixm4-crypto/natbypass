# ==============================================================================
# NatBypass Universal Diagnostic Script for Windows 10 / 11 / Server
# ==============================================================================
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\diag.ps1
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "          🔍 NatBypass Universal Network & L3 Diagnostic Tool         " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$reportFile = "$env:TEMP\natbypass_diag_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$lines = @()
$lines += "=== NatBypass Windows Diagnostic Report ==="
$lines += "Timestamp: $(Get-Date -Format 'o')"

function Log-Section($title) {
    Write-Host "`n▶ $title" -ForegroundColor Blue
    $script:lines += "`n--- $title ---"
}
function Log-Ok($msg) {
    Write-Host "  [✓] $msg" -ForegroundColor Green
    $script:lines += "  [OK] $msg"
}
function Log-Warn($msg) {
    Write-Host "  [!] $msg" -ForegroundColor Yellow
    $script:lines += "  [WARN] $msg"
}
function Log-Fail($msg) {
    Write-Host "  [✗] $msg" -ForegroundColor Red
    $script:lines += "  [FAIL] $msg"
}
function Log-Info($msg) {
    Write-Host "  [i] $msg" -ForegroundColor DarkCyan
    $script:lines += "  [INFO] $msg"
}

# 1. System & Admin
Log-Section "1. СИСТЕМНОЕ ОКРУЖЕНИЕ WINDOWS"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Log-Ok "Права Администратора: ДА (Elevated)"
} else {
    Log-Warn "Права Администратора: НЕТ (Рекомендуется запуск от имени Администратора)"
}
$osInfo = (Get-CimInstance Win32_OperatingSystem).Caption
Log-Info "ОС: $osInfo ($env:PROCESSOR_ARCHITECTURE)"

# 2. Process Check
Log-Section "2. СОСТОЯНИЕ ПРОЦЕССА NATBYPASS"
$procs = Get-Process -Name "*natbypass*" -ErrorAction SilentlyContinue
if ($procs) {
    foreach ($p in $procs) {
        Log-Ok "Процесс $($p.ProcessName) активен (PID: $($p.Id), CPU: $($p.CPU)s, RAM: $([math]::Round($p.WorkingSet64/1MB, 1)) MB)"
    }
} else {
    Log-Warn "Процесс NatBypass НЕ запущен!"
}

# 3. Wintun Adapters & IP
Log-Section "3. СЕТЕВЫЕ АДАПТЕРЫ WINTUN / NATBYPASS"
$adapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Wintun*" -or $_.InterfaceDescription -like "*NatBypass*" -or $_.Name -like "*NatBypass*" }
if ($adapters) {
    foreach ($a in $adapters) {
        if ($a.Status -eq "Up") {
            Log-Ok "Адаптер '$($a.Name)' (ifIndex $($a.ifIndex)): СТАТУС UP (Активен)"
            $ips = Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
            foreach ($ip in $ips) {
                Log-Info "  -> IP: $($ip.IPAddress)/$($ip.PrefixLength) (State: $($ip.AddressState))"
            }
        } else {
            Log-Warn "Адаптер '$($a.Name)' (ifIndex $($a.ifIndex)): СТАТУС $($a.Status)"
        }
    }
} else {
    Log-Fail "Сетевые адаптеры Wintun / NatBypass не найдены!"
}

# 4. Routes
Log-Section "4. ТАБЛИЦА МАРШРУТИЗАЦИИ ДЛЯ MESH ПОДСЕТЕЙ"
$routes = Get-NetRoute | Where-Object { $_.DestinationPrefix -like "10.123.111*" -or $_.DestinationPrefix -like "100.64.200*" }
if ($routes) {
    foreach ($r in $routes) {
        Log-Ok "Маршрут: $($r.DestinationPrefix) -> ifIndex $($r.InterfaceIndex) (Metric: $($r.RouteMetric))"
    }
} else {
    Log-Warn "Маршруты для 10.123.111.0/24 или 100.64.200.0/24 не найдены в таблице маршрутизации!"
}

# 5. Windows Firewall
Log-Section "5. БРАНДМАУЭР WINDOWS"
$rules = Get-NetFirewallRule -DisplayName "*NatBypass*" -ErrorAction SilentlyContinue
if ($rules) {
    foreach ($r in $rules) {
        Log-Ok "Правило брандмауэра: '$($r.DisplayName)' (Enabled: $($r.Enabled), Action: $($r.Action))"
    }
} else {
    Log-Info "Специальные правила NatBypass не найдены (трафик регулируется стандартным профилем)"
}

# 6. Local Daemon API
Log-Section "6. ЛОКАЛЬНЫЙ API ДЕМОНА (HTTP 127.0.0.1:8080)"
try {
    $status = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/status" -TimeoutSec 3 -ErrorAction Stop
    Log-Ok "API Status: OK (DeviceID: $($status.device_id), VirtualIP: $($status.virtual_ip), Port: $($status.wg_port))"
    $script:lines += "Status: $($status | ConvertTo-Json -Compress)"
    
    $peers = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/peers" -TimeoutSec 3 -ErrorAction Stop
    Log-Section "7. СПИСОК ПОДКЛЮЧЕННЫХ ПИРОВ"
    if ($peers.data) {
        foreach ($p in $peers.data) {
            $directStr = if ($p.direct_p2p) { "🟢 Прямой P2P" } else { "📡 Relay" }
            Log-Info "Пир: $($p.device_name) ($($p.device_id)) | VIP: $($p.virtual_ip) | $directStr | EP: $($p.active_endpoint) | Ping: $($p.ping_ms) ms"
        }
        $script:lines += "Peers: $($peers | ConvertTo-Json -Compress)"
    } else {
        Log-Warn "Список пиров пуст (нет активных узлов в сигнальном канале)"
    }
} catch {
    Log-Warn "Локальный API http://127.0.0.1:8080 недоступен: $($_.Exception.Message)"
}

# 7. ICMP Ping Test
Log-Section "8. СКВОЗНОЙ ТЕСТ ICMP PING ДО УЗЛОВ"
function Test-PeerPing($ip, $name) {
    $res = Test-Connection -ComputerName $ip -Count 3 -Quiet -ErrorAction SilentlyContinue
    if ($res) {
        Log-Ok "Ping до $name ($ip): УСПЕШНО (0% потерь)"
        $script:lines += "Ping $ip ($name): SUCCESS"
    } else {
        Log-Fail "Ping до $name ($ip): ПРЕВЫШЕН ИНТЕРВАЛ ОЖИДАНИЯ (100% потерь)"
        $script:lines += "Ping $ip ($name): FAIL"
    }
}

Test-PeerPing "10.123.111.1" "Keenetic (Router)"
Test-PeerPing "10.123.111.2" "Linux (Nextcloud)"
Test-PeerPing "10.123.111.110" "Windows (Local)"

$lines | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host "✓ Отчет сохранен в: $reportFile" -ForegroundColor Green
Write-Host "======================================================================`n" -ForegroundColor Green