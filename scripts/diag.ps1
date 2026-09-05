# ==============================================================================
# NatBypass Universal Diagnostic Script for Windows 10 / 11 / Server
# ==============================================================================
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\diag.ps1
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "          NatBypass Universal Network and L3 Diagnostic Tool          " -ForegroundColor Cyan
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

# 1. System and Admin
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

# 3. Wintun Adapters and IP
Log-Section "3. СЕТЕВЫЕ АДАПТЕРЫ WINTUN / NATBYPASS"
$adapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Wintun*" -or $_.InterfaceDescription -like "*NatBypass*" -or $_.Name -like "*NatBypass*" }
$wintunIfIndices = @()
if ($adapters) {
    foreach ($a in $adapters) {
        $wintunIfIndices += $a.ifIndex
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
$routes = Get-NetRoute | Where-Object { ($wintunIfIndices -contains $_.InterfaceIndex) -or $_.DestinationPrefix -like "10.11.12*" -or $_.DestinationPrefix -like "10.123.111*" -or $_.DestinationPrefix -like "100.64.200*" }
if ($routes) {
    foreach ($r in $routes) {
        Log-Ok "Маршрут: $($r.DestinationPrefix) -> ifIndex $($r.InterfaceIndex) (Metric: $($r.RouteMetric))"
    }
} else {
    Log-Warn "Маршруты для mesh-подсети не найдены в таблице маршрутизации!"
}

# 5. Windows Firewall
Log-Section "5. БРАНДМАУЭР WINDOWS"
$rules = Get-NetFirewallRule -DisplayName "*NatBypass*" -ErrorAction SilentlyContinue | Group-Object DisplayName
if ($rules) {
    foreach ($g in $rules) {
        $first = $g.Group[0]
        $count = if ($g.Count -gt 1) { " (всего правил: $($g.Count))" } else { "" }
        Log-Ok "Правило брандмауэра: '$($g.Name)'$count (Enabled: $($first.Enabled), Action: $($first.Action))"
    }
} else {
    Log-Info "Специальные правила NatBypass не найдены (трафик регулируется стандартным профилем)"
}

# 6. Local Daemon API
Log-Section "6. ЛОКАЛЬНЫЙ API ДЕМОНА (HTTP 127.0.0.1:8080)"
$status = $null
$peers = $null
try {
    $status = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/status" -TimeoutSec 3 -ErrorAction Stop
    $myPubIP = if ($status.public_ip) { $status.public_ip } else { "" }
    $myStun = if ($status.stun_addr) { $status.stun_addr } else { "" }
    Log-Ok "API Status: OK"
    Log-Info "  -> DeviceID: $($status.device_id) | Имя: $($status.device_name)"
    Log-Info "  -> Virtual IP: $($status.virtual_ip) | Профиль: $($status.active_profile)"
    Log-Info "  -> Внешний IP: $myPubIP | STUN: $myStun | Версия: $($status.version)"
    $script:lines += "Status: $($status | ConvertTo-Json -Compress)"
    
    $peers = Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/peers" -TimeoutSec 3 -ErrorAction Stop
    Log-Section "7. СПИСОК ПОДКЛЮЧЕННЫХ ПИРОВ"
    if ($peers.data) {
        foreach ($p in $peers.data) {
            $directStr = if ($p.direct_p2p) { "Прямой P2P" } else { "Relay" }
            $pName = if ($p.device_name) { $p.device_name } else { $p.device_id }
            $pingStr = if ($p.ping_ms -gt 0) { "$($p.ping_ms) ms" } else { "N/A" }
            Log-Info "Пир: $pName | VIP: $($p.virtual_ip) | $directStr | EP: $($p.active_endpoint) | Ping: $pingStr"
            if ($p.candidates -and $p.candidates.Count -gt 0) {
                Log-Info "   Кандидаты: $($p.candidates -join ', ')"
            }
        }
        $script:lines += "Peers: $($peers | ConvertTo-Json -Compress)"
    } else {
        Log-Warn "Список пиров пуст (нет активных узлов в сигнальном канале)"
    }
} catch {
    Log-Warn "Локальный API http://127.0.0.1:8080 недоступен: $($_.Exception.Message)"
}

# 8. Deep P2P, NAT, Wi-Fi and TSPU Diagnostics
Log-Section "8. ДИАГНОСТИКА P2P, NAT И ТСПУ (АНАЛИЗ ПРИЧИН RELAY)"

# 8.1. STUN UDP Test
function Test-STUNServer($serverHost, $serverPort, $label) {
    $u = New-Object System.Net.Sockets.UdpClient
    $u.Client.ReceiveTimeout = 2000
    $req = [byte[]](0x00,0x01, 0x00,0x00, 0x21,0x12,0xA4,0x42, 0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0A,0x0B,0x0C)
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($serverHost)
        if ($addrs -and $addrs.Count -gt 0) {
            $ep = New-Object System.Net.IPEndPoint($addrs[0], $serverPort)
            [void]$u.Send($req, $req.Length, $ep)
            $listenEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $resp = $u.Receive([ref]$listenEp)
            if ($resp -and $resp.Length -ge 20) {
                Log-Ok "STUN проба [$label] ($($serverHost):$($serverPort)): УСПЕШНО (UDP доступен)"
                return $true
            }
        }
    } catch {
        Log-Warn "STUN проба [$label] ($($serverHost):$($serverPort)): ТАЙМАУТ / НЕТ ОТВЕТА ($($_.Exception.Message))"
        return $false
    } finally {
        $u.Close()
    }
    return $false
}

$stun1 = Test-STUNServer "stun.l.google.com" 19302 "Google STUN"
$stun2 = Test-STUNServer "stun.cloudflare.com" 3478 "Cloudflare STUN"

if (-not $stun1 -and -not $stun2) {
    Log-Fail "КРИТИЧЕСКАЯ БЛОКИРОВКА: Внешние STUN-серверы недоступны по UDP!"
    Log-Warn "  -> Возможна блокировка протокола UDP на ТСПУ (РКН) или файрвол провайдера."
    Log-Warn "  -> В таких условиях прямой P2P невозможен, связь работает только через WSS/TCP Relay."
}

# 8.2. Peer connectivity and relay root cause analysis
if ($peers -and $peers.data) {
    $myPublicIP = if ($status -and $status.public_ip) { $status.public_ip.Trim() } else { "" }
    
    foreach ($p in $peers.data) {
        $pName = if ($p.device_name) { $p.device_name } else { $p.device_id }
        $pPubIP = if ($p.public_ip) { $p.public_ip.Trim() } else { "" }
        $isDirect = [bool]$p.direct_p2p
        $probes = if ($p.probe_count) { [int]$p.probe_count } else { 0 }
        
        Write-Host "`n  Анализ связности с '$pName' (VIP: $($p.virtual_ip)):" -ForegroundColor Cyan
        
        if ($isDirect) {
            Log-Ok "Прямой P2P установлен (Endpoint: $($p.active_endpoint), Ping: $($p.ping_ms) ms)"
            continue
        }
        
        Log-Warn "Статус: Relay (прямой P2P не подтвержден)"
        
        # Check 1: Same Wi-Fi / NAT Hairpinning
        if ($myPublicIP -and $pPubIP -and ($myPublicIP -eq $pPubIP)) {
            Log-Fail "  [!] ПРИЧИНА [Same Wi-Fi / NAT Hairpinning]:"
            Log-Warn "      Пир '$pName' и этот компьютер имеют ОДИНАКОВЫЙ внешний IP ($myPublicIP)!"
            Log-Info "      -> Они находятся в ОДНОЙ локальной сети / Wi-Fi роутере."
            Log-Info "      -> Роутер блокирует обратный трафик (NAT Loopback / Hairpinning) при обращении к собственному внешнему порту."
            Log-Info "      -> Решение: Убедитесь, что в Wi-Fi сети отключена изоляция клиентов (AP/Client Isolation), и обмен идет по локальным IP (LAN candidates: $(if ($p.candidates){$p.candidates -join ', '}else{'не найдены'}))."
        }
        
        # Check 2: TSPU / DPI / UDP drop
        if ($probes -gt 15) {
            Log-Fail "  [!] ПРИЧИНА [ТСПУ / Блокировка UDP / Закрытый порт]:"
            Log-Warn "      Отправлено $probes UDP-проб пробива NAT, но ни одного ответа не получено!"
            Log-Info "      -> Сигнальные маяки через MQTT доходят (узел виден), но UDP пакеты сбрасываются ТСПУ (DPI) на трансграничном стыке или файрволом."
            Log-Info "      -> Решение: Убедитесь, что у обоих узлов активирован строгий профиль AmneziaWG (AWG 3.1 strict) с обфускацией заголовков (H1..H4, S1..S4, Jc)."
        }
        
        # Check 3: Symmetric NAT
        $pNat = if ($p.nat_type) { $p.nat_type.ToLower() } else { "" }
        if ($pNat -like "*symmetric*") {
            Log-Warn "  [!] ФАКТОР [Symmetric NAT]:"
            Log-Info "      Удаленный узел находится за Symmetric NAT / мобильным CGNAT."
            Log-Info "      Роутер меняет внешний порт для каждого назначения, что препятствует прямому пробиву."
        }
        
        # Check 4: Outdated version
        $pVer = if ($p.version) { $p.version } else { "" }
        if ($pVer -and ($pVer -notmatch "1\.9\.22[12]")) {
            Log-Warn "  [!] ФАКТОР [Устаревшая версия]:"
            Log-Warn "      Пир использует устаревшую версию '$pVer' (текущая: $($status.version))."
            Log-Info "      Рекомендуется обновить оба узла до актуального билда."
        }
        
        # Check 5: AmneziaWG Mismatch
        $pHasAwg = ($p.awg -ne $null -and $p.awg.h1 -ne $null -and $p.awg.h1 -ne "" -and $p.awg.h1 -ne "0")
        $myHasAwg = ($status.awg_enabled -eq $true) -or ($status.awg -ne $null -and $status.awg.h1 -ne $null -and $status.awg.h1 -ne 0 -and $status.awg.h1 -ne "")
        if ($p.awg_mismatch -eq $true) {
            Log-Warn "  [!] ФАКТОР [Рассогласование AmneziaWG]:"
            Log-Warn "      Параметры обфускации (H1-H4/S1-S2) различаются между узлами. Пакеты WireGuard не расшифруются!"
        } elseif ($pHasAwg -ne $myHasAwg) {
            Log-Warn "  [!] ФАКТОР [Рассогласование AmneziaWG]:"
            Log-Warn "      На одном узле обфускация AWG включена, на втором выключена. Зашифрованные пакеты не распознаются!"
        }
    }
}

# 9. ICMP Ping Test
Log-Section "9. СКВОЗНОЙ ТЕСТ ICMP PING ДО ВСЕХ ОБНАРУЖЕННЫХ ПИРОВ"
function Test-PeerPing($ip, $name) {
    $cleanIp = ($ip -split '/')[0].Trim()
    if ([string]::IsNullOrWhiteSpace($cleanIp) -or $cleanIp -eq "0.0.0.0" -or $cleanIp -eq "<nil>") {
        return
    }
    $res = Test-Connection -ComputerName $cleanIp -Count 2 -Quiet -ErrorAction SilentlyContinue
    if ($res) {
        Log-Ok "Ping до $name ($cleanIp): УСПЕШНО (0% потерь)"
        $script:lines += "Ping $cleanIp ($name): SUCCESS"
    } else {
        Log-Fail "Ping до $name ($cleanIp): ПРЕВЫШЕН ИНТЕРВАЛ ОЖИДАНИЯ (100% потерь)"
        $script:lines += "Ping $cleanIp ($name): FAIL"
    }
}

# 1. Self ping
if ($status -and $status.virtual_ip) {
    Test-PeerPing $status.virtual_ip "Локальный узел (Self / Wintun)"
}

# 2. Peer ping
$pingedAny = $false
if ($peers -and $peers.data) {
    foreach ($p in $peers.data) {
        if ($p.virtual_ip -and $p.virtual_ip -ne $status.virtual_ip) {
            $pName = if ($p.device_name) { $p.device_name } else { $p.device_id }
            Test-PeerPing $p.virtual_ip $pName
            $pingedAny = $true
        }
    }
}

# Fallback
if (-not $pingedAny) {
    $myIP = ($status.virtual_ip -split '/')[0].Trim()
    if ($myIP -match '^(\d+\.\d+\.\d+)\.\d+$') {
        $subnetPref = $Matches[1]
        $fallbacks = @("$subnetPref.1", "$subnetPref.2")
        foreach ($fb in $fallbacks) {
            if ($fb -ne $myIP) {
                Test-PeerPing $fb "Mesh узел (Fallback $fb)"
            }
        }
    }
}

$lines | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host "✓ Отчет сохранен в: $reportFile" -ForegroundColor Green
Write-Host "======================================================================`n" -ForegroundColor Green
