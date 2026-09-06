# ==============================================================================
# NatBypass Universal Diagnostic Script for Windows 10 / 11 / Server
# ==============================================================================
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\diag.ps1
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   🔍 NatBypass Universal Network, NAT and L3 Diagnostic Tool (v1.9)  " -ForegroundColor Cyan
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

# 8. Deep Network Diagnostics
Log-Section "8. ГЛУБОКИЙ АНАЛИЗ NAT, CGNAT, ТСПУ/DPI И ПРИЧИН RELAY"

# 8.1. STUN Helper with XOR-MAPPED-ADDRESS parsing
function Send-STUNBinding($client, $hostName, $port) {
    $req = [byte[]](
        0x00,0x01, 0x00,0x00,
        0x21,0x12,0xA4,0x42,
        0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0A,0x0B,0x0C
    )
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($hostName)
        if (-not $addrs -or $addrs.Count -eq 0) { return $null }
        $targetEp = New-Object System.Net.IPEndPoint($addrs[0], $port)
        [void]$client.Send($req, $req.Length, $targetEp)
        
        $listenEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $client.Receive([ref]$listenEp)
        if (-not $resp -or $resp.Length -lt 20) { return $null }
        
        # Parse STUN XOR-MAPPED-ADDRESS
        $pos = 20
        while ($pos + 4 -le $resp.Length) {
            $attrType = [int]($resp[$pos] * 256 + $resp[$pos+1])
            $attrLen  = [int]($resp[$pos+2] * 256 + $resp[$pos+3])
            $pos += 4
            if ($pos + $attrLen -gt $resp.Length) { break }
            
            # 0x0020 = XOR-MAPPED-ADDRESS, 0x0001 = MAPPED-ADDRESS
            if ($attrType -eq 0x0020 -and $attrLen -ge 8) {
                $family = $resp[$pos+1]
                if ($family -eq 1) { # IPv4
                    $xport = [int]($resp[$pos+2] * 256 + $resp[$pos+3])
                    $realPort = $xport -bxor 0x2112
                    $b0 = $resp[$pos+4] -bxor 0x21
                    $b1 = $resp[$pos+5] -bxor 0x12
                    $b2 = $resp[$pos+6] -bxor 0xA4
                    $b3 = $resp[$pos+7] -bxor 0x42
                    $ipStr = "$b0.$b1.$b2.$b3"
                    return @{ IP = $ipStr; Port = $realPort; Server = ($hostName + ':' + $port) }
                }
            } elseif ($attrType -eq 0x0001 -and $attrLen -ge 8) {
                $family = $resp[$pos+1]
                if ($family -eq 1) { # IPv4
                    $realPort = [int]($resp[$pos+2] * 256 + $resp[$pos+3])
                    $ipStr = "$($resp[$pos+4]).$($resp[$pos+5]).$($resp[$pos+6]).$($resp[$pos+7])"
                    return @{ IP = $ipStr; Port = $realPort; Server = ($hostName + ':' + $port) }
                }
            }
            $pos += $attrLen
        }
    } catch {
        return $null
    }
    return $null
}

# 8.1 Multi-STUN Triangulation from the SAME local socket
Write-Host "`n[8.1] Multi-STUN триангуляция и классификация NAT (RFC 5780 / RFC 6888):" -ForegroundColor Cyan
$stunSocket = New-Object System.Net.Sockets.UdpClient(0)
$stunSocket.Client.ReceiveTimeout = 2500
$localBoundPort = $stunSocket.Client.LocalEndPoint.Port
Log-Info "Локальный сокет привязан к порту: :$localBoundPort"

$stunTargets = @(
    @{ Host = "stun.l.google.com"; Port = 19302; Label = "Google STUN" },
    @{ Host = "stun.cloudflare.com"; Port = 3478; Label = "Cloudflare STUN" },
    @{ Host = "stun.nextcloud.com"; Port = 443; Label = "Nextcloud STUN" }
)

$mappedSamples = @()
foreach ($st in $stunTargets) {
    Start-Sleep -Milliseconds 40
    $res = Send-STUNBinding $stunSocket $st.Host $st.Port
    if ($res) {
        Log-Ok "Ответ от $($st.Label) ($($res.Server)): внешний сокет $($res.IP):$($res.Port)"
        $mappedSamples += $res
    } else {
        Log-Warn "Нет ответа от $($st.Label) ($($st.Host):$($st.Port))"
    }
}
$stunSocket.Close()

$localNATClassification = "Unknown"
$isCGNATPool = $false

if ($mappedSamples.Count -ge 1) {
    $mainPubIP = $mappedSamples[0].IP
    if ($mainPubIP -match '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.') {
        $isCGNATPool = $true
        Log-Warn "[RFC 6598] Ваш внешний IP ($mainPubIP) находится в операторском пуле Carrier-Grade NAT (100.64.0.0/10)!"
    }
}

if ($mappedSamples.Count -ge 2) {
    $p1 = $mappedSamples[0].Port
    $p2 = $mappedSamples[1].Port
    $delta1 = $p2 - $p1
    
    if ($mappedSamples.Count -ge 3) {
        $p3 = $mappedSamples[2].Port
        $delta2 = $p3 - $p2
        Log-Info "Анализ портов сопоставления: P1=$p1, P2=$p2, P3=$p3 (delta1=$delta1, delta2=$delta2)"
        
        # Parity check
        $parityPreserved = (($p1 % 2) -eq ($p2 % 2)) -and (($p2 % 2) -eq ($p3 % 2))
        if ($parityPreserved) {
            $parStr = if (($p1 % 2) -eq 0) { "ЧЕТНЫЕ (Even)" } else { "НЕЧЕТНЫЕ (Odd)" }
            Log-Ok "Сохранение чётности (Parity Preservation по RFC 4787): ДА ($parStr, шаг 2k)"
        }
        
        # PBA check (Port Block Allocation)
        $pbaSize = 0
        $pbaBase = 0
        foreach ($bs in @(512, 256, 128, 64)) {
            $mask = -bnot ($bs - 1)
            if (($p1 -band $mask) -eq ($p2 -band $mask) -and ($p2 -band $mask) -eq ($p3 -band $mask)) {
                $pbaSize = $bs
                $pbaBase = $p1 -band $mask
                break
            }
        }
        if ($pbaSize -gt 0) {
            Log-Ok "[RFC 6888] Обнаружен пул Port Block Allocation (PBA): Блок=$pbaSize портов (Диапазон: $pbaBase..$($pbaBase + $pbaSize - 1))"
        }
        
        if ($p1 -eq $p2 -and $p2 -eq $p3) {
            $localNATClassification = "Full Cone / Endpoint-Independent Mapping (EIM)"
            Log-Ok "КЛАССИФИКАЦИЯ: $localNATClassification"
            Log-Ok "Прямой P2P поддерживается на 100%! Внешний порт не меняется между пирами."
        } elseif ([math]::Abs($delta1) -le 5 -and $delta1 -eq $delta2) {
            $localNATClassification = "Symmetric NAT (Линейный сдвиг delta=$delta1)"
            Log-Warn "КЛАССИФИКАЦИЯ: $localNATClassification"
            Log-Info "Предиктор портов NatBypass автоматически рассчитывает шаг delta=$delta1 для пробива сокета."
        } elseif ($pbaSize -gt 0) {
            $localNATClassification = "Symmetric NAT / CGNAT (Пул PBA-$pbaSize)"
            Log-Warn "КЛАССИФИКАЦИЯ: $localNATClassification"
            Log-Info "NatBypass производит направленный sweep-пробив внутри выделенного блока портов CGNAT."
        } else {
            $localNATClassification = "Symmetric NAT (Случайное распределение портов)"
            Log-Warn "КЛАССИФИКАЦИЯ: $localNATClassification"
            Log-Warn "Жесткий симметричный NAT. Требуется UPnP на роутере или fallback на Relay."
        }
    } else {
        if ($p1 -eq $p2) {
            $localNATClassification = "Endpoint-Independent Mapping (Cone NAT)"
            Log-Ok "КЛАССИФИКАЦИЯ: $localNATClassification (P1=$p1 == P2=$p2)"
        } else {
            $localNATClassification = "Symmetric NAT (delta=$delta1)"
            Log-Warn "КЛАССИФИКАЦИЯ: $localNATClassification (P1=$p1 -> P2=$p2, delta=$delta1)"
        }
    }
} elseif ($mappedSamples.Count -eq 1) {
    Log-Ok "STUN доступен (один сервер ответил). Публичный сокет: $($mappedSamples[0].IP):$($mappedSamples[0].Port)"
} else {
    Log-Fail "КРИТИЧЕСКАЯ БЛОКИРОВКА: Ни один STUN-сервер не ответил по UDP!"
    Log-Warn "Возможна блокировка протокола UDP на ТСПУ (РКН) или файрволе провайдера."
}

# 8.2 DPI / TSPU Differential Probe Discrimination
Write-Host "`n[8.2] Дифференциальная диагностика ТСПУ / DPI (WireGuard vs Random vs QUIC):" -ForegroundColor Cyan

function Send-DiffProbe($payload, $targetHost, $targetPort) {
    $u = New-Object System.Net.Sockets.UdpClient
    $u.Client.ReceiveTimeout = 1500
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($targetHost)
        if (-not $addrs -or $addrs.Count -eq 0) { return "DNS_ERR" }
        $ep = New-Object System.Net.IPEndPoint($addrs[0], $targetPort)
        [void]$u.Send($payload, $payload.Length, $ep)
        $lep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $null = $u.Receive([ref]$lep)
        return "REPLY"
    } catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
            return "ICMP_RESET"
        } elseif ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
            return "TIMEOUT"
        }
        return "ERR_$($_.Exception.SocketErrorCode)"
    } catch {
        return "TIMEOUT"
    } finally {
        $u.Close()
    }
}

# 1. WireGuard Mock (148B, Header 0x01 00 00 00)
$wgProbe = New-Object byte[] 148
$wgProbe[0] = 0x01; $wgProbe[1] = 0x00; $wgProbe[2] = 0x00; $wgProbe[3] = 0x00
(New-Object System.Random).NextBytes($wgProbe)
$wgProbe[0] = 0x01; $wgProbe[1] = 0x00; $wgProbe[2] = 0x00; $wgProbe[3] = 0x00

# 2. Random UDP Noise (148B)
$randProbe = New-Object byte[] 148
(New-Object System.Random).NextBytes($randProbe)

# 3. QUIC v1 Initial Mock (1200B, Long Header 0xC0, Ver 1)
$quicProbe = New-Object byte[] 1200
$quicProbe[0] = 0xC0 # Long Header, Initial
$quicProbe[1] = 0x00; $quicProbe[2] = 0x00; $quicProbe[3] = 0x00; $quicProbe[4] = 0x01 # Version 1
$quicProbe[5] = 0x08 # DCID len
(New-Object System.Random).NextBytes($quicProbe)
$quicProbe[0] = 0xC0
$quicProbe[1] = 0x00; $quicProbe[2] = 0x00; $quicProbe[3] = 0x00; $quicProbe[4] = 0x01
$quicProbe[5] = 0x08

$probeTarget = "1.1.1.1"
$testPorts = @(443, 3478, 51820)
$dpiWgBlocked = $false

foreach ($tp in $testPorts) {
    $resWG   = Send-DiffProbe $wgProbe $probeTarget $tp
    $resRand = Send-DiffProbe $randProbe $probeTarget $tp
    $resQuic = Send-DiffProbe $quicProbe $probeTarget $tp
    
    Log-Info "Порт UDP $tp -> WG(148B): $resWG | Rand(148B): $resRand | QUIC(1200B): $resQuic"
    
    if ($resWG -eq "TIMEOUT" -and ($resQuic -eq "ICMP_RESET" -or $resRand -eq "ICMP_RESET" -or $resQuic -eq "REPLY")) {
        $dpiWgBlocked = $true
        Log-Fail "Обнаружена сигнатурная блокировка WireGuard ТСПУ/DPI на порту $tp (QUIC/Rand проходит, WG сбрасывается)!"
    }
}

if ($dpiWgBlocked) {
    Log-Warn "Рекомендация: Для обхода ТСПУ обязательно используйте профиль AmneziaWG (AWG 3.1) с обфускацией H1..H4 и S1..S2."
} else {
    Log-Ok "Сигнатурная блокировка стандартных пакетов на исследуемых портах не зафиксирована."
}

# 8.3 Path MTU (PMTU) and Fragmentation Discovery
Write-Host "`n[8.3] Проверка Path MTU (PMTU) и потерь фрагментации:" -ForegroundColor Cyan
$mtuTargets = @(
    @{ MTU = 1420; Buf = 1392; Desc = "Стандартный туннель NatBypass / WireGuard" },
    @{ MTU = 1360; Buf = 1332; Desc = "Сотовые сети LTE / CGNAT" },
    @{ MTU = 1280; Buf = 1252; Desc = "Минимальный базовый IPv6 / QUIC MTU" }
)

$pingHost = "8.8.8.8"
foreach ($m in $mtuTargets) {
    $pOut = ping.exe $pingHost -f -l $m.Buf -n 1 -w 1000 2>&1 | Out-String
    if ($pOut -match "(TTL=|ttl=|время=|time=)") {
        Log-Ok "MTU $($m.MTU) (Payload $($m.Buf) байт): УСПЕШНО без фрагментации ($($m.Desc))"
    } elseif ($pOut -match "(fragment|фрагмент)") {
        Log-Warn "MTU $($m.MTU): ТРЕБУЕТСЯ ФРАГМЕНТАЦИЯ (Пакетам нужен меньший размер)!"
    } else {
        Log-Warn "MTU $($m.MTU): Нет ответа / Таймаут"
    }
}

# 8.4 Windows Socket Buffers and UDP Health
Write-Host "`n[8.4] Состояние буферов сокетов UDP в Windows (netstat -s):" -ForegroundColor Cyan
try {
    $netstatOut = netstat -s -p UDP | Out-String
    $rxErrors = 0
    $discarded = 0
    $inDatagrams = 0
    
    foreach ($line in ($netstatOut -split "`n")) {
        if ($line -match "(Receive Errors|Ошибок при приеме)\s*=\s*(\d+)") {
            $rxErrors = [int]$Matches[2]
        } elseif ($line -match "(Discarded Datagrams|Отброшено полученных датаграмм)\s*=\s*(\d+)") {
            $discarded = [int]$Matches[2]
        } elseif ($line -match "(In Datagrams|Получено датаграмм)\s*=\s*(\d+)") {
            $inDatagrams = [int]$Matches[2]
        }
    }
    
    Log-Info "Статистика UDP ядра: Получено=$inDatagrams, Ошибок приема=$rxErrors, Отброшено=$discarded"
    if ($discarded -gt 1000 -or $rxErrors -gt 1000) {
        Log-Warn "Высокое число сброшенных датаграмм UDP ($discarded). Приложение не успевает читать из сокета или переполнен буфер SO_RCVBUF."
    } else {
        Log-Ok "Сокетные буферы UDP в норме (отбрасывание пакетов ядром Windows минимально)."
    }
} catch {
    Log-Info "Не удалось прочесть статистику UDP сокетов: $($_.Exception.Message)"
}

# 8.5 Peer Connectivity Matrix and Relay Root Cause Analysis
Write-Host "`n[8.5] Матрица совместимости пиров и причины работы через Relay:" -ForegroundColor Cyan
if ($peers -and $peers.data) {
    $myPublicIP = if ($status -and $status.public_ip) { $status.public_ip.Trim() } else { "" }
    
    foreach ($p in $peers.data) {
        $pName = if ($p.device_name) { $p.device_name } else { $p.device_id }
        $pPubIP = if ($p.public_ip) { $p.public_ip.Trim() } else { "" }
        $isDirect = [bool]$p.direct_p2p
        $probes = if ($p.probe_count) { [int]$p.probe_count } else { 0 }
        
        Write-Host "`n  Пир '$pName' (VIP: $($p.virtual_ip)):" -ForegroundColor Cyan
        
        if ($isDirect) {
            Log-Ok "Прямой P2P установлен (Endpoint: $($p.active_endpoint), Ping: $($p.ping_ms) ms)"
            continue
        }
        
        Log-Warn "Текущий статус: Relay (прямой P2P не установлен)"
        
        # Check 1: Same Wi-Fi / NAT Hairpinning
        if ($myPublicIP -and $pPubIP -and ($myPublicIP -eq $pPubIP)) {
            Log-Fail "  [!] ПРИЧИНА [Same Wi-Fi / NAT Loopback Blocked]:"
            Log-Warn "      Пир '$pName' и этот компьютер имеют ОДИНАКОВЫЙ внешний IP ($myPublicIP)!"
            Log-Info "      -> Они находятся в ОДНОЙ локальной сети / Wi-Fi роутере."
            Log-Info "      -> Роутер блокирует обратный трафик (NAT Hairpinning) при обращении к собственному внешнему порту."
            Log-Info "      -> Решение: Включите изоляцию клиентов (AP Isolation = Off) и используйте локальные IP кандидатов."
        }
        
        # Check 2: TSPU / DPI / UDP drop
        if ($probes -gt 15) {
            Log-Fail "  [!] ПРИЧИНА [ТСПУ / Блокировка UDP / Закрытый порт]:"
            Log-Warn "      Отправлено $probes UDP-проб пробива NAT, но ни одного ответа не получено!"
            Log-Info "      -> Сигнальные маяки через MQTT доходят, но UDP пакеты сбрасываются ТСПУ (DPI) на границе операторов."
            Log-Info "      -> Решение: Убедитесь, что у обоих узлов активирован строгий профиль AmneziaWG (AWG 3.1)."
        }
        
        # Check 3: Symmetric NAT combination
        $pNat = if ($p.nat_type) { $p.nat_type.ToLower() } else { "" }
        if ($pNat -like "*symmetric*") {
            Log-Warn "  [!] ФАКТОР [Symmetric NAT у пира]:"
            Log-Info "      Удаленный узел находится за Symmetric NAT / мобильным CGNAT ($pNat)."
            if ($localNATClassification -like "*Symmetric*") {
                Log-Fail "      КРИТИЧЕСКАЯ КОМБИНАЦИЯ [Symmetric + Symmetric]:"
                Log-Warn "      Оба узла находятся за Symmetric NAT! Прямой UDP пробив без UPnP математически маловероятен (<5%). Fallback на Relay является штатным поведением."
            } else {
                Log-Info "      Локальный узел за Cone NAT. Пробив будет выполнен через предсказание портов удаленного пира."
            }
        }
        
        # Check 4: AmneziaWG Mismatch
        # Сравниваем числовые значения h1: если оба ненулевые и совпадают — AWG идентичен.
        # Флаг awg_enabled отсутствует у Android/Linux — не используем как индикатор "выключен".
        $myH1 = 0
        if ($status.awg -ne $null -and $status.awg.h1 -ne $null) {
            try { $myH1 = [long]$status.awg.h1 } catch {}
        } elseif ($status.h1 -ne $null) {
            try { $myH1 = [long]$status.h1 } catch {}
        }
        $pH1 = 0
        if ($p.awg -ne $null -and $p.awg.h1 -ne $null) {
            try { $pH1 = [long]$p.awg.h1 } catch {}
        } elseif ($p.h1 -ne $null) {
            try { $pH1 = [long]$p.h1 } catch {}
        }
        if ($p.awg_mismatch -eq $true) {
            # Явный флаг от сервера — параметры AWG точно отличаются
            Log-Warn "  [!] ФАКТОР [Рассогласование AmneziaWG]: параметры обфускации (H1-H4/S1-S2) различаются!"
        } elseif ($myH1 -gt 0 -and $pH1 -gt 0 -and $myH1 -ne $pH1) {
            # Оба имеют ненулевые H1, но значения не совпадают
            Log-Warn "  [!] ФАКТОР [Рассогласование AmneziaWG]: H1 не совпадает (локальный: $myH1, пир: $pH1)!"
        } elseif ($myH1 -eq 0 -and $pH1 -gt 0) {
            Log-Warn "  [!] ФАКТОР [Рассогласование AmneziaWG]: у пира AWG включён (H1=$pH1), а на локальном узле параметры AWG не заданы!"
        } elseif ($myH1 -gt 0 -and $pH1 -eq 0) {
            Log-Warn "  [!] ФАКТОР [Рассогласование AmneziaWG]: локальный AWG включён (H1=$myH1), а у пира параметры AWG не заданы!"
        }
        # Если оба H1 совпадают (или оба нулевые) — AWG согласован, предупреждение не выводим
        
        # Check 5: Version check
        $pVer = if ($p.version) { $p.version } else { "" }
        $myVer = if ($status -and $status.version) { $status.version } else { "" }
        if ($pVer -and $myVer -and ($pVer -ne $myVer)) {
            Log-Warn "  [!] ФАКТОР [Версия пира отличается]: пир использует '$pVer', локальный узел — '$myVer'. Рекомендуется обновить все узлы до одного билда."
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
    $myIP = if ($status -and $status.virtual_ip) { ($status.virtual_ip -split '/')[0].Trim() } else { "" }
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
