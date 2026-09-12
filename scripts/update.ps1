# ==============================================================================
#  NatBypass — PowerShell Updater for Windows
#  Usage: irm https://.../scripts/update.ps1 | iex
#         irm https://.../scripts/update.ps1 | iex -ArgumentList "-Beta"
# ==============================================================================
param(
    [switch]$Beta
)

$ErrorActionPreference = "Stop"
$Repo = "jamixm4-crypto/natbypass"

Write-Host "==============================================================" -ForegroundColor Cyan
if ($Beta) {
    Write-Host ">> Обновление NatBypass Windows (Канал: BETA / PRE-RELEASE)" -ForegroundColor Yellow
    $ApiUrl = "https://api.github.com/repos/$Repo/releases"
} else {
    Write-Host ">> Обновление NatBypass Windows (Канал: СТАБИЛЬНЫЙ)" -ForegroundColor Green
    $ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
}
Write-Host "==============================================================" -ForegroundColor Cyan

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Headers = @{ "User-Agent" = "NatBypass-Win-Updater" }
    $ReleaseData = Invoke-RestMethod -Uri $ApiUrl -Headers $Headers -TimeoutSec 15
    if ($Beta) {
        $Release = $ReleaseData | Where-Object { -not $_.draft } | Select-Object -First 1
    } else {
        $Release = $ReleaseData
    }

    $Tag = $Release.tag_name
    Write-Host "✓ Найден релиз: $Tag" -ForegroundColor Green
    Write-Host "  Описание: $($Release.name)" -ForegroundColor Gray

    $Asset = $Release.assets | Where-Object { $_.name -like "*NatBypass*.exe" -or $_.name -eq "NatBypass.exe" } | Select-Object -First 1
    if (-not $Asset) {
        $Asset = $Release.assets | Where-Object { $_.name -like "*.exe" } | Select-Object -First 1
    }

    if (-not $Asset) {
        throw "В релизе $Tag не найден исполняемый файл для Windows (.exe)."
    }

    $DownloadUrl = $Asset.browser_download_url
    $DestDir = $PSScriptRoot
    if (-not $DestDir -or -not (Test-Path $DestDir)) {
        $DestDir = (Get-Process -Name "NatBypass", "NatBypass-GUI" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -First 1 | Split-Path)
    }
    if (-not $DestDir) {
        $DestDir = "$env:ProgramFiles\NatBypass"
        if (-not (Test-Path $DestDir)) { $DestDir = "$env:LOCALAPPDATA\NatBypass" }
    }
    if (-not (Test-Path $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    }

    $DestFile = Join-Path $DestDir "NatBypass.exe"
    $TempFile = Join-Path $env:TEMP "NatBypass_update_$Tag.exe"

    # Ускоренная загрузка (BITS с многопоточной автодокачкой / .NET WebClient / зеркала ghproxy)
    function Download-FileAccelerated {
        param(
            [string]$Url,
            [string]$OutPath
        )
        $CandidateUrls = @($Url)
        if ($Url -like "*github.com/jamixm4-crypto/natbypass/releases/download/*") {
            $CandidateUrls += "https://ghproxy.net/$Url"
            $CandidateUrls += "https://gh-proxy.com/$Url"
        }

        foreach ($dlUrl in $CandidateUrls) {
            # 1. BITS: Многопоточная служба Windows с поддержкой Range, автодокачки и обхода троттлинга
            try {
                if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
                    Write-Host ">> Загрузка через службу Windows BITS: $dlUrl..." -ForegroundColor Cyan
                    Start-BitsTransfer -Source $dlUrl -Destination $OutPath -DisplayName "NatBypass Update" -Priority High -ErrorAction Stop
                    if ((Test-Path $OutPath) -and (Get-Item $OutPath).Length -gt 524288) {
                        return
                    }
                }
            } catch {
                Write-Host "  [i] BITS недоступен или вернул ошибку, переходим к следующему методу..." -ForegroundColor Gray
            }

            # 2. .NET WebClient
            try {
                Write-Host ">> Загрузка через .NET WebClient: $dlUrl..." -ForegroundColor Cyan
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("User-Agent", "NatBypass-Win-Updater")
                $wc.DownloadFile($dlUrl, $OutPath)
                $wc.Dispose()
                if ((Test-Path $OutPath) -and (Get-Item $OutPath).Length -gt 524288) {
                    return
                }
            } catch {
                Write-Host "  [i] WebClient ошибка: $($_.Exception.Message)" -ForegroundColor Gray
            }

            # 3. Invoke-WebRequest fallback
            try {
                Write-Host ">> Резервная загрузка через Invoke-WebRequest: $dlUrl..." -ForegroundColor Cyan
                Invoke-WebRequest -Uri $dlUrl -OutFile $OutPath -UserAgent "NatBypass-Win-Updater" -TimeoutSec 180
                if ((Test-Path $OutPath) -and (Get-Item $OutPath).Length -gt 524288) {
                    return
                }
            } catch {}
        }

        throw "Не удалось скачать исполняемый файл обновления ни из одного источника."
    }

    Download-FileAccelerated -Url $DownloadUrl -OutPath $TempFile

    Write-Host ">> Остановка активных процессов NatBypass..." -ForegroundColor Yellow
    Stop-Process -Name "NatBypass", "NatBypass-GUI" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800

    if (Test-Path $DestFile) {
        Copy-Item -Path $DestFile -Destination "$DestFile.bak" -Force -ErrorAction SilentlyContinue
    }
    Move-Item -Path $TempFile -Destination $DestFile -Force
    Write-Host "✓ Исполняемый файл успешно обновлен: $DestFile" -ForegroundColor Green

    # Проверка наличия официального драйвера Wintun
    $WintunDest = Join-Path $DestDir "wintun.dll"
    if (-not (Test-Path $WintunDest)) {
        Write-Host ">> Скачивание официального драйвера Wintun с https://www.wintun.net..." -ForegroundColor Cyan
        try {
            $zipTemp = Join-Path $env:TEMP "wintun-0.14.1.zip"
            $extractTemp = Join-Path $env:TEMP "wintun-0.14.1-extract"
            Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $zipTemp -UseBasicParsing -TimeoutSec 30
            Expand-Archive -Path $zipTemp -DestinationPath $extractTemp -Force
            $archDll = Join-Path $extractTemp "wintun\bin\amd64\wintun.dll"
            if (Test-Path $archDll) {
                Copy-Item $archDll $WintunDest -Force
                Write-Host "✓ Драйвер Wintun успешно установлен в $WintunDest" -ForegroundColor Green
            }
            Remove-Item -Path $zipTemp, $extractTemp -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  [i] Wintun будет автоматически загружен приложением при старте" -ForegroundColor Gray
        }
    }

    Write-Host ">> Запуск обновленного приложения..." -ForegroundColor Cyan
    Start-Process -FilePath $DestFile
    Write-Host "✓ NatBypass успешно запущен!" -ForegroundColor Green
} catch {
    Write-Host "[!] Ошибка при обновлении: $_" -ForegroundColor Red
    exit 1
}
