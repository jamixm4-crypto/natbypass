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

    Write-Host ">> Скачивание $($Asset.name) ($([math]::Round($Asset.size/1MB, 2)) MB)..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempFile -UserAgent "NatBypass-Win-Updater"

    Write-Host ">> Остановка активных процессов NatBypass..." -ForegroundColor Yellow
    Stop-Process -Name "NatBypass", "NatBypass-GUI" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800

    if (Test-Path $DestFile) {
        Copy-Item -Path $DestFile -Destination "$DestFile.bak" -Force -ErrorAction SilentlyContinue
    }
    Move-Item -Path $TempFile -Destination $DestFile -Force
    Write-Host "✓ Исполняемый файл успешно обновлен: $DestFile" -ForegroundColor Green

    Write-Host ">> Запуск обновленного приложения..." -ForegroundColor Cyan
    Start-Process -FilePath $DestFile
    Write-Host "✓ NatBypass успешно запущен!" -ForegroundColor Green
} catch {
    Write-Host "[!] Ошибка при обновлении: $_" -ForegroundColor Red
    exit 1
}
