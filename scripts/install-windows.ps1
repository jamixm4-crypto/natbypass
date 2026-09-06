# ==============================================================================
#  NatBypass — Universal PowerShell Installer for Windows
#  Usage: irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/install-windows.ps1 | iex
#         irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/install-windows.ps1 | iex -ArgumentList "-Beta"
# ==============================================================================
param(
    [switch]$Beta,
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"
$Repo = "jamixm4-crypto/natbypass"

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "   🚀 NatBypass Universal Windows Installer                   " -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

# Determine installation directory
if (-not $InstallDir) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $InstallDir = "$env:ProgramFiles\NatBypass"
    } else {
        $InstallDir = "$env:LOCALAPPDATA\NatBypass"
    }
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host ">> Каталог установки: $InstallDir" -ForegroundColor Gray

# 1. Fetch release information
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Headers = @{ "User-Agent" = "NatBypass-Win-Installer" }
    
    if ($Beta) {
        Write-Host ">> Поиск последнего BETA-релиза..." -ForegroundColor Yellow
        $ApiUrl = "https://api.github.com/repos/$Repo/releases"
        $releases = Invoke-RestMethod -Uri $ApiUrl -Headers $Headers -TimeoutSec 15
        $release = $releases | Where-Object { -not $_.draft } | Select-Object -First 1
    } else {
        Write-Host ">> Поиск последнего стабильного релиза..." -ForegroundColor Green
        $ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
        $release = Invoke-RestMethod -Uri $ApiUrl -Headers $Headers -TimeoutSec 15
    }

    if (-not $release) {
        throw "Не удалось получить информацию о релизе."
    }

    $tag = $release.tag_name
    Write-Host "✓ Найден релиз: $tag ($($release.name))" -ForegroundColor Green

    # Find Windows exe asset
    $asset = $release.assets | Where-Object { $_.name -like "*NatBypass*windows*amd64*.exe" -or $_.name -eq "NatBypass.exe" } | Select-Object -First 1
    if (-not $asset) {
        $asset = $release.assets | Where-Object { $_.name -like "*.exe" } | Select-Object -First 1
    }

    if (-not $asset) {
        throw "В релизе $tag не найден исполняемый файл для Windows (.exe)."
    }

    $exeTarget = Join-Path $InstallDir "NatBypass.exe"
    $tempExe = Join-Path $env:TEMP "NatBypass_setup_$tag.exe"

    Write-Host ">> Скачивание $($asset.name) ($([math]::Round($asset.size/1MB, 2)) MB)..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tempExe -UseBasicParsing -TimeoutSec 60

    # Stop running processes before replacing
    Stop-Process -Name "NatBypass", "NatBypass-GUI" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    Move-Item -Path $tempExe -Destination $exeTarget -Force
    Write-Host "✓ NatBypass установлен: $exeTarget" -ForegroundColor Green

    # 2. Download official signed Wintun driver
    $wintunTarget = Join-Path $InstallDir "wintun.dll"
    if (-not (Test-Path $wintunTarget)) {
        Write-Host ">> Скачивание официального Wintun драйвера с https://www.wintun.net..." -ForegroundColor Cyan
        try {
            $zipTemp = Join-Path $env:TEMP "wintun-0.14.1.zip"
            $extractTemp = Join-Path $env:TEMP "wintun-0.14.1-extract"
            Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $zipTemp -UseBasicParsing -TimeoutSec 30
            Expand-Archive -Path $zipTemp -DestinationPath $extractTemp -Force
            
            # Select architecture
            $arch = "amd64"
            if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
                $arch = "arm64"
            }
            $archDll = Join-Path $extractTemp "wintun\bin\$arch\wintun.dll"
            if (Test-Path $archDll) {
                Copy-Item $archDll $wintunTarget -Force
                Write-Host "✓ Официальный драйвер Wintun установлен: $wintunTarget" -ForegroundColor Green
            }
            Remove-Item -Path $zipTemp, $extractTemp -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  [i] Wintun будет автоматически загружен приложением при первом запуске: $_" -ForegroundColor Gray
        }
    } else {
        Write-Host "✓ Драйвер Wintun уже присутствует: $wintunTarget" -ForegroundColor Green
    }

    # 3. Create desktop shortcut
    try {
        $wshShell = New-Object -ComObject WScript.Shell
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $shortcut = $wshShell.CreateShortcut((Join-Path $desktopPath "NatBypass.lnk"))
        $shortcut.TargetPath = $exeTarget
        $shortcut.WorkingDirectory = $InstallDir
        $shortcut.Description = "NatBypass P2P Mesh VPN"
        $shortcut.Save()
        Write-Host "✓ Ярлык создан на Рабочем столе" -ForegroundColor Green
    } catch {
        # Optional, non-fatal
    }

    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host " Установка завершена успешно!" -ForegroundColor Green
    Write-Host " Запуск: $exeTarget" -ForegroundColor Green
    Write-Host "==============================================================" -ForegroundColor Green

    # Launch application
    Start-Process -FilePath $exeTarget
} catch {
    Write-Host "[!] Ошибка при установке: $_" -ForegroundColor Red
    exit 1
}
