<#
.SYNOPSIS
  NatBypass — автоматическая установка Go и сборка проекта
.DESCRIPTION
  Распаковывает Go из soft/ и собирает NatBypass под все платформы.
  Запускать из корня проекта (e:\qwen\fnat\):
    powershell -ExecutionPolicy Bypass -File setup.ps1
#>

param(
    [string]$Target = "all",   # all | linux | windows | router
    [switch]$SkipExtract       # не распаковывать Go (уже есть)
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$SoftDir     = Join-Path $ProjectRoot "soft"
$GoZip       = Join-Path $SoftDir "go1.27.0.windows-amd64.zip"
$GoDir       = Join-Path $SoftDir "go"
$GoExe       = Join-Path $GoDir "bin\go.exe"
$DistDir     = Join-Path $ProjectRoot "dist"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " NatBypass — Setup & Build Script" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ── 1. Распаковка Go ─────────────────────────────────────────
if (-not $SkipExtract) {
    if (-not (Test-Path $GoExe)) {
        if (-not (Test-Path $GoZip)) {
            Write-Host "ОШИБКА: не найден $GoZip" -ForegroundColor Red
            Write-Host "Скачайте вручную: https://go.dev/dl/go1.27.0.windows-amd64.zip"
            exit 1
        }
        Write-Host ">> Распаковка Go из $GoZip..." -ForegroundColor Yellow
        Expand-Archive -Path $GoZip -DestinationPath $SoftDir -Force
        Write-Host "   OK: Go распакован в $GoDir" -ForegroundColor Green
    } else {
        Write-Host ">> Go уже распакован: $GoExe" -ForegroundColor Green
    }
}

# Проверяем Go
$goVersion = & $GoExe version 2>&1
Write-Host ">> Go: $goVersion" -ForegroundColor Green

# ── 2. go mod tidy ───────────────────────────────────────────
Write-Host ""
Write-Host ">> go mod tidy..." -ForegroundColor Yellow
$env:GOPATH = Join-Path $SoftDir "gopath"
New-Item -ItemType Directory -Force -Path $env:GOPATH | Out-Null

& $GoExe mod tidy 2>&1 | Write-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "ОШИБКА: go mod tidy завершился с ошибкой" -ForegroundColor Red
    exit 1
}
Write-Host "   OK: зависимости загружены" -ForegroundColor Green

# ── 3. Функция сборки ────────────────────────────────────────
function Build-Target {
    param($GOOS, $GOARCH, $Extension="", $ExtraEnv=@{})

    $OutName = "natbypass-$GOOS-$GOARCH$Extension"
    $OutPath = Join-Path $DistDir $OutName

    Write-Host "   >> $GOOS/$GOARCH..." -NoNewline

    $buildEnv = @{
        "GOOS"        = $GOOS
        "GOARCH"      = $GOARCH
        "CGO_ENABLED" = "0"
        "GOPATH"      = $env:GOPATH
        "PATH"        = "$GoDir\bin;$env:PATH"
    }
    foreach ($k in $ExtraEnv.Keys) { $buildEnv[$k] = $ExtraEnv[$k] }

    $oldEnv = @{}
    foreach ($k in $buildEnv.Keys) {
        $oldEnv[$k] = [System.Environment]::GetEnvironmentVariable($k)
        [System.Environment]::SetEnvironmentVariable($k, $buildEnv[$k])
    }

    $result = & $GoExe build -trimpath -ldflags="-s -w" -o $OutPath "./cmd/natbypass" 2>&1

    foreach ($k in $oldEnv.Keys) {
        [System.Environment]::SetEnvironmentVariable($k, $oldEnv[$k])
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Host " ОШИБКА" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
        return $false
    }

    $size = [math]::Round((Get-Item $OutPath).Length / 1MB, 1)
    Write-Host " OK ($size МБ)" -ForegroundColor Green
    return $true
}

# ── 4. Сборка ────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
Write-Host ""
Write-Host ">> Сборка: $Target" -ForegroundColor Yellow
Write-Host ""

$ok = $true

switch ($Target) {
    "all" {
        $ok = $ok -and (Build-Target "windows" "amd64" ".exe")
        $ok = $ok -and (Build-Target "linux"   "amd64")
        $ok = $ok -and (Build-Target "linux"   "arm64")
        $ok = $ok -and (Build-Target "linux"   "mips"   "" @{"GOMIPS"="softfloat"})
        $ok = $ok -and (Build-Target "linux"   "mipsle" "" @{"GOMIPS"="softfloat"})
    }
    "linux" {
        $ok = $ok -and (Build-Target "linux" "amd64")
        $ok = $ok -and (Build-Target "linux" "arm64")
    }
    "windows" {
        $ok = $ok -and (Build-Target "windows" "amd64" ".exe")
    }
    "router" {
        $ok = $ok -and (Build-Target "linux" "arm64")
        $ok = $ok -and (Build-Target "linux" "mips"   "" @{"GOMIPS"="softfloat"})
        $ok = $ok -and (Build-Target "linux" "mipsle" "" @{"GOMIPS"="softfloat"})
    }
    default {
        Write-Host "Неизвестная цель: $Target" -ForegroundColor Red
        Write-Host "Доступные: all, linux, windows, router"
        exit 1
    }
}

# ── 5. Итог ──────────────────────────────────────────────────
Write-Host ""
if ($ok) {
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " Сборка завершена успешно!" -ForegroundColor Green
    Write-Host " Бинарники в: $DistDir\" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Get-ChildItem $DistDir | Where-Object { -not $_.PSIsContainer } |
        Select-Object Name, @{N="Размер";E={[math]::Round($_.Length/1MB,1).ToString()+" МБ"}} |
        Format-Table -AutoSize
} else {
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " Сборка завершена с ОШИБКАМИ!" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    exit 1
}
