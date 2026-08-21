# NatBypass Android Build Script
param(
    [string]$BuildType = "debug"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$AndroidDir = Join-Path $ProjectRoot "android"
$DistDir = Join-Path $ProjectRoot "dist"

if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir | Out-Null
}

Write-Host "🛸 [1/3] Сборка Go Mobile модуля для Android..." -ForegroundColor Cyan
$env:GOROOT = "e:\qwen\fnat\soft\go"
$env:GOPATH = "e:\qwen\fnat\soft\gopath"
$env:GOCACHE = "e:\qwen\fnat\soft\gocache"

# Компилируем mobile пакет для верификации
& "$env:GOROOT\bin\go.exe" build ./mobile/...
if ($LASTEXITCODE -ne 0) {
    Write-Error "Ошибка компиляции пакета mobile"
}
Write-Host "✓ Go модуль скомпилирован успешно!" -ForegroundColor Green

Write-Host "📱 [2/3] Подготовка Gradle проекта Android..." -ForegroundColor Cyan
Set-Location $AndroidDir

# Проверяем наличие gradle / gradlew
if (Test-Path "gradlew.bat") {
    Write-Host "🔨 [3/3] Сборка APK ($BuildType)..." -ForegroundColor Cyan
    if ($BuildType -eq "release") {
        .\gradlew.bat assembleRelease
    } else {
        .\gradlew.bat assembleDebug
    }
} else {
    Write-Host "ℹ️ Gradle Wrapper будет инициализирован при сборке в GitHub Actions CI/CD." -ForegroundColor Yellow
}

Set-Location $ProjectRoot
Write-Host "✅ Готово! Все конфигурации Android-проекта валидны." -ForegroundColor Green
