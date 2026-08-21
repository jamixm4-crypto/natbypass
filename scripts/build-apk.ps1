param(
    [string]$Target = "all" # all, bin, aar, apk
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path (Split-Path $MyInvocation.MyCommand.Path)
$DistDir = Join-Path $ProjectRoot "dist"
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$GoExe = "go"
if (Test-Path "$ProjectRoot\soft\go\bin\go.exe") {
    $GoExe = "$ProjectRoot\soft\go\bin\go.exe"
    $env:GOROOT = "$ProjectRoot\soft\go"
    $env:GOPATH = "$ProjectRoot\soft\gopath"
    $env:PATH = "$env:GOROOT\bin;$env:PATH"
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ">> Сборка NatBypass для Android" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Standalone Android ARM64 binary (для Termux, Magisk, ADB Shell)
if ($Target -eq "all" -or $Target -eq "bin") {
    Write-Host "`n[1/3] Сборка Android ARM64 бинарника (Termux / ADB / Root)..." -ForegroundColor Yellow
    $env:CGO_ENABLED = "0"
    $env:GOOS = "android"
    $env:GOARCH = "arm64"
    $binOut = Join-Path $DistDir "natbypass-android-arm64"
    & $GoExe build -trimpath -ldflags="-s -w" -o $binOut "./cmd/natbypass-cli"
    if ($LASTEXITCODE -eq 0) {
        $sz = [math]::Round((Get-Item $binOut).Length / 1MB, 2)
        Write-Host "   ✓ Успешно: dist\natbypass-android-arm64 ($sz MB)" -ForegroundColor Green
    }
}

# 2. Android Archive (.aar) библиотека через gomobile bind (для Android Studio)
if ($Target -eq "all" -or $Target -eq "aar") {
    Write-Host "`n[2/3] Сборка Android AAR библиотеки (для Kotlin/Java приложений)..." -ForegroundColor Yellow
    if (Get-Command gomobile -ErrorAction SilentlyContinue) {
        $aarOut = Join-Path $DistDir "natbypass.aar"
        & gomobile bind -target=android/arm64,android/arm,android/amd64 -o $aarOut "./pkg/mobile"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✓ Успешно: dist\natbypass.aar" -ForegroundColor Green
        }
    } else {
        Write-Host "   ℹ Gomobile не найден в PATH. Для сборки .aar: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init" -ForegroundColor Gray
    }
}

# 3. Полный Android APK пакет
if ($Target -eq "all" -or $Target -eq "apk") {
    Write-Host "`n[3/3] Сборка Android APK пакета (gomobile build)..." -ForegroundColor Yellow
    if (Get-Command gomobile -ErrorAction SilentlyContinue -and $env:ANDROID_HOME) {
        $apkOut = Join-Path $DistDir "natbypass.apk"
        & gomobile build -target=android/arm64 -o $apkOut "./cmd/natbypass-cli"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✓ Успешно: dist\natbypass.apk" -ForegroundColor Green
        }
    } else {
        Write-Host "   ℹ Для сборки .apk требуется Android SDK / NDK (переменная ANDROID_HOME / ANDROID_NDK_HOME)." -ForegroundColor Gray
        Write-Host "   ℹ Готовый автономный бинарник для Android доступен: dist\natbypass-android-arm64" -ForegroundColor Cyan
    }
}

Write-Host "`n✓ Завершено! Все собранные файлы находятся в папке dist\" -ForegroundColor Green