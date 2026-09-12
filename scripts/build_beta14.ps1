$ErrorActionPreference = "Stop"
$ProjectRoot = "e:\qwen\fnat"
Set-Location $ProjectRoot

$Version = "v1.9.226-beta14"
$BuildDir = Join-Path $ProjectRoot "build"
$DistDir = Join-Path $ProjectRoot "dist"
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   Building NatBypass $Version Release Binaries      " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Windows AMD64
Write-Host "`n>> Compiling Windows AMD64 binaries..." -ForegroundColor Yellow
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:GOMIPS = $null
$env:GOARM = $null

go build -trimpath -ldflags="-s -w -H=windowsgui -X main.Version=$Version" -o (Join-Path $BuildDir "NatBypass.exe") ./cmd/natbypass
Write-Host "   OK: NatBypass.exe (WebUI + Tray)" -ForegroundColor Green

go build -trimpath -ldflags="-s -w -H=windowsgui -X main.Version=$Version" -o (Join-Path $BuildDir "NatBypass-GUI.exe") ./cmd/natbypass-gui
Write-Host "   OK: NatBypass-GUI.exe (Win32 Pure GUI)" -ForegroundColor Green

go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-cli.exe") ./cmd/natbypass-cli
Write-Host "   OK: natbypass-cli.exe (Console Daemon)" -ForegroundColor Green

go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "NatBypass-Probe.exe") ./cmd/natbypass-probe
Write-Host "   OK: NatBypass-Probe.exe (DPI & Network Probe)" -ForegroundColor Green

go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "NatBypass-Diag.exe") ./cmd/natbypass-diag
Write-Host "   OK: NatBypass-Diag.exe (Cluster Diagnostics)" -ForegroundColor Green

# Copy to root directory so local running/testing immediately runs the new build!
Copy-Item (Join-Path $BuildDir "NatBypass.exe") (Join-Path $ProjectRoot "NatBypass.exe") -Force
Copy-Item (Join-Path $BuildDir "NatBypass-GUI.exe") (Join-Path $ProjectRoot "NatBypass-GUI.exe") -Force
Copy-Item (Join-Path $BuildDir "NatBypass-GUI.exe") (Join-Path $ProjectRoot "NatBypass-gui.exe") -Force
Copy-Item (Join-Path $BuildDir "natbypass-cli.exe") (Join-Path $ProjectRoot "natbypass-cli.exe") -Force
Copy-Item (Join-Path $BuildDir "natbypass-cli.exe") (Join-Path $ProjectRoot "NatBypass-cli.exe") -Force
Copy-Item (Join-Path $BuildDir "NatBypass-Probe.exe") (Join-Path $ProjectRoot "NatBypass-Probe.exe") -Force
Copy-Item (Join-Path $BuildDir "NatBypass-Diag.exe") (Join-Path $ProjectRoot "NatBypass-Diag.exe") -Force
Copy-Item (Join-Path $BuildDir "NatBypass-Diag.exe") (Join-Path $ProjectRoot "natbypass-diag.exe") -Force
Write-Host "   OK: Copied Windows binaries to project root $ProjectRoot" -ForegroundColor Green

# Copy to dist directory
Copy-Item (Join-Path $BuildDir "NatBypass.exe") (Join-Path $DistDir "NatBypass.exe") -Force
Copy-Item (Join-Path $BuildDir "NatBypass-GUI.exe") (Join-Path $DistDir "NatBypass-GUI.exe") -Force
Copy-Item (Join-Path $BuildDir "natbypass-cli.exe") (Join-Path $DistDir "natbypass-cli.exe") -Force
Copy-Item (Join-Path $BuildDir "NatBypass-Probe.exe") (Join-Path $DistDir "natbypass-probe.exe") -Force
Copy-Item (Join-Path $BuildDir "NatBypass-Diag.exe") (Join-Path $DistDir "NatBypass-Diag.exe") -Force

# Copy diag scripts
Copy-Item scripts/diag.ps1 (Join-Path $BuildDir "diag.ps1") -Force
Copy-Item scripts/diag.sh (Join-Path $BuildDir "diag.sh") -Force
Write-Host "   OK: diag.ps1 / diag.sh" -ForegroundColor Green

# 2. Linux AMD64
Write-Host "`n>> Compiling Linux AMD64 binaries..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-linux-amd64") ./cmd/natbypass
go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-probe-linux-amd64") ./cmd/natbypass-probe
Copy-Item (Join-Path $BuildDir "natbypass-linux-amd64") (Join-Path $DistDir "natbypass-linux-amd64") -Force
Write-Host "   OK: natbypass-linux-amd64 & probe" -ForegroundColor Green

# 3. Linux ARM64
Write-Host "`n>> Compiling Linux ARM64 binaries..." -ForegroundColor Yellow
$env:GOARCH = "arm64"
go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-linux-arm64") ./cmd/natbypass
go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-probe-linux-arm64") ./cmd/natbypass-probe
Copy-Item (Join-Path $BuildDir "natbypass-linux-arm64") (Join-Path $DistDir "natbypass-linux-arm64") -Force
Write-Host "   OK: natbypass-linux-arm64 & probe" -ForegroundColor Green

# 4. Linux MIPSLE softfloat (Keenetic & OpenWrt)
Write-Host "`n>> Compiling Linux MIPSLE softfloat (Keenetic/OpenWrt)..." -ForegroundColor Yellow
$env:GOARCH = "mipsle"
$env:GOMIPS = "softfloat"
go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-keenetic-mipsle") ./cmd/natbypass
go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-probe-keenetic-mipsle") ./cmd/natbypass-probe
Copy-Item (Join-Path $BuildDir "natbypass-keenetic-mipsle") (Join-Path $BuildDir "natbypass-router-mipsle") -Force
Copy-Item (Join-Path $BuildDir "natbypass-probe-keenetic-mipsle") (Join-Path $BuildDir "natbypass-probe-router-mipsle") -Force
Copy-Item (Join-Path $BuildDir "natbypass-keenetic-mipsle") (Join-Path $DistDir "natbypass-router-mipsle") -Force
Copy-Item (Join-Path $BuildDir "natbypass-keenetic-mipsle") (Join-Path $DistDir "natbypass-keenetic-mipsle") -Force
Write-Host "   OK: natbypass-keenetic-mipsle & router-mipsle" -ForegroundColor Green

# 5. Linux MIPS softfloat (Big Endian)
Write-Host "`n>> Compiling Linux MIPS softfloat..." -ForegroundColor Yellow
$env:GOARCH = "mips"
$env:GOMIPS = "softfloat"
go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-router-mips") ./cmd/natbypass
Copy-Item (Join-Path $BuildDir "natbypass-router-mips") (Join-Path $DistDir "natbypass-router-mips") -Force
Write-Host "   OK: natbypass-router-mips" -ForegroundColor Green

# 6. Linux ARMv7 (OpenWrt routers)
Write-Host "`n>> Compiling Linux ARMv7 (OpenWrt)..." -ForegroundColor Yellow
$env:GOARCH = "arm"
$env:GOMIPS = $null
$env:GOARM = "7"
go build -trimpath -ldflags="-s -w -X main.Version=$Version" -o (Join-Path $BuildDir "natbypass-openwrt-armv7") ./cmd/natbypass
Copy-Item (Join-Path $BuildDir "natbypass-openwrt-armv7") (Join-Path $BuildDir "natbypass-router-armv7") -Force
Copy-Item (Join-Path $BuildDir "natbypass-openwrt-armv7") (Join-Path $DistDir "natbypass-router-armv7") -Force
Copy-Item (Join-Path $BuildDir "natbypass-openwrt-armv7") (Join-Path $DistDir "natbypass-openwrt-armv7") -Force
Write-Host "   OK: natbypass-openwrt-armv7 & router-armv7" -ForegroundColor Green

# Reset env
[System.Environment]::SetEnvironmentVariable('GOOS', $null)
[System.Environment]::SetEnvironmentVariable('GOARCH', $null)
[System.Environment]::SetEnvironmentVariable('GOMIPS', $null)
[System.Environment]::SetEnvironmentVariable('GOARM', $null)
[System.Environment]::SetEnvironmentVariable('CGO_ENABLED', $null)

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "   BUILD FINISHED SUCCESSFULLY!                      " -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan

Get-ChildItem $BuildDir | Where-Object { -not $_.PSIsContainer } |
    Select-Object Name, @{N="Size (MB)";E={[math]::Round($_.Length/1MB, 2)}}, LastWriteTime |
    Sort-Object LastWriteTime -Descending |
    Format-Table -AutoSize
