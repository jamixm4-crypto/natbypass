param(
    [string]$Target = "",
    [switch]$Unattended,
    [string]$TgToken    = "",
    [string]$TgChatID   = "",
    [string]$MQTTBroker = "",
    [string]$MQTTTopic  = "",
    [string]$WebhookURL = "",
    [string]$DeviceID   = "",
    [string]$WebUIPort  = "8080",
    [string]$WebUIUser  = "admin",
    [string]$WebUIPass  = "",
    [string]$LogLevel   = "info"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$SoftDir     = Join-Path $ProjectRoot "soft"
$GoExe       = Join-Path $SoftDir "go\bin\go.exe"
$GoPath      = Join-Path $SoftDir "gopath"
$DistDir     = Join-Path $ProjectRoot "dist"
$Module      = "github.com/natbypass/natbypass"
$Cmd         = "./cmd/natbypass"

function Write-Header { Write-Host $args -ForegroundColor Cyan }
function Write-Step   { Write-Host ">> $args" -ForegroundColor Yellow }
function Write-OK     { Write-Host "   OK: $args" -ForegroundColor Green }
function Write-Err    { Write-Host "   ERROR: $args" -ForegroundColor Red }
function Write-Info   { Write-Host "   $args" -ForegroundColor Gray }

function Prompt-Value {
    param([string]$Label, [string]$Default = "", [switch]$Secret)
    $hint = if ($Default) { " [$Default]" } else { "" }
    Write-Host "  $Label$hint : " -NoNewline -ForegroundColor White
    if ($Secret) {
        $secure = Read-Host -AsSecureString
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
        if ([string]::IsNullOrEmpty($plain) -and -not [string]::IsNullOrEmpty($Default)) { return $Default }
        return $plain
    } else {
        $val = Read-Host
        if ([string]::IsNullOrEmpty($val) -and -not [string]::IsNullOrEmpty($Default)) { return $Default }
        return $val
    }
}

function Prompt-Choice {
    param([string]$Label, [string[]]$Options, [string]$Default)
    Write-Host ""
    Write-Host "  $Label" -ForegroundColor White
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $mark = if ($Options[$i] -eq $Default) { " *" } else { "  " }
        Write-Host "$mark  $($i+1). $($Options[$i])" -ForegroundColor Gray
    }
    Write-Host "  Choice [Enter = $Default]: " -NoNewline -ForegroundColor White
    $in = Read-Host
    if ([string]::IsNullOrEmpty($in)) { return $Default }
    $idx = 0
    if ([int]::TryParse($in, [ref]$idx)) {
        $idx = $idx - 1
        if ($idx -ge 0 -and $idx -lt $Options.Count) { return $Options[$idx] }
    }
    return $Default
}

Write-Host ""
Write-Header "======================================================"
Write-Header "       NatBypass - Cross-Platform Builder (Windows)   "
Write-Header "======================================================"
Write-Host ""

Write-Step "Checking Go toolchain in soft/go..."
if (-not (Test-Path $GoExe)) {
    $GoZip = Join-Path $SoftDir "go1.27.0.windows-amd64.zip"
    if (-not (Test-Path $GoZip)) {
        Write-Err "Go not found in soft/go and $GoZip does not exist."
        exit 1
    }
    Write-Step "Extracting Go from $GoZip..."
    Expand-Archive -Path $GoZip -DestinationPath $SoftDir -Force
}

$env:GOROOT = Join-Path $SoftDir "go"
$env:GOPATH = $GoPath
$env:PATH   = "$($env:GOROOT)\bin;$($env:GOPATH)\bin;$($env:PATH)"
New-Item -ItemType Directory -Force -Path $GoPath | Out-Null

$goVer = & $GoExe version 2>&1
Write-OK $goVer

if (-not $Unattended) {
    Write-Host ""
    Write-Header "--- Interactive Configuration ---"
    Write-Host "Parameters will be embedded into the binary as defaults." -ForegroundColor DarkGray
    Write-Host "They can always be overridden via config.yaml or environment variables." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  [Telegram Bot API]" -ForegroundColor Cyan
    $TgToken  = Prompt-Value "Bot Token (@BotFather)" $TgToken -Secret
    $TgChatID = Prompt-Value "Chat/Channel ID (e.g. -1001234567890)" $TgChatID

    Write-Host ""
    Write-Host "  [MQTT]" -ForegroundColor Cyan
    $MQTTBroker = Prompt-Value "Broker URL (e.g. tcp://broker:1883)" $MQTTBroker
    if (-not [string]::IsNullOrEmpty($MQTTBroker)) {
        $defTopic = if ($MQTTTopic) { $MQTTTopic } else { "natbypass/mynet/peers" }
        $MQTTTopic = Prompt-Value "Topic" $defTopic
    }

    Write-Host ""
    Write-Host "  [HTTP Webhook]" -ForegroundColor Cyan
    $WebhookURL = Prompt-Value "Webhook URL (e.g. https://worker.dev/peers)" $WebhookURL

    Write-Host ""
    Write-Host "  [General Settings]" -ForegroundColor Cyan
    $DeviceID  = Prompt-Value "Device ID (Enter = auto-generate)" $DeviceID
    $WebUIPort = Prompt-Value "Web UI Port" $WebUIPort
    $WebUIUser = Prompt-Value "Web UI Username" $WebUIUser
    $WebUIPass = Prompt-Value "Web UI Password" $WebUIPass -Secret
    $LogLevel  = Prompt-Choice "Log Level" @("info","debug","warn","error") $LogLevel

    Write-Host ""
    Write-Host "  [Target Platforms]" -ForegroundColor Cyan
    if ([string]::IsNullOrEmpty($Target)) {
        $chosen = Prompt-Choice "Select targets to build" @(
            "all      - Windows, Linux amd64/arm64, MIPS, MIPSLE",
            "router   - Keenetic, OpenWrt, RPi (mips + mipsle + arm64)",
            "windows  - Windows x64 (.exe)",
            "linux    - Linux amd64 + arm64"
        ) "all      - Windows, Linux amd64/arm64, MIPS, MIPSLE"
        $Target = ($chosen -split " ")[0].Trim()
    }
}

if ([string]::IsNullOrEmpty($Target)) { $Target = "all" }

$Version   = "1.0.0"
$Commit    = "release"
$BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host ""
Write-Header "--- Build Parameters ---"
Write-Info "Version:    $Version ($Commit)"
Write-Info "Date:       $BuildDate"
Write-Info "Telegram:   $(if ($TgToken) { 'Configured' } else { 'Disabled' })"
Write-Info "Chat ID:    $(if ($TgChatID) { $TgChatID } else { 'None' })"
Write-Info "MQTT:       $(if ($MQTTBroker) { $MQTTBroker } else { 'Disabled' })"
Write-Info "Webhook:    $(if ($WebhookURL) { $WebhookURL } else { 'Disabled' })"
Write-Info "Web UI:     Port $WebUIPort (User: $WebUIUser)"
Write-Info "Target:     $Target"
Write-Host ""

if (-not $Unattended) {
    Write-Host "  Start build? [Y/n]: " -NoNewline -ForegroundColor White
    $confirm = Read-Host
    if ($confirm -eq "n" -or $confirm -eq "N") {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

$LDFlags = "-s -w " +
    "-X ${Module}/cmd/natbypass.Version=${Version} " +
    "-X ${Module}/cmd/natbypass.Commit=${Commit} " +
    "-X ${Module}/cmd/natbypass.BuildDate=${BuildDate} " +
    "-X ${Module}/cmd/natbypass.DefaultTgToken=${TgToken} " +
    "-X ${Module}/cmd/natbypass.DefaultTgChatID=${TgChatID} " +
    "-X ${Module}/cmd/natbypass.DefaultMQTTBroker=${MQTTBroker} " +
    "-X ${Module}/cmd/natbypass.DefaultMQTTTopic=${MQTTTopic} " +
    "-X ${Module}/cmd/natbypass.DefaultWebhookURL=${WebhookURL} " +
    "-X ${Module}/cmd/natbypass.DefaultDeviceID=${DeviceID} " +
    "-X ${Module}/cmd/natbypass.DefaultWebUIPort=${WebUIPort} " +
    "-X ${Module}/cmd/natbypass.DefaultWebUIUser=${WebUIUser} " +
    "-X ${Module}/cmd/natbypass.DefaultWebUIPass=${WebUIPass} " +
    "-X ${Module}/cmd/natbypass.DefaultLogLevel=${LogLevel}"

Write-Host ""
Write-Step "Resolving Go dependencies (go mod tidy)..."
Set-Location $ProjectRoot
& $GoExe mod tidy
Write-OK "Dependencies ready"

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

function Build-Arch {
    param($GOOS, $GOARCH, $Ext="", [hashtable]$Extra=@{})
    $outName = "natbypass-${GOOS}-${GOARCH}${Ext}"
    $outPath = Join-Path $DistDir $outName
    Write-Host "   Compiling for $GOOS/$GOARCH..." -NoNewline

    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH
    $env:CGO_ENABLED = "0"
    if ($Extra.ContainsKey("GOMIPS")) {
        $env:GOMIPS = $Extra["GOMIPS"]
    } else {
        $env:GOMIPS = $null
    }

    $outLog = & $GoExe build -trimpath -ldflags "$LDFlags" -o $outPath $Cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $outLog -ForegroundColor DarkRed
        return $false
    }
    $sz = [math]::Round((Get-Item $outPath).Length / 1MB, 2)
    Write-Host " OK ($sz MB)" -ForegroundColor Green
    return $true
}

Write-Host ""
Write-Header "--- Compiling Targets ($Target) ---"
$buildSuccess = $true

switch -Wildcard ($Target) {
    "all*" {
        $buildSuccess = $buildSuccess -and (Build-Arch "windows" "amd64" ".exe")
        $buildSuccess = $buildSuccess -and (Build-Arch "linux"   "amd64")
        $buildSuccess = $buildSuccess -and (Build-Arch "linux"   "arm64")
        $buildSuccess = $buildSuccess -and (Build-Arch "linux"   "mips"   "" @{GOMIPS="softfloat"})
        $buildSuccess = $buildSuccess -and (Build-Arch "linux"   "mipsle" "" @{GOMIPS="softfloat"})
    }
    "router*" {
        $buildSuccess = $buildSuccess -and (Build-Arch "linux" "arm64")
        $buildSuccess = $buildSuccess -and (Build-Arch "linux" "mips"   "" @{GOMIPS="softfloat"})
        $buildSuccess = $buildSuccess -and (Build-Arch "linux" "mipsle" "" @{GOMIPS="softfloat"})
    }
    "windows*" {
        $buildSuccess = $buildSuccess -and (Build-Arch "windows" "amd64" ".exe")
    }
    "linux*" {
        $buildSuccess = $buildSuccess -and (Build-Arch "linux" "amd64")
        $buildSuccess = $buildSuccess -and (Build-Arch "linux" "arm64")
    }
}

# Generate config.yaml
$configOut = Join-Path $DistDir "config.yaml"
$cfgYaml = @"
app:
  name: "NatBypass"
  version: "$Version"
  log_level: "$LogLevel"
  publish_interval: 60
  device_id: "$DeviceID"

web_ui:
  enabled: true
  port: $WebUIPort
  username: "$WebUIUser"
  password: "$WebUIPass"

network:
  upnp_enabled: true
  stun_servers:
    - "stun.l.google.com:19302"
    - "stun1.l.google.com:19302"
    - "stun.cloudflare.com:3478"
  ip_apis:
    - "https://api.ipify.org"
    - "https://ifconfig.me/ip"
    - "https://icanhazip.com"

signaling:
  channels:
"@

if (-not [string]::IsNullOrEmpty($TgToken)) {
$cfgYaml += @"

    - type: "telegram"
      priority: 1
      enabled: true
      params:
        token: "$TgToken"
        chat_id: "$TgChatID"
"@
}

if (-not [string]::IsNullOrEmpty($MQTTBroker)) {
$cfgYaml += @"

    - type: "mqtt"
      priority: 2
      enabled: true
      params:
        broker_url: "$MQTTBroker"
        topic: "$MQTTTopic"
"@
}

if (-not [string]::IsNullOrEmpty($WebhookURL)) {
$cfgYaml += @"

    - type: "webhook"
      priority: 3
      enabled: true
      params:
        post_url: "$WebhookURL"
        poll_url: "$WebhookURL"
"@
}

$cfgYaml += @"

wireguard:
  enabled: false
  interface: "wg0"
  listen_port: 51820
"@

[System.IO.File]::WriteAllText($configOut, $cfgYaml, [System.Text.UTF8Encoding]::new($false))
Write-Info "Generated config saved to $configOut"

if (Test-Path "$ProjectRoot\wintun.dll") {
    Copy-Item "$ProjectRoot\wintun.dll" "$DistDir\wintun.dll" -Force
} elseif (Test-Path "$ProjectRoot\internal\tunnel\wintun.dll") {
    Copy-Item "$ProjectRoot\internal\tunnel\wintun.dll" "$DistDir\wintun.dll" -Force
}

Write-Host ""

if ($buildSuccess) {
    Write-Header "======================================================"
    Write-Header "  BUILD COMPLETED SUCCESSFULLY!                       "
    Write-Header "======================================================"
    Write-Host ""
    Get-ChildItem $DistDir | Where-Object { -not $_.PSIsContainer } |
        Select-Object Name, @{N="Size";E={"$([math]::Round($_.Length/1MB,2)) MB"}} |
        Format-Table -AutoSize
} else {
    Write-Err "Some targets failed to compile."
    exit 1
}