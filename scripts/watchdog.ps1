param(
    [string]$ExePath = "dist\NatBypass.exe",
    [string]$ConfigPath = "config.yaml",
    [string]$LogLevel = "debug",
    [string]$UIMode = "auto",
    [string]$LogFile = "dist\natbypass.log",
    [string]$CrashLog = "dist\crash.log"
)

$ErrorActionPreference = "Continue"

Write-Host "=== Starting NatBypass Watchdog ===" -ForegroundColor Cyan
Write-Host "Executable : $ExePath"
Write-Host "Config     : $ConfigPath"
Write-Host "Log file   : $LogFile"
Write-Host "Crash log  : $CrashLog"

while ($true) {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    Write-Host "[$timestamp] Launching $ExePath..." -ForegroundColor Green
    
    $argsList = @("--config", $ConfigPath, "--log-level", $LogLevel, "--ui", $UIMode)
    
    $proc = Start-Process -FilePath $ExePath -ArgumentList $argsList -PassThru -NoNewWindow -Wait
    $exitCode = $proc.ExitCode
    $exitTimestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    
    $logEntry = "[$exitTimestamp] Process $ExePath exited with code $exitCode (0x$($exitCode.ToString('X8')))"
    Write-Host $logEntry -ForegroundColor Yellow
    
    Add-Content -Path $CrashLog -Value $logEntry
    
    if ($exitCode -eq 0) {
        Write-Host "Clean exit detected. Restarting in 2 seconds..." -ForegroundColor Gray
    } else {
        Write-Host "Unexpected exit/crash detected! Exit code: $exitCode. Restarting in 2 seconds..." -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 2
}