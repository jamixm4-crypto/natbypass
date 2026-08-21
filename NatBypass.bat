@echo off
title NatBypass Desktop
cd /d "%~dp0"

if exist "%~dp0app-gui.ps1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0app-gui.ps1"
) else if exist "%~dp0..\app-gui.ps1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0..\app-gui.ps1"
) else (
    echo [ERROR] app-gui.ps1 not found!
    pause
)