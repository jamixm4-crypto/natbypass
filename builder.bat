@echo off
title NatBypass Builder
cd /d "%~dp0"

if exist "%~dp0build-gui.ps1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0build-gui.ps1"
) else if exist "%~dp0..\build-gui.ps1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0..\build-gui.ps1"
) else (
    echo [ERROR] build-gui.ps1 not found!
    pause
)