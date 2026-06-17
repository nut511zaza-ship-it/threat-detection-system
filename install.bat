@echo off
echo ============================================
echo   Threat Detection System - Install
echo ============================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run as Administrator
    pause
    exit /b 1
)

set SCRIPT_PATH=%~dp0agent.py
set PYTHON_PATH=pythonw

echo [1/2] Creating Task Scheduler entry...
schtasks /create /tn "ThreatDetectionAgent" /tr "%PYTHON_PATH% \"%SCRIPT_PATH%\"" /sc onlogon /rl highest /f >nul
if errorlevel 1 (
    echo [ERROR] Failed to create task
    pause
    exit /b 1
)
echo       Done.

echo.
echo [2/2] Starting agent now...
start "" pythonw "%SCRIPT_PATH%"
echo       Done.

echo.
echo ============================================
echo   Install complete!
echo   System will auto-start on every login.
echo ============================================
pause
