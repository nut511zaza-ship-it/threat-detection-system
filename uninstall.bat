@echo off
echo ============================================
echo   Threat Detection System - Uninstall
echo ============================================

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run as Administrator
    pause
    exit /b 1
)

echo [1/2] Removing Task Scheduler entry...
schtasks /delete /tn "ThreatDetectionAgent" /f >nul 2>&1
echo       Done.

echo [2/2] Restoring hosts file...
python -c "
hosts = r'C:\Windows\System32\drivers\etc\hosts'
marker = '# === THREAT DETECTION SYSTEM ==='
marker_end = '# === END THREAT DETECTION SYSTEM ==='
with open(hosts, 'r') as f:
    lines = f.readlines()
new_lines = []
skip = False
for line in lines:
    if marker in line:
        skip = True
    if not skip:
        new_lines.append(line)
    if marker_end in line:
        skip = False
with open(hosts, 'w') as f:
    f.writelines(new_lines)
import os
os.system('ipconfig /flushdns >nul 2>&1')
print('hosts file restored.')
"
echo       Done.

echo.
echo ============================================
echo   Uninstall complete!
echo ============================================
pause
