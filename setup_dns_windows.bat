@echo off
echo ============================================
echo   DNS Agent Setup - Windows
echo ============================================
echo.

echo [1/3] Installing dependencies...
pip install scapy --quiet
echo       Done.

echo.
echo [2/3] Disabling Windows DNS Client service...
sc stop "DNS Client" >nul 2>&1
sc config "DNS Client" start= disabled >nul 2>&1
echo       Done. (ปิด Windows DNS Client เพื่อให้ port 53 ว่าง)

echo.
echo [3/3] Setting DNS to localhost...
netsh interface ip set dns "Wi-Fi" static 127.0.0.1 >nul 2>&1
netsh interface ip set dns "Ethernet" static 127.0.0.1 >nul 2>&1
echo       Done.

echo.
echo ============================================
echo   Setup complete!
echo   รัน agent.py ด้วย Administrator แล้วใช้งานได้เลย
echo ============================================
pause
