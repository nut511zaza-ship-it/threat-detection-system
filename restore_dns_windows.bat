@echo off
echo Restoring DNS settings...
sc config "DNS Client" start= auto >nul 2>&1
sc start "DNS Client" >nul 2>&1
netsh interface ip set dns "Wi-Fi" dhcp >nul 2>&1
netsh interface ip set dns "Ethernet" dhcp >nul 2>&1
echo Done. DNS restored to automatic (DHCP)
pause
