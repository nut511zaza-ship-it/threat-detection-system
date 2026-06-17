@echo off
echo Building Uninstall.exe...
python -m PyInstaller --onefile --windowed --name Uninstall uninstall_agent.py --noconfirm
if errorlevel 1 (
    echo [ERROR] Build failed
    pause
    exit /b 1
)
copy "dist\Uninstall.exe" "Uninstall.exe" >nul
echo Done! Uninstall.exe is ready.
pause
