import ctypes
import sys
import os
import subprocess
import tkinter as tk
from tkinter import messagebox

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def uninstall():
    root = tk.Tk()
    root.withdraw()

    if not messagebox.askyesno(
        "Uninstall",
        "ต้องการถอนการติดตั้ง Threat Detection System ใช่มั้ย?\n\nระบบจะ:\n- ลบออกจาก Task Scheduler\n- คืนค่า hosts file\n- ลบไฟล์โปรแกรม"
    ):
        root.destroy()
        return

    errors = []

    # 0. ปิด ThreatDetection.exe ก่อนลบ
    try:
        subprocess.run(["taskkill", "/f", "/im", "ThreatDetection.exe"], capture_output=True)
        import time
        time.sleep(1)
    except:
        pass


    # 1. หยุด Task Scheduler
    try:
        result = subprocess.run(
            ["schtasks", "/delete", "/tn", "ThreatDetectionAgent", "/f"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            errors.append("ลบ Task Scheduler ไม่ได้")
    except Exception as e:
        errors.append(f"Task Scheduler error: {e}")

    try:
        subprocess.run(
            ["schtasks", "/delete", "/tn", "ThreatDetectionOpenLogin", "/f"],
            capture_output=True, text=True
        )
    except Exception as e:
        errors.append(f"ThreatDetectionOpenLogin task error: {e}")

    # 2. คืนค่า hosts file
    try:
        hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
        marker = "# === THREAT DETECTION SYSTEM ==="
        marker_end = "# === END THREAT DETECTION SYSTEM ==="

        with open(hosts_file, "r", encoding="utf-8") as f:
            content = f.read()

        lines = content.split("\n")
        new_lines = []
        skip = False
        for line in lines:
            if marker in line:
                skip = True
            if not skip:
                new_lines.append(line)
            if marker_end in line:
                skip = False

        with open(hosts_file, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines))

        os.system("ipconfig /flushdns >nul 2>&1")
    except Exception as e:
        errors.append(f"คืนค่า hosts ไม่ได้: {e}")

    # 3. ลบไฟล์ที่เกี่ยวข้อง
    import time
    current_dir = os.path.dirname(os.path.abspath(__file__))
    files_to_delete = ["agent.py", "agent.py.bak", "agent_log.txt",
                       "ThreatDetection.exe", "ThreatDetection.spec"]
    for fname in files_to_delete:
        fpath = os.path.join(current_dir, fname)
        for attempt in range(5):
            try:
                if os.path.exists(fpath):
                    subprocess.run(["attrib", "-h", "-s", "-r", fpath], capture_output=True)
                    os.remove(fpath)
                break
            except:
                time.sleep(1)

    if errors:
        messagebox.showwarning("Uninstall", f"เสร็จแล้วแต่มีปัญหา:\n" + "\n".join(errors))
    else:
        messagebox.showinfo("Uninstall", "✅ ถอนการติดตั้งสำเร็จแล้วครับ!\n\nระบบคืนค่าทุกอย่างกลับปกติแล้ว")

    root.destroy()

    # ลบไฟล์ทั้งหมดผ่าน bat file (รอให้ process ปิดก่อน) — เป็น fallback เผื่อ Python ลบไม่สำเร็จ
    try:
        self_path = os.path.abspath(sys.argv[0])
        current_dir = os.path.dirname(self_path)
        threat_path = os.path.join(current_dir, "ThreatDetection.exe")
        log_path = os.path.join(current_dir, "agent_log.txt")
        agent_path = os.path.join(current_dir, "agent.py")
        agent_bak_path = os.path.join(current_dir, "agent.py.bak")
        spec_path = os.path.join(current_dir, "ThreatDetection.spec")
        bat_path = os.path.join(current_dir, "_cleanup.bat")
        bat_content = f'''@echo off
taskkill /f /im ThreatDetection.exe >nul 2>&1
timeout /t 2 /nobreak >nul
:retry
if exist "{threat_path}" (
    attrib -h -s -r "{threat_path}" >nul 2>&1
    del /f /q "{threat_path}" >nul 2>&1
    if exist "{threat_path}" (
        timeout /t 1 /nobreak >nul
        goto retry
    )
)
attrib -h -s -r "{log_path}" >nul 2>&1
del /f /q "{log_path}" >nul 2>&1
attrib -h -s -r "{agent_path}" >nul 2>&1
del /f /q "{agent_path}" >nul 2>&1
attrib -h -s -r "{agent_bak_path}" >nul 2>&1
del /f /q "{agent_bak_path}" >nul 2>&1
attrib -h -s -r "{spec_path}" >nul 2>&1
del /f /q "{spec_path}" >nul 2>&1
del /f /q "{self_path}" >nul 2>&1
del /f /q "%~f0" >nul 2>&1
'''
        with open(bat_path, "w") as f:
            f.write(bat_content)
        subprocess.Popen(["cmd", "/c", bat_path], creationflags=0x08000000)
    except:
        pass

def main():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1
        )
        sys.exit()
    uninstall()

if __name__ == "__main__":
    main()
