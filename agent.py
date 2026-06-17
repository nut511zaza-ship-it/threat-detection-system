import urllib.request
import json
import threading
import datetime
import os
import sys
import ctypes
import subprocess
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pass

SERVER_URL = "http://143.14.200.159:8000"
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_MARKER = "# === THREAT DETECTION SYSTEM ==="
HOSTS_MARKER_END = "# === END THREAT DETECTION SYSTEM ==="
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "agent_log.txt")
LOCAL_PORT = 47812
CURRENT_USER = ""

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def log(msg):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        subprocess.run(["attrib", "+h", LOG_FILE], capture_output=True)
    except:
        pass

def fetch_blacklist():
    try:
        req = urllib.request.Request(f"{SERVER_URL}/blacklist")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return [item["domain"] for item in data]
    except Exception as e:
        log(f"ดึง Blacklist ไม่ได้: {e}")
        return []

def update_hosts(domains):
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        lines = content.split("\n")
        new_lines = []
        skip = False
        for line in lines:
            if HOSTS_MARKER in line:
                skip = True
            if not skip:
                new_lines.append(line)
            if HOSTS_MARKER_END in line:
                skip = False
        new_lines.append(HOSTS_MARKER)
        for domain in domains:
            new_lines.append(f"0.0.0.0 {domain}")
            new_lines.append(f"0.0.0.0 www.{domain}")
        new_lines.append(HOSTS_MARKER_END)
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines))
        os.system("ipconfig /flushdns >nul 2>&1")
        log(f"อัปเดต hosts file — บล็อก {len(domains)} domain")
        if CURRENT_USER:
            for domain in domains:
                report_blocked(domain)
        return True
    except Exception as e:
        log(f"แก้ hosts file ไม่ได้: {e}")
        return False

def report_blocked(domain):
    def _send():
        try:
            data = json.dumps({"domain": domain, "client_ip": CURRENT_USER}).encode()
            req = urllib.request.Request(
                f"{SERVER_URL}/check", data=data,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            urllib.request.urlopen(req, timeout=3)
        except:
            pass
    threading.Thread(target=_send, daemon=True).start()

def clear_hosts():
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        lines = content.split("\n")
        new_lines = []
        skip = False
        for line in lines:
            if HOSTS_MARKER in line:
                skip = True
            if not skip:
                new_lines.append(line)
            if HOSTS_MARKER_END in line:
                skip = False
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines))
        os.system("ipconfig /flushdns >nul 2>&1")
        log("คืนค่า hosts file แล้ว")
    except Exception as e:
        log(f"คืนค่า hosts ไม่ได้: {e}")

def send_log(username, action, detail=""):
    def _send():
        try:
            data = json.dumps({"username": username, "expression": action, "result": detail}).encode()
            req = urllib.request.Request(
                f"{SERVER_URL}/log", data=data,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            urllib.request.urlopen(req, timeout=3)
        except:
            pass
    threading.Thread(target=_send, daemon=True).start()

def create_tray_icon(color="#00d4aa"):
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon([(32,4),(60,16),(60,38),(32,60),(4,38),(4,16)], fill=color)
    draw.polygon([(32,12),(52,22),(52,38),(32,52),(12,38),(12,22)], fill="#0a0c10")
    return img

def open_url(url):
    """เปิด URL ด้วย explorer.exe เพื่อให้เปิดใน session ของ user ปกติ
    แม้ตัว agent รันด้วยสิทธิ์ admin (จาก Task Scheduler) ก็ตาม"""
    try:
        subprocess.run(["explorer.exe", url])
    except Exception as e:
        log(f"เปิด browser ด้วย explorer ไม่ได้: {e}")
        try:
            webbrowser.open(url)
        except Exception as e2:
            log(f"เปิด browser ไม่ได้: {e2}")


def install_open_login_task(login_url):
    """สร้าง Task ที่รันด้วยสิทธิ์ผู้ใช้ปกติ (ไม่ใช่ admin) สำหรับเปิด browser
    เพราะ process สิทธิ์ admin (จาก Task Scheduler /rl highest) ถูก UIPI บล็อก
    ไม่ให้เปิดหน้าต่างใน session ของ user ปกติได้"""
    subprocess.run(
        ["schtasks", "/delete", "/tn", "ThreatDetectionOpenLogin", "/f"],
        capture_output=True
    )
    tr = f"cmd /c start {login_url}"
    result = subprocess.run([
        "schtasks", "/create",
        "/tn", "ThreatDetectionOpenLogin",
        "/tr", tr,
        "/sc", "onlogon",
        "/rl", "limited",
        "/f"
    ], capture_output=True, text=True)
    if result.returncode == 0:
        log("ติดตั้ง ThreatDetectionOpenLogin task สำเร็จ")
    else:
        log(f"ติดตั้ง ThreatDetectionOpenLogin task error: {result.stderr}")


def open_login_page():
    """เรียกเปิดหน้า login ผ่าน task ที่รันด้วยสิทธิ์ผู้ใช้ปกติ"""
    result = subprocess.run(
        ["schtasks", "/run", "/tn", "ThreatDetectionOpenLogin"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log("เปิดหน้า web login ผ่าน task แล้ว")
    else:
        log(f"เปิดหน้า login ผ่าน task ไม่ได้: {result.stderr} — ลอง explorer.exe แทน")
        open_url(f"{SERVER_URL}/login")


def install_task_scheduler(self_path):
    subprocess.run(
        ["schtasks", "/delete", "/tn", "ThreatDetectionAgent", "/f"],
        capture_output=True
    )
    log("ติดตั้ง Task Scheduler...")
    task_run = f'\\"{self_path}\\"'
    result = subprocess.run([
        "schtasks", "/create",
        "/tn", "ThreatDetectionAgent",
        "/tr", task_run,
        "/sc", "onlogon",
        "/rl", "highest",
        "/it", "/f"
    ], capture_output=True, text=True)
    if result.returncode == 0:
        log("ติดตั้ง Task Scheduler สำเร็จ")
    else:
        log(f"Task Scheduler error: {result.stderr}")


# ===== Local callback server: รับ username จากหน้า web login =====
class LoginCallbackHandler(BaseHTTPRequestHandler):
    tray_agent = None

    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def do_POST(self):
        if self.path != "/set-user":
            self.send_response(404)
            self._send_cors()
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            username = str(data.get("username", "")).strip()
        except:
            username = ""

        if username:
            global CURRENT_USER
            CURRENT_USER = username
            log(f"User '{username}' เข้าใช้งาน (ผ่านหน้า web login)")
            if LoginCallbackHandler.tray_agent:
                LoginCallbackHandler.tray_agent.set_username(username)

        self.send_response(200)
        self._send_cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, fmt, *args):
        pass


def start_local_server(tray_agent):
    LoginCallbackHandler.tray_agent = tray_agent
    try:
        server = ThreadingHTTPServer(("127.0.0.1", LOCAL_PORT), LoginCallbackHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        log(f"Local callback server เริ่มทำงานที่ port {LOCAL_PORT}")
    except Exception as e:
        log(f"เริ่ม local server ไม่ได้: {e}")


class TrayAgent:
    def __init__(self, blacklist):
        self.blacklist = blacklist
        self.running = True
        self.tray = None
        self.blocked_count = len(blacklist)
        self.username = "ยังไม่ login"

    def start(self):
        threading.Thread(target=self._run_tray, daemon=True).start()
        threading.Thread(target=self._auto_update_loop, daemon=True).start()

    def _build_menu(self):
        return pystray.Menu(
            pystray.MenuItem(lambda item: f"User: {self.username}", None, enabled=False),
            pystray.MenuItem(lambda item: f"Blocking {self.blocked_count} domains", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Update Blacklist", self._on_update),
            pystray.MenuItem("เปิดหน้า Login", self._on_open_login),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._on_exit),
        )

    def _run_tray(self):
        icon_img = create_tray_icon("#00d4aa")
        self.tray = pystray.Icon(
            "ThreatDetection", icon_img,
            "Protection ON",
            menu=self._build_menu()
        )
        self.tray.run()

    def set_username(self, username):
        global CURRENT_USER
        self.username = username
        if self.tray:
            self.tray.title = f"Protection ON — {username}"
            self.tray.menu = self._build_menu()

    def _auto_update_loop(self):
        import time
        while self.running:
            time.sleep(60)
            if self.running:
                self._do_update()

    def _do_update(self):
        blacklist = fetch_blacklist()
        update_hosts(blacklist)
        self.blacklist = blacklist
        self.blocked_count = len(blacklist)
        if self.tray:
            self.tray.menu = self._build_menu()
        log(f"Auto-updated: บล็อก {len(blacklist)} domain")

    def _on_update(self, icon, item):
        threading.Thread(target=self._do_update, daemon=True).start()

    def _on_open_login(self, icon, item):
        open_login_page()

    def _on_exit(self, icon, item):
        global CURRENT_USER
        if CURRENT_USER:
            send_log(CURRENT_USER, "EXIT", "")
        CURRENT_USER = ""
        self.running = False
        clear_hosts()
        if self.tray:
            self.tray.stop()
        os._exit(0)


def main():
    self_path = os.path.abspath(sys.argv[0])
    log(f"=== เริ่มโปรแกรม === argv={sys.argv} admin={is_admin()}")

    if not is_admin():
        log("ไม่ใช่ admin, ขอ runas...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{self_path}"', None, 1
        )
        sys.exit()

    install_task_scheduler(self_path)
    install_open_login_task(f"{SERVER_URL}/login")

    import time
    time.sleep(2)

    log("Startup: ดึง Blacklist และบล็อกทันที...")
    blacklist = fetch_blacklist()
    if blacklist:
        update_hosts(blacklist)
        log(f"Startup: บล็อก {len(blacklist)} domain แล้ว")

    agent = TrayAgent(blacklist)
    start_local_server(agent)
    agent.start()

    # เปิดหน้า web login อัตโนมัติ
    open_login_page()

    # Keep main thread alive
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()
