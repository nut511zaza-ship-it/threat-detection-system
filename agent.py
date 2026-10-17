import urllib.request
import json
import threading
import datetime
import os
import sys
import ctypes
import subprocess
import webbrowser
import socket
import socketserver
import time
import urllib.parse
import ssl
import secrets
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pass

# ใช้สร้าง Root CA / ใบรับรองสำหรับ Block Page ของเว็บ HTTPS (ถ้าไม่มี จะทำได้แค่แจ้งเตือน)
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

SERVER_URL = "http://143.14.200.159:8000"
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_MARKER = "# === THREAT DETECTION SYSTEM ==="
HOSTS_MARKER_END = "# === END THREAT DETECTION SYSTEM ==="
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "agent_log.txt")
LOCAL_PORT = 47812
CURRENT_USER = ""

# ===== Block Page (sinkhole) =====
# hosts ชี้โดเมนอันตรายมาที่ 127.0.0.1 แล้วให้ agent รับ connection ไว้เอง
#   - HTTP  (port 80)  : redirect ไปหน้า Block Page ของ server + รายงาน admin
#   - HTTPS (port 443) : ใช้ใบรับรองจาก Local Root CA → redirect ไปหน้า Block Page + รายงาน admin
#                        (ถ้าเตรียม CA ไม่ได้ จะอ่าน SNI แล้วรายงาน admin อย่างเดียว)
BLOCK_IP = "127.0.0.1"
SINKHOLE_HTTP_PORT = 80
SINKHOLE_HTTPS_PORT = 443
BLOCK_PAGE_URL = f"{SERVER_URL}/blocked"
ATTEMPT_COOLDOWN = 30          # วินาที — กันรายงานซ้ำโดเมนเดิม (เบราว์เซอร์ retry หลายรอบ)
BLOCKED_DOMAINS = frozenset()  # อัปเดตทุกครั้งที่เขียน hosts
_last_attempt = {}
_attempt_lock = threading.Lock()

# ===== Local Root CA (Block Page สำหรับเว็บ HTTPS) =====
# สร้าง CA ใหม่ทุกครั้งที่ agent เริ่มทำงาน — private key อยู่ในหน่วยความจำเท่านั้น ไม่เขียนลงดิสก์
# ติดตั้งใบรับรอง CA ลง Windows (LocalMachine\Root) แล้วออกใบรับรองให้เฉพาะโดเมนใน blacklist
# ลบ CA ออกจาก Windows ตอนกด Exit / ถอนการติดตั้ง / เริ่ม agent รอบถัดไป
CA_COMMON_NAME = "Threat Detection Local CA"
CA_ORGANIZATION = "Threat Detection System (Block Page)"
DEFAULT_TLS_NAME = "blocked.threat-detection.local"
LOCAL_CA = None        # LocalCA ที่ใช้งานอยู่ (None = ทำ Block Page ของ HTTPS ไม่ได้ → แจ้งเตือนอย่างเดียว)
TLS_BASE_CTX = None    # SSLContext หลักที่สลับใบรับรองตามชื่อโดเมน (SNI)

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
    global BLOCKED_DOMAINS
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
            new_lines.append(f"{BLOCK_IP} {domain}")
            new_lines.append(f"{BLOCK_IP} www.{domain}")
        new_lines.append(HOSTS_MARKER_END)
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines))
        BLOCKED_DOMAINS = frozenset(d.strip().lower() for d in domains if d.strip())
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
    ไม่ให้เปิดหน้าต่างใน session ของ user ปกติได้
    ใช้ XML เพื่อปิด battery restriction เหมือน install_task_scheduler()
    (schtasks /create ธรรมดาจะติ๊ก 'Start only on AC power' ให้โดย default)"""
    subprocess.run(
        ["schtasks", "/delete", "/tn", "ThreatDetectionOpenLogin", "/f"],
        capture_output=True
    )
    task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c start {login_url}</Arguments>
    </Exec>
  </Actions>
</Task>'''
    xml_path = os.path.join(os.environ.get("TEMP", "C:\\"), "threatdetection_openlogin_task.xml")
    try:
        with open(xml_path, "w", encoding="utf-16") as f:
            f.write(task_xml)
        result = subprocess.run([
            "schtasks", "/create",
            "/tn", "ThreatDetectionOpenLogin",
            "/xml", xml_path,
            "/f"
        ], capture_output=True, text=True)
        if result.returncode == 0:
            log("ติดตั้ง ThreatDetectionOpenLogin task สำเร็จ (ปิด battery restriction แล้ว)")
        else:
            log(f"ติดตั้ง ThreatDetectionOpenLogin task error: {result.stderr}")
    except Exception as e:
        log(f"สร้าง ThreatDetectionOpenLogin task ด้วย XML ไม่ได้: {e}")


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

    # ใช้ XML แทน schtasks /create ตรงๆ เพราะ command-line ไม่มี flag ปิด
    # battery restriction ได้ — ค่า default ของ schtasks คือ "ไม่รันถ้าใช้แบตเตอรี่ล้วน"
    # และ "หยุดทันทีถ้าสลับมาใช้แบตเตอรี่" ซึ่งทำให้ agent ไม่ทำงานตอนไม่เสียบสายชาร์จ
    task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{self_path}</Command>
    </Exec>
  </Actions>
</Task>'''

    xml_path = os.path.join(os.environ.get("TEMP", "C:\\"), "threatdetection_task.xml")
    try:
        with open(xml_path, "w", encoding="utf-16") as f:
            f.write(task_xml)
        result = subprocess.run([
            "schtasks", "/create",
            "/tn", "ThreatDetectionAgent",
            "/xml", xml_path,
            "/f"
        ], capture_output=True, text=True)
        if result.returncode == 0:
            log("ติดตั้ง Task Scheduler สำเร็จ (ปิด battery restriction แล้ว)")
        else:
            log(f"Task Scheduler error: {result.stderr}")
    except Exception as e:
        log(f"สร้าง Task Scheduler ด้วย XML ไม่ได้: {e}")


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


# ===== Block Page / Sinkhole: รับ connection ของโดเมนที่ถูกบล็อก =====
def match_blocked(host):
    """คืนโดเมนใน blacklist ที่ตรงกับ host (ตัด port, จุดท้าย, www. ออก) ถ้าไม่ตรงคืน None"""
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if host.startswith("["):          # IPv6 literal เช่น [::1]:80
        return None
    host = host.split(":", 1)[0]
    blocked = BLOCKED_DOMAINS
    if host in blocked:
        return host
    if host.startswith("www.") and host[4:] in blocked:
        return host[4:]
    return None


def report_attempt(domain, protocol):
    """แจ้ง server ว่าผู้ใช้พยายามเข้าโดเมนที่ถูกบล็อก (กันซ้ำโดเมนเดิมภายใน ATTEMPT_COOLDOWN วินาที)"""
    now = time.time()
    with _attempt_lock:
        if now - _last_attempt.get(domain, 0) < ATTEMPT_COOLDOWN:
            return
        _last_attempt[domain] = now
    username = CURRENT_USER
    log(f"ตรวจพบการพยายามเข้า {domain} ({protocol}) — user: {username or 'ยังไม่ login'}")

    def _send():
        try:
            data = json.dumps({"domain": domain, "username": username, "protocol": protocol}).encode()
            req = urllib.request.Request(
                f"{SERVER_URL}/attempt", data=data,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            log(f"รายงานการพยายามเข้า {domain} ไม่ได้: {e}")
    threading.Thread(target=_send, daemon=True).start()


class BlockPageHandler(BaseHTTPRequestHandler):
    """port 80: เว็บ HTTP ที่ถูกบล็อก → redirect ไปหน้า Block Page ของ server"""

    def _handle(self):
        domain = match_blocked(self.headers.get("Host", ""))
        if not domain:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        report_attempt(domain, "http")
        location = f"{BLOCK_PAGE_URL}?domain={urllib.parse.quote(domain)}"
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = _handle

    def log_message(self, fmt, *args):
        pass


def parse_sni(data):
    """อ่านชื่อโดเมน (SNI) จาก TLS ClientHello — คืน None ถ้าไม่ใช่ ClientHello หรือไม่มี SNI"""
    try:
        if len(data) < 5 or data[0] != 0x16:              # ต้องเป็น TLS Handshake record
            return None
        record_len = int.from_bytes(data[3:5], "big")
        body = data[5:5 + record_len]
        if len(body) < 4 or body[0] != 0x01:              # ต้องเป็น ClientHello
            return None
        p = 4 + 2 + 32                                    # handshake header + version + random
        p += 1 + body[p]                                  # session id
        p += 2 + int.from_bytes(body[p:p + 2], "big")     # cipher suites
        p += 1 + body[p]                                  # compression methods
        ext_end = p + 2 + int.from_bytes(body[p:p + 2], "big")
        p += 2
        while p + 4 <= min(ext_end, len(body)):
            ext_type = int.from_bytes(body[p:p + 2], "big")
            ext_len = int.from_bytes(body[p + 2:p + 4], "big")
            p += 4
            if ext_type == 0x0000:                        # server_name
                q = p + 2                                 # ข้าม server_name_list length
                while q + 3 <= p + ext_len:
                    name_type = body[q]
                    name_len = int.from_bytes(body[q + 1:q + 3], "big")
                    q += 3
                    if name_type == 0:
                        return body[q:q + name_len].decode("ascii", "ignore").lower() or None
                    q += name_len
                return None
            p += ext_len
    except (IndexError, ValueError):
        return None
    return None


def _sni_report_only(sock):
    """โหมดสำรอง (ไม่มี Local CA): อ่าน SNI จาก ClientHello, รายงาน admin แล้วปิด connection"""
    sock.settimeout(3)
    data = b""
    try:
        while len(data) < 16389:                          # 5-byte header + record สูงสุด 16 KB
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) >= 5 and len(data) >= 5 + int.from_bytes(data[3:5], "big"):
                break
    except (socket.timeout, OSError):
        pass
    domain = match_blocked(parse_sni(data))
    if domain:
        report_attempt(domain, "https")


# ===== Local Root CA =====
def _run_hidden(args):
    """รันคำสั่งโดยไม่เด้งหน้าต่าง console (agent build แบบ --windowed)"""
    return subprocess.run(args, capture_output=True, text=True,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


class LocalCA:
    """CA ชั่วคราวของ agent: key สร้างในหน่วยความจำ ไม่เคยเขียนลงดิสก์
    ออกใบรับรองให้เฉพาะโดเมนที่ถูกบล็อก เพื่อให้ redirect เว็บ HTTPS ไปหน้า Block Page ได้"""

    def __init__(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
        ])
        public_key = self.key.public_key()
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            # path_length=0 → CA นี้ออกได้แค่ใบรับรองปลายทาง สร้าง CA ลูกต่อไม่ได้
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        self.cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        # key ของใบรับรองปลายทางเขียนลงไฟล์ชั่วคราวแบบเข้ารหัสด้วยรหัสสุ่มนี้ แล้วลบทิ้งทันที
        # (ssl.load_cert_chain รับได้แค่ path ของไฟล์)
        self._key_password = secrets.token_bytes(32)
        self._contexts = {}
        self._domain_by_ctx = {}
        self._lock = threading.Lock()

    def _issue(self, domain):
        now = datetime.datetime.now(datetime.timezone.utc)
        names = [domain] if domain == DEFAULT_TLS_NAME else [domain, f"www.{domain}"]
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .issuer_name(self.cert.subject)
            .public_key(self.leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def context_for(self, domain):
        """SSLContext ที่มีใบรับรองของ domain (สร้างครั้งแรกแล้ว cache ไว้)"""
        with self._lock:
            ctx = self._contexts.get(domain)
            if ctx:
                return ctx
            chain_pem = self._issue(domain).public_bytes(serialization.Encoding.PEM) + self.cert_pem
            key_pem = self.leaf_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self._key_password))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            paths = []
            try:
                for data in (chain_pem, key_pem):
                    fd, path = tempfile.mkstemp(prefix="td_", suffix=".pem")
                    paths.append(path)
                    with os.fdopen(fd, "wb") as f:
                        f.write(data)
                ctx.load_cert_chain(paths[0], paths[1], password=self._key_password)
            finally:
                for path in paths:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
            self._contexts[domain] = ctx
            self._domain_by_ctx[id(ctx)] = domain
            return ctx

    def domain_for(self, ctx):
        return self._domain_by_ctx.get(id(ctx))


def remove_local_ca():
    """ลบใบรับรอง CA ของระบบ (ทุกตัวที่เคยติดตั้ง) ออกจาก Windows"""
    script = ("$c = Get-ChildItem Cert:\\LocalMachine\\Root | "
              f"Where-Object {{ $_.Subject -like '*CN={CA_COMMON_NAME}*' }}; "
              "$c | Remove-Item; ($c | Measure-Object).Count")
    try:
        r = _run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        removed = (r.stdout or "").strip()
        if removed and removed != "0":
            log(f"ลบ Root CA เดิมออกจาก Windows แล้ว {removed} รายการ")
        elif r.returncode != 0:
            log(f"ลบ Root CA ไม่ได้: {(r.stderr or '').strip()}")
    except Exception as e:
        log(f"ลบ Root CA ไม่ได้: {e}")


def install_local_ca(ca):
    """ติดตั้งใบรับรอง CA (ส่วน public เท่านั้น) ลง LocalMachine\\Root"""
    fd, path = tempfile.mkstemp(prefix="td_ca_", suffix=".cer")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(ca.cert.public_bytes(serialization.Encoding.DER))
        r = _run_hidden(["certutil", "-addstore", "-f", "Root", path])
        if r.returncode != 0:
            log(f"ติดตั้ง Root CA ไม่ได้: {(r.stdout or r.stderr or '').strip()[-300:]}")
            return False
        return True
    except Exception as e:
        log(f"ติดตั้ง Root CA ไม่ได้: {e}")
        return False
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _sni_callback(ssl_sock, server_name, base_ctx):
    """เลือกใบรับรองตามชื่อโดเมนที่เบราว์เซอร์ขอ — ออกให้เฉพาะโดเมนที่ถูกบล็อก"""
    domain = match_blocked(server_name)
    if not domain:
        return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    try:
        ssl_sock.context = LOCAL_CA.context_for(domain)
    except Exception as e:
        log(f"ออกใบรับรองให้ {domain} ไม่ได้: {e}")
        report_attempt(domain, "https")
        return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR
    report_attempt(domain, "https")
    return None


def setup_tls_block_page():
    """เตรียม Block Page สำหรับเว็บ HTTPS — คืน True ถ้าพร้อม, False = ใช้โหมดแจ้งเตือนอย่างเดียว"""
    global LOCAL_CA, TLS_BASE_CTX
    if not HAS_CRYPTO:
        log("ไม่พบไลบรารี cryptography — เว็บ HTTPS จะแจ้งเตือนได้อย่างเดียว ไม่มี Block Page")
        return False
    try:
        remove_local_ca()                    # ลบ CA ของรอบก่อน (เผื่อ agent ถูกปิดกะทันหัน)
        ca = LocalCA()
        if not install_local_ca(ca):
            return False
        base_ctx = ca.context_for(DEFAULT_TLS_NAME)
        base_ctx.sni_callback = _sni_callback
        LOCAL_CA, TLS_BASE_CTX = ca, base_ctx
        log("ติดตั้ง Root CA สำหรับ Block Page (HTTPS) แล้ว — key อยู่ในหน่วยความจำเท่านั้น")
        return True
    except Exception as e:
        log(f"เตรียม Block Page (HTTPS) ไม่ได้: {e}")
        return False


class HttpsSinkholeHandler(socketserver.BaseRequestHandler):
    """port 443: เว็บ HTTPS ที่ถูกบล็อก
    - มี Local CA: TLS handshake ด้วยใบรับรองของโดเมนนั้น แล้ว redirect ไปหน้า Block Page
    - ไม่มี: อ่าน SNI, รายงาน admin แล้วปิด connection"""

    def handle(self):
        base_ctx = TLS_BASE_CTX
        if base_ctx is None:
            _sni_report_only(self.request)
            return
        self.request.settimeout(5)
        try:
            tls = base_ctx.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return                           # ไม่ใช่โดเมนที่ถูกบล็อก / เบราว์เซอร์ไม่ยอมรับใบรับรอง
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 16384:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            domain = LOCAL_CA.domain_for(tls.context)
            if not domain or domain == DEFAULT_TLS_NAME:
                return
            location = f"{BLOCK_PAGE_URL}?domain={urllib.parse.quote(domain)}"
            tls.sendall((
                "HTTP/1.1 302 Found\r\n"
                f"Location: {location}\r\n"
                "Cache-Control: no-store\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n").encode("ascii"))
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass


# ปิด SO_REUSEADDR: บน Windows ค่านี้ยอมให้ bind ทับ port ที่โปรแกรมอื่นใช้อยู่ได้
class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


class _BlockPageServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def start_sinkhole():
    """เปิดตัวรับ connection ที่ 127.0.0.1:80 และ :443 — ถ้า port ถูกโปรแกรมอื่นใช้อยู่
    การบล็อกยังทำงานตามปกติ (connection ถูกปฏิเสธทันที) แค่ไม่มี Block Page / การแจ้งเตือน"""
    try:
        http_srv = _BlockPageServer((BLOCK_IP, SINKHOLE_HTTP_PORT), BlockPageHandler)
        threading.Thread(target=http_srv.serve_forever, daemon=True).start()
        log(f"Block Page (HTTP) เริ่มทำงานที่ {BLOCK_IP}:{SINKHOLE_HTTP_PORT}")
    except Exception as e:
        log(f"เปิด Block Page port {SINKHOLE_HTTP_PORT} ไม่ได้: {e}")
    try:
        https_srv = _ThreadingTCPServer((BLOCK_IP, SINKHOLE_HTTPS_PORT), HttpsSinkholeHandler)
        threading.Thread(target=https_srv.serve_forever, daemon=True).start()
        mode = "Block Page + แจ้งเตือน" if TLS_BASE_CTX else "แจ้งเตือนอย่างเดียว (SNI)"
        log(f"HTTPS sinkhole เริ่มทำงานที่ {BLOCK_IP}:{SINKHOLE_HTTPS_PORT} — โหมด: {mode}")
    except Exception as e:
        log(f"เปิด HTTPS sinkhole port {SINKHOLE_HTTPS_PORT} ไม่ได้: {e}")


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
        if LOCAL_CA is not None:
            remove_local_ca()
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
    setup_tls_block_page()
    start_sinkhole()
    agent.start()

    # เปิดหน้า web login อัตโนมัติ
    open_login_page()

    # Keep main thread alive
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()
