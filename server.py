from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import sqlite3
import urllib.request
import urllib.error
import json
import time
import os
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
import threading

# ===== VirusTotal API Key =====
# ตั้งค่าผ่าน environment variable VT_API_KEY (ดูตัวอย่างใน .env.example)
VT_API_KEY = os.environ.get("VT_API_KEY", "")
# ==============================

app = FastAPI(title="Threat Detection Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "calculator.db"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        expression TEXT NOT NULL,
        result TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        reason TEXT,
        added_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        added_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS dns_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT,
        client_ip TEXT,
        timestamp TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS vt_cache (
        domain TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        reason TEXT,
        checked_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        email TEXT,
        created_at TEXT NOT NULL
    )""")
    # Migration: เพิ่ม column email ให้ database เก่าที่สร้างไว้ก่อนหน้านี้
    try:
        c.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except sqlite3.OperationalError:
        pass
    c.execute("""CREATE TABLE IF NOT EXISTS password_resets (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS threat_feed (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        source TEXT NOT NULL,
        fetched_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS admin_sessions (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

init_db()

# ===== VirusTotal =====
VT_LAST_CALL = 0

def check_virustotal(domain):
    global VT_LAST_CALL

    if not VT_API_KEY:
        return "safe", ""

    # เช็ค cache ก่อน (24 ชั่วโมง)
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT status, reason, checked_at FROM vt_cache WHERE domain=?", (domain,))
    cached = c.fetchone()
    conn.close()

    if cached:
        checked_time = datetime.strptime(cached[2], "%Y-%m-%d %H:%M:%S")
        age_hours = (datetime.now() - checked_time).total_seconds() / 3600
        if age_hours < 24:
            return cached[0], cached[1]

    # Rate limit 4/min
    elapsed = time.time() - VT_LAST_CALL
    if elapsed < 15:
        time.sleep(15 - elapsed)
    VT_LAST_CALL = time.time()

    try:

        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 3:
            status = "danger"
            reason = f"VirusTotal: {malicious} engines flagged as malicious"
        elif malicious >= 1 or suspicious >= 3:
            status = "suspicious"
            reason = f"VirusTotal: {malicious} malicious, {suspicious} suspicious"
        else:
            status = "safe"
            reason = ""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_conn()
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO vt_cache (domain,status,reason,checked_at) VALUES (?,?,?,?)",
                  (domain, status, reason, timestamp))
        conn.commit()

        # ถ้าอันตราย → เพิ่มใน blacklist อัตโนมัติ
        if status == "danger":
            try:
                c.execute("INSERT INTO blacklist (domain,reason,added_at) VALUES (?,?,?)",
                          (domain, reason, timestamp))
                conn.commit()
            except:
                pass
        conn.close()

        return status, reason

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "safe", "ไม่พบใน VirusTotal"
        return "safe", f"VT error {e.code}"
    except Exception as e:
        return "safe", f"VT error: {str(e)}"

# ===== Models =====
class CalculationLog(BaseModel):
    username: str
    expression: str
    result: str

class DomainCheck(BaseModel):
    domain: str
    client_ip: str = "unknown"

class DomainEntry(BaseModel):
    domain: str
    reason: str = ""

class AuthRequest(BaseModel):
    username: str = ""
    password: str
    email: str = ""

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

# ===== Password hashing =====
def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

# ===== Seed default admin account ถ้ายังไม่มี admin เลย =====
def seed_default_admin():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM admin_users")
    count = c.fetchone()[0]
    if count == 0:
        default_username = os.environ.get("ADMIN_USERNAME", "admin")
        default_password = os.environ.get("ADMIN_PASSWORD", "admin123")
        salt = secrets.token_hex(16)
        password_hash = hash_password(default_password, salt)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO admin_users (username,password_hash,salt,created_at) VALUES (?,?,?,?)",
                  (default_username, password_hash, salt, timestamp))
        conn.commit()
    conn.close()

seed_default_admin()

def is_valid_admin_session(request: Request) -> bool:
    token = request.cookies.get("admin_session")
    if not token:
        return False
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username FROM admin_sessions WHERE token=?", (token,))
    row = c.fetchone()
    conn.close()
    return row is not None

# ===== Auth endpoints =====
@app.post("/register")
def register(data: AuthRequest):
    username = data.username.strip()
    password = data.password
    email = data.email.strip().lower()
    if not username or not password:
        raise HTTPException(status_code=400, detail="กรุณากรอกชื่อผู้ใช้และรหัสผ่าน")
    if not email:
        raise HTTPException(status_code=400, detail="กรุณากรอกอีเมล (ใช้สำหรับกู้คืนรหัสผ่าน)")

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="มีชื่อผู้ใช้นี้แล้ว")

    c.execute("SELECT id FROM users WHERE email=?", (email,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="อีเมลนี้มีบัญชีผู้ใช้อยู่แล้ว กรุณาใช้อีเมลอื่น หรือกู้คืนรหัสผ่านของบัญชีเดิม")

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO users (username,password_hash,salt,email,created_at) VALUES (?,?,?,?,?)",
              (username, password_hash, salt, email, timestamp))
    conn.commit()
    conn.close()
    return {"status": "ok", "username": username}

# ===== Email (Gmail SMTP) สำหรับ reset password =====
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD", "")
SITE_URL = os.environ.get("SITE_URL", "http://143.14.200.159:8000")

def send_email(to_email: str, subject: str, body: str) -> bool:
    if not SMTP_USER or not SMTP_APP_PASSWORD:
        return False
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_APP_PASSWORD)
            server.sendmail(SMTP_USER, [to_email], msg.as_string())
        return True
    except Exception as e:
        print(f"ส่งอีเมลไม่สำเร็จ: {e}")
        return False

@app.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    email = data.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="กรุณากรอกอีเมล")

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE email=?", (email,))
    row = c.fetchone()

    # ไม่บอกว่าพบ/ไม่พบอีเมล เพื่อความปลอดภัย (ป้องกันการเดาว่าอีเมลไหนมีในระบบ)
    if row:
        username = row[0]
        token = secrets.token_urlsafe(32)
        from datetime import timedelta
        expires_dt = datetime.now() + timedelta(minutes=15)
        c.execute("INSERT INTO password_resets (token, username, expires_at, used) VALUES (?,?,?,0)",
                  (token, username, expires_dt.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()

        reset_link = f"{SITE_URL}/reset-password?token={token}"
        body = f"""สวัสดีคุณ {username}

คุณได้ขอกู้คืนรหัสผ่านสำหรับระบบ Threat Detection
กรุณาคลิกลิงก์ด้านล่างเพื่อตั้งรหัสผ่านใหม่ (ลิงก์นี้จะหมดอายุภายใน 15 นาที):

{reset_link}

หากคุณไม่ได้ขอกู้คืนรหัสผ่าน กรุณาเพิกเฉยต่ออีเมลนี้
"""
        send_email(email, "กู้คืนรหัสผ่าน — Threat Detection System", body)

    conn.close()
    return {"status": "ok", "message": "หากอีเมลนี้มีอยู่ในระบบ เราได้ส่งลิงก์กู้คืนรหัสผ่านไปแล้ว"}

@app.post("/reset-password")
def reset_password(data: ResetPasswordRequest):
    token = data.token.strip()
    new_password = data.new_password
    if not token or not new_password:
        raise HTTPException(status_code=400, detail="ข้อมูลไม่ครบถ้วน")

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username, expires_at, used FROM password_resets WHERE token=?", (token,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="ลิงก์ไม่ถูกต้องหรือไม่พบ")

    username, expires_at, used = row
    if used:
        conn.close()
        raise HTTPException(status_code=400, detail="ลิงก์นี้ถูกใช้ไปแล้ว")
    if datetime.now() > datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S"):
        conn.close()
        raise HTTPException(status_code=400, detail="ลิงก์หมดอายุแล้ว กรุณาขอลิงก์ใหม่")

    salt = secrets.token_hex(16)
    password_hash = hash_password(new_password, salt)
    c.execute("UPDATE users SET password_hash=?, salt=? WHERE username=?", (password_hash, salt, username))
    c.execute("UPDATE password_resets SET used=1 WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "เปลี่ยนรหัสผ่านสำเร็จแล้ว"}

@app.post("/login")
def login(data: AuthRequest):
    email = data.email.strip().lower()
    password = data.password
    if not email or not password:
        raise HTTPException(status_code=400, detail="กรุณากรอกอีเมลและรหัสผ่าน")

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username, password_hash, salt FROM users WHERE email=?", (email,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="ไม่พบบัญชีที่ใช้อีเมลนี้ กรุณาสมัครสมาชิกก่อน")

    username, stored_hash, salt = row
    if hash_password(password, salt) != stored_hash:
        conn.close()
        raise HTTPException(status_code=401, detail="รหัสผ่านไม่ถูกต้อง")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO history (username,expression,result,timestamp) VALUES (?,?,?,?)",
              (username, "LOGIN", "web-login", timestamp))
    conn.commit()
    conn.close()
    return {"status": "ok", "username": username}

# ===== Calculator endpoints =====
@app.post("/log")
def log_calculation(data: CalculationLog):
    if not data.username.strip():
        raise HTTPException(status_code=400, detail="กรุณาระบุชื่อผู้ใช้")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO history (username,expression,result,timestamp) VALUES (?,?,?,?)",
              (data.username.strip(), data.expression.strip(), data.result.strip(), timestamp))
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    return {"status": "ok", "id": new_id, "timestamp": timestamp}

@app.get("/history")
def get_history(request: Request, username: str = None, limit: int = 50):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    if username:
        c.execute("SELECT id,username,expression,result,timestamp FROM history WHERE username=? ORDER BY id DESC LIMIT ?", (username, limit))
    else:
        c.execute("SELECT id,username,expression,result,timestamp FROM history ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"username":r[1],"expression":r[2],"result":r[3],"timestamp":r[4]} for r in rows]

@app.get("/stats")
def get_stats(request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM history")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(DISTINCT username) FROM history")
    users = c.fetchone()[0]
    c.execute("SELECT username,COUNT(*) as cnt FROM history GROUP BY username ORDER BY cnt DESC LIMIT 5")
    top_users = [{"username":r[0],"count":r[1]} for r in c.fetchall()]
    conn.close()
    return {"total_calculations": total, "total_users": users, "top_users": top_users}

# ===== DNS Check endpoint =====
@app.post("/check")
def check_domain(data: DomainCheck):
    domain = data.domain.lower().strip()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    c = conn.cursor()

    # 1. เช็ค whitelist ก่อน
    c.execute("SELECT id FROM whitelist WHERE domain=?", (domain,))
    if c.fetchone():
        c.execute("INSERT INTO dns_log (domain,status,reason,client_ip,timestamp) VALUES (?,?,?,?,?)",
                  (domain, "whitelist", "", data.client_ip, timestamp))
        conn.commit()
        conn.close()
        return {"status": "whitelist", "domain": domain}

    # 2. เช็ค blacklist
    c.execute("SELECT reason FROM blacklist WHERE domain=?", (domain,))
    row = c.fetchone()
    if row:
        # เช็คว่า domain + username นี้บันทึกไปแล้วในวันนี้มั้ย
        today = timestamp[:10]
        c.execute("SELECT id FROM dns_log WHERE domain=? AND client_ip=? AND timestamp LIKE ?",
                  (domain, data.client_ip, today + "%"))
        if not c.fetchone():
            c.execute("INSERT INTO dns_log (domain,status,reason,client_ip,timestamp) VALUES (?,?,?,?,?)",
                      (domain, "blacklist", row[0], data.client_ip, timestamp))
            conn.commit()
        conn.close()
        return {"status": "blacklist", "domain": domain, "reason": row[0]}

    conn.close()

    # 3. ส่งไป VirusTotal
    vt_status, vt_reason = check_virustotal(domain)

    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO dns_log (domain,status,reason,client_ip,timestamp) VALUES (?,?,?,?,?)",
              (domain, vt_status, vt_reason, data.client_ip, timestamp))
    conn.commit()
    conn.close()

    return {"status": vt_status, "domain": domain, "reason": vt_reason}

# ===== Blacklist =====
@app.get("/blacklist")
def get_blacklist():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id,domain,reason,added_at FROM blacklist ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"domain":r[1],"reason":r[2],"added_at":r[3]} for r in rows]

@app.post("/blacklist")
def add_blacklist(data: DomainEntry, request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO blacklist (domain,reason,added_at) VALUES (?,?,?)",
                  (data.domain.lower().strip(), data.reason, timestamp))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="domain นี้มีอยู่แล้ว")
    conn.close()
    return {"status": "ok", "domain": data.domain}

@app.delete("/blacklist/{domain}")
def remove_blacklist(domain: str, request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM blacklist WHERE domain=?", (domain,))
    conn.commit()
    affected = c.rowcount
    conn.close()
    if affected == 0:
        raise HTTPException(status_code=404, detail="ไม่พบ domain นี้")
    return {"status": "deleted", "domain": domain}

# ===== Threat Feed (URLhaus) =====
URLHAUS_HOSTFILE_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
THREAT_FEED_LIMIT = 10

def fetch_urlhaus_feed():
    """ดึงรายชื่อ domain อันตรายจาก URLhaus hostfile แล้วเก็บเฉพาะ domain ใหม่
    ที่ยังไม่อยู่ใน blacklist (My Blacklist) — จำกัดแค่ THREAT_FEED_LIMIT รายการล่าสุด"""
    try:
        req = urllib.request.Request(URLHAUS_HOSTFILE_URL, headers={"User-Agent": "ThreatDetectionSystem"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode(errors="ignore")
    except Exception as e:
        return {"status": "error", "detail": str(e)}

    domains = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            domains.append(parts[1].lower())

    conn = get_conn()
    c = conn.cursor()

    # ดึง domain ที่อยู่ใน My Blacklist อยู่แล้ว เพื่อกรองออก
    c.execute("SELECT domain FROM blacklist")
    my_blacklist = set(r[0] for r in c.fetchall())

    new_domains = [d for d in domains if d not in my_blacklist]

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # เก็บแค่ THREAT_FEED_LIMIT รายการล่าสุด: ล้างของเก่าก่อนแล้วใส่ใหม่
    c.execute("DELETE FROM threat_feed WHERE source='urlhaus'")
    added = 0
    for d in new_domains[:THREAT_FEED_LIMIT]:
        try:
            c.execute("INSERT OR REPLACE INTO threat_feed (domain,source,fetched_at) VALUES (?,?,?)",
                      (d, "urlhaus", timestamp))
            added += 1
        except:
            pass
    conn.commit()
    conn.close()

    return {"status": "ok", "total_in_feed": len(domains), "new_domains": len(new_domains), "added": added, "fetched_at": timestamp}

@app.post("/threat-feed/refresh")
def refresh_threat_feed(request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    return fetch_urlhaus_feed()

@app.get("/threat-feed")
def get_threat_feed(request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT domain, source, fetched_at FROM threat_feed ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"domain": r[0], "source": r[1], "fetched_at": r[2]} for r in rows]

# ===== Whitelist =====
@app.get("/whitelist")
def get_whitelist(request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id,domain,added_at FROM whitelist ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"domain":r[1],"added_at":r[2]} for r in rows]

@app.post("/whitelist")
def add_whitelist(data: DomainEntry, request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO whitelist (domain,added_at) VALUES (?,?)",
                  (data.domain.lower().strip(), timestamp))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="domain นี้มีอยู่แล้ว")
    conn.close()
    return {"status": "ok", "domain": data.domain}

@app.delete("/whitelist/{domain}")
def remove_whitelist(domain: str, request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM whitelist WHERE domain=?", (domain,))
    conn.commit()
    affected = c.rowcount
    conn.close()
    if affected == 0:
        raise HTTPException(status_code=404, detail="ไม่พบ domain นี้")
    return {"status": "deleted", "domain": domain}

# ===== DNS Log =====
@app.get("/dns-log")
def get_dns_log(request: Request, limit: int = 100):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id,domain,status,reason,client_ip,timestamp FROM dns_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"id":r[0],"domain":r[1],"status":r[2],"reason":r[3],"client_ip":r[4],"timestamp":r[5]} for r in rows]

# ===== VT Cache =====
@app.get("/vt-cache")
def get_vt_cache(request: Request, limit: int = 50):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT domain,status,reason,checked_at FROM vt_cache ORDER BY checked_at DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"domain":r[0],"status":r[1],"reason":r[2],"checked_at":r[3]} for r in rows]

# ===== Auto-update endpoints =====
AGENT_VERSION = "1.2b"
AGENT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.py")

@app.get("/version")
def get_version():
    return {"version": AGENT_VERSION}

@app.get("/download/agent")
def download_agent():
    from fastapi.responses import FileResponse
    if not os.path.exists(AGENT_FILE):
        raise HTTPException(status_code=404, detail="ไม่พบไฟล์ agent.py")
    return FileResponse(AGENT_FILE, filename="agent.py", media_type="text/plain")

@app.post("/admin/login")
def admin_login(data: AuthRequest):
    username = data.username.strip()
    password = data.password
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM admin_users WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="ไม่พบชื่อผู้ใช้ admin นี้")
    stored_hash, salt = row
    if hash_password(password, salt) != stored_hash:
        conn.close()
        raise HTTPException(status_code=401, detail="รหัสผ่านไม่ถูกต้อง")

    token = secrets.token_hex(32)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO admin_sessions (token, username, created_at) VALUES (?,?,?)",
              (token, username, timestamp))
    conn.commit()
    conn.close()

    from fastapi.responses import JSONResponse
    resp = JSONResponse({"status": "ok", "username": username})
    resp.set_cookie("admin_session", token, httponly=True, max_age=8*60*60, samesite="lax")
    return resp

@app.post("/admin/logout")
def admin_logout(request: Request):
    token = request.cookies.get("admin_session")
    if token:
        conn = get_conn()
        c = conn.cursor()
        c.execute("DELETE FROM admin_sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    from fastapi.responses import JSONResponse
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie("admin_session")
    return resp

@app.get("/admin/login")
def admin_login_page():
    from fastapi.responses import HTMLResponse
    html = """<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Login — Threat Detection</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Sarabun:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background:#0a0c10; color:#e6edf3; font-family:'Sarabun',sans-serif;
    min-height:100vh; display:flex; align-items:center; justify-content:center;
  }
  .card {
    background:#0f1318; border:1px solid #21262d; border-radius:12px;
    padding:40px; width:360px; text-align:center;
    border-top:3px solid #00d4aa;
  }
  .icon { font-size:36px; margin-bottom:8px; }
  h1 { font-family:'JetBrains Mono',monospace; font-size:16px; color:#00d4aa; letter-spacing:1px; margin-bottom:4px; }
  .sub { font-size:13px; color:#7d8590; margin-bottom:24px; }
  label { display:block; text-align:left; font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590; margin-bottom:6px; letter-spacing:1px; }
  input {
    width:100%; background:#161b22; border:1px solid #21262d; border-radius:6px;
    padding:12px 14px; color:#e6edf3; font-family:'JetBrains Mono',monospace; font-size:14px;
    outline:none; margin-bottom:16px; transition:border-color .2s;
  }
  input:focus { border-color:#00d4aa; }
  button {
    width:100%; padding:14px; border:none; border-radius:6px;
    background:#00d4aa; color:#000; font-family:'JetBrains Mono',monospace;
    font-size:13px; font-weight:700; letter-spacing:1px; cursor:pointer; transition:background .2s;
  }
  button:hover { background:#00f0c0; }
  .status { font-family:'JetBrains Mono',monospace; font-size:12px; min-height:18px; margin-bottom:12px; text-align:left; }
  .status.err { color:#f85149; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>ADMIN ACCESS</h1>
    <div class="sub">เฉพาะผู้ดูแลระบบเท่านั้น</div>
    <form id="adminLoginForm">
      <label>ADMIN USERNAME</label>
      <input type="text" id="username" autocomplete="username" required autofocus>
      <label>PASSWORD</label>
      <input type="password" id="password" autocomplete="current-password" required>
      <div class="status" id="status"></div>
      <button type="submit">เข้าสู่ระบบ →</button>
    </form>
  </div>
<script>
document.getElementById('adminLoginForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const status = document.getElementById('status');
  if (!username || !password) return;
  status.className = 'status';
  status.textContent = 'กำลังเข้าสู่ระบบ...';
  try {
    const res = await fetch('/admin/login', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({username, password})
    });
    const data = await res.json();
    if (!res.ok) {
      status.className = 'status err';
      status.textContent = data.detail || 'เข้าสู่ระบบไม่สำเร็จ';
      return;
    }
    window.location.href = '/admin';
  } catch(e) {
    status.className = 'status err';
    status.textContent = 'เกิดข้อผิดพลาด ลองใหม่อีกครั้ง';
  }
});
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/admin")
def serve_admin(request: Request):
    from fastapi.responses import FileResponse, RedirectResponse
    if not is_valid_admin_session(request):
        return RedirectResponse(url="/admin/login")
    return FileResponse("/opt/calculator/admin.html")

@app.get("/users")
def get_users(request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username, MAX(timestamp) as last_seen, COUNT(*) as total FROM history WHERE expression='LOGIN' GROUP BY username ORDER BY last_seen DESC")
    rows = c.fetchall()
    conn.close()
    return [{"username": r[0], "last_seen": r[1], "total_logins": r[2]} for r in rows]

@app.get("/user-activity")
def get_user_activity(request: Request, username: str = None, limit: int = 100):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    if username:
        c.execute("SELECT client_ip, domain, status, timestamp FROM dns_log WHERE client_ip=? ORDER BY timestamp DESC LIMIT ?", (username, limit))
    else:
        c.execute("SELECT client_ip, domain, status, timestamp FROM dns_log ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"username": r[0], "domain": r[1], "status": r[2], "timestamp": r[3]} for r in rows]

# ===== User Management (Admin) =====
class UserEditRequest(BaseModel):
    email: str = None
    new_password: str = None

@app.get("/admin/users-full")
def get_users_full(request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username, email, created_at FROM users ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"username": r[0], "email": r[1] or "", "created_at": r[2]} for r in rows]

@app.get("/admin/duplicate-emails")
def get_duplicate_emails(request: Request):
    """หา user ที่ใช้อีเมลซ้ำกัน (เผื่อมีอยู่ก่อนระบบบังคับ unique email)
    เพื่อให้ admin ไปจัดการ (แก้ไอเมล/ลบ) เองผ่าน Manage Users"""
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("""SELECT email, GROUP_CONCAT(username, ', '), COUNT(*) as cnt
                 FROM users
                 WHERE email IS NOT NULL AND email != ''
                 GROUP BY email
                 HAVING cnt > 1""")
    rows = c.fetchall()
    conn.close()
    return [{"email": r[0], "usernames": r[1], "count": r[2]} for r in rows]

@app.put("/admin/users/{username}")
def edit_user(username: str, data: UserEditRequest, request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=?", (username,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="ไม่พบผู้ใช้นี้")

    if data.email is not None:
        c.execute("UPDATE users SET email=? WHERE username=?", (data.email.strip(), username))
    if data.new_password:
        salt = secrets.token_hex(16)
        password_hash = hash_password(data.new_password, salt)
        c.execute("UPDATE users SET password_hash=?, salt=? WHERE username=?", (password_hash, salt, username))
    conn.commit()
    conn.close()
    return {"status": "ok", "username": username}

@app.delete("/admin/users/{username}")
def delete_user(username: str, request: Request):
    if not is_valid_admin_session(request):
        raise HTTPException(status_code=401, detail="กรุณาเข้าสู่ระบบ admin ก่อน")
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    affected = c.rowcount
    conn.close()
    if affected == 0:
        raise HTTPException(status_code=404, detail="ไม่พบผู้ใช้นี้")
    return {"status": "deleted", "username": username}

@app.get("/")
def root():
    return {"message": "Threat Detection Server กำลังทำงาน 🛡️", "docs": "/docs"}

# ===== Web Login Page =====
@app.get("/login")
def login_page():
    from fastapi.responses import HTMLResponse
    html = """<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>เข้าสู่ระบบ — Threat Detection</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Sarabun:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background:#0a0c10; color:#e6edf3; font-family:'Sarabun',sans-serif;
    min-height:100vh; display:flex; align-items:center; justify-content:center;
  }
  .card {
    background:#0f1318; border:1px solid #21262d; border-radius:12px;
    padding:40px; width:380px; text-align:center;
    border-top:3px solid #00d4aa;
  }
  .icon { font-size:40px; margin-bottom:8px; }
  h1 { font-family:'JetBrains Mono',monospace; font-size:16px; color:#00d4aa; letter-spacing:1px; margin-bottom:4px; }
  .sub { font-size:13px; color:#7d8590; margin-bottom:20px; }
  .notice { font-size:11px; color:#484f58; margin-bottom:20px; }

  .switcher { display:flex; border:1px solid #21262d; border-radius:6px; overflow:hidden; margin-bottom:24px; }
  .switcher button {
    flex:1; padding:10px; border:none; background:#161b22; color:#7d8590;
    font-family:'JetBrains Mono',monospace; font-size:12px; font-weight:600; letter-spacing:1px;
    cursor:pointer; transition:all .2s;
  }
  .switcher button.active { background:#00d4aa; color:#000; }

  label { display:block; text-align:left; font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590; margin-bottom:6px; letter-spacing:1px; }
  input {
    width:100%; background:#161b22; border:1px solid #21262d; border-radius:6px;
    padding:12px 14px; color:#e6edf3; font-family:'JetBrains Mono',monospace; font-size:14px;
    outline:none; margin-bottom:16px; transition:border-color .2s;
  }
  input:focus { border-color:#00d4aa; }
  button[type=submit] {
    width:100%; padding:14px; border:none; border-radius:6px;
    background:#00d4aa; color:#000; font-family:'JetBrains Mono',monospace;
    font-size:13px; font-weight:700; letter-spacing:1px; cursor:pointer; transition:background .2s;
  }
  button[type=submit]:hover { background:#00f0c0; }
  button[type=submit]:disabled { opacity:.5; cursor:default; }
  .status { font-family:'JetBrains Mono',monospace; font-size:12px; min-height:20px; margin-bottom:12px; }
  .status.ok { color:#00d4aa; }
  .status.err { color:#f85149; }
  .form { display:none; }
  .form.active { display:block; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">🛡️</div>
    <h1>THREAT DETECTION</h1>
    <div class="sub">ระบบควบคุมการเข้าถึง</div>
    <div class="notice">การใช้งานจะถูกบันทึกเพื่อความปลอดภัยขององค์กร</div>

    <div class="switcher">
      <button id="tab-login" class="active" onclick="switchForm('login')">เข้าสู่ระบบ</button>
      <button id="tab-register" onclick="switchForm('register')">สมัครสมาชิก</button>
    </div>

    <form id="loginForm" class="form active">
      <label>EMAIL</label>
      <input type="email" id="login-email" autocomplete="email" required>
      <label>PASSWORD</label>
      <input type="password" id="login-password" autocomplete="current-password" required>
      <div class="status" id="login-status"></div>
      <button type="submit">ENTER  →</button>
      <div style="text-align:right;margin-top:12px"><a href="/forgot-password" style="color:#7d8590;font-size:11px;font-family:'JetBrains Mono',monospace;text-decoration:none">ลืมรหัสผ่าน?</a></div>
    </form>

    <form id="registerForm" class="form">
      <label>USERNAME</label>
      <input type="text" id="reg-username" autocomplete="username" required>
      <label>EMAIL</label>
      <input type="email" id="reg-email" autocomplete="email" required>
      <label>PASSWORD</label>
      <input type="password" id="reg-password" autocomplete="new-password" required>
      <label>CONFIRM PASSWORD</label>
      <input type="password" id="reg-confirm" autocomplete="new-password" required>
      <div class="status" id="register-status"></div>
      <button type="submit">สมัครสมาชิก →</button>
    </form>
  </div>
<script>
function switchForm(name) {
  document.getElementById('tab-login').classList.toggle('active', name==='login');
  document.getElementById('tab-register').classList.toggle('active', name==='register');
  document.getElementById('loginForm').classList.toggle('active', name==='login');
  document.getElementById('registerForm').classList.toggle('active', name==='register');
}

async function notifyAgent(username) {
  try {
    await fetch('http://127.0.0.1:47812/set-user', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({username: username})
    });
  } catch(e) {}
}

document.getElementById('loginForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const status = document.getElementById('login-status');
  const btn = e.target.querySelector('button');
  if (!email || !password) return;
  status.className = 'status';
  status.textContent = 'กำลังเข้าสู่ระบบ...';
  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email, password})
    });
    const data = await res.json();
    if (!res.ok) {
      status.className = 'status err';
      status.textContent = data.detail || 'เข้าสู่ระบบไม่สำเร็จ';
      return;
    }
    await notifyAgent(data.username);
    status.className = 'status ok';
    status.textContent = '✓ เข้าสู่ระบบสำเร็จ — คุณสามารถปิดหน้านี้ได้';
    btn.disabled = true;
  } catch(e) {
    status.className = 'status err';
    status.textContent = 'เกิดข้อผิดพลาด ลองใหม่อีกครั้ง';
  }
});

document.getElementById('registerForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const username = document.getElementById('reg-username').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm = document.getElementById('reg-confirm').value;
  const status = document.getElementById('register-status');
  if (!username || !email || !password) return;
  if (password !== confirm) {
    status.className = 'status err';
    status.textContent = 'รหัสผ่านไม่ตรงกัน';
    return;
  }
  status.className = 'status';
  status.textContent = 'กำลังสมัครสมาชิก...';
  try {
    const res = await fetch('/register', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({username, email, password})
    });
    const data = await res.json();
    if (!res.ok) {
      status.className = 'status err';
      status.textContent = data.detail || 'สมัครสมาชิกไม่สำเร็จ';
      return;
    }
    status.className = 'status ok';
    status.textContent = '✓ สมัครสมาชิกสำเร็จ — กำลังไปหน้าเข้าสู่ระบบ...';
    setTimeout(() => {
      switchForm('login');
      document.getElementById('login-email').value = email;
      document.getElementById('login-password').focus();
      status.textContent = '';
    }, 1200);
  } catch(e) {
    status.className = 'status err';
    status.textContent = 'เกิดข้อผิดพลาด ลองใหม่อีกครั้ง';
  }
});
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/forgot-password")
def forgot_password_page():
    from fastapi.responses import HTMLResponse
    html = """<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ลืมรหัสผ่าน — Threat Detection</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Sarabun:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background:#0a0c10; color:#e6edf3; font-family:'Sarabun',sans-serif;
    min-height:100vh; display:flex; align-items:center; justify-content:center;
  }
  .card {
    background:#0f1318; border:1px solid #21262d; border-radius:12px;
    padding:40px; width:380px; text-align:center;
    border-top:3px solid #00d4aa;
  }
  .icon { font-size:36px; margin-bottom:8px; }
  h1 { font-family:'JetBrains Mono',monospace; font-size:16px; color:#00d4aa; letter-spacing:1px; margin-bottom:4px; }
  .sub { font-size:13px; color:#7d8590; margin-bottom:24px; }
  label { display:block; text-align:left; font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590; margin-bottom:6px; letter-spacing:1px; }
  input {
    width:100%; background:#161b22; border:1px solid #21262d; border-radius:6px;
    padding:12px 14px; color:#e6edf3; font-family:'JetBrains Mono',monospace; font-size:14px;
    outline:none; margin-bottom:16px; transition:border-color .2s;
  }
  input:focus { border-color:#00d4aa; }
  button {
    width:100%; padding:14px; border:none; border-radius:6px;
    background:#00d4aa; color:#000; font-family:'JetBrains Mono',monospace;
    font-size:13px; font-weight:700; letter-spacing:1px; cursor:pointer; transition:background .2s;
  }
  button:hover { background:#00f0c0; }
  .status { font-family:'JetBrains Mono',monospace; font-size:12px; min-height:18px; margin-bottom:12px; text-align:left; }
  .status.err { color:#f85149; }
  .status.ok { color:#00d4aa; }
  .back { display:block; margin-top:16px; color:#7d8590; font-size:11px; font-family:'JetBrains Mono',monospace; text-decoration:none; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">🔑</div>
    <h1>ลืมรหัสผ่าน</h1>
    <div class="sub">กรอกอีเมลที่ใช้สมัครสมาชิก เราจะส่งลิงก์กู้คืนรหัสผ่านให้</div>
    <form id="forgotForm">
      <label>EMAIL</label>
      <input type="email" id="email" autocomplete="email" required autofocus>
      <div class="status" id="status"></div>
      <button type="submit">ส่งลิงก์กู้คืนรหัสผ่าน →</button>
    </form>
    <a href="/login" class="back">← กลับไปหน้าเข้าสู่ระบบ</a>
  </div>
<script>
document.getElementById('forgotForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const email = document.getElementById('email').value.trim();
  const status = document.getElementById('status');
  const btn = e.target.querySelector('button');
  if (!email) return;
  status.className = 'status';
  status.textContent = 'กำลังส่ง...';
  try {
    const res = await fetch('/forgot-password', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email})
    });
    const data = await res.json();
    status.className = 'status ok';
    status.textContent = data.message || 'หากอีเมลนี้มีอยู่ในระบบ เราได้ส่งลิงก์กู้คืนรหัสผ่านไปแล้ว';
    btn.disabled = true;
  } catch(e) {
    status.className = 'status err';
    status.textContent = 'เกิดข้อผิดพลาด ลองใหม่อีกครั้ง';
  }
});
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/reset-password")
def reset_password_page(token: str = ""):
    from fastapi.responses import HTMLResponse
    html = """<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ตั้งรหัสผ่านใหม่ — Threat Detection</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Sarabun:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background:#0a0c10; color:#e6edf3; font-family:'Sarabun',sans-serif;
    min-height:100vh; display:flex; align-items:center; justify-content:center;
  }
  .card {
    background:#0f1318; border:1px solid #21262d; border-radius:12px;
    padding:40px; width:380px; text-align:center;
    border-top:3px solid #00d4aa;
  }
  .icon { font-size:36px; margin-bottom:8px; }
  h1 { font-family:'JetBrains Mono',monospace; font-size:16px; color:#00d4aa; letter-spacing:1px; margin-bottom:4px; }
  .sub { font-size:13px; color:#7d8590; margin-bottom:24px; }
  label { display:block; text-align:left; font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590; margin-bottom:6px; letter-spacing:1px; }
  input {
    width:100%; background:#161b22; border:1px solid #21262d; border-radius:6px;
    padding:12px 14px; color:#e6edf3; font-family:'JetBrains Mono',monospace; font-size:14px;
    outline:none; margin-bottom:16px; transition:border-color .2s;
  }
  input:focus { border-color:#00d4aa; }
  button {
    width:100%; padding:14px; border:none; border-radius:6px;
    background:#00d4aa; color:#000; font-family:'JetBrains Mono',monospace;
    font-size:13px; font-weight:700; letter-spacing:1px; cursor:pointer; transition:background .2s;
  }
  button:hover { background:#00f0c0; }
  .status { font-family:'JetBrains Mono',monospace; font-size:12px; min-height:18px; margin-bottom:12px; text-align:left; }
  .status.err { color:#f85149; }
  .status.ok { color:#00d4aa; }
  .back { display:block; margin-top:16px; color:#7d8590; font-size:11px; font-family:'JetBrains Mono',monospace; text-decoration:none; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>ตั้งรหัสผ่านใหม่</h1>
    <div class="sub">กรอกรหัสผ่านใหม่ของคุณ</div>
    <form id="resetForm">
      <input type="hidden" id="token" value="TOKEN_PLACEHOLDER">
      <label>รหัสผ่านใหม่</label>
      <input type="password" id="new-password" autocomplete="new-password" required>
      <label>ยืนยันรหัสผ่านใหม่</label>
      <input type="password" id="confirm-password" autocomplete="new-password" required>
      <div class="status" id="status"></div>
      <button type="submit">ตั้งรหัสผ่านใหม่ →</button>
    </form>
    <a href="/login" class="back">← กลับไปหน้าเข้าสู่ระบบ</a>
  </div>
<script>
document.getElementById('resetForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const token = document.getElementById('token').value;
  const newPassword = document.getElementById('new-password').value;
  const confirmPassword = document.getElementById('confirm-password').value;
  const status = document.getElementById('status');
  const btn = e.target.querySelector('button');
  if (!newPassword) return;
  if (newPassword !== confirmPassword) {
    status.className = 'status err';
    status.textContent = 'รหัสผ่านไม่ตรงกัน';
    return;
  }
  status.className = 'status';
  status.textContent = 'กำลังบันทึก...';
  try {
    const res = await fetch('/reset-password', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({token, new_password: newPassword})
    });
    const data = await res.json();
    if (!res.ok) {
      status.className = 'status err';
      status.textContent = data.detail || 'เกิดข้อผิดพลาด';
      return;
    }
    status.className = 'status ok';
    status.textContent = '✓ เปลี่ยนรหัสผ่านสำเร็จแล้ว — กำลังไปหน้าเข้าสู่ระบบ...';
    btn.disabled = true;
    setTimeout(() => window.location.href = '/login', 1500);
  } catch(e) {
    status.className = 'status err';
    status.textContent = 'เกิดข้อผิดพลาด ลองใหม่อีกครั้ง';
  }
});
</script>
</body>
</html>""".replace("TOKEN_PLACEHOLDER", token)
    return HTMLResponse(content=html)

# ===== Background: refresh threat feed ทุก 24 ชม. =====
@app.on_event("startup")
def start_threat_feed_scheduler():
    def _loop():
        while True:
            try:
                fetch_urlhaus_feed()
            except:
                pass
            time.sleep(24 * 60 * 60)
    threading.Thread(target=_loop, daemon=True).start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
