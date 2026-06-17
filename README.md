# Threat Detection & Parental Control System

ระบบตรวจจับและป้องกันภัยคุกคามทางอินเทอร์เน็ต สำหรับใช้งานในห้องคอมพิวเตอร์ของมหาวิทยาลัย (โปรเจกต์จบสายวิชาคอมพิวเตอร์)

ระบบประกอบด้วย agent ที่ติดตั้งบนเครื่อง Windows ของผู้ใช้ (พร้อมแจ้งให้ผู้ใช้ทราบอย่างชัดเจน) และ server กลางสำหรับจัดการ Blacklist/Whitelist พร้อม Admin Panel

## ขอบเขตของระบบ

- รองรับระบบ Authentication & Access Control (ทั้งฝั่ง user และฝั่ง admin)
- ตรวจสอบได้ว่า URL เป็นภัยคุกคามหรือไม่ ผ่าน VirusTotal API
- มีฐานข้อมูลกลาง (cloud) เก็บ Blacklist และ Whitelist
- Admin จัดการ Blacklist/Whitelist ผ่าน Admin Panel ได้
- บล็อกการเข้าถึงโดเมนอันตรายผ่านการแก้ไข hosts file
- ดึงรายชื่อโดเมนอันตรายเพิ่มเติมจาก threat feed สาธารณะ (URLhaus)

## โครงสร้างโปรเจกต์

| ไฟล์ | หน้าที่ |
|---|---|
| `agent.py` | Windows client — บล็อก hosts file, system tray, เปิดหน้า login อัตโนมัติตอน restart |
| `server.py` | FastAPI backend — Blacklist/Whitelist, VirusTotal, Auth, Admin session |
| `admin.html` | Admin Panel — Dashboard, Blacklist, Whitelist, User Activity |
| `uninstall_agent.py` | ตัวถอนการติดตั้ง agent |

## การติดตั้ง (Server)

```bash
pip install -r requirements.txt
cp .env.example .env
# แก้ไข .env ใส่ VT_API_KEY และ ADMIN_USERNAME/ADMIN_PASSWORD ของคุณเอง
python server.py
```

ตัวแปรแวดล้อมที่ต้องตั้งค่าใน `.env`:

- `VT_API_KEY` — VirusTotal API Key (สมัครฟรีได้)
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` — บัญชี admin คนแรกที่ระบบสร้างให้อัตโนมัติตอนเริ่มต้น (ใช้ได้เฉพาะตอนยังไม่มี admin ในระบบ)

## การติดตั้ง (Agent — Windows Client)

```bash
pip install -r requirements.txt
python -m PyInstaller --onefile --windowed --name ThreatDetection agent.py --noconfirm
```

นำ `dist/ThreatDetection.exe` ไปติดตั้งบนเครื่องผู้ใช้ ระบบจะลงทะเบียน Task Scheduler ให้ทำงานอัตโนมัติทุกครั้งที่ล็อกอินเข้า Windows

## ความโปร่งใสต่อผู้ใช้

ระบบนี้ถูกออกแบบให้ผู้ใช้ทราบว่ามีการติดตั้งซอฟต์แวร์อยู่บนเครื่องเสมอ:

- หน้า login แสดงชื่อซอฟต์แวร์และข้อความแจ้งว่าการใช้งานจะถูกบันทึกเพื่อความปลอดภัยขององค์กร
- ไม่มีการซ่อนไฟล์ในลักษณะที่ปกปิดการทำงานของระบบ (ยกเว้นไฟล์ log ที่ซ่อนตามมาตรฐานทั่วไป)
- มีตัวถอนการติดตั้ง (`uninstall_agent.py`) ที่คืนค่าระบบกลับสู่สภาพเดิมได้ครบถ้วน

## หมายเหตุด้านความเป็นส่วนตัว (PDPA)

ระบบเก็บข้อมูลเฉพาะ:
- เวลาล็อกอิน/ล็อกเอาท์ของผู้ใช้
- โดเมนที่ถูกบล็อกเท่านั้น (ไม่เก็บประวัติการเข้าเว็บไซต์ทั้งหมด)

## License

โปรเจกต์นี้จัดทำขึ้นเพื่อการศึกษา (โปรเจกต์จบมหาวิทยาลัย)
