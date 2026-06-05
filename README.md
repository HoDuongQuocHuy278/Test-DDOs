# 🛡️ Security Testing Suite v3.0

> **Dành cho mục đích học thuật và kiểm thử bảo mật hệ thống cá nhân.**
> Không sử dụng để tấn công hệ thống của người khác.

Bộ công cụ kiểm thử bảo mật toàn diện gồm **4 module** chạy trên local:

| Module | Mô tả |
|---|---|
| 💥 **DDoS Simulator** | HTTP Flood, Slowloris, POST Flood + 5 kiểu nâng cao |
| 🎣 **Phishing Test** | Kiểm tra Security Headers, Clickjacking, CSRF, Open Redirect |
| 🔐 **Ransomware Test** | File Upload, SQLi, Path Traversal, Default Creds, Backup Exposure |
| 🔍 **WAF Scanner** | Phát hiện 150+ loại WAF (tích hợp wafw00f) |

---

## 🚀 Cài đặt nhanh

### 1. Clone & cài dependencies

```bash
git clone https://github.com/HoDuongQuocHuy278/Test-DDOs.git
cd Test-DDOs
pip install -r requirements.txt
```

### 2. Cài wafw00f (WAF Scanner)

```bash
cd wafw00f
pip install -e .
cd ..
```

### 3. Khởi động hệ thống

```bash
python run.py
```

Launcher sẽ **tự tìm port trống**, patch dashboard, và **tự mở browser**.

---

## 🌐 URLs (mặc định)

| Service | URL |
|---|---|
| 🎯 Target Server | http://localhost:5100 |
| ⚙️ API Server | http://localhost:8910 |
| 🖥️ **Dashboard** | **http://localhost:8910/dashboard** |
| 📖 API Docs | http://localhost:8910/docs |

> Port tự động thay đổi nếu bị conflict. Xem terminal output để biết port chính xác.

---

## 🔧 Tính năng chi tiết

### 💥 DDoS Simulator

**Standard attacks:**
- `http_flood` — GET/POST flood với async workers
- `post_flood` — POST với large body
- `slowloris` — Connection exhaustion

**Enhanced attacks (mới v3):**
- `xml_bomb` — XML entity expansion → crash XML parser, RAM exhaustion
- `large_payload` — 512KB POST × N workers → bandwidth + memory flood
- `header_overflow` — 8KB headers + 50 cookies → buffer stress
- `cache_bypass` — Random query params → bypass CDN cache 100%
- `ua_flood` — Rotating User-Agent + fake IP → evade WAF rate limiting

### 🎣 Phishing Resistance Test

Kiểm tra **15+ security checks**:
- HTTPS enforcement
- Security Headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Clickjacking protection
- Open Redirect vulnerability
- Cookie security flags (Secure, HttpOnly, SameSite)
- Sensitive path exposure (/.env, /.git, /admin...)
- HTTP Methods (TRACE, PUT, DELETE)
- Mixed content
- Information disclosure headers

**Output:** Security Score /100 + Grade (A+ → F) + chi tiết từng check + khuyến nghị sửa

### 🔐 Ransomware Resilience Test

Kiểm tra **7 vector tấn công**:
- File Upload (PHP webshell, malicious files)
- Path Traversal
- SQL Injection (GET + POST)
- Command Injection
- Default Credentials brute-force
- Backup/Config file exposure
- Unauthenticated API endpoints

**Output:** Risk Level (Safe/Low/Medium/High/Critical) + Risk Score /100

### 🔍 WAF Scanner

- Tích hợp [wafw00f](https://github.com/EnableSecurity/wafw00f)
- Phát hiện 150+ WAF providers
- Raw output log

---

## 📁 Cấu trúc dự án

```
Test-DDOs/
├── run.py                  # Launcher chính (auto port detection)
├── api_server.py           # FastAPI backend (WebSocket + REST)
├── requirements.txt
├── target_server/
│   └── app.py              # Flask target server (victim web)
├── ddos_engine/
│   └── stress_test.py      # Standard DDoS engine
├── security_engine/        # NEW v3
│   ├── phishing_test.py    # Phishing resistance checker
│   ├── ransomware_test.py  # Vulnerability scanner
│   └── enhanced_ddos.py    # Advanced DDoS attack types
├── dashboard/
│   ├── index.html          # UI (4 tabs)
│   ├── style.css           # Dark glassmorphism theme
│   └── app.js              # Frontend logic
└── wafw00f/                # WAF detection library
```

---

## ⚙️ Khởi động từng service thủ công

```bash
# Target server (victim)
FLASK_PORT=5100 python target_server/app.py

# API server
python -m uvicorn api_server:app --port 8910

# Dashboard: mở browser tại http://localhost:8910/dashboard
```

---

## 📦 Requirements

```
Python 3.10+
fastapi, uvicorn, aiohttp, flask, requests
websockets, python-multipart, colorama, rich, psutil
```

---

## ⚠️ Cảnh báo pháp lý

Công cụ này **chỉ được sử dụng**:
- Trên hệ thống của chính bạn
- Trên hệ thống bạn có giấy phép kiểm thử bằng văn bản

Sử dụng để tấn công hệ thống của người khác là **vi phạm pháp luật** (Điều 224 BLHS Việt Nam, Computer Fraud and Abuse Act Hoa Kỳ).

---

## 📄 License

MIT License — Educational & Research use only.
