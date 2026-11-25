import os
import time
import apsw
import sqlite3
import secrets
import hashlib
import requests
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Query
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional
from vfs import HTTPRangeVFS

# ==========================================
# ⚙️ SETTINGS
# ==========================================
app = FastAPI()
security = HTTPBasic()

DB_URL = os.environ.get("DB_URL", "").strip()
HF_TOKEN = os.environ.get("HF_TOKEN", "").strip() or None

db_conn = None 

CREDITS = {
    "developer": "Cyber_insight_309",
    "name": "Devid",
    "telegram": "@cyber_insight_309",
    "co_developer": "Gope",
    "co_developer_name": "Annomous"
}

def hash_pass(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

# ==========================================
# 🗄️ ADMIN DATABASE SETUP (users.db)
# ==========================================
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS admins (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
    c.execute("SELECT count(*) FROM admins")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO admins (username, password, role) VALUES (?, ?, ?)", ("admin", hash_pass("CyberAdmin123"), "superadmin"))

    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        api_key TEXT PRIMARY KEY, owner_name TEXT, expiry_date TEXT, max_limit INTEGER, 
        used_count INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1, created_date TEXT, 
        rate_limit_seconds INTEGER DEFAULT 1, last_request_time TEXT, allowed_ip TEXT,
        key_type TEXT DEFAULT 'id'
    )''')
    
    try: c.execute("ALTER TABLE api_keys ADD COLUMN key_type TEXT DEFAULT 'id'")
    except: pass 
    
    c.execute('''CREATE TABLE IF NOT EXISTS search_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, api_key TEXT, number TEXT, status TEXT, timestamp TEXT, ip_address TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('maintenance', '0')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('global_rate_limit', '1')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('tg_token', '')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('tg_chatid', '')")
    
    conn.commit()
    conn.close()

init_db()

def get_setting(key):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def set_setting(key, value):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
    conn.commit()
    conn.close()

def send_telegram_alert(message):
    token = get_setting("tg_token")
    chat_id = get_setting("tg_chatid")
    if token and chat_id:
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            requests.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"}, timeout=5)
        except: pass

# ==========================================
# 🚀 LIFESPAN (Remote VFS Load)
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_conn
    print("⏳ Remote Database se connect ho raha hai (HTTP Range VFS)...")
    
    if not DB_URL:
        raise Exception("DB_URL env variable missing!")
        
    try:
        # VFS mein asli URL pass kar rahe hain
        vfs = HTTPRangeVFS("httpvfs", url=DB_URL, token=HF_TOKEN)
        
        # SQLite ko dummy naam de rahe hain taaki wo path na badle
        db_conn = apsw.Connection("remote_db.sqlite", flags=apsw.SQLITE_OPEN_READONLY, vfs="httpvfs")
        db_conn.execute("PRAGMA query_only = ON;")
        print("✅ Database ready! API is live.")
    except Exception as e:
        print(f"❌ DB Error: {e}")
        raise e
        
    yield
    
    if db_conn:
        db_conn.close()

app.router.lifespan_context = lifespan

# ==========================================
# 🔐 AUTHENTICATION
# ==========================================
def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT password, role FROM admins WHERE username = ?", (credentials.username,))
    row = c.fetchone()
    conn.close()
    
    if not row or not secrets.compare_digest(hash_pass(credentials.password), row[0]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Credentials", headers={"WWW-Authenticate": "Basic"})
    return {"username": credentials.username, "role": row[1]}

# ==========================================
# 🌐 PUBLIC STATUS PAGE
# ==========================================
@app.get("/status", response_class=HTMLResponse)
async def status_page():
    is_maint = get_setting("maintenance") == "1"
    status_color = "#ff477e" if is_maint else "#00ffad"
    status_text = "MAINTENANCE MODE" if is_maint else "SYSTEM ONLINE"
    return f"""
    <html><head><title>Cyber DB API Status</title><style>body{{background:#02080b;color:#e2faff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;text-align:center;}} .box{{border:1px solid #10474a;padding:40px;border-radius:16px;background:#061318;}} h1{{color:{status_color};}}</style></head>
    <body><div class="box"><h1>{status_text}</h1><p>API is currently {status_text.lower()}.</p></div></body></html>
    """

# ==========================================
# 📊 API FOR FRONTEND DASHBOARD
# ==========================================
@app.get("/api/admin/dashboard")
async def get_dashboard_data(admin: dict = Depends(verify_admin)):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM api_keys ORDER BY created_date DESC")
    rows = c.fetchall()
    c.execute("SELECT * FROM search_logs ORDER BY id DESC LIMIT 100")
    logs_rows = c.fetchall()
    c.execute("SELECT username, role FROM admins")
    admins_rows = c.fetchall()
    c.execute("SELECT timestamp FROM search_logs")
    all_logs = c.fetchall()
    conn.close()

    keys_list = []
    for r in rows:
        key, owner, expiry, limit, used, active, created, rate_limit, last_req, allowed_ip, key_type = r
        status_str = "active" if active else "blocked"
        try:
            if datetime.strptime(expiry, "%Y-%m-%d").date() < datetime.now().date(): status_str = "expired"
        except: pass
        keys_list.append({"id": key, "key": key, "owner": owner, "expiry": expiry, "limit": limit, "used": used, "status": status_str, "created": created, "rate_limit": rate_limit, "allowed_ip": allowed_ip, "key_type": key_type})

    logs_list = [{"id": l[0], "key": l[1], "number": l[2], "status": l[3], "time": l[4], "ip": l[5]} for l in logs_rows]
    admins_list = [{"username": a[0], "role": a[1]} for a in admins_rows]

    chart_data = [0]*7
    today = datetime.now().date()
    for log in all_logs:
        try:
            log_date = datetime.strptime(log[0][:10], "%Y-%m-%d").date()
            diff = (today - log_date).days
            if 0 <= diff < 7: chart_data[6 - diff] += 1
        except: pass

    return {
        "stats": {"total": len(keys_list), "active": sum(1 for k in keys_list if k["status"] == "active"), "requests": sum(k["used"] for k in keys_list), "blocked": sum(1 for k in keys_list if k["status"] != "active")},
        "keys": keys_list, "logs": logs_list, "admins": admins_list, "chart_data": chart_data,
        "settings": {"maintenance": get_setting("maintenance"), "global_rate_limit": get_setting("global_rate_limit"), "tg_token": get_setting("tg_token"), "tg_chatid": get_setting("tg_chatid")},
        "current_role": admin["role"]
    }

@app.post("/api/admin/generate")
async def generate_key(owner: str = Form(...), days: int = Form(...), limit: int = Form(...), key_type: str = Form("id"), allowed_ip: str = Form(""), admin: dict = Depends(verify_admin)):
    new_key = f"HTK-{secrets.token_hex(4).upper()}"
    expiry_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    created_date = datetime.now().strftime("%Y-%m-%d")
    rate_limit = int(get_setting("global_rate_limit") or 1)
    clean_ip = allowed_ip.strip() if allowed_ip.strip() else None
    
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO api_keys (api_key, owner_name, expiry_date, max_limit, created_date, rate_limit_seconds, allowed_ip, key_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (new_key, owner, expiry_date, limit, created_date, rate_limit, clean_ip, key_type))
    conn.commit()
    conn.close()
    return {"success": True, "key": new_key}

class ActionPayload(BaseModel):
    key: str
    action: str
    value: Optional[str] = None

@app.post("/api/admin/action")
async def admin_action(payload: ActionPayload, admin: dict = Depends(verify_admin)):
    if admin["role"] != "superadmin" and payload.action in ["delete", "edit", "block", "unblock"]:
        raise HTTPException(status_code=403, detail="Sub-admins cannot modify keys.")
        
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    if payload.action == "extend":
        c.execute("SELECT expiry_date FROM api_keys WHERE api_key = ?", (payload.key,))
        row = c.fetchone()
        if row:
            try: new_date = (datetime.strptime(row[0], "%Y-%m-%d") + timedelta(days=30)).strftime("%Y-%m-%d")
            except: new_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            c.execute("UPDATE api_keys SET expiry_date = ? WHERE api_key = ?", (new_date, payload.key))
    elif payload.action == "increase":
        c.execute("UPDATE api_keys SET max_limit = max_limit + 500 WHERE api_key = ?", (payload.key,))
    elif payload.action == "edit":
        try:
            new_limit, new_expiry, new_ip = payload.value.split("|")
            new_ip = new_ip.strip() if new_ip.strip() else None
            c.execute("UPDATE api_keys SET max_limit = ?, expiry_date = ?, allowed_ip = ? WHERE api_key = ?", (int(new_limit), new_expiry, new_ip, payload.key))
        except: pass
    elif payload.action == "block":
        c.execute("UPDATE api_keys SET is_active = 0 WHERE api_key = ?", (payload.key,))
    elif payload.action == "unblock":
        c.execute("UPDATE api_keys SET is_active = 1 WHERE api_key = ?", (payload.key,))
    elif payload.action == "delete":
        c.execute("DELETE FROM api_keys WHERE api_key = ?", (payload.key,))
        
    conn.commit()
    conn.close()
    return {"success": True}

class SettingsPayload(BaseModel):
    maintenance: str
    global_rate_limit: str
    tg_token: str
    tg_chatid: str

@app.post("/api/admin/settings")
async def update_settings(payload: SettingsPayload, admin: dict = Depends(verify_admin)):
    if admin["role"] != "superadmin": raise HTTPException(status_code=403, detail="Access Denied")
    set_setting("maintenance", payload.maintenance)
    set_setting("global_rate_limit", payload.global_rate_limit)
    set_setting("tg_token", payload.tg_token)
    set_setting("tg_chatid", payload.tg_chatid)
    return {"success": True}

class SubAdminPayload(BaseModel):
    username: str
    password: str

@app.post("/api/admin/add_subadmin")
async def add_subadmin(payload: SubAdminPayload, admin: dict = Depends(verify_admin)):
    if admin["role"] != "superadmin": raise HTTPException(status_code=403, detail="Access Denied")
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO admins (username, password, role) VALUES (?, ?, 'subadmin')", (payload.username, hash_pass(payload.password)))
        conn.commit()
        success = True
    except sqlite3.IntegrityError: success = False
    conn.close()
    return {"success": success}

@app.delete("/api/admin/remove_subadmin/{username}")
async def remove_subadmin(username: str, admin: dict = Depends(verify_admin)):
    if admin["role"] != "superadmin": raise HTTPException(status_code=403, detail="Access Denied")
    if username == "admin": return {"success": False}
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("DELETE FROM admins WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return {"success": True}

# ==========================================
# 🖥️ ADMIN HTML
# ==========================================
ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Insta Database API — Admin Panel</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg:#02080b;--panel:#061318;--line:#0a4949;--green:#00ffad;--cyan:#00e5ff;--text:#e2faff;--muted:#86aebc;--red:#ff477e;--radius:16px;}
*{box-sizing:border-box} body{margin:0;background:radial-gradient(ellipse at 50% 0%,#06242a 0,#02080b 55%,#010507 100%);color:var(--text);font-family:Inter,sans-serif;min-height:100vh;}
button,input,select{font:inherit} button{cursor:pointer}
.app{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}
.sidebar{position:sticky;top:0;height:100vh;padding:26px 16px;border-right:1px solid #0b353c;background:rgba(2,12,16,.92);display:flex;flex-direction:column;gap:28px;z-index:100;}
.brand{display:flex;align-items:center;gap:12px;padding:0 10px 22px;border-bottom:1px solid #10383d}
.logo{width:42px;height:42px;display:grid;place-items:center;color:#001c18;background:var(--green);font-size:24px;font-weight:900;}
.brand strong{font-size:15px;color:var(--green);display:block}.brand small{color:var(--muted);font-size:11px}
.nav{display:grid;gap:8px}.nav button{display:flex;align-items:center;gap:13px;padding:13px 14px;border:1px solid transparent;border-radius:10px;background:transparent;color:#9bbfc8;text-align:left}
.nav button:hover,.nav button.active{border-color:#087e71;background:linear-gradient(90deg,#05372f,#06232a);color:var(--green);box-shadow:inset 3px 0 var(--green);}
main{padding:28px 42px;width:100%}.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}
h1{font-size:24px;margin:0}.subtitle{color:var(--muted);font-size:14px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:22px}
.stat{border:1px solid #10474a;border-radius:var(--radius);padding:18px;background:linear-gradient(145deg,#071d22,#041015);}
.stat .stat-icon{font-size:21px;color:var(--green)}.stat label{color:#8bb9c2;font-size:12px;margin-top:14px;display:block}
.stat strong{font-size:28px;margin:3px 0}.stat small{color:var(--green);font-size:11px}
.content-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:20px;align-items:start}
.card{border:1px solid #10474a;border-radius:var(--radius);background:linear-gradient(150deg,rgba(6,27,32,.97),rgba(3,13,18,.98));margin-bottom:20px;}
.card-head{padding:19px 21px;border-bottom:1px solid #10363d;display:flex;justify-content:space-between;align-items:center;}
.card-head h2{font-size:17px;margin:0;color:var(--green)}.card-body{padding:20px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:17px}.field{display:grid;gap:8px}.field.full{grid-column:1/-1}
.field label{font-size:12px;color:#a8d2da}.field input,.field select,.search{width:100%;padding:13px;color:var(--text);background:#020d12;border:1px solid #15515a;border-radius:10px;outline:none}
.btn{border:1px solid transparent;border-radius:10px;padding:13px;font-weight:700;color:#00150f;background:var(--green);}.btn.full{width:100%;grid-column:1/-1}
.btn.secondary{background:#09232b;color:#b7e9ef;border-color:#15515a}.btn.danger{background:#390d20;color:#ff8eae;}
.key-row{display:grid;grid-template-columns:35px 1fr auto 28px;gap:10px;padding:14px 4px;border-bottom:1px solid #0c2c33;align-items:center;}
.key-main strong{font:12px monospace;display:block}.key-main small{color:#83abb8;font-size:11px}
.status{font-size:10px;padding:6px 9px;border-radius:20px;font-weight:700;background:#063c30;color:var(--green)}
.status.expired{background:#451026;color:#ff7aa3}.status.blocked{background:#132b45;color:#8cc8ff}
.log-table{width:100%;border-collapse:collapse}.log-table th{text-align:left;padding:10px;color:var(--muted);font-size:12px;border-bottom:1px solid #10363d;}.log-table td{padding:10px;font-size:12px;border-bottom:1px solid #0c2c33;}
.switch{position:relative;display:inline-block;width:46px;height:24px;}.switch input{opacity:0;width:0;height:0;}.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:#2a3b45;transition:.4s;border-radius:24px;}.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background-color:white;transition:.4s;border-radius:50%;}input:checked + .slider{background-color:var(--green);}input:checked + .slider:before{transform:translateX(22px);}
.page-section{display:none;}.page-section.active{display:block;}
.toast{position:fixed;right:22px;bottom:22px;padding:14px 18px;border:1px solid var(--green);border-radius:12px;background:#041b18;color:#caffed;display:none;z-index:200}.toast.show{display:block;}
@media (max-width: 900px){.app{display:block}.sidebar{position:fixed;left:-270px;width:250px;transition:left .3s;z-index:999;height:100vh}.sidebar.open{left:0}.stats{grid-template-columns:1fr 1fr}.content-grid{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}main{padding:15px}}
.mobile-menu{display:none;background:none;border:none;color:white;font-size:24px}
@media(max-width:900px){.mobile-menu{display:block}}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar" id="sidebar">
    <div class="brand"><div class="logo">ϟ</div><div><strong>Insta DB API</strong><small id="roleLabel">LOADING...</small></div></div>
    <nav class="nav" aria-label="Main navigation">
      <button class="active" onclick="showPage('dashboard', this)">⌂ Dashboard</button>
      <button onclick="showPage('keys', this)">⚿ API Keys</button>
      <button onclick="showPage('generate', this)" id="navGenerate">⊕ Generate Key</button>
      <button onclick="showPage('logs', this)">📄 Search Logs</button>
      <button onclick="showPage('team', this)" id="navTeam">👥 Sub-Admins</button>
      <button onclick="showPage('settings', this)" id="navSettings">⚙ Settings</button>
    </nav>
  </aside>
  <main>
    <header class="topbar">
      <div style="display:flex;gap:12px;align-items:center">
        <button class="mobile-menu" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
        <div><h1>Insta Database API</h1><p class="subtitle">Your keys. Your rules. Total control.</p></div>
      </div>
      <button class="btn secondary" onclick="loadData()">↻ Refresh</button>
    </header>

    <div id="page-dashboard" class="page-section active">
        <section class="stats">
        <article class="stat"><div class="stat-icon">⚿</div><label>Total Keys</label><strong id="totalStat">0</strong><small>↗ Created</small></article>
        <article class="stat"><div class="stat-icon">ϟ</div><label>Active</label><strong id="activeStat">0</strong><small>● Enabled</small></article>
        <article class="stat"><div class="stat-icon">⇄</div><label>Requests</label><strong id="requestStat">0</strong><small>↗ All time</small></article>
        <article class="stat" style="border-color:#5c2038"><div class="stat-icon" style="color:var(--red)">⊘</div><label>Blocked</label><strong id="blockedStat">0</strong><small style="color:var(--red)">● Restricted</small></article>
        </section>
        <article class="card">
            <div class="card-head"><h2>📈 Last 7 Days Analytics</h2></div>
            <div class="card-body"><canvas id="usageChart" height="100"></canvas></div>
        </article>
    </div>

    <div id="page-generate" class="page-section">
        <article class="card">
          <div class="card-head"><h2>⌁ Generate New API Key</h2></div>
          <div class="card-body">
            <form id="keyForm" class="form-grid">
              <div class="field"><label>Owner name</label><input id="owner" placeholder="e.g. John Doe" required></div>
              <div class="field">
                  <label>Search Type (Strict)</label>
                  <select id="key_type">
                      <option value="id">ID Only</option>
                      <option value="phone">Phone Number Only</option>
                      <option value="username">Username Only</option>
                      <option value="email">Email Only</option>
                  </select>
              </div>
              <div class="field"><label>Valid days</label><select id="expiry"><option value="1">1 day</option><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option><option value="365">365 days</option></select></div>
              <div class="field"><label>Max requests</label><select id="limit"><option value="50">50</option><option value="100" selected>100</option><option value="500">500</option><option value="1000">1,000</option><option value="5000">5,000</option></select></div>
              <div class="field full"><label>Allowed IP (Optional)</label><input id="allowed_ip" placeholder="e.g. 192.168.1.1"></div>
              <button class="btn full" type="submit" id="genBtn">ϟ GENERATE API KEY</button>
            </form>
          </div>
        </article>
    </div>

    <div id="page-keys" class="page-section">
        <div class="content-grid">
          <section>
            <article class="card">
              <div class="card-head"><h2>⌘ Managed Keys</h2><input class="search" id="searchInput" placeholder="Search..." style="width:150px"></div>
              <div class="card-body" id="keyList"></div>
            </article>
          </section>
          <section>
            <article class="card">
              <div class="card-head"><h2>◈ Key Intelligence</h2></div>
              <div class="card-body" id="keyDetails">
                <div style="text-align:center; color:var(--muted)">Select a key to manage.</div>
              </div>
            </article>
          </section>
        </div>
    </div>

    <div id="page-logs" class="page-section">
        <article class="card">
            <div class="card-head"><h2>📄 Search Logs</h2></div>
            <div class="card-body" style="overflow-x:auto;">
                <table class="log-table"><thead><tr><th>Time</th><th>Key</th><th>Query</th><th>IP</th><th>Status</th></tr></thead><tbody id="logsBody"></tbody></table>
            </div>
        </article>
    </div>

    <div id="page-team" class="page-section">
        <div class="content-grid">
            <section>
                <article class="card">
                    <div class="card-head"><h2>👥 Add Sub-Admin</h2></div>
                    <div class="card-body">
                        <form id="subadminForm" class="form-grid">
                            <div class="field full"><label>Username</label><input id="subUser" required></div>
                            <div class="field full"><label>Password</label><input type="password" id="subPass" required></div>
                            <button class="btn full" type="submit">CREATE SUB-ADMIN</button>
                        </form>
                    </div>
                </article>
            </section>
            <section>
                <article class="card">
                    <div class="card-head"><h2>👥 Team Members</h2></div>
                    <div class="card-body" id="teamList"></div>
                </article>
            </section>
        </div>
    </div>

    <div id="page-settings" class="page-section">
        <article class="card">
            <div class="card-head"><h2>⚙ Global Settings</h2></div>
            <div class="card-body">
                <form id="settingsForm">
                    <div class="field" style="flex-direction:row; justify-content:space-between; margin-bottom:20px;">
                        <div><label>Maintenance Mode</label></div>
                        <label class="switch"><input type="checkbox" id="setMaintenance"><span class="slider"></span></label>
                    </div>
                    <div class="field" style="margin-bottom:20px;"><label>Rate Limit (Secs)</label><input type="number" id="setRateLimit" class="search" required></div>
                    <div style="border-top:1px solid #10363d; padding-top:20px;">
                        <h3 style="color:var(--green)">Telegram Alerts</h3>
                        <div class="field" style="margin-bottom:15px;"><label>Bot Token</label><input type="text" id="setTgToken" class="search"></div>
                        <div class="field" style="margin-bottom:15px;"><label>Chat ID</label><input type="text" id="setTgChatId" class="search"></div>
                    </div>
                    <button type="submit" class="btn full">SAVE SETTINGS</button>
                </form>
            </div>
        </article>
    </div>
  </main>
</div>
<div class="toast" id="toast"></div>
<script>
let keys = [], logs = [], admins = [], currentSettings = {}, currentRole = "subadmin", selectedId = null, chartInstance = null;
const $ = id => document.getElementById(id);
function showPage(pageId, btn) { document.querySelectorAll('.page-section').forEach(p => p.classList.remove('active')); $('page-' + pageId).classList.add('active'); if(btn) { document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active')); btn.classList.add('active'); } if(pageId === 'settings') loadSettingsUI(); if(window.innerWidth <= 900) $('sidebar').classList.remove('open'); }
function toast(message){ const t=$("toast"); t.textContent=message; t.classList.add("show"); setTimeout(()=>t.classList.remove("show"),3200); }
function escapeHtml(s){ return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function loadSettingsUI() { $("setMaintenance").checked = currentSettings.maintenance === "1"; $("setRateLimit").value = currentSettings.global_rate_limit || "1"; $("setTgToken").value = currentSettings.tg_token || ""; $("setTgChatId").value = currentSettings.tg_chatid || ""; }
function updateStats(stats){ $("totalStat").textContent = stats.total; $("activeStat").textContent = stats.active; $("blockedStat").textContent = stats.blocked; $("requestStat").textContent = stats.requests.toLocaleString(); }
function renderChart(data) { if(chartInstance) chartInstance.destroy(); const ctx = document.getElementById('usageChart').getContext('2d'); chartInstance = new Chart(ctx, { type: 'line', data: { labels: ['6d','5d','4d','3d','2d','1d','Today'], datasets: [{ data: data, borderColor: '#00ffad', backgroundColor: 'rgba(0, 255, 173, 0.1)', borderWidth: 2, fill: true, tension: 0.4 }] }, options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true }, x: { grid: { display: false } } } } }); }

function renderKeys(){
    const query=$("searchInput").value.trim().toLowerCase();
    const shown=keys.filter(k=>(`${k.key} ${k.owner} ${k.status}`.toLowerCase().includes(query)));
    $("keyList").innerHTML = shown.length ? shown.map(k=>`
        <div class="key-row">
            <div class="stat-icon">⚿</div>
            <div class="key-main"><strong>${escapeHtml(k.key)}</strong><small>${escapeHtml(k.owner)} • ${k.used}/${k.limit} • ${k.key_type.toUpperCase()}</small></div>
            <span class="status ${k.status}">${k.status.toUpperCase()}</span>
            <button class="btn secondary" onclick="selectKey('${k.key}')">›</button>
        </div>`).join("") : `<p style="color:var(--muted)">No keys found.</p>`;
}

function selectKey(id){
    selectedId=id; const k=keys.find(x=>x.key===id); if(!k) return;
    let actionButtons = currentRole === "superadmin" ? `
            <button class="btn" onclick="performAction('${k.key}', 'extend')">Extend 30 Days</button>
            <button class="btn secondary" onclick="performAction('${k.key}', 'increase')">Increase Limit</button>
            <button class="btn secondary" onclick="editKey('${k.key}', ${k.limit}, '${k.expiry}', '${k.allowed_ip||""}')">Edit Settings</button>
            <button class="btn ${k.status==="active"?"danger":"secondary"}" onclick="performAction('${k.key}', '${k.status==="active"?"block":"unblock"}')">${k.status==="active"?"Block":"Unblock"}</button>
            <button class="btn danger" onclick="deleteKey('${k.key}')">DELETE KEY</button>` 
            : `<div style="color:var(--red); font-size:12px;">Read-only access.</div>`;

    $("keyDetails").innerHTML = `
        <div class="detail-top"><h3>${k.key}</h3><span class="status ${k.status}">${k.status.toUpperCase()}</span></div>
        <p><b>Owner:</b> ${k.owner}</p><p><b>Type:</b> ${k.key_type.toUpperCase()}</p>
        <p><b>Expiry:</b> ${k.expiry}</p><p><b>Used:</b> ${k.used} / ${k.limit}</p>
        <div class="actions" style="display:grid; gap:8px;">${actionButtons}</div>`;
}

function editKey(key, currentLimit, currentExpiry, currentIp) {
    const newLimit = prompt("Enter new Max Request Limit:", currentLimit); if(newLimit === null) return;
    const newExpiry = prompt("Enter new Expiry Date (YYYY-MM-DD):", currentExpiry); if(newExpiry === null) return;
    const newIp = prompt("Enter Allowed IP (Leave blank for any):", currentIp || ""); if(newIp === null) return;
    performAction(key, 'edit', newLimit + "|" + newExpiry + "|" + newIp);
}
function deleteKey(key) { if(confirm("Permanently delete this API key?")) { performAction(key, "delete"); $("keyDetails").innerHTML = 'Select a key.'; } }

async function performAction(key, action, value=null) {
    try {
        const res = await fetch('/api/admin/action', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({key, action, value}) });
        if(res.ok) { toast("Action successful"); await loadData(); if(action !== "delete") selectKey(key); } else { toast("Action failed!"); }
    } catch(e) { toast("Network error!"); }
}

async function loadData() {
    try {
        const res = await fetch('/api/admin/dashboard'); const data = await res.json();
        keys = data.keys; logs = data.logs; admins = data.admins; currentSettings = data.settings; currentRole = data.current_role;
        $("roleLabel").textContent = currentRole.toUpperCase();
        $("navTeam").style.display = currentRole !== "superadmin" ? "none" : "flex";
        $("navSettings").style.display = currentRole !== "superadmin" ? "none" : "flex";
        updateStats(data.stats); renderKeys(); renderChart(data.chart_data);
        
        $("logsBody").innerHTML = logs.map(l => `<tr><td style="color:var(--muted)">${l.time}</td><td style="color:var(--cyan)">${l.key}</td><td>${l.number}</td><td style="color:var(--muted)">${l.ip}</td><td style="color:${l.status==='Found'?'var(--green)':'var(--red)'}">${l.status}</td></tr>`).join("") || '<tr><td colspan="5">No logs.</td></tr>';
        $("teamList").innerHTML = admins.map(a => `<div class="detail-line" style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #222"><div>${a.username} (${a.role})</div>${a.username !== "admin" ? `<button class="btn danger" style="padding:2px 8px;font-size:10px" onclick="removeAdmin('${a.username}')">Remove</button>` : ''}</div>`).join("");
        if($("page-settings").classList.contains('active')) loadSettingsUI();
    } catch(e) { toast("Failed to load data"); }
}

$("keyForm").addEventListener("submit", async (e)=>{
    e.preventDefault(); $("genBtn").disabled = true; $("genBtn").textContent = "Generating...";
    const formData = new FormData(); formData.append("owner", $("owner").value); formData.append("key_type", $("key_type").value); formData.append("days", $("expiry").value); formData.append("limit", $("limit").value); formData.append("allowed_ip", $("allowed_ip").value);
    try { const res = await fetch('/api/admin/generate', { method: 'POST', body: formData }); if(res.ok) { const r = await res.json(); $("owner").value=""; $("allowed_ip").value=""; toast("Key: " + r.key); await loadData(); } } catch(e) {}
    $("genBtn").disabled = false; $("genBtn").textContent = "ϟ GENERATE API KEY";
});
$("settingsForm").addEventListener("submit", async (e) => { e.preventDefault(); const payload = { maintenance: $("setMaintenance").checked ? "1" : "0", global_rate_limit: $("setRateLimit").value, tg_token: $("setTgToken").value, tg_chatid: $("setTgChatId").value }; try { const res = await fetch('/api/admin/settings', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) }); if(res.ok) { toast("Saved!"); await loadData(); } } catch(e) {} });
$("subadminForm").addEventListener("submit", async (e) => { e.preventDefault(); const payload = { username: $("subUser").value, password: $("subPass").value }; try { const res = await fetch('/api/admin/add_subadmin', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) }); const d = await res.json(); if(d.success) { toast("Created!"); $("subUser").value=""; $("subPass").value=""; await loadData(); } } catch(e) {} });
async function removeAdmin(username) { if(!confirm("Remove?")) return; try { const res = await fetch(`/api/admin/remove_subadmin/${username}`, { method: 'DELETE' }); if(res.ok) { toast("Removed."); await loadData(); } } catch(e) {} }
$("searchInput").addEventListener("input",renderKeys); loadData();
</script>
</body>
</html>
"""

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(admin: dict = Depends(verify_admin)):
    return HTMLResponse(content=ADMIN_HTML)

# ==========================================
# 🔍 MAIN API ROUTE (Strict Key Type Validation)
# ==========================================
@app.get("/search")
async def search_user_data(
    key: str = Query(..., description="API Key"),
    id: str = Query(None, description="Search by ID"),
    phone: str = Query(None, description="Search by Phone Number"),
    username: str = Query(None, description="Search by Username"),
    email: str = Query(None, description="Search by Email"),
    request: Request = None
):
    if get_setting("maintenance") == "1":
        return JSONResponse({"error": "Server is under maintenance."}, status_code=503)

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "Unknown").split(",")[0].strip()

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT expiry_date, max_limit, used_count, is_active, rate_limit_seconds, last_request_time, allowed_ip, key_type FROM api_keys WHERE api_key = ?", (key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return JSONResponse({"error": "Invalid API Key", "credits": CREDITS}, status_code=401)

    expiry_str, max_limit, used_count, is_active, rate_limit, last_req_str, allowed_ip, key_type = row

    if allowed_ip and allowed_ip.strip() != "":
        if client_ip != allowed_ip.strip():
            conn.close()
            return JSONResponse({"error": f"Access Denied. IP mismatch."}, status_code=403)

    if not is_active:
        conn.close()
        return JSONResponse({"error": "API Key is blocked by Admin", "credits": CREDITS}, status_code=403)

    if datetime.strptime(expiry_str, "%Y-%m-%d").date() < datetime.now().date():
        conn.close()
        return JSONResponse({"error": "API Key Expired", "credits": CREDITS}, status_code=403)

    if used_count >= max_limit:
        conn.close()
        return JSONResponse({"error": "API Limit Exceeded", "credits": CREDITS}, status_code=429)

    if last_req_str:
        last_req_time = datetime.strptime(last_req_str, "%Y-%m-%d %H:%M:%S")
        if (datetime.now() - last_req_time).total_seconds() < rate_limit:
            conn.close()
            return JSONResponse({"error": f"Rate limit exceeded. Wait {rate_limit}s."}, status_code=429)

    # 2. STRICT KEY TYPE VALIDATION
    if key_type == "id":
        if not id: return JSONResponse({"error": "This Key is restricted to 'id' search only."}, status_code=400)
        if phone or username or email: return JSONResponse({"error": "Invalid parameters for this key."}, status_code=400)
    elif key_type == "phone":
        if not phone: return JSONResponse({"error": "This Key is restricted to 'phone' search only."}, status_code=400)
        if id or username or email: return JSONResponse({"error": "Invalid parameters for this key."}, status_code=400)
    elif key_type == "username":
        if not username: return JSONResponse({"error": "This Key is restricted to 'username' search only."}, status_code=400)
        if id or phone or email: return JSONResponse({"error": "Invalid parameters for this key."}, status_code=400)
    elif key_type == "email":
        if not email: return JSONResponse({"error": "This Key is restricted to 'email' search only."}, status_code=400)
        if id or phone or username: return JSONResponse({"error": "Invalid parameters for this key."}, status_code=400)

    # 3. REMOTE SQLITE SEARCH LOGIC (apsw)
    cursor = db_conn.cursor()
    query = "SELECT id, username, email, phone, name, address FROM users WHERE 1=1"
    params = []
    search_term_for_log = "Unknown"

    if id:
        query += " AND id = ?"
        params.append(str(id).strip())
        search_term_for_log = id.strip()
    if phone:
        query += " AND phone = ?"
        params.append(str(phone).strip())
        search_term_for_log = phone.strip()
    if username:
        query += " AND username = ?"
        params.append(str(username).strip())
        search_term_for_log = username.strip()
    if email:
        query += " AND email = ?"
        params.append(str(email).strip())
        search_term_for_log = email.strip()

    query += " LIMIT 10" 
    start_time = time.time()
    
    try:
        cursor.execute(query, params)
        desc = cursor.getdescription()
        results = [{col[0]: row[i] for i, col in enumerate(desc)} for row in cursor]
        search_time = round((time.time() - start_time) * 1000, 2)
        found = len(results) > 0
        status_str = "Found" if found else "Not Found"
    except Exception as e:
        conn.close()
        return JSONResponse({"error": f"Database error: {str(e)}"}, status_code=500)

    # 4. Update DB & Logs
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("UPDATE api_keys SET used_count = used_count + 1, last_request_time = ? WHERE api_key = ?", (now_str, key))
    c.execute("INSERT INTO search_logs (api_key, number, status, timestamp, ip_address) VALUES (?, ?, ?, ?, ?)", (key, search_term_for_log, status_str, now_str, client_ip))
    conn.commit()
    
    # 5. Telegram Alert (90% Limit)
    if used_count + 1 >= int(max_limit * 0.9) and used_count < int(max_limit * 0.9):
        send_telegram_alert(f"⚠️ <b>API Limit Alert!</b>\n\nKey: <code>{key}</code>\nUsed: {used_count + 1}/{max_limit}")
        
    conn.close()

    return JSONResponse({
        "status": "Success" if found else "Not Found",
        "time_taken_ms": search_time,
        "credits": CREDITS,
        "total_results": len(results),
        "data": results
    })

if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 8080))
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
