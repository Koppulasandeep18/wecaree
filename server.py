import os
import sys
import json
import sqlite3
import random
import csv
import io
import time
import hashlib
import secrets
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

PORT = int(os.environ.get('PORT', sys.argv[1] if len(sys.argv) > 1 else 8080))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'leads.db')

os.makedirs(DATA_DIR, exist_ok=True)

# In-memory Rate Limiting with Periodic Eviction (Protects Against Memory Leak)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 30
LOGIN_RATE_LIMIT_WINDOW = 900  # 15 minutes
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 5

ip_request_history = {}
login_attempt_history = {}
rate_limiter_lock = threading.Lock()

def check_rate_limit(client_ip):
    now = time.time()
    with rate_limiter_lock:
        # Periodic eviction when table exceeds 1000 tracked IPs
        if len(ip_request_history) > 1000:
            for ip in list(ip_request_history.keys()):
                valid_times = [t for t in ip_request_history[ip] if now - t < RATE_LIMIT_WINDOW]
                if valid_times:
                    ip_request_history[ip] = valid_times
                else:
                    del ip_request_history[ip]

        history = ip_request_history.get(client_ip, [])
        history = [t for t in history if now - t < RATE_LIMIT_WINDOW]
        if len(history) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        history.append(now)
        ip_request_history[client_ip] = history
        return True

def check_login_rate_limit(client_ip):
    now = time.time()
    with rate_limiter_lock:
        if len(login_attempt_history) > 1000:
            for ip in list(login_attempt_history.keys()):
                valid_times = [t for t in login_attempt_history[ip] if now - t < LOGIN_RATE_LIMIT_WINDOW]
                if valid_times:
                    login_attempt_history[ip] = valid_times
                else:
                    del login_attempt_history[ip]

        history = login_attempt_history.get(client_ip, [])
        history = [t for t in history if now - t < LOGIN_RATE_LIMIT_WINDOW]
        login_attempt_history[client_ip] = history
        if len(history) >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
            return False
        return True

def record_login_attempt(client_ip, success):
    now = time.time()
    with rate_limiter_lock:
        if success:
            if client_ip in login_attempt_history:
                del login_attempt_history[client_ip]
        else:
            history = login_attempt_history.get(client_ip, [])
            history = [t for t in history if now - t < LOGIN_RATE_LIMIT_WINDOW]
            history.append(now)
            login_attempt_history[client_ip] = history

# Database Connection Helper (Enforces WAL Mode & Foreign Keys Per Connection)
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

# Password Hashing Utilities
def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return hashed, salt

def verify_password(password, stored_hash, salt):
    hashed, _ = hash_password(password, salt)
    return secrets.compare_digest(hashed, stored_hash)

# Database Initialization and Non-Destructive Migrations
def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode = WAL;")
    cursor.execute("PRAGMA foreign_keys = ON;")

    # Base inquiries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS inquiries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ref_code TEXT UNIQUE,
            inquiry_type TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT,
            phone TEXT NOT NULL,
            city TEXT,
            state TEXT,
            business_name TEXT,
            business_type TEXT,
            selected_size TEXT,
            flow_rate TEXT,
            raw_water_tds TEXT,
            notes TEXT,
            monthly_volume TEXT,
            status TEXT DEFAULT 'NEW',
            sales_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Non-destructive migrations for inquiries table
    cursor.execute("PRAGMA table_info(inquiries)")
    columns = [row[1] for row in cursor.fetchall()]

    new_cols = {
        'stage': "TEXT DEFAULT 'NEW'",
        'priority': "TEXT DEFAULT 'MEDIUM'",
        'assigned_to': "TEXT DEFAULT 'Unassigned'",
        'next_followup_at': "DATETIME",
        'water_hardness': "TEXT",
        'lead_source': "TEXT DEFAULT 'Website'",
        'deal_value': "REAL DEFAULT 0.0"
    }

    for col, col_type in new_cols.items():
        if col not in columns:
            cursor.execute(f"ALTER TABLE inquiries ADD COLUMN {col} {col_type}")

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT,
            role TEXT NOT NULL DEFAULT 'SALES_EXECUTIVE',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Sessions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Activity and Audit Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lead_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            details TEXT NOT NULL,
            performed_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(lead_id) REFERENCES inquiries(id)
        )
    ''')

    # Settings & Communication Templates Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    # Seed Default Users if none exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_users = [
            ('admin', 'Admin@WeCare2026!', 'Super Admin', 'admin@wecare.com', 'SUPER_ADMIN'),
            ('manager', 'Manager@WeCare2026!', 'Vikram Malhotra (Sales Manager)', 'vikram@wecare.com', 'SALES_MANAGER'),
            ('executive', 'Executive@WeCare2026!', 'Pooja Sharma (Sales Exec)', 'pooja@wecare.com', 'SALES_EXECUTIVE')
        ]
        for username, plain_pass, full_name, email, role in default_users:
            p_hash, salt = hash_password(plain_pass)
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, full_name, email, role)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, p_hash, salt, full_name, email, role))

    # Seed Default Templates if none exist
    default_templates = {
        'tpl_new_quotation': "Hello {customer_name}, thank you for inquiring about {product_size} (Ref: {ref_code}). Our application engineer has received your parameters and is preparing your calibrated technical sheet.",
        'tpl_dealer_registration': "Hello {customer_name}, your dealer application for {business_name} (Ref: {ref_code}) has been received. Our Channel Development Director will contact you within 24 hours.",
        'tpl_water_testing': "Hello {customer_name}, your certified water testing ticket (Ref: {ref_code}) has been logged for {city}. An engineer will reach out to coordinate on-site sample collection.",
        'tpl_followup_reminder': "Hello {customer_name}, following up regarding your WE CARE water scale control inquiry (Ref: {ref_code}). Do you have any updates on your pipeline sizing or installation timeline?",
        'tpl_quotation_sent': "Hello {customer_name}, your official technical sizing and price quotation for {product_size} (Ref: {ref_code}) is ready. Please let us know if you would like us to arrange a site inspection.",
        'tpl_feedback_request': "Hello {customer_name}, how is the water quality after installing your WE CARE scale control unit? We would love your feedback on Ref: {ref_code}.",
        'smtp_host': 'smtp.example.com',
        'smtp_port': '587',
        'smtp_user': 'notifications@wecare.com',
        'smtp_pass': '',
        'notify_email': 'sales@wecare.com',
        'email_notifications_enabled': '0',
        'wa_api_enabled': '0'
    }

    for k, v in default_templates.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    # Performance: Secondary Indexes for fast CRM querying and filtering
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_inquiries_stage ON inquiries(stage);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_inquiries_type ON inquiries(inquiry_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_inquiries_priority ON inquiries(priority);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_inquiries_assigned ON inquiries(assigned_to);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_lead ON activity_logs(lead_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);")

    # Synchronize stage with status if stage is null
    cursor.execute("UPDATE inquiries SET stage = status WHERE stage IS NULL OR stage = ''")
    conn.commit()
    conn.close()

def generate_ref_code(inquiry_type):
    prefix = {
        'quote': 'WC-Q',
        'dealer': 'WC-D',
        'water_test': 'WC-T',
        'contact': 'WC-C'
    }.get(inquiry_type, 'WC-I')
    rand_num = random.randint(1000, 9999)
    return f"{prefix}-{rand_num}"

def sanitize_csv_field(val):
    if val is None:
        return ""
    val_str = str(val)
    # Prevent CSV Formula Injection
    if val_str and val_str[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + val_str
    return val_str

def send_email_async(subject, body_text, body_html=None):
    """Background asynchronous dispatcher for sales notifications via configured SMTP."""
    def _worker():
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT key, value FROM settings WHERE key IN ('email_notifications_enabled', 'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'notify_email')")
            s = dict(cur.fetchall())
            conn.close()

            if s.get('email_notifications_enabled') != '1':
                return

            smtp_host = s.get('smtp_host', '').strip()
            smtp_port = int(s.get('smtp_port', 587) or 587)
            smtp_user = s.get('smtp_user', '').strip()
            smtp_pass = s.get('smtp_pass', '').strip()
            notify_email = s.get('notify_email', '').strip()

            if not smtp_host or not notify_email:
                return

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = smtp_user or 'notifications@wecare.com'
            msg['To'] = notify_email
            msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
            if body_html:
                msg.attach(MIMEText(body_html, 'html', 'utf-8'))

            with smtplib.SMTP(smtp_host, smtp_port, timeout=8) as server:
                server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(msg['From'], [notify_email], msg.as_string())
        except Exception as e:
            # Safely log warning without failing inquiry ingestion
            print(f"[SMTP Notification Notice] {e}")

    threading.Thread(target=_worker, daemon=True).start()

class WeCareRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def _get_client_ip(self):
        return self.client_address[0] if self.client_address else '127.0.0.1'

    def _read_json_body(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                return {}
            raw = self.rfile.read(content_length).decode('utf-8')
            return json.loads(raw)
        except Exception:
            return None

    def _send_json_response(self, data, status_code=200):
        body = json.dumps(data, default=str).encode('utf-8')
        self.send_response(status_code)
        self._send_cors_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authenticate(self):
        # Extract token from Authorization header or Cookie
        auth_header = self.headers.get('Authorization', '')
        token = None
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
        else:
            cookie_header = self.headers.get('Cookie', '')
            for cookie in cookie_header.split(';'):
                if 'wecare_session=' in cookie:
                    token = cookie.split('wecare_session=')[1].strip()
                    break

        if not token:
            return None

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT user_id, username, role, full_name, expires_at 
            FROM sessions WHERE token = ?
        ''', (token,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        # Check expiration and clean up expired session
        expires_at = datetime.fromisoformat(row['expires_at'])
        if datetime.now() > expires_at:
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()
            return None

        conn.close()
        u = dict(row)
        u['id'] = u['user_id']
        return u

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # SECURITY RULE: Block direct access to database, python files, logs, and sensitive data
        clean_path = path.lower()
        if (clean_path.startswith('/data/') or 
            clean_path.startswith('/backup') or 
            clean_path.endswith('.bak') or 
            clean_path.endswith('.db') or 
            clean_path.endswith('.py') or 
            clean_path.endswith('.log') or 
            '/.' in clean_path):
            self.send_error(403, "Access Denied: Protected System Resource")
            return

        # ADMIN PORTAL SPA ROUTE HANDLING: /admin and any /admin/* sub-route
        if path == '/admin' or path.startswith('/admin/'):
            self.path = '/admin.html'
            return super().do_GET()

        # PUBLIC WEBSITE SPA ROUTE HANDLING:
        public_spa_routes = [
            '/', '/about', '/products', '/products/scale-remover', '/products/ro-purifiers',
            '/technology', '/applications', '/industries', '/water-testing',
            '/calculator', '/dealers', '/case-studies', '/blog',
            '/contact', '/quote', '/legal/privacy', '/legal/terms'
        ]
        if path in public_spa_routes:
            self.path = '/index.html'
            return super().do_GET()

        # PUBLIC API: None for admin data
        # PROTECTED API: GET /api/auth/me
        if path == '/api/auth/me':
            user = self._authenticate()
            if not user:
                self._send_json_response({"success": False, "authenticated": False}, 401)
                return
            self._send_json_response({"success": True, "authenticated": True, "user": user})
            return

        # PROTECTED REST APIS:
        if path.startswith('/api/'):
            user = self._authenticate()
            if not user:
                self._send_json_response({"success": False, "error": "Unauthorized: Session login required"}, 401)
                return

            if path == '/api/stats':
                self._handle_api_stats()
                return

            if path == '/api/leads':
                params = parse_qs(parsed.query)
                self._handle_api_leads(params)
                return

            if path.startswith('/api/leads/') and path.count('/') == 3:
                lead_id_str = path.split('/')[-1]
                if lead_id_str.isdigit():
                    self._handle_api_get_lead_details(int(lead_id_str))
                    return

            if path == '/api/leads/export':
                params = parse_qs(parsed.query)
                self._handle_api_export_csv(params)
                return

            if path == '/api/reports':
                self._handle_api_reports()
                return

            if path == '/api/templates':
                self._handle_api_get_templates()
                return

            if path == '/api/settings':
                self._handle_api_get_settings()
                return

            if path == '/api/users':
                if user['role'] != 'SUPER_ADMIN':
                    self._send_json_response({"success": False, "error": "Forbidden: Requires Super Admin"}, 403)
                    return
                self._handle_api_get_users()
                return

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # PUBLIC ENDPOINT: Lead Inquiries from Website
        if path == '/api/inquiries':
            client_ip = self._get_client_ip()
            if not check_rate_limit(client_ip):
                self._send_json_response({
                    "success": False, 
                    "error": "Rate limit exceeded. Please wait a minute before submitting again."
                }, 429)
                return
            self._handle_api_create_inquiry()
            return

        # PUBLIC AUTH: Admin Login with Brute-Force Rate Limiting
        if path == '/api/auth/login':
            client_ip = self._get_client_ip()
            if not check_login_rate_limit(client_ip):
                self._send_json_response({
                    "success": False,
                    "error": "Too many failed login attempts from this IP. Please wait 15 minutes before retrying."
                }, 429)
                return
            self._handle_api_login()
            return

        # PROTECTED AUTH: Admin Logout
        if path == '/api/auth/logout':
            self._handle_api_logout()
            return

        # PROTECTED APIS:
        user = self._authenticate()
        if not user:
            self._send_json_response({"success": False, "error": "Unauthorized"}, 401)
            return

        if path == '/api/leads':
            # Manual lead creation by staff
            self._handle_api_create_manual_lead(user)
            return

        if path == '/api/templates':
            if user['role'] not in ('SUPER_ADMIN', 'SALES_MANAGER'):
                self._send_json_response({"success": False, "error": "Forbidden"}, 403)
                return
            self._handle_api_save_templates()
            return

        if path == '/api/settings':
            if user['role'] != 'SUPER_ADMIN':
                self._send_json_response({"success": False, "error": "Forbidden"}, 403)
                return
            self._handle_api_save_settings()
            return

        if path == '/api/users':
            if user['role'] != 'SUPER_ADMIN':
                self._send_json_response({"success": False, "error": "Forbidden"}, 403)
                return
            self._handle_api_create_user()
            return

        self.send_error(404, "Endpoint Not Found")

    def do_PATCH(self):
        parsed = urlparse(self.path)
        path = parsed.path

        user = self._authenticate()
        if not user:
            self._send_json_response({"success": False, "error": "Unauthorized"}, 401)
            return

        if path.startswith('/api/leads/'):
            lead_id_str = path.replace('/api/leads/', '').strip()
            if lead_id_str.isdigit():
                self._handle_api_update_lead(int(lead_id_str), user)
                return

        if path.startswith('/api/users/'):
            if user['role'] != 'SUPER_ADMIN':
                self._send_json_response({"success": False, "error": "Forbidden: Requires Super Admin"}, 403)
                return
            user_id_str = path.replace('/api/users/', '').strip()
            if user_id_str.isdigit():
                self._handle_api_update_user(int(user_id_str), user)
                return

        self.send_error(404, "Endpoint Not Found")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path

        user = self._authenticate()
        if not user:
            self._send_json_response({"success": False, "error": "Unauthorized"}, 401)
            return

        if path.startswith('/api/leads/'):
            if user['role'] not in ('SUPER_ADMIN', 'SALES_MANAGER'):
                self._send_json_response({"success": False, "error": "Forbidden: Requires Super Admin or Sales Manager role to delete leads"}, 403)
                return
            lead_id_str = path.replace('/api/leads/', '').strip()
            if lead_id_str.isdigit():
                self._handle_api_delete_lead(int(lead_id_str), user)
                return

        if path.startswith('/api/users/'):
            if user['role'] != 'SUPER_ADMIN':
                self._send_json_response({"success": False, "error": "Forbidden: Requires Super Admin role to delete accounts"}, 403)
                return
            user_id_str = path.replace('/api/users/', '').strip()
            if user_id_str.isdigit():
                self._handle_api_delete_user(int(user_id_str), user)
                return

        self.send_error(404, "Endpoint Not Found")

    # --- HANDLERS ---

    def _handle_api_login(self):
        payload = self._read_json_body()
        if not payload:
            self._send_json_response({"success": False, "error": "Invalid request body"}, 400)
            return

        username = payload.get('username', '').strip()
        password = payload.get('password', '')

        if not username or not password:
            self._send_json_response({"success": False, "error": "Username and password required"}, 400)
            return

        client_ip = self._get_client_ip()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
        user_row = cursor.fetchone()

        if not user_row or not verify_password(password, user_row['password_hash'], user_row['salt']):
            conn.close()
            record_login_attempt(client_ip, success=False)
            self._send_json_response({"success": False, "error": "Invalid username or password"}, 401)
            return

        record_login_attempt(client_ip, success=True)

        token = secrets.token_hex(32)
        expires_at = datetime.now() + timedelta(hours=24)

        cursor.execute('''
            INSERT INTO sessions (token, user_id, username, role, full_name, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (token, user_row['id'], user_row['username'], user_row['role'], user_row['full_name'], expires_at.isoformat()))
        conn.commit()
        conn.close()

        # Return session token and user info
        user_data = {
            "id": user_row['id'],
            "username": user_row['username'],
            "fullName": user_row['full_name'],
            "role": user_row['role'],
            "email": user_row['email']
        }

        body = json.dumps({"success": True, "token": token, "user": user_data}).encode('utf-8')
        self.send_response(200)
        self._send_cors_headers()
        self.send_header('Set-Cookie', f'wecare_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400')
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_api_logout(self):
        auth_header = self.headers.get('Authorization', '')
        token = auth_header[7:].strip() if auth_header.startswith('Bearer ') else None
        if not token:
            cookie_header = self.headers.get('Cookie', '')
            for cookie in cookie_header.split(';'):
                if 'wecare_session=' in cookie:
                    token = cookie.split('wecare_session=')[1].strip()
                    break

        if token:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()

        body = json.dumps({"success": True, "message": "Logged out successfully"}).encode('utf-8')
        self.send_response(200)
        self._send_cors_headers()
        self.send_header('Set-Cookie', 'wecare_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_api_create_inquiry(self):
        payload = self._read_json_body()
        if payload is None:
            self._send_json_response({"success": False, "error": "Invalid JSON body"}, 400)
            return

        inquiry_type = payload.get('type', 'quote').strip().lower()
        full_name = payload.get('fullName', '').strip()[:100]
        phone = payload.get('phone', '').strip()[:30]
        email = payload.get('email', '').strip()[:100]
        city = payload.get('city', '').strip()[:80]
        state = payload.get('state', '').strip()[:80]
        business_name = payload.get('businessName', '').strip()[:120]
        business_type = payload.get('businessType', '').strip()[:100]
        selected_size = payload.get('selectedSize', '').strip()[:80]
        flow_rate = payload.get('flowRate', '').strip()[:60]
        raw_water_tds = payload.get('tds', '').strip()[:50]
        water_hardness = payload.get('hardness', '').strip()[:50]
        notes = payload.get('notes', '').strip()[:1000]
        monthly_volume = payload.get('monthlyVolume', '').strip()[:80]
        lead_source = payload.get('source', 'Website').strip()[:50]

        if not full_name or not phone:
            self._send_json_response({"success": False, "error": "Full Name and Phone Number are required."}, 422)
            return

        ref_code = generate_ref_code(inquiry_type)

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO inquiries (
                    ref_code, inquiry_type, full_name, email, phone,
                    city, state, business_name, business_type,
                    selected_size, flow_rate, raw_water_tds, water_hardness,
                    notes, monthly_volume, status, stage, priority, lead_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NEW', 'NEW', 'MEDIUM', ?)
            ''', (
                ref_code, inquiry_type, full_name, email, phone,
                city, state, business_name, business_type,
                selected_size, flow_rate, raw_water_tds, water_hardness,
                notes, monthly_volume, lead_source
            ))
            new_id = cursor.lastrowid

            # Add initial activity log
            cursor.execute('''
                INSERT INTO activity_logs (lead_id, action_type, details, performed_by)
                VALUES (?, 'LEAD_CREATED', ?, 'System (Website Ingestion)')
            ''', (new_id, f"Inquiry registered via {lead_source} for {selected_size or 'General'}. Ref: {ref_code}"))

            # Fetch customizable WhatsApp template
            cursor.execute("SELECT value FROM settings WHERE key = 'tpl_new_quotation'")
            tpl_row = cursor.fetchone()
            tpl = tpl_row[0] if tpl_row else "Hello {customer_name}, thank you for contacting We Care regarding {product_size} (Ref: {ref_code})."
            conn.commit()
        except Exception as e:
            conn.rollback()
            self._send_json_response({"success": False, "error": f"Database error: {str(e)}"}, 500)
            return
        finally:
            conn.close()

        # Trigger asynchronous email notification to sales desk
        email_subject = f"[New Lead] {inquiry_type.upper()}: {full_name} ({ref_code}) - {selected_size or 'General'}"
        email_body = f"""New WE CARE Lead Notification

Reference Code: {ref_code}
Inquiry Type:   {inquiry_type.upper()}
Customer Name:  {full_name}
Phone:          {phone}
Email:          {email or 'N/A'}
City / State:   {city or 'N/A'}, {state or 'N/A'}
Selected Size:  {selected_size or 'General / Unspecified'}
Flow Rate:      {flow_rate or 'N/A'}
Raw Water TDS:  {raw_water_tds or 'N/A'}
Hardness:       {water_hardness or 'N/A'}
Source:         {lead_source}
Notes:          {notes or 'None'}

Access Admin CRM to manage this lead: http://localhost:{PORT}/admin
"""
        send_email_async(email_subject, email_body)

        # Format template
        wa_text = tpl.replace('{customer_name}', full_name)\
                     .replace('{ref_code}', ref_code)\
                     .replace('{product_size}', selected_size or 'our Scale Removers')\
                     .replace('{city}', city or 'your location')
        
        import urllib.parse
        clean_digits = ''.join(c for c in phone if c.isdigit())
        wa_url = f"https://wa.me/{clean_digits}?text={urllib.parse.quote(wa_text)}"

        self._send_json_response({
            "success": True,
            "ref_code": ref_code,
            "lead_id": new_id,
            "message": f"Your inquiry (Ref: {ref_code}) has been securely recorded. An application engineer will contact you shortly.",
            "whatsapp_chat_url": wa_url
        }, 201)

    def _handle_api_create_manual_lead(self, user):
        payload = self._read_json_body()
        if not payload:
            self._send_json_response({"success": False, "error": "Missing payload"}, 400)
            return

        inquiry_type = payload.get('type', 'quote').strip().lower()
        full_name = payload.get('fullName', '').strip()[:100]
        phone = payload.get('phone', '').strip()[:30]
        email = payload.get('email', '').strip()[:100]
        city = payload.get('city', '').strip()[:80]
        selected_size = payload.get('selectedSize', '').strip()[:80]
        priority = payload.get('priority', 'MEDIUM').strip().upper()
        assigned_to = payload.get('assignedTo', user['full_name']).strip()
        notes = payload.get('notes', '').strip()[:1000]

        if not full_name or not phone:
            self._send_json_response({"success": False, "error": "Customer Name and Phone are required"}, 422)
            return

        ref_code = generate_ref_code(inquiry_type)

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO inquiries (
                    ref_code, inquiry_type, full_name, email, phone, city,
                    selected_size, notes, status, stage, priority, assigned_to, lead_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'NEW', 'NEW', ?, ?, 'Manual Phone/Walk-in')
            ''', (ref_code, inquiry_type, full_name, email, phone, city, selected_size, notes, priority, assigned_to))
            new_id = cursor.lastrowid

            cursor.execute('''
                INSERT INTO activity_logs (lead_id, action_type, details, performed_by)
                VALUES (?, 'LEAD_CREATED', ?, ?)
            ''', (new_id, f"Manually logged by {user['full_name']} ({user['role']})", user['full_name']))

            conn.commit()
            conn.close()

            self._send_json_response({
                "success": True,
                "ref_code": ref_code,
                "lead_id": new_id,
                "message": f"Lead {ref_code} logged successfully."
            }, 201)
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_leads(self, params):
        lead_type = params.get('type', [None])[0]
        stage = params.get('stage', [None])[0] or params.get('status', [None])[0]
        priority = params.get('priority', [None])[0]
        assigned_to = params.get('assignedTo', [None])[0]
        search = params.get('search', [None])[0]
        overdue_only = params.get('overdue', ['0'])[0] == '1'

        query = 'SELECT * FROM inquiries WHERE 1=1'
        bindings = []

        if lead_type and lead_type != 'all':
            query += ' AND inquiry_type = ?'
            bindings.append(lead_type)

        if stage and stage != 'all':
            query += ' AND (stage = ? OR status = ?)'
            bindings.extend([stage, stage])

        if priority and priority != 'all':
            query += ' AND priority = ?'
            bindings.append(priority)

        if assigned_to and assigned_to != 'all':
            query += ' AND assigned_to = ?'
            bindings.append(assigned_to)

        if overdue_only:
            query += " AND next_followup_at IS NOT NULL AND next_followup_at < datetime('now') AND stage != 'CLOSED'"

        if search:
            query += ' AND (full_name LIKE ? OR business_name LIKE ? OR phone LIKE ? OR city LIKE ? OR ref_code LIKE ?)'
            search_pat = f"%{search}%"
            bindings.extend([search_pat, search_pat, search_pat, search_pat, search_pat])

        query += ' ORDER BY id DESC'

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query, bindings)
            rows = cursor.fetchall()
            leads = [dict(row) for row in rows]
            conn.close()

            self._send_json_response({
                "success": True,
                "count": len(leads),
                "leads": leads
            })
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_get_lead_details(self, lead_id):
        try:
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM inquiries WHERE id = ?", (lead_id,))
            lead_row = cursor.fetchone()
            if not lead_row:
                conn.close()
                self._send_json_response({"success": False, "error": "Lead not found"}, 404)
                return

            lead = dict(lead_row)

            # Fetch related previous inquiries with same phone or email
            cursor.execute('''
                SELECT id, ref_code, inquiry_type, selected_size, created_at, stage 
                FROM inquiries 
                WHERE (phone = ? OR (email != '' AND email = ?)) AND id != ?
                ORDER BY id DESC
            ''', (lead['phone'], lead['email'], lead_id))
            previous_inquiries = [dict(r) for r in cursor.fetchall()]

            # Fetch activity logs
            cursor.execute('''
                SELECT * FROM activity_logs WHERE lead_id = ? ORDER BY id DESC
            ''', (lead_id,))
            logs = [dict(r) for r in cursor.fetchall()]

            conn.close()

            self._send_json_response({
                "success": True,
                "lead": lead,
                "previous_inquiries": previous_inquiries,
                "activity_logs": logs
            })
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_update_lead(self, lead_id, user):
        payload = self._read_json_body()
        if not payload:
            self._send_json_response({"success": False, "error": "Missing payload"}, 400)
            return

        stage = payload.get('stage') or payload.get('status')
        priority = payload.get('priority')
        assigned_to = payload.get('assigned_to')
        next_followup_at = payload.get('next_followup_at')
        sales_notes = payload.get('sales_notes')
        water_hardness = payload.get('water_hardness')
        raw_water_tds = payload.get('raw_water_tds')
        deal_value = payload.get('deal_value')
        log_action = payload.get('log_action', 'STATUS_CHANGE')

        updates = []
        params = []
        changes_desc = []

        if stage:
            updates.extend(["stage = ?", "status = ?"])
            params.extend([stage, stage])
            changes_desc.append(f"Stage changed to {stage}")

        if priority:
            updates.append("priority = ?")
            params.append(priority)
            changes_desc.append(f"Priority set to {priority}")

        if assigned_to is not None:
            updates.append("assigned_to = ?")
            params.append(assigned_to)
            changes_desc.append(f"Assigned to {assigned_to}")

        if next_followup_at is not None:
            updates.append("next_followup_at = ?")
            params.append(next_followup_at if next_followup_at != "" else None)
            changes_desc.append(f"Follow-up scheduled for {next_followup_at}" if next_followup_at else "Follow-up cleared")

        if sales_notes is not None:
            updates.append("sales_notes = ?")
            params.append(sales_notes)
            changes_desc.append("Updated internal sales remarks")

        if water_hardness is not None:
            updates.append("water_hardness = ?")
            params.append(water_hardness)

        if raw_water_tds is not None:
            updates.append("raw_water_tds = ?")
            params.append(raw_water_tds)

        if deal_value is not None:
            updates.append("deal_value = ?")
            params.append(deal_value)

        if not updates:
            self._send_json_response({"success": False, "error": "No valid fields provided"}, 400)
            return

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(lead_id)

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(f"UPDATE inquiries SET {', '.join(updates)} WHERE id = ?", params)
            updated = cursor.rowcount > 0

            if updated and changes_desc:
                cursor.execute('''
                    INSERT INTO activity_logs (lead_id, action_type, details, performed_by)
                    VALUES (?, ?, ?, ?)
                ''', (lead_id, log_action, '; '.join(changes_desc), user['full_name']))

            conn.commit()
            conn.close()

            if updated:
                self._send_json_response({"success": True, "message": f"Lead #{lead_id} updated successfully."})
            else:
                self._send_json_response({"success": False, "error": "Lead not found"}, 404)
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_stats(self):
        try:
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM inquiries")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE date(created_at) = date('now')")
            new_today = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE next_followup_at IS NOT NULL AND stage != 'CLOSED'")
            pending_followups = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE next_followup_at IS NOT NULL AND next_followup_at < datetime('now') AND stage != 'CLOSED'")
            overdue_followups = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE stage = 'QUALIFIED'")
            qualified = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE stage = 'CLOSED'")
            closed = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE inquiry_type = 'dealer'")
            dealers = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE inquiry_type = 'quote'")
            quotes = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE inquiry_type = 'water_test'")
            water_tests = cursor.fetchone()[0]

            # Stage counts
            stages = ['NEW', 'IN_REVIEW', 'CONTACTED', 'QUALIFIED', 'CLOSED']
            stage_counts = {}
            for s in stages:
                cursor.execute("SELECT COUNT(*) FROM inquiries WHERE stage = ? OR (stage IS NULL AND status = ?)", (s, s))
                stage_counts[s] = cursor.fetchone()[0]

            # Source breakdown
            cursor.execute("SELECT lead_source, COUNT(*) FROM inquiries GROUP BY lead_source")
            sources = {row[0] or 'Website': row[1] for row in cursor.fetchall()}

            conn.close()

            conversion_rate = f"{(closed / total * 100):.1f}%" if total > 0 else "0%"

            self._send_json_response({
                "success": True,
                "stats": {
                    "total": total,
                    "new_today": new_today,
                    "pending_followups": pending_followups,
                    "overdue_followups": overdue_followups,
                    "qualified": qualified,
                    "closed": closed,
                    "dealers": dealers,
                    "quotes": quotes,
                    "water_tests": water_tests,
                    "conversion_rate": conversion_rate,
                    "stage_counts": stage_counts,
                    "sources": sources
                }
            })
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_reports(self):
        try:
            conn = get_db()
            cursor = conn.cursor()

            # City-wise
            cursor.execute('''
                SELECT COALESCE(NULLIF(city, ''), 'Unspecified') as city, COUNT(*) as count 
                FROM inquiries GROUP BY city ORDER BY count DESC LIMIT 8
            ''')
            city_leads = [dict(r) for r in cursor.fetchall()]

            # State-wise
            cursor.execute('''
                SELECT COALESCE(NULLIF(state, ''), 'Unspecified') as state, COUNT(*) as count 
                FROM inquiries GROUP BY state ORDER BY count DESC LIMIT 8
            ''')
            state_leads = [dict(r) for r in cursor.fetchall()]

            # Product-size demand
            cursor.execute('''
                SELECT COALESCE(NULLIF(selected_size, ''), 'General / Unspecified') as size, COUNT(*) as count 
                FROM inquiries GROUP BY selected_size ORDER BY count DESC
            ''')
            product_demand = [dict(r) for r in cursor.fetchall()]

            # Dealer conversion rate
            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE inquiry_type = 'dealer'")
            total_dealers = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM inquiries WHERE inquiry_type = 'dealer' AND stage IN ('QUALIFIED', 'CLOSED')")
            qualified_dealers = cursor.fetchone()[0]

            conn.close()

            self._send_json_response({
                "success": True,
                "city_leads": city_leads,
                "state_leads": state_leads,
                "product_demand": product_demand,
                "dealer_metrics": {
                    "total": total_dealers,
                    "converted": qualified_dealers,
                    "rate": f"{(qualified_dealers / total_dealers * 100):.1f}%" if total_dealers > 0 else "0%"
                }
            })
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_get_templates(self):
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings WHERE key LIKE 'tpl_%'")
            templates = {row[0]: row[1] for row in cursor.fetchall()}
            conn.close()
            self._send_json_response({"success": True, "templates": templates})
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_save_templates(self):
        payload = self._read_json_body()
        if not payload:
            self._send_json_response({"success": False, "error": "Missing payload"}, 400)
            return

        try:
            conn = get_db()
            cursor = conn.cursor()
            for k, v in payload.items():
                if k.startswith('tpl_'):
                    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(v)))
            conn.commit()
            conn.close()
            self._send_json_response({"success": True, "message": "Templates updated successfully."})
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_get_settings(self):
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings")
            rows = cursor.fetchall()
            conn.close()

            settings = {}
            for k, v in rows:
                if k == 'smtp_pass' and v:
                    settings[k] = '••••••••'
                else:
                    settings[k] = v

            self._send_json_response({"success": True, "settings": settings})
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_save_settings(self):
        payload = self._read_json_body()
        if not payload:
            self._send_json_response({"success": False, "error": "Missing payload"}, 400)
            return

        try:
            conn = get_db()
            cursor = conn.cursor()
            for k, v in payload.items():
                if k == 'smtp_pass' and v == '••••••••':
                    continue  # Keep existing password
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(v)))
            conn.commit()
            conn.close()
            self._send_json_response({"success": True, "message": "Settings saved successfully."})
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_get_users(self):
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, full_name, email, role, is_active, created_at FROM users")
            users = [dict(r) for r in cursor.fetchall()]
            conn.close()
            self._send_json_response({"success": True, "users": users})
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_create_user(self):
        payload = self._read_json_body()
        username = payload.get('username', '').strip()
        password = payload.get('password', '').strip()
        full_name = payload.get('fullName', '').strip()
        email = payload.get('email', '').strip()
        role = payload.get('role', 'SALES_EXECUTIVE').strip().upper()

        if not username or not password or not full_name:
            self._send_json_response({"success": False, "error": "Username, Password, and Full Name required"}, 400)
            return

        p_hash, salt = hash_password(password)

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, full_name, email, role)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, p_hash, salt, full_name, email, role))
            conn.commit()
            conn.close()
            self._send_json_response({"success": True, "message": f"User {username} created."})
        except sqlite3.IntegrityError:
            self._send_json_response({"success": False, "error": "Username already exists."}, 409)
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_update_user(self, user_id, user):
        payload = self._read_json_body()
        if not payload:
            self._send_json_response({"success": False, "error": "Missing payload"}, 400)
            return

        full_name = payload.get('fullName')
        email = payload.get('email')
        role = payload.get('role')
        is_active = payload.get('isActive')
        password = payload.get('password')

        updates = []
        params = []

        if full_name is not None:
            updates.append("full_name = ?")
            params.append(str(full_name).strip()[:100])

        if email is not None:
            updates.append("email = ?")
            params.append(str(email).strip()[:100])

        if role is not None and role.upper() in ('SUPER_ADMIN', 'SALES_MANAGER', 'SALES_EXECUTIVE'):
            updates.append("role = ?")
            params.append(role.upper())

        if is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active in (1, True, '1', 'true') else 0)

        if password:
            p_hash, salt = hash_password(password)
            updates.append("password_hash = ?")
            params.append(p_hash)
            updates.append("salt = ?")
            params.append(salt)

        if not updates:
            self._send_json_response({"success": False, "error": "No valid fields to update"}, 400)
            return

        params.append(user_id)

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
            if cursor.rowcount == 0:
                conn.close()
                self._send_json_response({"success": False, "error": "User not found"}, 404)
                return

            # If password or active status changed, terminate any active sessions
            if password or is_active is not None:
                cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

            conn.commit()
            conn.close()

            self._send_json_response({"success": True, "message": f"User account #{user_id} updated successfully."})
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_delete_user(self, user_id, user):
        current_id = user.get('id') or user.get('user_id')
        if user_id == current_id:
            self._send_json_response({"success": False, "error": "Cannot delete your own active account."}, 400)
            return

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            target = cursor.fetchone()
            if not target:
                conn.close()
                self._send_json_response({"success": False, "error": "User not found"}, 404)
                return

            username = target['username']
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()

            self._send_json_response({
                "success": True,
                "message": f"User account '{username}' has been deleted."
            })
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_delete_lead(self, lead_id, user):
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT ref_code, full_name FROM inquiries WHERE id = ?", (lead_id,))
            lead = cursor.fetchone()
            if not lead:
                conn.close()
                self._send_json_response({"success": False, "error": "Lead not found"}, 404)
                return

            ref_code = lead['ref_code']
            # Delete associated activity logs
            cursor.execute("DELETE FROM activity_logs WHERE lead_id = ?", (lead_id,))
            cursor.execute("DELETE FROM inquiries WHERE id = ?", (lead_id,))
            conn.commit()
            conn.close()

            self._send_json_response({
                "success": True,
                "message": f"Lead #{lead_id} ({ref_code}) deleted permanently by {user['full_name']}."
            })
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

    def _handle_api_export_csv(self, params):
        lead_type = params.get('type', [None])[0]
        stage = params.get('stage', [None])[0]

        query = "SELECT * FROM inquiries WHERE 1=1"
        bindings = []

        if lead_type and lead_type != 'all':
            query += " AND inquiry_type = ?"
            bindings.append(lead_type)

        if stage and stage != 'all':
            query += " AND stage = ?"
            bindings.append(stage)

        query += " ORDER BY id DESC"

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(query, bindings)
            rows = cursor.fetchall()
            conn.close()

            output = io.StringIO()
            if rows:
                fieldnames = list(rows[0].keys())
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    sanitized_row = {k: sanitize_csv_field(row[k]) for k in fieldnames}
                    writer.writerow(sanitized_row)
            else:
                output.write("No leads recorded matching criteria.\n")

            csv_bytes = output.getvalue().encode('utf-8')
            self.send_response(200)
            self._send_cors_headers()
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="we_care_leads_export.csv"')
            self.send_header('Content-Length', str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
        except Exception as e:
            self._send_json_response({"success": False, "error": str(e)}, 500)

def run():
    init_db()
    server_address = ('', PORT)
    httpd = ThreadingHTTPServer(server_address, WeCareRequestHandler)
    httpd.daemon_threads = True
    print(f"==================================================")
    print(f"      WE CARE SECURED BACKEND & SALES CRM        ")
    print(f"==================================================")
    print(f"Server Engine:     ThreadingHTTPServer (Concurrent I/O)")
    print(f"Website:           http://localhost:{PORT}/")
    print(f"Admin CRM Portal:  http://localhost:{PORT}/admin")
    print(f"Default Super Admin: admin / Admin@WeCare2026!")
    print(f"Default Manager:     manager / Manager@WeCare2026!")
    print(f"Default Executive:   executive / Executive@WeCare2026!")
    print(f"SQLite DB:         {DB_PATH} (WAL Mode, FK Enabled)")
    print(f"Security:          RBAC, PBKDF2 Hashing, Brute-Force Shield")
    print(f"==================================================")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
