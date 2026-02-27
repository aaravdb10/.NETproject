# pyright: reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownLambdaType=false, reportMissingTypeArgument=false, reportAttributeAccessIssue=false, reportOptionalSubscript=false, reportDeprecated=false, reportUndefinedVariable=false, reportUnusedVariable=false

from flask import Flask, render_template, request, jsonify, send_from_directory, has_request_context, session, redirect
from flask_cors import CORS
from dotenv import load_dotenv
import sqlite3
import hashlib
import os
import json

load_dotenv()  # loads .env into os.environ
from datetime import datetime
from datetime import timedelta
import secrets
import hmac
import urllib.parse
import urllib.request
import urllib.error
from typing import Tuple

from email_config import send_otp_email

app = Flask(__name__)
app.secret_key = 'rbac-demo-secret-key-2024'
CORS(app)

# Database configuration
DATABASE = 'rbac_system.db'
DB_TYPE = (os.getenv('DB_TYPE', 'sqlite') or 'sqlite').strip().lower()
DB_SERVER = (os.getenv('DB_SERVER', '') or '').strip()
DB_NAME = (os.getenv('DB_NAME', '') or '').strip()
DB_USER = (os.getenv('DB_USER', '') or '').strip()
DB_PASSWORD = (os.getenv('DB_PASSWORD', '') or '').strip()
DB_DRIVER = (os.getenv('DB_DRIVER', '') or '').strip()
SQLSERVER_ENABLED = DB_TYPE == 'sqlserver'

OTP_EXPIRY_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
OAUTH_TEMP_TOKEN_EXPIRY_SECONDS = 180

RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY', '').strip()
RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY', '').strip()
RECAPTCHA_ENABLED = bool(RECAPTCHA_SECRET_KEY and RECAPTCHA_SITE_KEY)

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '').strip()
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '').strip()
_legacy_google_redirect = os.getenv('GOOGLE_OAUTH_ENABLED', '').strip()
_google_redirect_from_env = os.getenv('GOOGLE_REDIRECT_URI', '').strip()
if _google_redirect_from_env:
    _resolved_google_redirect_uri = _google_redirect_from_env
elif _legacy_google_redirect.startswith('http://') or _legacy_google_redirect.startswith('https://'):
    _resolved_google_redirect_uri = _legacy_google_redirect
else:
    _resolved_google_redirect_uri = 'http://localhost:5000/api/auth/google/callback'
GOOGLE_REDIRECT_URI = _resolved_google_redirect_uri
GOOGLE_OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID', '').strip()
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET', '').strip()
GITHUB_REDIRECT_URI = os.getenv('GITHUB_REDIRECT_URI', 'http://localhost:5000/api/auth/github/callback').strip()
GITHUB_OAUTH_ENABLED = bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)

otp_sessions = {}
pending_registrations = {}
pending_logins = {}
pending_oauth_callbacks = {}

def get_db_connection():
    """Get database connection"""
    if SQLSERVER_ENABLED:
        try:
            import pyodbc
        except Exception as e:
            raise RuntimeError('pyodbc is required for SQL Server connections. Install it with: pip install pyodbc') from e

        if not DB_SERVER or not DB_NAME or not DB_DRIVER:
            raise RuntimeError('DB_SERVER, DB_NAME, and DB_DRIVER must be set for SQL Server usage')

        if DB_USER:
            conn_str = (
                f"DRIVER={{{DB_DRIVER}}};"
                f"SERVER={DB_SERVER};DATABASE={DB_NAME};"
                f"UID={DB_USER};PWD={DB_PASSWORD};"
                "Encrypt=yes;TrustServerCertificate=yes;"
            )
        else:
            conn_str = (
                f"DRIVER={{{DB_DRIVER}}};"
                f"SERVER={DB_SERVER};DATABASE={DB_NAME};"
                "Trusted_Connection=yes;Encrypt=yes;TrustServerCertificate=yes;"
            )
        try:
            return pyodbc.connect(conn_str, timeout=5)
        except pyodbc.InterfaceError as e:
            message = str(e)
            if 'Login failed for user' in message:
                raise RuntimeError(
                    'SQL Server login failed. Check DB_USER/DB_PASSWORD and ensure SQL authentication is enabled for this login.'
                ) from e
            raise RuntimeError(f'SQL Server connection failed: {message}') from e
        except pyodbc.OperationalError as e:
            message = str(e)
            if 'certificate chain was issued by an authority that is not trusted' in message:
                raise RuntimeError(
                    'SQL Server TLS certificate is not trusted by this machine. For local dev, use TrustServerCertificate=yes or install a trusted cert.'
                ) from e
            raise RuntimeError(f'SQL Server connection failed: {message}') from e

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def _rows_to_dicts(cursor, rows):
    if not rows:
        return []
    if isinstance(rows[0], sqlite3.Row):
        return [dict(r) for r in rows]
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in rows]


def fetch_one(query, params=()):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    row = cur.fetchone()
    result = None
    if row is not None:
        result = _rows_to_dicts(cur, [row])[0]
    conn.close()
    return result


def fetch_all(query, params=()):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    result = _rows_to_dicts(cur, rows)
    conn.close()
    return result


def execute_commit(query, params=()):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    conn.commit()
    conn.close()


def execute_insert_returning_id(query, params=()):
    conn = get_db_connection()
    cur = conn.cursor()

    if SQLSERVER_ENABLED:
        cur.execute(f"{query}; SELECT CAST(SCOPE_IDENTITY() AS INT) AS new_id;", params)
        row = None

        try:
            row = cur.fetchone()
        except Exception:
            row = None

        while row is None and cur.nextset():
            try:
                row = cur.fetchone()
            except Exception:
                row = None

        conn.commit()
        conn.close()
        return int(row[0]) if row and row[0] is not None else None

    cur.execute(query, params)
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def sql_full_name_expr(alias='u'):
    return f"{alias}.first_name + ' ' + {alias}.last_name" if SQLSERVER_ENABLED else f"{alias}.first_name || ' ' || {alias}.last_name"

def init_database():
    """Initialize database with tables and demo data"""
    if SQLSERVER_ENABLED:
        return
    conn = get_db_connection()
    
    # Create users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee',
            department TEXT,
            phone TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Migrate: add phone and bio columns if they don't exist
    try:
        conn.execute('ALTER TABLE users ADD COLUMN phone TEXT DEFAULT ""')
    except Exception:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ""')
    except Exception:
        pass
    
    # Create audit log table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            request_path TEXT,
            http_method TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Migrate: add request metadata columns if they don't exist
    try:
        conn.execute('ALTER TABLE audit_log ADD COLUMN ip_address TEXT')
    except Exception:
        pass
    try:
        conn.execute('ALTER TABLE audit_log ADD COLUMN user_agent TEXT')
    except Exception:
        pass
    try:
        conn.execute('ALTER TABLE audit_log ADD COLUMN request_path TEXT')
    except Exception:
        pass
    try:
        conn.execute('ALTER TABLE audit_log ADD COLUMN http_method TEXT')
    except Exception:
        pass
    
    # Create leave requests table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS leave_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL DEFAULT 'vacation',
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            days INTEGER NOT NULL DEFAULT 1,
            reason TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Insert demo users if they don't exist
    demo_users = [
        ('Rahul', 'Sharma', 'admin@company.com', 'admin123', 'admin', 'IT'),
        ('Priya', 'Patel', 'manager@company.com', 'manager123', 'manager', 'HR'),
        ('Vikram', 'Singh', 'employee@company.com', 'employee123', 'employee', 'Finance'),
        ('Aarav', 'Gandhi', 'aarav.gandhi@company.com', 'password123', 'employee', 'IT'),
        ('Neha', 'Gupta', 'neha.gupta@company.com', 'password123', 'manager', 'Marketing'),
        ('Rohan', 'Verma', 'rohan.verma@company.com', 'password123', 'employee', 'Operations')
    ]
    
    for user in demo_users:
        existing = conn.execute('SELECT id FROM users WHERE email = ?', (user[2],)).fetchone()
        if not existing:
            hashed_password = hashlib.sha256(user[3].encode()).hexdigest()
            conn.execute('''
                INSERT INTO users (first_name, last_name, email, password, role, department)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user[0], user[1], user[2], hashed_password, user[4], user[5]))
    
    # Seed demo leave requests
    existing_leaves = conn.execute('SELECT COUNT(*) FROM leave_requests').fetchone()[0]
    if existing_leaves == 0:
        # Get user IDs for seeding
        emp = conn.execute("SELECT id FROM users WHERE email='employee@company.com'").fetchone()
        aarav = conn.execute("SELECT id FROM users WHERE email='aarav.gandhi@company.com'").fetchone()
        neha = conn.execute("SELECT id FROM users WHERE email='neha.gupta@company.com'").fetchone()
        rohan = conn.execute("SELECT id FROM users WHERE email='rohan.verma@company.com'").fetchone()
        if emp and aarav and neha and rohan:
            demo_leaves = [
                (emp['id'],  'vacation', '2025-03-01', '2025-03-05', 5,  'Family trip',          'approved'),
                (aarav['id'],'sick',     '2025-02-15', '2025-02-17', 3,  'Flu recovery',         'approved'),
                (emp['id'],  'personal', '2025-04-10', '2025-04-10', 1,  'Personal errand',      'pending'),
                (rohan['id'],'vacation', '2025-05-20', '2025-05-30', 11, 'Summer vacation',      'pending'),
                (aarav['id'],'sick',     '2025-01-20', '2025-01-21', 2,  'Medical appointment',  'rejected'),
                (neha['id'], 'vacation', '2025-06-10', '2025-06-14', 5,  'Holiday',              'pending'),
            ]
            for lv in demo_leaves:
                conn.execute(
                    'INSERT INTO leave_requests (user_id, type, start_date, end_date, days, reason, status) VALUES (?,?,?,?,?,?,?)',
                    lv
                )

    conn.commit()
    conn.close()

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()


def generate_otp() -> str:
    """Generate 6-digit OTP code"""
    return f"{secrets.randbelow(900000) + 100000}"


def hash_otp(code: str) -> str:
    """Hash OTP for secure in-memory storage"""
    return hashlib.sha256(code.encode()).hexdigest()


def cleanup_expired_security_state():
    """Remove expired OTP sessions and pending auth payloads"""
    now = datetime.utcnow()

    expired_otp = [token for token, payload in otp_sessions.items() if payload['expires_at'] < now]
    for token in expired_otp:
        otp_sessions.pop(token, None)

    expired_reg = [token for token, payload in pending_registrations.items() if payload['expires_at'] < now]
    for token in expired_reg:
        pending_registrations.pop(token, None)

    expired_login = [token for token, payload in pending_logins.items() if payload['expires_at'] < now]
    for token in expired_login:
        pending_logins.pop(token, None)

    expired_oauth = [token for token, payload in pending_oauth_callbacks.items() if payload['expires_at'] < now]
    for token in expired_oauth:
        pending_oauth_callbacks.pop(token, None)


def verify_recaptcha(token: str | None, remote_ip: str | None = None) -> Tuple[bool, str]:
    """Verify Google reCAPTCHA token on server side"""
    if not RECAPTCHA_ENABLED:
        return True, 'reCAPTCHA bypassed in local dev mode'

    if not token:
        return False, 'reCAPTCHA token is required'

    try:
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': token,
        }
        if remote_ip:
            payload['remoteip'] = remote_ip

        encoded = urllib.parse.urlencode(payload).encode('utf-8')
        req = urllib.request.Request(
            'https://www.google.com/recaptcha/api/siteverify',
            data=encoded,
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read().decode('utf-8')

        result = json.loads(raw)

        if result.get('success'):
            return True, 'verified'

        return False, 'reCAPTCHA verification failed'
    except Exception:
        return False, 'Unable to verify reCAPTCHA'


def create_otp_session(email: str, purpose: str, token: str | None = None):
    """Create OTP challenge session and send OTP email"""
    cleanup_expired_security_state()

    challenge_token = token or secrets.token_urlsafe(32)
    otp_code = generate_otp()

    otp_sessions[challenge_token] = {
        'email': email,
        'purpose': purpose,
        'otp_hash': hash_otp(otp_code),
        'attempts': 0,
        'expires_at': datetime.utcnow() + timedelta(seconds=OTP_EXPIRY_SECONDS),
    }

    try:
        send_otp_email(email, otp_code)
    except Exception as e:
        otp_sessions.pop(challenge_token, None)
        raise RuntimeError('Unable to send OTP email. Please verify SMTP settings and try again.') from e

    return challenge_token


def verify_otp_session(token: str, otp: str, expected_purpose: str):
    """Verify OTP challenge token and code"""
    cleanup_expired_security_state()

    payload = otp_sessions.get(token)
    if not payload:
        return False, 'Verification session expired or invalid'

    if payload['purpose'] != expected_purpose:
        return False, 'Verification purpose mismatch'

    if payload['expires_at'] < datetime.utcnow():
        otp_sessions.pop(token, None)
        return False, 'OTP has expired'

    if payload['attempts'] >= OTP_MAX_ATTEMPTS:
        otp_sessions.pop(token, None)
        return False, 'Too many OTP attempts. Please request a new OTP'

    if not otp or not otp.isdigit() or len(otp) != 6:
        payload['attempts'] += 1
        return False, 'OTP must be a 6-digit code'

    if not hmac.compare_digest(payload['otp_hash'], hash_otp(otp)):
        payload['attempts'] += 1
        return False, 'Invalid OTP code'

    otp_sessions.pop(token, None)
    return True, 'OTP verified'

def get_client_ip() -> str:
    """Get best-effort client IP, proxy-aware."""
    forwarded_for = (request.headers.get('X-Forwarded-For') or '').strip()
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()

    real_ip = (request.headers.get('X-Real-IP') or '').strip()
    if real_ip:
        return real_ip

    return (request.remote_addr or '').strip()


def get_user_from_session() -> int | None:
    """Best-effort user id from server session."""
    value = session.get('user_id')
    return int(value) if isinstance(value, int) else None


def normalize_google_name(given_name: str, family_name: str, full_name: str):
    """Map Google profile name fields to first/last name."""
    first_name = (given_name or '').strip()
    last_name = (family_name or '').strip()

    if not first_name and full_name:
        name_parts = [part for part in (full_name or '').strip().split(' ') if part]
        if name_parts:
            first_name = name_parts[0]
            last_name = ' '.join(name_parts[1:])

    return first_name or 'Google', last_name or 'User'


def build_user_payload(row):
    """Create frontend user payload from DB row/dict."""
    return {
        'id': row.get('id'),
        'firstName': row.get('first_name'),
        'lastName': row.get('last_name'),
        'email': row.get('email'),
        'role': row.get('role'),
        'department': row.get('department'),
        'status': row.get('status'),
    }


def exchange_google_code_for_token(code: str):
    """Exchange authorization code for Google tokens."""
    payload = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    encoded = urllib.parse.urlencode(payload).encode('utf-8')
    req = urllib.request.Request(
        'https://oauth2.googleapis.com/token',
        data=encoded,
        method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode('utf-8')

    return json.loads(raw)


def fetch_google_userinfo(access_token: str):
    """Fetch Google user profile using access token."""
    req = urllib.request.Request(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        method='GET',
        headers={'Authorization': f'Bearer {access_token}'}
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode('utf-8')

    return json.loads(raw)


def find_or_create_google_user(email: str, given_name: str, family_name: str, full_name: str):
    """Find existing active user by email or create an employee account."""
    existing = fetch_one('''
        SELECT id, first_name, last_name, email, role, department, status
        FROM users
        WHERE email = ?
    ''', (email,))

    if existing:
        if existing.get('status') != 'active':
            raise RuntimeError('Your account is inactive. Please contact admin.')
        return build_user_payload(existing), False

    first_name, last_name = normalize_google_name(given_name, family_name, full_name)
    random_password = hash_password(secrets.token_urlsafe(24))

    user_id = execute_insert_returning_id('''
        INSERT INTO users (first_name, last_name, email, password, role, department)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (first_name, last_name, email, random_password, 'employee', 'General'))

    created = fetch_one('''
        SELECT id, first_name, last_name, email, role, department, status
        FROM users
        WHERE id = ?
    ''', (user_id,))

    return build_user_payload(created), True


def exchange_github_code_for_token(code: str):
    """Exchange authorization code for GitHub access token."""
    payload = {
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': code,
        'redirect_uri': GITHUB_REDIRECT_URI,
    }
    encoded = urllib.parse.urlencode(payload).encode('utf-8')
    req = urllib.request.Request(
        'https://github.com/login/oauth/access_token',
        data=encoded,
        method='POST',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode('utf-8')

    return json.loads(raw)


def fetch_github_userinfo(access_token: str):
    """Fetch GitHub profile and primary verified email."""
    base_headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'RBAC2-App',
    }

    user_req = urllib.request.Request(
        'https://api.github.com/user',
        method='GET',
        headers=base_headers,
    )
    with urllib.request.urlopen(user_req, timeout=10) as resp:
        user_raw = resp.read().decode('utf-8')
    user_data = json.loads(user_raw)

    emails_req = urllib.request.Request(
        'https://api.github.com/user/emails',
        method='GET',
        headers=base_headers,
    )
    with urllib.request.urlopen(emails_req, timeout=10) as resp:
        emails_raw = resp.read().decode('utf-8')
    email_rows = json.loads(emails_raw)

    verified_primary = None
    for row in email_rows:
        if row.get('primary') and row.get('verified'):
            verified_primary = (row.get('email') or '').strip().lower()
            break

    if not verified_primary:
        for row in email_rows:
            if row.get('verified'):
                verified_primary = (row.get('email') or '').strip().lower()
                break

    return {
        'email': verified_primary,
        'name': user_data.get('name') or '',
        'login': user_data.get('login') or '',
    }


def find_or_create_github_user(email: str, name: str, login: str):
    """Find existing active user by email or create an employee account from GitHub profile."""
    existing = fetch_one('''
        SELECT id, first_name, last_name, email, role, department, status
        FROM users
        WHERE email = ?
    ''', (email,))

    if existing:
        if existing.get('status') != 'active':
            raise RuntimeError('Your account is inactive. Please contact admin.')
        return build_user_payload(existing), False

    first_name, last_name = normalize_google_name('', '', name)
    if first_name == 'Google' and login:
        first_name = login
        last_name = ''

    random_password = hash_password(secrets.token_urlsafe(24))

    user_id = execute_insert_returning_id('''
        INSERT INTO users (first_name, last_name, email, password, role, department)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (first_name, last_name, email, random_password, 'employee', 'General'))

    created = fetch_one('''
        SELECT id, first_name, last_name, email, role, department, status
        FROM users
        WHERE id = ?
    ''', (user_id,))

    return build_user_payload(created), True


def log_action(user_id, action, details=None):
    """Log user action to audit log with request metadata when available."""
    ip_address = None
    user_agent = None
    request_path = None
    http_method = None

    if has_request_context():
        ip_address = get_client_ip()
        user_agent = (request.headers.get('User-Agent') or '')[:255]
        request_path = (request.path or '')[:255]
        http_method = (request.method or '')[:20]

    execute_commit('''
        INSERT INTO audit_log (user_id, action, details, ip_address, user_agent, request_path, http_method)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, action, details, ip_address, user_agent, request_path, http_method))


@app.route('/api/security/config', methods=['GET'])
def get_security_config():
    """Expose non-sensitive security configuration to frontend"""
    return jsonify({
        'success': True,
        'recaptchaEnabled': RECAPTCHA_ENABLED,
        'recaptchaSiteKey': RECAPTCHA_SITE_KEY,
        'otpExpirySeconds': OTP_EXPIRY_SECONDS,
        'googleOAuthEnabled': GOOGLE_OAUTH_ENABLED,
        'githubOAuthEnabled': GITHUB_OAUTH_ENABLED,
    })


@app.route('/api/auth/google/start', methods=['GET'])
def google_oauth_start():
    """Start Google OAuth flow (login/signup)."""
    if not GOOGLE_OAUTH_ENABLED:
        return jsonify({'success': False, 'message': 'Google OAuth is not configured'}), 503

    mode = (request.args.get('mode') or 'login').strip().lower()
    if mode not in ('login', 'signup'):
        mode = 'login'

    state = secrets.token_urlsafe(24)
    session['google_oauth_state'] = state
    session['google_oauth_mode'] = mode

    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'prompt': 'select_account',
        'access_type': 'online',
        'include_granted_scopes': 'true',
    }

    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)


@app.route('/api/auth/google/callback', methods=['GET'])
def google_oauth_callback():
    """Handle Google OAuth callback and create temporary login handoff token."""
    def _redirect_with_error(message: str):
        return redirect('/#oauth_error=' + urllib.parse.quote(message))

    try:
        if not GOOGLE_OAUTH_ENABLED:
            return _redirect_with_error('Google OAuth is not configured')

        oauth_error = (request.args.get('error') or '').strip()
        if oauth_error:
            return _redirect_with_error('Google sign-in was cancelled or denied')

        state = request.args.get('state')
        expected_state = session.pop('google_oauth_state', None)
        mode = session.pop('google_oauth_mode', 'login')

        if not state or not expected_state or not hmac.compare_digest(state, expected_state):
            return _redirect_with_error('OAuth state validation failed')

        code = (request.args.get('code') or '').strip()
        if not code:
            return _redirect_with_error('Missing authorization code from Google')

        token_data = exchange_google_code_for_token(code)
        access_token = token_data.get('access_token')
        if not access_token:
            return _redirect_with_error('Unable to complete Google authentication')

        profile = fetch_google_userinfo(access_token)
        email = (profile.get('email') or '').strip().lower()
        email_verified = bool(profile.get('email_verified'))

        if not email or not email_verified:
            return _redirect_with_error('Google account email is missing or unverified')

        user, created = find_or_create_google_user(
            email=email,
            given_name=profile.get('given_name') or '',
            family_name=profile.get('family_name') or '',
            full_name=profile.get('name') or '',
        )

        temp_token = secrets.token_urlsafe(24)
        pending_oauth_callbacks[temp_token] = {
            'user': user,
            'mode': mode,
            'created': created,
            'provider': 'google',
            'expires_at': datetime.utcnow() + timedelta(seconds=OAUTH_TEMP_TOKEN_EXPIRY_SECONDS),
        }

        return redirect('/#oauth_token=' + urllib.parse.quote(temp_token))

    except urllib.error.HTTPError as e:
        raw = ''
        try:
            raw = e.read().decode('utf-8', errors='ignore')
        except Exception:
            raw = ''

        message = 'Google OAuth HTTP error. Please verify client credentials and redirect URI'
        if raw:
            try:
                payload = json.loads(raw)
                detail = (payload.get('error_description') or payload.get('error') or '').strip()
                if detail:
                    message = f'Google OAuth failed: {detail}'
            except Exception:
                message = f'Google OAuth failed: {raw[:180]}'

        app.logger.error('Google OAuth HTTPError %s: %s', e.code, raw)
        return _redirect_with_error(message)
    except RuntimeError as e:
        return _redirect_with_error(str(e))
    except Exception as e:
        app.logger.exception('Google OAuth callback failed: %s', e)
        return _redirect_with_error('Google login failed. Check redirect URI/domain and try again')


@app.route('/api/auth/github/start', methods=['GET'])
def github_oauth_start():
    """Start GitHub OAuth flow (login/signup)."""
    if not GITHUB_OAUTH_ENABLED:
        return jsonify({'success': False, 'message': 'GitHub OAuth is not configured'}), 503

    mode = (request.args.get('mode') or 'login').strip().lower()
    if mode not in ('login', 'signup'):
        mode = 'login'

    state = secrets.token_urlsafe(24)
    session['github_oauth_state'] = state
    session['github_oauth_mode'] = mode

    params = {
        'client_id': GITHUB_CLIENT_ID,
        'redirect_uri': GITHUB_REDIRECT_URI,
        'scope': 'read:user user:email',
        'state': state,
        'allow_signup': 'true',
    }

    auth_url = f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)


@app.route('/api/auth/github/callback', methods=['GET'])
def github_oauth_callback():
    """Handle GitHub OAuth callback and create temporary login handoff token."""
    def _redirect_with_error(message: str):
        return redirect('/#oauth_error=' + urllib.parse.quote(message))

    try:
        if not GITHUB_OAUTH_ENABLED:
            return _redirect_with_error('GitHub OAuth is not configured')

        oauth_error = (request.args.get('error') or '').strip()
        if oauth_error:
            return _redirect_with_error('GitHub sign-in was cancelled or denied')

        state = request.args.get('state')
        expected_state = session.pop('github_oauth_state', None)
        mode = session.pop('github_oauth_mode', 'login')

        if not state or not expected_state or not hmac.compare_digest(state, expected_state):
            return _redirect_with_error('OAuth state validation failed')

        code = (request.args.get('code') or '').strip()
        if not code:
            return _redirect_with_error('Missing authorization code from GitHub')

        token_data = exchange_github_code_for_token(code)
        access_token = (token_data.get('access_token') or '').strip()
        if not access_token:
            return _redirect_with_error('Unable to complete GitHub authentication')

        profile = fetch_github_userinfo(access_token)
        email = (profile.get('email') or '').strip().lower()
        if not email:
            return _redirect_with_error('No verified email found in GitHub account')

        user, created = find_or_create_github_user(
            email=email,
            name=profile.get('name') or '',
            login=profile.get('login') or '',
        )

        temp_token = secrets.token_urlsafe(24)
        pending_oauth_callbacks[temp_token] = {
            'user': user,
            'mode': mode,
            'created': created,
            'provider': 'github',
            'expires_at': datetime.utcnow() + timedelta(seconds=OAUTH_TEMP_TOKEN_EXPIRY_SECONDS),
        }

        return redirect('/#oauth_token=' + urllib.parse.quote(temp_token))
    except RuntimeError as e:
        return _redirect_with_error(str(e))
    except Exception:
        return _redirect_with_error('GitHub login failed. Please try again')


@app.route('/api/auth/oauth/finalize', methods=['POST'])
def oauth_finalize_login():
    """Finalize OAuth login from temporary callback token."""
    try:
        cleanup_expired_security_state()
        data = request.get_json() or {}
        token = (data.get('token') or '').strip()

        if not token:
            return jsonify({'success': False, 'message': 'OAuth token is required'}), 400

        payload = pending_oauth_callbacks.pop(token, None)
        if not payload:
            return jsonify({'success': False, 'message': 'OAuth session expired or invalid'}), 400

        user = payload['user']
        mode = payload.get('mode') or 'login'
        created = bool(payload.get('created'))
        provider = (payload.get('provider') or 'oauth').strip().lower()

        action = f'{provider}_oauth_signup' if created or mode == 'signup' else f'{provider}_oauth_login'
        detail = f"{provider.title()} OAuth {'signup' if created else 'login'} for {user.get('email')}"
        log_action(user.get('id'), action, detail)

        return jsonify({
            'success': True,
            'message': f'{provider.title()} authentication successful',
            'user': user,
        })
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to finalize OAuth login'}), 500


@app.route('/api/auth/register-init', methods=['POST'])
def register_init():
    """Step 1 of registration: validate inputs, verify reCAPTCHA, send OTP"""
    try:
        cleanup_expired_security_state()
        data = request.get_json() or {}

        first_name = (data.get('firstName') or '').strip()
        last_name = (data.get('lastName') or '').strip()
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        department = (data.get('department') or 'General').strip()
        recaptcha_token = data.get('recaptchaToken')

        if not all([first_name, last_name, email, password, department]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        captcha_ok, captcha_msg = verify_recaptcha(recaptcha_token, request.remote_addr)
        if not captcha_ok:
            return jsonify({'success': False, 'message': captcha_msg}), 400

        existing = fetch_one('SELECT id FROM users WHERE email = ?', (email,))
        if existing:
            return jsonify({'success': False, 'message': 'Email already registered'}), 409

        verification_token = secrets.token_urlsafe(32)
        pending_registrations[verification_token] = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password_hash': hash_password(password),
            'department': department,
            'expires_at': datetime.utcnow() + timedelta(seconds=OTP_EXPIRY_SECONDS),
        }

        create_otp_session(email=email, purpose='register', token=verification_token)

        return jsonify({
            'success': True,
            'message': 'OTP sent to your email address',
            'verificationToken': verification_token,
        })
    except RuntimeError as e:
        return jsonify({'success': False, 'message': str(e)}), 502
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Unable to start registration verification', 'error': str(e)}), 500


@app.route('/api/auth/register-verify', methods=['POST'])
def register_verify():
    """Step 2 of registration: verify OTP and create account"""
    try:
        cleanup_expired_security_state()
        data = request.get_json() or {}

        token = data.get('verificationToken')
        otp = (data.get('otp') or '').strip()

        if not token or not otp:
            return jsonify({'success': False, 'message': 'Verification token and OTP are required'}), 400

        pending = pending_registrations.get(token)
        if not pending:
            return jsonify({'success': False, 'message': 'Registration session expired'}), 400

        otp_ok, otp_msg = verify_otp_session(token, otp, expected_purpose='register')
        if not otp_ok:
            return jsonify({'success': False, 'message': otp_msg}), 400

        existing = fetch_one('SELECT id FROM users WHERE email = ?', (pending['email'],))
        if existing:
            pending_registrations.pop(token, None)
            return jsonify({'success': False, 'message': 'Email already registered'}), 409

        user_id = execute_insert_returning_id('''
            INSERT INTO users (first_name, last_name, email, password, role, department)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            pending['first_name'],
            pending['last_name'],
            pending['email'],
            pending['password_hash'],
            'employee',
            pending['department'],
        ))

        pending_registrations.pop(token, None)
        log_action(user_id, 'register_2fa', f"New user registered with OTP verification: {pending['email']}")

        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {
                'id': user_id,
                'firstName': pending['first_name'],
                'lastName': pending['last_name'],
                'email': pending['email'],
                'role': 'employee',
                'department': pending['department'],
                'status': 'active',
            }
        })
    except Exception:
        return jsonify({'success': False, 'message': 'Registration verification failed'}), 500


@app.route('/api/auth/login-init', methods=['POST'])
def login_init():
    """Step 1 of login: verify credentials + reCAPTCHA and send OTP"""
    try:
        cleanup_expired_security_state()
        data = request.get_json() or {}

        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        recaptcha_token = data.get('recaptchaToken')

        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400

        captcha_ok, captcha_msg = verify_recaptcha(recaptcha_token, request.remote_addr)
        if not captcha_ok:
            return jsonify({'success': False, 'message': captcha_msg}), 400

        hashed_password = hash_password(password)
        user = fetch_one('''
            SELECT id, first_name, last_name, email, role, department, status
            FROM users
            WHERE email = ? AND password = ? AND status = 'active'
        ''', (email, hashed_password))

        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        login_token = secrets.token_urlsafe(32)
        pending_logins[login_token] = {
            'user': {
                'id': user['id'],
                'firstName': user['first_name'],
                'lastName': user['last_name'],
                'email': user['email'],
                'role': user['role'],
                'department': user['department'],
                'status': user['status'],
            },
            'expires_at': datetime.utcnow() + timedelta(seconds=OTP_EXPIRY_SECONDS),
        }

        create_otp_session(email=email, purpose='login', token=login_token)

        return jsonify({
            'success': True,
            'message': 'OTP sent to your email address',
            'verificationToken': login_token,
        })
    except RuntimeError as e:
        return jsonify({'success': False, 'message': str(e)}), 502
    except Exception:
        return jsonify({'success': False, 'message': 'Unable to start login verification'}), 500


@app.route('/api/auth/login-verify', methods=['POST'])
def login_verify():
    """Step 2 of login: verify OTP and complete login"""
    try:
        cleanup_expired_security_state()
        data = request.get_json() or {}

        token = data.get('verificationToken')
        otp = (data.get('otp') or '').strip()

        if not token or not otp:
            return jsonify({'success': False, 'message': 'Verification token and OTP are required'}), 400

        pending = pending_logins.get(token)
        if not pending:
            return jsonify({'success': False, 'message': 'Login session expired'}), 400

        otp_ok, otp_msg = verify_otp_session(token, otp, expected_purpose='login')
        if not otp_ok:
            return jsonify({'success': False, 'message': otp_msg}), 400

        user = pending['user']
        pending_logins.pop(token, None)
        log_action(user['id'], 'login_2fa', f"User logged in with OTP from {request.remote_addr}")

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': user,
        })
    except Exception:
        return jsonify({'success': False, 'message': 'Login verification failed'}), 500

@app.route('/')
def index():
    """Serve the main HTML page (assembled from Jinja2 partials)"""
    return render_template('index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory('.', filename)

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Handle user login"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password required'}), 400
        
        hashed_password = hash_password(password)
        user = fetch_one('''
            SELECT id, first_name, last_name, email, role, department, status
            FROM users
            WHERE email = ? AND password = ? AND status = 'active'
        ''', (email, hashed_password))
        
        if user:
            user_data = {
                'id': user['id'],
                'firstName': user['first_name'],
                'lastName': user['last_name'],
                'email': user['email'],
                'role': user['role'],
                'department': user['department'],
                'status': user['status']
            }
            
            log_action(user['id'], 'login', f'User logged in from {request.remote_addr}')
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': user_data
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Handle user registration"""
    try:
        data = request.get_json()
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        email = data.get('email')
        password = data.get('password')
        department = data.get('department', 'General')
        
        if not all([first_name, last_name, email, password]):
            return jsonify({'success': False, 'message': 'All fields required'}), 400
        
        existing = fetch_one('SELECT id FROM users WHERE email = ?', (email,))
        if existing:
            return jsonify({'success': False, 'message': 'Email already registered'}), 409
        
        hashed_password = hash_password(password)
        user_id = execute_insert_returning_id('''
            INSERT INTO users (first_name, last_name, email, password, role, department)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (first_name, last_name, email, hashed_password, 'employee', department))
        
        log_action(user_id, 'register', f'New user registered: {email}')
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {
                'id': user_id,
                'firstName': first_name,
                'lastName': last_name,
                'email': email,
                'role': 'employee',
                'department': department,
                'status': 'active'
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users"""
    try:
        users = fetch_all('''
            SELECT id, first_name, last_name, email, role, department, phone, bio, status, created_at
            FROM users
            ORDER BY created_at DESC
        ''')
        users_list = [
            {
                'id': user.get('id'),
                'firstName': user.get('first_name'),
                'lastName': user.get('last_name'),
                'email': user.get('email'),
                'role': user.get('role'),
                'department': user.get('department'),
                'phone': user.get('phone') or '',
                'bio': user.get('bio') or '',
                'status': user.get('status'),
                'joinDate': user.get('created_at')
            }
            for user in users
        ]
        return jsonify({'success': True, 'users': users_list})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to fetch users'}), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create new user"""
    try:
        data = request.get_json()
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        email = data.get('email')
        role = data.get('role', 'employee')
        department = data.get('department')
        
        if not all([first_name, last_name, email, role]):
            return jsonify({'success': False, 'message': 'All fields required'}), 400
        
        existing = fetch_one('SELECT id FROM users WHERE email = ?', (email,))
        if existing:
            return jsonify({'success': False, 'message': 'Email already exists'}), 409
        
        temp_password = 'temp123'
        hashed_password = hash_password(temp_password)
        user_id = execute_insert_returning_id('''
            INSERT INTO users (first_name, last_name, email, password, role, department)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (first_name, last_name, email, hashed_password, role, department))
        
        log_action(user_id, 'user_created', f'User created: {email}')
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user': {
                'id': user_id,
                'firstName': first_name,
                'lastName': last_name,
                'email': email,
                'role': role,
                'department': department,
                'status': 'active'
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to create user'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Update user information"""
    try:
        data = request.get_json()
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        email = data.get('email')
        role = data.get('role')
        status = data.get('status')
        phone = data.get('phone', '')
        bio = data.get('bio', '')
        
        existing = fetch_one('SELECT id FROM users WHERE id = ?', (user_id,))
        if not existing:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        department = data.get('department')
        execute_commit('''
            UPDATE users 
            SET first_name = ?, last_name = ?, email = ?, role = ?, status = ?, department = ?, phone = ?, bio = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (first_name, last_name, email, role, status, department, phone, bio, user_id))
        
        log_action(user_id, 'user_updated', f'User updated: {email}')
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to update user'}), 500


@app.route('/api/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    """Get user profile with extended info"""
    try:
        user = fetch_one('''
            SELECT id, first_name, last_name, email, role, department, phone, bio, status, created_at, updated_at
            FROM users WHERE id = ?
        ''', (user_id,))
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        return jsonify({
            'success': True,
            'user': {
                'id': user.get('id'),
                'firstName': user.get('first_name'),
                'lastName': user.get('last_name'),
                'email': user.get('email'),
                'role': user.get('role'),
                'department': user.get('department'),
                'phone': user.get('phone') or '',
                'bio': user.get('bio') or '',
                'status': user.get('status'),
                'joinDate': user.get('created_at'),
                'updatedAt': user.get('updated_at')
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to fetch profile'}), 500


@app.route('/api/profile/<int:user_id>/password', methods=['PUT'])
def change_password(user_id):
    """Change user password (self-service)"""
    try:
        data = request.get_json() or {}
        current_password = data.get('currentPassword', '')
        new_password = data.get('newPassword', '')

        if not current_password or not new_password:
            return jsonify({'success': False, 'message': 'Current and new passwords are required'}), 400

        if len(new_password) < 8:
            return jsonify({'success': False, 'message': 'New password must be at least 8 characters'}), 400

        user = fetch_one('SELECT id, password FROM users WHERE id = ?', (user_id,))
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        if user.get('password') != hash_password(current_password):
            return jsonify({'success': False, 'message': 'Current password is incorrect'}), 403

        execute_commit('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                       (hash_password(new_password), user_id))

        log_action(user_id, 'password_changed', 'User changed their password')
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to change password'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete user"""
    try:
        user = fetch_one('SELECT email FROM users WHERE id = ?', (user_id,))
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        execute_commit('UPDATE audit_log SET user_id = NULL WHERE user_id = ?', (user_id,))
        execute_commit('DELETE FROM leave_requests WHERE user_id = ?', (user_id,))
        execute_commit('DELETE FROM users WHERE id = ?', (user_id,))
        
        log_action(user_id, 'user_deleted', f'User deleted: {user.get("email")}')
        
        return jsonify({'success': True, 'message': 'User deleted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to delete user'}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Dashboard statistics"""
    try:
        total_users   = (fetch_one('SELECT COUNT(*) AS count FROM users') or {}).get('count', 0)
        active_users  = (fetch_one("SELECT COUNT(*) AS count FROM users WHERE status='active'") or {}).get('count', 0)
        admin_count   = (fetch_one("SELECT COUNT(*) AS count FROM users WHERE role='admin'") or {}).get('count', 0)
        manager_count = (fetch_one("SELECT COUNT(*) AS count FROM users WHERE role='manager'") or {}).get('count', 0)
        employee_count= (fetch_one("SELECT COUNT(*) AS count FROM users WHERE role='employee'") or {}).get('count', 0)
        pending_leaves= (fetch_one("SELECT COUNT(*) AS count FROM leave_requests WHERE status='pending'") or {}).get('count', 0)
        total_logs    = (fetch_one('SELECT COUNT(*) AS count FROM audit_log') or {}).get('count', 0)
        return jsonify({
            'success': True,
            'stats': {
                'totalUsers':    total_users,
                'activeUsers':   active_users,
                'adminCount':    admin_count,
                'managerCount':  manager_count,
                'employeeCount': employee_count,
                'pendingLeaves': pending_leaves,
                'totalLogs':     total_logs
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/leaves', methods=['GET'])
def get_leaves():
    """Get all leave requests with employee info"""
    try:
        full_name = sql_full_name_expr('u')
        rows = fetch_all(f'''
            SELECT lr.id, lr.user_id, lr.type, lr.start_date, lr.end_date, lr.days,
                   lr.reason, lr.status, lr.created_at,
                   {full_name} AS employee_name,
                   u.department
            FROM leave_requests lr
            JOIN users u ON lr.user_id = u.id
            ORDER BY lr.created_at DESC
        ''')
        leaves = [dict(r) for r in rows]
        return jsonify({'success': True, 'leaves': leaves})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/leaves', methods=['POST'])
def create_leave():
    """Submit a new leave request"""
    try:
        data = request.get_json()
        user_id    = data.get('userId') or (get_user_from_session() if hasattr(app, '_test_user') else None)
        ltype      = data.get('type', 'vacation')
        start_date = data.get('startDate')
        end_date   = data.get('endDate')
        reason     = data.get('reason', '')
        if not user_id or not start_date or not end_date:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        from datetime import date
        d1 = date.fromisoformat(start_date)
        d2 = date.fromisoformat(end_date)
        days = max(1, (d2 - d1).days + 1)
        execute_commit(
            'INSERT INTO leave_requests (user_id, type, start_date, end_date, days, reason) VALUES (?,?,?,?,?,?)',
            (user_id, ltype, start_date, end_date, days, reason)
        )
        log_action(user_id, 'leave_submitted', f'Leave request ({ltype}) submitted')
        return jsonify({'success': True, 'message': 'Leave request submitted'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/leaves/<int:leave_id>', methods=['PUT'])
def update_leave(leave_id):
    """Approve or reject a leave request"""
    try:
        data   = request.get_json()
        status = data.get('status')
        if status not in ('approved', 'rejected', 'pending'):
            return jsonify({'success': False, 'message': 'Invalid status'}), 400
        row = fetch_one('SELECT id FROM leave_requests WHERE id = ?', (leave_id,))
        if not row:
            return jsonify({'success': False, 'message': 'Leave request not found'}), 404
        execute_commit(
            'UPDATE leave_requests SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            (status, leave_id)
        )
        log_action(None, 'leave_updated', f'Leave #{leave_id} status → {status}')
        return jsonify({'success': True, 'message': f'Leave request {status}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get audit logs with user info. Supports ?userId=N to filter by user."""
    try:
        limit = int(request.args.get('limit', 200))
        user_id_filter = request.args.get('userId')
        full_name = sql_full_name_expr('u')
        if SQLSERVER_ENABLED:
            if user_id_filter:
                rows = fetch_all(f'''
                    SELECT TOP (?) al.id, al.action, al.details, al.timestamp,
                           COALESCE(al.ip_address, '') AS ip_address,
                           COALESCE(al.user_agent, '') AS user_agent,
                           COALESCE(al.request_path, '') AS request_path,
                           COALESCE(al.http_method, '') AS http_method,
                           COALESCE({full_name}, 'System') AS user_name,
                           COALESCE(u.email, '') AS user_email
                    FROM audit_log al
                    LEFT JOIN users u ON al.user_id = u.id
                    WHERE al.user_id = ?
                    ORDER BY al.timestamp DESC
                ''', (limit, int(user_id_filter)))
            else:
                rows = fetch_all(f'''
                  SELECT TOP (?) al.id, al.action, al.details, al.timestamp,
                      COALESCE(al.ip_address, '') AS ip_address,
                      COALESCE(al.user_agent, '') AS user_agent,
                      COALESCE(al.request_path, '') AS request_path,
                      COALESCE(al.http_method, '') AS http_method,
                           COALESCE({full_name}, 'System') AS user_name,
                           COALESCE(u.email, '') AS user_email
                    FROM audit_log al
                    LEFT JOIN users u ON al.user_id = u.id
                    ORDER BY al.timestamp DESC
                ''', (limit,))
        else:
            if user_id_filter:
                rows = fetch_all(f'''
                    SELECT al.id, al.action, al.details, al.timestamp,
                           COALESCE(al.ip_address, '') AS ip_address,
                           COALESCE(al.user_agent, '') AS user_agent,
                           COALESCE(al.request_path, '') AS request_path,
                           COALESCE(al.http_method, '') AS http_method,
                           COALESCE({full_name}, 'System') AS user_name,
                           COALESCE(u.email, '') AS user_email
                    FROM audit_log al
                    LEFT JOIN users u ON al.user_id = u.id
                    WHERE al.user_id = ?
                    ORDER BY al.timestamp DESC
                    LIMIT ?
                ''', (int(user_id_filter), limit))
            else:
                rows = fetch_all(f'''
                  SELECT al.id, al.action, al.details, al.timestamp,
                      COALESCE(al.ip_address, '') AS ip_address,
                      COALESCE(al.user_agent, '') AS user_agent,
                      COALESCE(al.request_path, '') AS request_path,
                      COALESCE(al.http_method, '') AS http_method,
                           COALESCE({full_name}, 'System') AS user_name,
                           COALESCE(u.email, '') AS user_email
                    FROM audit_log al
                    LEFT JOIN users u ON al.user_id = u.id
                    ORDER BY al.timestamp DESC
                    LIMIT ?
                ''', (limit,))

        logs = [dict(r) for r in rows]
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/reports', methods=['GET'])
def get_reports():
    """Aggregated leave reports"""
    try:
        full_name = sql_full_name_expr('u')
        # Per-employee summary
        by_employee = fetch_all(f'''
            SELECT {full_name} AS name, u.department,
                   COUNT(*) AS total,
                   SUM(CASE WHEN lr.status='approved'  THEN 1 ELSE 0 END) AS approved,
                   SUM(CASE WHEN lr.status='pending'   THEN 1 ELSE 0 END) AS pending,
                   SUM(CASE WHEN lr.status='rejected'  THEN 1 ELSE 0 END) AS rejected,
                   SUM(CASE WHEN lr.status='approved'  THEN lr.days ELSE 0 END) AS approved_days
            FROM leave_requests lr
            JOIN users u ON lr.user_id = u.id
            GROUP BY lr.user_id
            ORDER BY total DESC
        ''')
        # Per-type summary
        by_type = fetch_all('''
            SELECT type,
                   COUNT(*) AS total,
                   SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) AS approved
            FROM leave_requests
            GROUP BY type
        ''')
        return jsonify({
            'success': True,
            'byEmployee': [dict(r) for r in by_employee],
            'byType':     [dict(r) for r in by_type]
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


if __name__ == '__main__':
    init_database()
    print("🚀 RBAC Backend Server Starting...")
    print("📊 Database initialized with demo accounts")
    print("🔗 Frontend: http://localhost:5000")
    print("🛡️  Backend API: http://localhost:5000/api")
    app.run(debug=True, host='0.0.0.0', port=5000)