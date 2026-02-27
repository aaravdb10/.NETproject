# SecureFlow RBAC

A Flask-based Role-Based Access Control web application with two-factor OTP authentication, Google and GitHub OAuth2, reCAPTCHA, leave management, audit trails, and role-driven dashboards. Runs on SQLite by default with optional SQL Server support.

---

## Features

### Authentication
- Two-step registration: validate inputs + reCAPTCHA → OTP email → create account
- Two-step login: validate credentials + reCAPTCHA → OTP email → session
- OTP validity: 5 minutes, max 5 attempts per session, hashed in memory
- Google OAuth2 (Authorization Code flow) — login and signup
- GitHub OAuth2 (Authorization Code flow, fetches verified primary email) — login and signup
- Legacy single-step login and register endpoints (no OTP) kept as fallback
- "Keep me signed in" checkbox on login
- Passwords hashed with SHA-256 before storage

### RBAC & User Management
- Three roles: `admin`, `manager`, `employee`
- Admin can create, edit, activate/deactivate, and delete users
- Profile view with extended fields: phone, bio, department, join date
- Self-service password change (requires current password)

### Leave Management
- Submit leave requests (vacation, sick, personal) with date range
- Auto-calculated working days
- Approve / reject workflow (manager/admin)
- Per-employee and per-type aggregated leave reports

### Audit Logging
- Every significant action (login, register, OAuth, user changes, leave ops) written to `audit_log`
- Captures: user ID, action, details, IP address, user agent, request path, HTTP method, timestamp
- Admin can filter audit log by user

### Security Modules
Standalone reference implementations included in the repo:

| File | Purpose |
|------|---------|
| `sql_injection_prevention.py` | Parameterised query patterns and input sanitisation helpers |
| `idor_protection.py` | Object-level authorisation checks |
| `session_security.py` | Session fixation and expiry patterns |
| `audit_trail.py` | Audit logging reference implementation |

### Frontend
- Single-page app (SPA) — all views assembled from Jinja2 partials, no client-side router needed
- Vanilla JavaScript, no framework dependencies
- Two-column auth layout: branded left panel + form right panel
- Step indicator for multi-step auth flows
- Password strength meter with per-rule checklist
- Social sign-in: circular icon buttons (Google, GitHub) with brand-coloured hover states
- OTP input with large letter-spaced display
- Demo account quick-login buttons on the login page
- Dark mode via `[data-theme="dark"]` CSS custom properties
- Responsive — single-column layout below 860 px

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.8+, Flask 2.3, Flask-CORS 4.0, Werkzeug 2.3 |
| Database | SQLite (default) · SQL Server via `pyodbc` (optional) |
| Auth | Email OTP, Google OAuth2, GitHub OAuth2, Google reCAPTCHA v2 |
| Frontend | Jinja2 templates, CSS custom properties, vanilla JS |
| Email | SMTP (configurable — works with Gmail, SendGrid, etc.) |
| Rate limiting | Flask-Limiter 2.7 |
| Config | python-dotenv |

---

## Project Structure

```
RBAC2/
├── app.py                        # Flask app — all routes and business logic
├── email_config.py               # SMTP OTP email sender
├── requirements.txt
├── start_backend.bat             # Windows one-click start
├── .env                          # Environment variables (not committed)
│
├── style.css                     # Main stylesheet (CSS custom properties, dark mode)
├── enhancements.css              # Form layout, remember-me, animation helpers
├── otp-styles.css                # OTP input and reveal panel styles
├── script.js                     # SPA logic — auth flows, dashboard, API calls
│
├── templates/
│   ├── index.html                # Root template — assembles all partials
│   └── partials/
│       ├── _head.html            # <head>, CSS/font imports, reCAPTCHA script
│       ├── _home.html            # Landing / home page
│       ├── _register.html        # Registration form (step 1 fields + OTP step)
│       ├── _login.html           # Login form (step 1 fields + OTP step) + demo buttons
│       ├── _dashboard.html       # Role-driven dashboard views
│       ├── _modals.html          # Create/edit user modals, leave request modal
│       └── _toast.html           # Toast notification container
│
├── sql_injection_prevention.py   # Security reference module
├── idor_protection.py            # Security reference module
├── session_security.py           # Security reference module
├── audit_trail.py                # Security reference module
│
└── db_backups/                   # SQLite backup directory
```

---

## Database Schema

Three tables auto-created by `init_database()` on first run (SQLite mode).

### `users`
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | Auto-increment |
| `first_name` | TEXT | |
| `last_name` | TEXT | |
| `email` | TEXT UNIQUE | |
| `password` | TEXT | SHA-256 hash |
| `role` | TEXT | `admin` · `manager` · `employee` |
| `department` | TEXT | IT, HR, Finance, Marketing, Operations, General |
| `phone` | TEXT | Optional |
| `bio` | TEXT | Optional |
| `status` | TEXT | `active` · `inactive` |
| `created_at` | TIMESTAMP | |
| `updated_at` | TIMESTAMP | |

### `audit_log`
| Column | Type |
|--------|------|
| `id` | INTEGER PK |
| `user_id` | INTEGER FK → users |
| `action` | TEXT |
| `details` | TEXT |
| `ip_address` | TEXT |
| `user_agent` | TEXT |
| `request_path` | TEXT |
| `http_method` | TEXT |
| `timestamp` | TIMESTAMP |

### `leave_requests`
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `user_id` | INTEGER FK | |
| `type` | TEXT | `vacation` · `sick` · `personal` |
| `start_date` | TEXT | ISO date |
| `end_date` | TEXT | ISO date |
| `days` | INTEGER | Auto-calculated |
| `reason` | TEXT | |
| `status` | TEXT | `pending` · `approved` · `rejected` |
| `created_at` | TIMESTAMP | |
| `updated_at` | TIMESTAMP | |

---

## Demo Accounts

Seeded automatically when using SQLite:

| Name | Email | Password | Role | Department |
|------|-------|----------|------|------------|
| Rahul Sharma | admin@company.com | admin123 | admin | IT |
| Priya Patel | manager@company.com | manager123 | manager | HR |
| Vikram Singh | employee@company.com | employee123 | employee | Finance |
| Aarav Gandhi | aarav.gandhi@company.com | password123 | employee | IT |
| Neha Gupta | neha.gupta@company.com | password123 | manager | Marketing |
| Rohan Verma | rohan.verma@company.com | password123 | employee | Operations |

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment variables

Create a `.env` file in the project root:

```env
# ── reCAPTCHA (optional — skipped if blank) ──────────────────────────────────
RECAPTCHA_SITE_KEY=
RECAPTCHA_SECRET_KEY=

# ── Google OAuth2 (optional — buttons hidden if blank) ────────────────────────
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:5000/api/auth/google/callback

# ── GitHub OAuth2 (optional — buttons hidden if blank) ────────────────────────
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=http://localhost:5000/api/auth/github/callback

# ── OTP email (required for OTP delivery) ────────────────────────────────────
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=

# ── Database (leave blank to use SQLite) ─────────────────────────────────────
DB_TYPE=sqlite
# For SQL Server set DB_TYPE=sqlserver and fill in:
DB_SERVER=
DB_NAME=
DB_USER=
DB_PASSWORD=
DB_DRIVER=
```

### 3. Run

```bash
python app.py
```

Windows shortcut:
```bat
start_backend.bat
```

### 4. Open

```
http://localhost:5000
```

---

## OAuth2 Setup

### Google
1. Go to [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials
2. Create an **OAuth 2.0 Client ID** (Web application)
3. Add authorised redirect URI: `http://localhost:5000/api/auth/google/callback`
4. Copy **Client ID** → `GOOGLE_CLIENT_ID` and **Client Secret** → `GOOGLE_CLIENT_SECRET`

### GitHub
1. Go to GitHub → Settings → Developer settings → **OAuth Apps** → New OAuth App
2. Homepage URL: `http://localhost:5000`
3. Authorization callback URL: `http://localhost:5000/api/auth/github/callback`
4. Copy **Client ID** → `GITHUB_CLIENT_ID` and generate + copy **Client Secret** → `GITHUB_CLIENT_SECRET`

> OAuth buttons are automatically hidden on the frontend when the corresponding credentials are not set.

---

## API Reference

Base URL: `http://localhost:5000/api`

### Security / Config

| Method | Path | Description |
|--------|------|-------------|
| GET | `/security/config` | Returns reCAPTCHA site key and OAuth enabled flags |

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register-init` | Step 1 — validate fields + reCAPTCHA, send OTP |
| POST | `/auth/register-verify` | Step 2 — verify OTP, create account |
| POST | `/auth/login-init` | Step 1 — validate credentials + reCAPTCHA, send OTP |
| POST | `/auth/login-verify` | Step 2 — verify OTP, return user session |
| GET | `/auth/google/start` | Redirect to Google OAuth consent screen |
| GET | `/auth/google/callback` | Google OAuth callback — issues temp handoff token |
| GET | `/auth/github/start` | Redirect to GitHub OAuth consent screen |
| GET | `/auth/github/callback` | GitHub OAuth callback — issues temp handoff token |
| POST | `/auth/oauth/finalize` | Exchange temp OAuth token for user session |
| POST | `/auth/login` | Legacy single-step login (no OTP) |
| POST | `/auth/register` | Legacy single-step register (no OTP) |

### Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/users` | List all users |
| POST | `/users` | Create user (role defaults to `employee`) |
| PUT | `/users/<id>` | Update user details, role, status, department |
| DELETE | `/users/<id>` | Delete user and associated leave requests |
| GET | `/profile/<id>` | Get extended profile (phone, bio, dates) |
| PUT | `/profile/<id>/password` | Self-service password change |

### Dashboard & Operations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats` | Counts: users, active, roles, pending leaves, log entries |
| GET | `/leaves` | All leave requests joined with employee info |
| POST | `/leaves` | Submit a leave request |
| PUT | `/leaves/<id>` | Approve or reject a leave request |
| GET | `/logs` | Audit log — supports `?userId=N` and `?limit=N` |
| GET | `/reports` | Aggregated leave stats by employee and by type |

---

## OAuth Flow (Technical)

```
Browser                    Flask                       Provider
   │                          │                            │
   ├─ GET /auth/google/start ─►│                            │
   │                          ├─ set session state ─────────┤
   │◄─ 302 → Google consent ──┤                            │
   │                                                       │
   ├─────────────────────────────────────────── user approves
   │                                                       │
   │◄─ 302 → /api/auth/google/callback?code=&state= ───────┤
   │                          │                            │
   ├─ follows redirect ───────►│                            │
   │                          ├─ validate HMAC state        │
   │                          ├─ exchange code for token ──►│
   │                          ├─ fetch userinfo ───────────►│
   │                          ├─ find_or_create_user        │
   │                          ├─ store temp_token (180s)    │
   │◄─ 302 → /#oauth_token=X ─┤                            │
   │                          │                            │
   ├─ POST /auth/oauth/finalize {token: X} ─────────────────┤
   │◄─ {success, user} ───────┤                            │
```

---

## Notes

- OTP flows require valid SMTP credentials. Without them, `register-init` and `login-init` will return 502.
- reCAPTCHA is bypassed in local dev when `RECAPTCHA_SITE_KEY`/`RECAPTCHA_SECRET_KEY` are not set.
- OAuth state is validated with `hmac.compare_digest` to prevent CSRF.
- OAuth temp tokens expire in 180 seconds. Expired entries are cleaned up on each new auth request.
- New accounts created via Google or GitHub are assigned the `employee` role and `General` department by default. An admin can change these afterwards.
- GitHub OAuth requires the account to have at least one verified email address.
- SQL Server mode requires `DB_TYPE=sqlserver`, `DB_SERVER`, `DB_NAME`, `DB_DRIVER`, and `pyodbc` with a matching ODBC driver installed.
- The SQLite database file `rbac_system.db` is created automatically on first run. The `db_backups/` directory can be used for manual snapshots.

---

## License

MIT — see `LICENSE`.
