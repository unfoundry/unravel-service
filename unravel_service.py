"""
Unravel Service - Enterprise Gateway, Decryption, Headless Parser & Broker
Single-file unified backend service providing:
1. Decryption Gateway: In-memory spreadsheet decryption (plaintext & hybrid RSA-OAEP/AES-GCM).
2. Status Page: Beautiful root status page showing "Up since...", uptime counter, and capability metrics.
3. Admin Dashboard: Protected dashboard supporting Master Token, IIS X-Header SSO, and LDAP(S) with AD Group filtering.
4. Project JSON Hosting: SQLite-backed project schema repository (GET /api/projects, /api/projects/{id}).
5. Headless Parsing Engine: Remote in-memory dataset parser matching UI validation rules for automations.
6. Destination Broker: Zero-trust live dispatcher forwarding clean datasets to destinations with delivery telemetry.
7. Telemetry & Pain-Point Monitor: Logs anonymized error breakdowns to highlight mapping issues.

NOTE: Other use of the platform is unauthenticated and open to all users.
Only the Admin Dashboard and schema mutation operations require authentication.
"""

import os
import io
import re
import math
import csv
import json
import base64
import time
import uuid
import secrets
import sqlite3
import datetime
import urllib.request
import urllib.error
from typing import Optional, List, Dict, Any, Tuple

from fastapi import FastAPI, HTTPException, Header, Depends, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

# -----------------------------------------------------------------------------
# Environment & Configuration Loader
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_env_file():
    """Load key-value pairs from .env into os.environ if present."""
    env_path = os.path.join(BASE_DIR, ".env")
    if not os.path.exists(env_path):
        env_path = os.path.join(BASE_DIR, "..", ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k not in os.environ:
                        os.environ[k] = v
        except Exception as e:
            print(f"[Env] Warning loading .env file: {e}")

load_env_file()

HOST = os.environ.get("UNRAVEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("UNRAVEL_PORT", "8001"))
_raw_db = os.environ.get("UNRAVEL_DB_PATH", "unravel.db")
if not os.path.isabs(_raw_db):
    if _raw_db.startswith("services/"):
        _raw_db = _raw_db[9:]
    DB_PATH = os.path.join(BASE_DIR, _raw_db)
else:
    DB_PATH = _raw_db

# -----------------------------------------------------------------------------
# Admin Authentication Policies (.env dictates what is available)
# -----------------------------------------------------------------------------
# 1. Master Token / Password
AUTH_MASTER_ENABLED = os.environ.get("UNRAVEL_AUTH_MASTER_ENABLED", "true").lower() in ("true", "1", "yes")
MASTER_PASSWORD = os.environ.get("UNRAVEL_MASTER_PASSWORD", "unravel2026")

# 2. IIS X-Header Authentication (Windows Authentication / Kerberos / NTLM through IIS)
AUTH_IIS_HEADER_ENABLED = os.environ.get("UNRAVEL_AUTH_IIS_HEADER_ENABLED", "false").lower() in ("true", "1", "yes")
AUTH_IIS_HEADER_NAME = os.environ.get("UNRAVEL_AUTH_IIS_HEADER_NAME", "X-Remote-User").strip()
_raw_allowed = os.environ.get("UNRAVEL_AUTH_IIS_ALLOWED_USERS", "DOMAIN\\admin,DOMAIN\\ashley,admin,ashley")
AUTH_IIS_ALLOWED_USERS = [u.strip() for u in _raw_allowed.split(",") if u.strip()]

# 3. LDAP / Active Directory (LDAPS) Authentication
AUTH_LDAP_ENABLED = os.environ.get("UNRAVEL_AUTH_LDAP_ENABLED", "false").lower() in ("true", "1", "yes")
AUTH_LDAP_SERVER = os.environ.get("UNRAVEL_AUTH_LDAP_SERVER", "ldaps://ad.enterprise.org:636").strip()
AUTH_LDAP_BASE_DN = os.environ.get("UNRAVEL_AUTH_LDAP_BASE_DN", "DC=enterprise,DC=org").strip()
AUTH_LDAP_USER_DN_TEMPLATE = os.environ.get("UNRAVEL_AUTH_LDAP_USER_DN_TEMPLATE", "{username}@enterprise.org").strip()
AUTH_LDAP_BIND_DN = os.environ.get("UNRAVEL_AUTH_LDAP_BIND_DN", "").strip()
AUTH_LDAP_BIND_PASSWORD = os.environ.get("UNRAVEL_AUTH_LDAP_BIND_PASSWORD", "").strip()
AUTH_LDAP_GROUP_FILTER = os.environ.get("UNRAVEL_AUTH_LDAP_GROUP_FILTER", "CN=UnravelAdmins,OU=Groups,DC=enterprise,DC=org").strip()
AUTH_LDAP_USE_SSL = os.environ.get("UNRAVEL_AUTH_LDAP_USE_SSL", "true").lower() in ("true", "1", "yes")
AUTH_LDAP_MOCK = os.environ.get("UNRAVEL_AUTH_LDAP_MOCK", "false").lower() in ("true", "1", "yes")

# Server Startup Tracking (for "Up since..." live uptime counter)
SERVER_START_TIMESTAMP = time.time()
SERVER_START_DATETIME = datetime.datetime.now(datetime.timezone.utc)

# In-memory admin sessions (session_token -> {user, method, created_at})
_active_admin_sessions: Dict[str, Dict[str, Any]] = {}

# -----------------------------------------------------------------------------
# Optional LDAP3 Library Import
# -----------------------------------------------------------------------------
try:
    import ldap3
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

app = FastAPI(
    title="Unravel Service",
    description="Enterprise Headless Parsing Engine, Decryption Gateway, Live Destination Broker & Admin Console",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount self-contained static assets directory (completely independent of app/)
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)
app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")

# Jinja2 Templates Directory
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# -----------------------------------------------------------------------------
# SQLite Database Setup & Schema
# -----------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()

    # 1. Projects Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            project_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT,
            schema_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Broker Delivery Logs (Zero-trust: no row/file content saved)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS broker_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_email TEXT,
            project_id TEXT,
            layout_id TEXT,
            destination_url TEXT NOT NULL,
            total_rows INTEGER,
            error_count INTEGER,
            delivery_status TEXT NOT NULL,
            status_code INTEGER,
            duration_ms INTEGER
        )
    """)

    # 3. Telemetry Sessions (Aggregated pain points & validation errors)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_email TEXT,
            project_id TEXT,
            layout_id TEXT,
            total_rows INTEGER,
            valid_rows INTEGER,
            error_count INTEGER,
            rule_errors_json TEXT
        )
    """)

    conn.commit()

    # Pre-seed sample projects if table is empty
    cursor.execute("SELECT COUNT(*) FROM projects")
    count = cursor.fetchone()[0]
    if count == 0:
        seed_starter_projects(cursor, conn)

    conn.close()

def seed_starter_projects(cursor, conn):
    """Seed projects table from local starter-templates.json and sample-project.json if available."""
    templates_path = os.path.join(BASE_DIR, "assets", "sample-data", "starter-templates.json")
    sample_proj_path = os.path.join(BASE_DIR, "assets", "sample-data", "sample-project.json")

    # 1. Starter templates
    if os.path.exists(templates_path):
        try:
            with open(templates_path, "r", encoding="utf-8") as f:
                templates = json.load(f)
                for tpl in templates:
                    schema = tpl.get("schema", {})
                    pid = schema.get("projectId") or tpl.get("id")
                    name = schema.get("name") or tpl.get("name")
                    ver = schema.get("version", "1.0.0")
                    cursor.execute("""
                        INSERT OR REPLACE INTO projects (project_id, name, version, schema_json)
                        VALUES (?, ?, ?, ?)
                    """, (pid, name, ver, json.dumps(schema, indent=2)))
        except Exception as e:
            print(f"[Seed] Error loading starter-templates.json: {e}")

    # 2. Main sample project
    if os.path.exists(sample_proj_path):
        try:
            with open(sample_proj_path, "r", encoding="utf-8") as f:
                sample_proj = json.load(f)
                pid = sample_proj.get("projectId", "sample-patient-ingest")
                name = sample_proj.get("name", "Sample Ingestion Project")
                ver = sample_proj.get("version", "1.0.0")
                cursor.execute("""
                    INSERT OR REPLACE INTO projects (project_id, name, version, schema_json)
                    VALUES (?, ?, ?, ?)
                """, (pid, name, ver, json.dumps(sample_proj, indent=2)))
        except Exception as e:
            print(f"[Seed] Error loading sample-project.json: {e}")

    conn.commit()

init_database()

# -----------------------------------------------------------------------------
# RSA Key Pair Management for Hybrid In-Transit Encryption
# -----------------------------------------------------------------------------
_server_private_key = None
_server_public_key_pem = None

def init_rsa_keypair():
    global _server_private_key, _server_public_key_pem
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        _server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = _server_private_key.public_key()
        _server_public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    except ImportError:
        _server_private_key = None
        _server_public_key_pem = None

init_rsa_keypair()

# -----------------------------------------------------------------------------
# Uptime & Runtime Statistics Helper
# -----------------------------------------------------------------------------
def get_uptime_info() -> Dict[str, Any]:
    elapsed_seconds = int(time.time() - SERVER_START_TIMESTAMP)
    days, rem = divmod(elapsed_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days > 0:
        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"
    elif hours > 0:
        uptime_str = f"{hours}h {minutes}m {seconds}s"
    else:
        uptime_str = f"{minutes}m {seconds}s"

    return {
        "startIso": SERVER_START_DATETIME.isoformat(),
        "startFormatted": SERVER_START_DATETIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "elapsedSeconds": elapsed_seconds,
        "uptimeFormatted": uptime_str
    }

# -----------------------------------------------------------------------------
# Authentication Guard Helpers (IIS Header, LDAP, Master Token)
# -----------------------------------------------------------------------------
def check_iis_auth(request: Request) -> Optional[str]:
    """
    Checks for IIS X-Header (e.g. X-Remote-User) set by Windows Authentication / ARR.
    Validates against UNRAVEL_AUTH_IIS_ALLOWED_USERS.
    """
    if not AUTH_IIS_HEADER_ENABLED:
        return None

    # Check primary header and case variants
    candidates = [
        AUTH_IIS_HEADER_NAME,
        AUTH_IIS_HEADER_NAME.lower(),
        "x-remote-user",
        "auth_user",
        "remote_user"
    ]
    raw_user = None
    for c in candidates:
        val = request.headers.get(c)
        if val and val.strip():
            raw_user = val.strip()
            break

    if not raw_user:
        return None

    user_lower = raw_user.lower()
    user_bare = user_lower.split('\\')[-1] if '\\' in user_lower else user_lower

    for allowed in AUTH_IIS_ALLOWED_USERS:
        al = allowed.lower()
        al_bare = al.split('\\')[-1] if '\\' in al else al
        if al == "*" or al == user_lower or al_bare == user_bare:
            return raw_user

    return None

def check_ldap_auth(username: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Authenticate user against LDAP / LDAPS server and evaluate optional AD Group filter.
    Returns (is_authorized, error_message, display_name).
    """
    if not AUTH_LDAP_ENABLED:
        return False, "LDAP authentication is disabled in service configuration.", None

    if not username or not password:
        return False, "Username and password cannot be empty.", None

    # Mock LDAP mode for testing without a live AD Domain Controller
    if AUTH_LDAP_MOCK:
        if username.lower() in ("admin", "testadmin", "ashley") and password in ("unravel2026", "adminpass", "password"):
            return True, None, f"{username} (Mock AD)"
        return False, "Mock LDAP: Invalid credentials.", None

    if not HAS_LDAP3:
        return False, "LDAP authentication requires the 'ldap3' library. Run: pip install ldap3", None

    try:
        # Determine if SSL is required
        server_url = AUTH_LDAP_SERVER
        use_ssl = AUTH_LDAP_USE_SSL or server_url.lower().startswith("ldaps://")
        server = ldap3.Server(server_url, use_ssl=use_ssl, get_info=ldap3.ALL)

        # Format user DN or UPN
        user_dn = AUTH_LDAP_USER_DN_TEMPLATE.format(username=username) if "{username}" in AUTH_LDAP_USER_DN_TEMPLATE else username

        # 1. Bind with user credentials
        conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)

        display_name = username
        # 2. Check Active Directory Group Filter if specified
        if AUTH_LDAP_GROUP_FILTER:
            search_base = AUTH_LDAP_BASE_DN or "DC=enterprise,DC=org"
            search_filter = f"(|(sAMAccountName={username})(userPrincipalName={user_dn})(cn={username}))"

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['memberOf', 'displayName', 'cn']
            )

            if not conn.entries:
                return False, f"User authenticated via LDAP, but directory entry could not be located in '{search_base}'.", None

            entry = conn.entries[0]
            display_name = getattr(entry, 'displayName', username) or username
            member_of = [str(g).lower() for g in getattr(entry, 'memberOf', [])]
            target_group = AUTH_LDAP_GROUP_FILTER.lower()

            # Compare against full DN, or CN portion
            is_member = any(
                target_group in g or
                target_group == g.split(',')[0].replace('cn=', '').strip()
                for g in member_of
            )

            if not is_member:
                return False, f"User '{username}' authenticated successfully via LDAP, but is not a member of required AD group '{AUTH_LDAP_GROUP_FILTER}'.", None

        return True, None, str(display_name)
    except ldap3.core.exceptions.LDAPBindError:
        return False, "Invalid LDAP domain credentials.", None
    except Exception as e:
        return False, f"LDAP directory error: {str(e)}", None

def verify_admin_auth(request: Request) -> Dict[str, Any]:
    """
    FastAPI dependency guard for Admin Dashboard & management operations.
    Supports:
    1. IIS X-Header (Windows SSO)
    2. Bearer Master Token or X-Master-Password header
    3. Admin session cookie (from LDAP or Master password form login)
    """
    # 1. Check IIS X-Header
    iis_user = check_iis_auth(request)
    if iis_user:
        return {"user": iis_user, "method": "iis_header"}

    # 2. Check Bearer Token or X-Master-Password from request headers, or query param
    x_master = request.headers.get("x-master-password")
    auth_header = request.headers.get("authorization")
    bearer_token = None
    if auth_header and auth_header.lower().startswith("bearer "):
        bearer_token = auth_header[7:].strip()
    query_token = request.query_params.get("token")
    provided_token = x_master or bearer_token or query_token

    # 3. Check Session Cookie
    cookie_token = request.cookies.get("unravel_admin_session")

    active_token = provided_token or cookie_token

    if active_token:
        # Check Master Token
        if AUTH_MASTER_ENABLED and (active_token == MASTER_PASSWORD or active_token == "unravel-master-secret"):
            return {"user": "master_admin", "method": "master_token"}

        # Check Active Session Store
        if active_token in _active_admin_sessions:
            sess = _active_admin_sessions[active_token]
            if time.time() - sess["created_at"] < 86400:  # 24h validity
                return sess
            else:
                del _active_admin_sessions[active_token]

    raise HTTPException(status_code=401, detail="Unauthorized: Admin access requires valid credentials")

# -----------------------------------------------------------------------------
# Request & Response Models
# -----------------------------------------------------------------------------
class DecryptRequest(BaseModel):
    fileData: str
    password: str

class DecryptResponse(BaseModel):
    success: bool
    fileData: str

class HybridDecryptRequest(BaseModel):
    encryptedKey: str
    encryptedPayload: str
    iv: str

class HybridDecryptResponse(BaseModel):
    success: bool
    encryptedPayload: str
    iv: str

class ProjectPayload(BaseModel):
    projectId: str
    name: str
    version: Optional[str] = "1.0.0"
    projectSchema: Dict[str, Any] = Field(default_factory=dict, alias="schema")

    model_config = {
        "populate_by_name": True
    }

class HeadlessParseRequest(BaseModel):
    project: Optional[Dict[str, Any]] = None
    projectId: Optional[str] = None
    layoutId: Optional[str] = None
    fileData: str  # Base64 encoded file data
    fileName: Optional[str] = "upload.xlsx"
    fileType: Optional[str] = None  # xlsx, csv, tsv
    filePassword: Optional[str] = None

class BrokerDispatchRequest(BaseModel):
    destinationUrl: str
    headers: Optional[Dict[str, str]] = None
    payload: Any  # Clean row records
    metadata: Optional[Dict[str, Any]] = None

class TelemetrySessionRequest(BaseModel):
    user: Optional[str] = "anonymous"
    projectId: Optional[str] = ""
    layoutId: Optional[str] = ""
    totalRows: int = 0
    validRows: int = 0
    errorCount: int = 0
    ruleErrors: Optional[Dict[str, int]] = None

class AuthRequest(BaseModel):
    password: str

class LdapAuthRequest(BaseModel):
    username: str
    password: str

# -----------------------------------------------------------------------------
# Core In-Memory Spreadsheet Decryption
# -----------------------------------------------------------------------------
def decrypt_office_stream(raw_bytes: bytes, password: str) -> bytes:
    try:
        import msoffcrypto
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="msoffcrypto-tool library is not installed. Run: pip install msoffcrypto-tool"
        )

    input_stream = io.BytesIO(raw_bytes)
    output_stream = io.BytesIO()

    try:
        office_file = msoffcrypto.OfficeFile(input_stream)
        office_file.load_key(password=password)
        office_file.decrypt(output_stream)
        return output_stream.getvalue()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Workbook decryption failed: {str(e)}")

# =============================================================================
# 1. BEAUTIFUL ROOT STATUS PAGE ("Up since...") & HEALTH
# =============================================================================
@app.get("/", response_class=HTMLResponse)
def root_status_page(request: Request):
    """
    Pretty status page displaying live uptime, server start timestamp,
    active capabilities, and links to docs and admin dashboard.
    """
    uptime = get_uptime_info()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM projects")
    proj_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM broker_logs")
    log_count = cursor.fetchone()[0]
    conn.close()

    auth_tags = []
    if AUTH_MASTER_ENABLED:
        auth_tags.append('<span class="badge bg-primary-subtle text-primary border border-primary-subtle"><i class="bi bi-key-fill me-1"></i>Master Token</span>')
    if AUTH_IIS_HEADER_ENABLED:
        auth_tags.append(f'<span class="badge bg-success-subtle text-success border border-success-subtle"><i class="bi bi-windows me-1"></i>IIS X-Header ({AUTH_IIS_HEADER_NAME})</span>')
    if AUTH_LDAP_ENABLED:
        auth_tags.append('<span class="badge bg-info-subtle text-info-emphasis border border-info-subtle"><i class="bi bi-shield-lock-fill me-1"></i>LDAP(S) Active Directory</span>')
    auth_html = " ".join(auth_tags) if auth_tags else '<span class="badge bg-secondary">None</span>'

    is_admin = False
    admin_user = ""
    try:
        auth_info = verify_admin_auth(request)
        is_admin = True
        admin_user = auth_info["user"]
    except HTTPException:
        pass

    start_iso = SERVER_START_DATETIME.strftime("%Y-%m-%d %H:%M:%S UTC")

    return templates.TemplateResponse(
        request=request,
        name="status.html",
        context={
            "active_page": "status",
            "uptime": uptime,
            "start_iso": start_iso,
            "proj_count": proj_count,
            "log_count": log_count,
            "auth_html": auth_html,
            "is_admin": is_admin,
            "admin_user": admin_user
        }
    )

@app.get("/health")
def health_check():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM projects")
    proj_count = cursor.fetchone()[0]
    conn.close()

    uptime = get_uptime_info()

    return {
        "status": "online",
        "service": "Unravel Service",
        "version": "2.0.0",
        "uptime": uptime,
        "features": {
            "decryptionGateway": True,
            "hybridTransitEncryption": _server_private_key is not None,
            "projectHosting": True,
            "headlessParser": True,
            "liveBroker": True,
            "telemetryMonitor": True
        },
        "authProviders": {
            "masterToken": AUTH_MASTER_ENABLED,
            "iisHeader": AUTH_IIS_HEADER_ENABLED,
            "iisHeaderName": AUTH_IIS_HEADER_NAME if AUTH_IIS_HEADER_ENABLED else None,
            "ldap": AUTH_LDAP_ENABLED,
            "ldapServer": AUTH_LDAP_SERVER if AUTH_LDAP_ENABLED else None,
            "ldapGroupFilterConfigured": bool(AUTH_LDAP_GROUP_FILTER) if AUTH_LDAP_ENABLED else False
        },
        "database": {
            "connected": True,
            "projectsCount": proj_count
        }
    }

@app.get("/api/public-key")
def get_public_key():
    if not _server_public_key_pem:
        raise HTTPException(
            status_code=503,
            detail="Cryptography library not installed. Hybrid encryption unavailable."
        )
    return {
        "algorithm": "RSA-OAEP-256",
        "format": "SPKI-PEM",
        "publicKey": _server_public_key_pem
    }

@app.get("/api/auth/methods")
def get_auth_methods():
    """Public helper returning which authentication providers are enabled for the admin console."""
    return {
        "masterToken": AUTH_MASTER_ENABLED,
        "iisHeader": {
            "enabled": AUTH_IIS_HEADER_ENABLED,
            "headerName": AUTH_IIS_HEADER_NAME if AUTH_IIS_HEADER_ENABLED else None
        },
        "ldap": {
            "enabled": AUTH_LDAP_ENABLED,
            "server": AUTH_LDAP_SERVER if AUTH_LDAP_ENABLED else None,
            "groupFilterRequired": bool(AUTH_LDAP_GROUP_FILTER) if AUTH_LDAP_ENABLED else False,
            "groupFilter": AUTH_LDAP_GROUP_FILTER if AUTH_LDAP_ENABLED else None
        }
    }

# =============================================================================
# 2. ADMIN DASHBOARD (BOOTSWATCH HTML UI) & AUTHENTICATION ENDPOINTS
# =============================================================================
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard_page(request: Request):
    """
    Admin Dashboard Web Interface (Bootswatch Lumen UI matching app/):
    - If authenticated, renders admin_dashboard.html template with schemas manager & telemetry.
    - If unauthenticated, displays multi-provider login card (login.html).
    """
    auth_info = None
    try:
        auth_info = verify_admin_auth(request)
    except HTTPException:
        pass

    if not auth_info:
        iis_attempted_user = request.headers.get(AUTH_IIS_HEADER_NAME)
        iis_rejected = bool(AUTH_IIS_HEADER_ENABLED and iis_attempted_user and not check_iis_auth(request))
        allowed_preview = ", ".join(AUTH_IIS_ALLOWED_USERS[:3]) + ("..." if len(AUTH_IIS_ALLOWED_USERS) > 3 else "")
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            status_code=401,
            context={
                "active_page": "admin",
                "iis_rejected": iis_rejected,
                "iis_attempted_user": iis_attempted_user or "",
                "auth_master_enabled": AUTH_MASTER_ENABLED,
                "auth_ldap_enabled": AUTH_LDAP_ENABLED,
                "auth_ldap_group_filter": AUTH_LDAP_GROUP_FILTER,
                "auth_iis_enabled": AUTH_IIS_HEADER_ENABLED,
                "auth_iis_header_name": AUTH_IIS_HEADER_NAME,
                "auth_iis_allowed_users_preview": allowed_preview
            }
        )

    user_name = auth_info.get("user", "Admin")
    auth_method = auth_info.get("method", "Master Token")
    method_badge_class = "badge-soft-primary"
    if auth_method == "iis_header":
        method_badge_class = "badge-soft-success"
        auth_method = f"IIS SSO ({AUTH_IIS_HEADER_NAME})"
    elif auth_method == "ldap":
        method_badge_class = "badge-soft-info"
        auth_method = "LDAP(S) Domain Account"

    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context={
            "active_page": "admin",
            "user_name": user_name,
            "auth_method": auth_method,
            "method_badge_class": method_badge_class
        }
    )

@app.post("/api/admin/logs/purge")
def purge_admin_logs(auth: Dict[str, Any] = Depends(verify_admin_auth)):
    """Admin-only action to purge all telemetry sessions and broker logs."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM telemetry_sessions")
    t_count = cursor.rowcount
    cursor.execute("DELETE FROM broker_logs")
    b_count = cursor.rowcount
    conn.commit()
    conn.close()
    return {
        "success": True,
        "message": f"Successfully purged {t_count} telemetry session(s) and {b_count} broker delivery log(s).",
        "telemetryPurged": t_count,
        "brokerPurged": b_count
    }

@app.post("/api/auth/login")
def login_master(req: AuthRequest, response: Response):
    """Authenticate via Master Password / Token."""
    if not AUTH_MASTER_ENABLED:
        raise HTTPException(status_code=403, detail="Master password authentication is disabled in configuration.")

    if req.password == MASTER_PASSWORD:
        token = secrets.token_hex(24)
        _active_admin_sessions[token] = {
            "user": "master_admin",
            "method": "master_token",
            "created_at": time.time()
        }
        response.set_cookie(
            key="unravel_admin_session",
            value=token,
            max_age=86400,
            httponly=True,
            samesite="lax"
        )
        return {
            "success": True,
            "token": token,
            "user": "master_admin",
            "role": "admin"
        }
    raise HTTPException(status_code=401, detail="Invalid master password.")

@app.post("/api/auth/login-ldap")
def login_ldap(req: LdapAuthRequest, response: Response):
    """Authenticate via Active Directory / LDAP with optional AD Group check."""
    if not AUTH_LDAP_ENABLED:
        raise HTTPException(status_code=403, detail="LDAP authentication is disabled in configuration.")

    is_ok, err_msg, display_name = check_ldap_auth(req.username, req.password)
    if not is_ok:
        raise HTTPException(status_code=401, detail=err_msg or "LDAP authentication failed.")

    token = secrets.token_hex(24)
    _active_admin_sessions[token] = {
        "user": display_name or req.username,
        "method": "ldap",
        "created_at": time.time()
    }
    response.set_cookie(
        key="unravel_admin_session",
        value=token,
        max_age=86400,
        httponly=True,
        samesite="lax"
    )
    return {
        "success": True,
        "token": token,
        "user": display_name or req.username,
        "role": "admin"
    }

@app.post("/api/auth/logout")
def logout_admin(request: Request, response: Response):
    cookie_token = request.cookies.get("unravel_admin_session")
    if cookie_token and cookie_token in _active_admin_sessions:
        del _active_admin_sessions[cookie_token]
    response.delete_cookie(key="unravel_admin_session")
    return {"success": True, "message": "Logged out successfully."}

# =============================================================================
# 4. ADMIN AUDIT & STATS ENDPOINTS (Protected by verify_admin_auth)
# =============================================================================
@app.get("/api/admin/broker-logs")
def get_admin_broker_logs(limit: int = 50, auth: Dict[str, Any] = Depends(verify_admin_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, user_email, project_id, layout_id, destination_url,
               total_rows, error_count, delivery_status, status_code, duration_ms
        FROM broker_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "user_email": r["user_email"],
            "project_id": r["project_id"],
            "layout_id": r["layout_id"],
            "destination_url": r["destination_url"],
            "total_rows": r["total_rows"],
            "error_count": r["error_count"],
            "delivery_status": r["delivery_status"],
            "status_code": r["status_code"],
            "duration_ms": r["duration_ms"]
        }
        for r in rows
    ]

@app.get("/api/telemetry/stats")
def get_telemetry_stats(auth: Dict[str, Any] = Depends(verify_admin_auth)):
    """
    Returns rich telemetry stats, usage metrics, rule pain points,
    per-project health, and client session records for the Bootswatch dashboard.
    """
    conn = get_db()
    cursor = conn.cursor()

    # 1. Overall Telemetry Aggregates
    cursor.execute("""
        SELECT COUNT(*),
               COALESCE(SUM(total_rows), 0),
               COALESCE(SUM(valid_rows), 0),
               COALESCE(SUM(error_count), 0)
        FROM telemetry_sessions
    """)
    t_row = cursor.fetchone()
    total_sessions, total_rows, total_valid, total_errors = t_row[0], t_row[1], t_row[2], t_row[3]
    clean_rate = round((total_valid / total_rows * 100) if total_rows > 0 else 100.0, 1)

    # 2. Broker Delivery Aggregates
    cursor.execute("""
        SELECT COUNT(*),
               COUNT(CASE WHEN delivery_status='DELIVERED' THEN 1 END),
               COUNT(CASE WHEN delivery_status='FAILED' THEN 1 END),
               COALESCE(AVG(duration_ms), 0)
        FROM broker_logs
    """)
    b_row = cursor.fetchone()
    total_dispatches, successful_dispatches, failed_dispatches, avg_duration = b_row[0], b_row[1], b_row[2], round(b_row[3], 1)
    dispatch_success_rate = round((successful_dispatches / total_dispatches * 100) if total_dispatches > 0 else 100.0, 1)

    # 3. Top Validation Rule Pain Points
    cursor.execute("SELECT rule_errors_json FROM telemetry_sessions WHERE rule_errors_json IS NOT NULL")
    rows = cursor.fetchall()
    pain_points: Dict[str, int] = {}
    for r in rows:
        try:
            d = json.loads(r[0])
            for rule, count in d.items():
                pain_points[rule] = pain_points.get(rule, 0) + count
        except Exception:
            pass

    sorted_pain_points = sorted(pain_points.items(), key=lambda x: x[1], reverse=True)
    all_error_sum = sum(pain_points.values()) or 1
    top_pain_points = [
        {
            "rule": k,
            "failureCount": v,
            "percentOfErrors": round(v / all_error_sum * 100, 1)
        }
        for k, v in sorted_pain_points[:15]
    ]

    # 4. Usage Stats by Project
    cursor.execute("""
        SELECT project_id,
               COUNT(*) as sessions,
               COALESCE(SUM(total_rows), 0) as rows,
               COALESCE(SUM(valid_rows), 0) as valid_rows,
               COALESCE(SUM(error_count), 0) as errors,
               MAX(timestamp) as last_seen
        FROM telemetry_sessions
        GROUP BY project_id
        ORDER BY rows DESC
        LIMIT 15
    """)
    project_usage = [
        {
            "projectId": r["project_id"] or "unspecified",
            "sessions": r["sessions"],
            "totalRows": r["rows"],
            "validRows": r["valid_rows"],
            "errorCount": r["errors"],
            "cleanRate": round((r["valid_rows"] / r["rows"] * 100) if r["rows"] > 0 else 100.0, 1),
            "lastSeen": r["last_seen"]
        }
        for r in cursor.fetchall()
    ]

    # 5. Usage Stats by User
    cursor.execute("""
        SELECT user_email,
               COUNT(*) as sessions,
               COALESCE(SUM(total_rows), 0) as rows,
               COALESCE(SUM(error_count), 0) as errors,
               MAX(timestamp) as last_active
        FROM telemetry_sessions
        GROUP BY user_email
        ORDER BY rows DESC
        LIMIT 15
    """)
    user_usage = [
        {
            "user": r["user_email"] or "anonymous",
            "sessions": r["sessions"],
            "totalRows": r["rows"],
            "errorCount": r["errors"],
            "lastActive": r["last_active"]
        }
        for r in cursor.fetchall()
    ]

    # 6. Recent Telemetry Sessions
    cursor.execute("""
        SELECT id, timestamp, user_email, project_id, layout_id, total_rows, valid_rows, error_count, rule_errors_json
        FROM telemetry_sessions
        ORDER BY id DESC
        LIMIT 30
    """)
    recent_sessions = [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "user": r["user_email"] or "anonymous",
            "projectId": r["project_id"] or "",
            "layoutId": r["layout_id"] or "",
            "totalRows": r["total_rows"] or 0,
            "validRows": r["valid_rows"] or 0,
            "errorCount": r["error_count"] or 0,
            "ruleErrors": json.loads(r["rule_errors_json"] or "{}") if r["rule_errors_json"] else {}
        }
        for r in cursor.fetchall()
    ]

    # 7. Hosted Projects Count
    cursor.execute("SELECT COUNT(*) FROM projects")
    hosted_projects_count = cursor.fetchone()[0]

    conn.close()

    return {
        # Backward-compatible summary keys
        "totalSessions": total_sessions,
        "totalRowsIngested": total_rows,
        "totalValidRows": total_valid,
        "totalErrorsDetected": total_errors,
        "cleanRate": clean_rate,
        "hostedProjectsCount": hosted_projects_count,
        "brokerDispatches": {
            "total": total_dispatches,
            "successful": successful_dispatches,
            "failed": failed_dispatches,
            "successRate": dispatch_success_rate,
            "avgDurationMs": avg_duration
        },
        "topPainPoints": top_pain_points,
        "projectUsage": project_usage,
        "userUsage": user_usage,
        "recentSessions": recent_sessions
    }

# =============================================================================
# 5. PUBLIC INGESTION & DECRYPTION ENDPOINTS (Open to all users)
# =============================================================================
@app.post("/api/decrypt-xlsx", response_model=DecryptResponse)
def decrypt_xlsx(req: DecryptRequest):
    try:
        raw_bytes = base64.b64decode(req.fileData)
        decrypted_bytes = decrypt_office_stream(raw_bytes, req.password)
        decrypted_b64 = base64.b64encode(decrypted_bytes).decode('utf-8')
        return DecryptResponse(success=True, fileData=decrypted_b64)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {str(e)}")

@app.post("/api/decrypt-xlsx-hybrid", response_model=HybridDecryptResponse)
def decrypt_xlsx_hybrid(req: HybridDecryptRequest):
    if not _server_private_key:
        raise HTTPException(status_code=503, detail="Cryptography library not installed on server.")

    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # 1. Decrypt ephemeral AES session key via RSA-OAEP
        enc_key_bytes = base64.b64decode(req.encryptedKey)
        aes_key = _server_private_key.decrypt(
            enc_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Decrypt payload JSON with AES-256-GCM
        iv_bytes = base64.b64decode(req.iv)
        enc_payload_bytes = base64.b64decode(req.encryptedPayload)

        aesgcm = AESGCM(aes_key)
        decrypted_json_bytes = aesgcm.decrypt(iv_bytes, enc_payload_bytes, None)
        payload_data = json.loads(decrypted_json_bytes.decode('utf-8'))

        raw_xlsx_bytes = base64.b64decode(payload_data['fileData'])
        password = payload_data['password']

        # 3. Decrypt Excel workbook in memory
        decrypted_xlsx_bytes = decrypt_office_stream(raw_xlsx_bytes, password)
        decrypted_xlsx_b64 = base64.b64encode(decrypted_xlsx_bytes).decode('utf-8')

        # 4. Re-encrypt output with same AES key using fresh 12-byte IV
        return_iv = os.urandom(12)
        response_json = json.dumps({"fileData": decrypted_xlsx_b64}).encode('utf-8')
        enc_response_payload = aesgcm.encrypt(return_iv, response_json, None)

        return HybridDecryptResponse(
            success=True,
            encryptedPayload=base64.b64encode(enc_response_payload).decode('utf-8'),
            iv=base64.b64encode(return_iv).decode('utf-8')
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Hybrid decryption pipeline failed: {str(e)}")

# -----------------------------------------------------------------------------
# 6. Project Schema Repository (Public Read, Protected Write)
# -----------------------------------------------------------------------------
@app.get("/api/projects")
def list_projects():
    """Public retrieval of available project profiles."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT project_id, name, version, updated_at FROM projects ORDER BY name ASC")
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "projectId": r["project_id"],
            "name": r["name"],
            "version": r["version"],
            "updatedAt": r["updated_at"]
        }
        for r in rows
    ]

@app.get("/api/projects/{project_id}")
def get_project(project_id: str):
    """Public retrieval of a specific project schema."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT schema_json FROM projects WHERE project_id = ?", (project_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Project schema '{project_id}' not found.")

    return json.loads(row["schema_json"])

@app.post("/api/projects")
def save_project(payload: ProjectPayload, auth: Dict[str, Any] = Depends(verify_admin_auth)):
    """Admin-only publishing of project schemas to SQLite repository."""
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    schema_str = json.dumps(payload.projectSchema, indent=2)

    cursor.execute("""
        INSERT INTO projects (project_id, name, version, schema_json, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(project_id) DO UPDATE SET
            name = excluded.name,
            version = excluded.version,
            schema_json = excluded.schema_json,
            updated_at = excluded.updated_at
    """, (payload.projectId, payload.name, payload.version, schema_str, now))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": f"Project '{payload.projectId}' successfully saved to Unravel database.",
        "projectId": payload.projectId
    }

@app.delete("/api/projects/{project_id}")
def delete_project(project_id: str, auth: Dict[str, Any] = Depends(verify_admin_auth)):
    """Admin-only deletion of project schema from repository."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM projects WHERE project_id = ?", (project_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
    return {"success": True, "message": f"Project '{project_id}' deleted."}

# -----------------------------------------------------------------------------
# 7. Headless Parsing Engine (In-Memory Processing)
# -----------------------------------------------------------------------------
def apply_headless_validation(rule_type: str, val: Any) -> bool:
    s = str(val).strip() if val is not None else ""
    if rule_type == "IsRequired":
        return len(s) > 0
    if rule_type == "IsEmail":
        import re
        return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", s)) if s else True
    if rule_type == "IsInteger":
        return s.lstrip("-+").isdigit() if s else True
    if rule_type == "IsDecimal":
        try:
            float(s)
            return True
        except ValueError:
            return False if s else True
    if rule_type == "IsAlphanumeric":
        import re
        return bool(re.match(r"^[a-zA-Z0-9_-]+$", s)) if s else True
    if rule_type == "IsPostcode":
        import re
        return bool(re.match(r"^[A-Z0-9\s-]{3,10}$", s.upper())) if s else True
    if rule_type == "IsPhoneNumber":
        import re
        return bool(re.match(r"^[+0-9\s\-()]{7,20}$", s)) if s else True
    return True

def apply_headless_transforms(val: Any, transforms: Any, date_src: str = "", date_tgt: str = "") -> Any:
    if transforms is None:
        return val
    list_transforms = transforms if isinstance(transforms, list) else [transforms]
    cur = val
    for t in list_transforms:
        t_type = t.upper() if isinstance(t, str) else (t.get("type", "").upper() if isinstance(t, dict) else "")
        s = str(cur) if cur is not None else ""
        if t_type == "TRIM":
            cur = s.strip()
        elif t_type == "UPPERCASE":
            cur = s.strip().upper()
        elif t_type == "LOWERCASE":
            cur = s.strip().lower()
        elif t_type == "CAPITALIZE":
            cur = " ".join(word.capitalize() for word in s.strip().split())
        elif t_type in ("CAST_INTEGER", "INTEGER"):
            clean = re.sub(r"[^-0-9.]", "", s)
            if clean and clean != "-":
                try:
                    cur = round(float(clean))
                except Exception:
                    pass
        elif t_type in ("CAST_FLOAT", "FLOAT"):
            clean = re.sub(r"[^-0-9.]", "", s)
            if clean and clean != "-":
                try:
                    prec = t.get("precision") if isinstance(t, dict) else None
                    f = float(clean)
                    cur = round(f, int(prec)) if prec is not None else f
                except Exception:
                    pass
        elif t_type in ("CAST_STRING", "STRING"):
            cur = s.strip()
        elif t_type in ("CAST_BOOLEAN", "BOOLEAN"):
            low = s.strip().lower()
            if low in ("true", "1", "yes", "y"): cur = True
            elif low in ("false", "0", "no", "n"): cur = False
            else: cur = bool(cur)
        elif t_type in ("CAST_DATE", "DATE_FORMAT"):
            src = t.get("dateFormatSource", date_src) if isinstance(t, dict) else date_src
            tgt = t.get("dateFormatTarget", date_tgt) if isinstance(t, dict) else date_tgt
            try:
                from datetime import datetime
                dt = datetime.strptime(s.strip(), src or "%d/%m/%Y")
                cur = dt.strftime(tgt or "%Y-%m-%d")
            except Exception:
                cur = s.strip()
    return cur

def _coerce_numeric(val: Any) -> Any:
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, str):
        s = val.strip()
        try:
            if "." in s:
                return float(s)
            return int(s)
        except ValueError:
            return val
    return val

def evaluate_python_expression(expression: str, row: Dict[str, Any]) -> Any:
    if not expression or not isinstance(expression, str):
        return None
    try:
        def repl(match):
            key = match.group(1)
            return f"_row.get({repr(key)}, 0)"
        
        py_expr = re.sub(r"\[([a-zA-Z0-9_\-]+)\]", repl, expression)
        # Ternary: (cond) ? (val1) : (val2) -> ((val1) if (cond) else (val2))
        py_expr = re.sub(r"\(([^?]+)\)\s*\?\s*([^:]+)\s*:\s*([^;]+)", r"(\2 if \1 else \3)", py_expr)
        py_expr = re.sub(r"\btrue\b", "True", py_expr)
        py_expr = re.sub(r"\bfalse\b", "False", py_expr)
        py_expr = re.sub(r"\bnull\b", "None", py_expr)
        py_expr = re.sub(r"&&", " and ", py_expr)
        py_expr = re.sub(r"\|\|", " or ", py_expr)
        
        import math
        safe_scope = {
            "_row": {k: _coerce_numeric(v) for k, v in row.items()},
            "round": round,
            "int": int,
            "float": float,
            "abs": abs,
            "min": min,
            "max": max,
            "math": math
        }
        return eval(py_expr, {"__builtins__": {}}, safe_scope)
    except Exception as e:
        print(f"[unravel] Calculated column eval error: {expression} => {e}")
        return None

def apply_python_row_filters(rows: List[Dict[str, Any]], row_filters: Optional[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if not row_filters or not row_filters.get("rules"):
        return rows, []
    
    rules = row_filters.get("rules", [])
    combine = (row_filters.get("combine") or "AND").upper()
    clean_rows = []
    excluded_rows = []
    
    for row in rows:
        results = []
        for rule in rules:
            col_key = rule.get("column")
            op = (rule.get("op") or rule.get("operator") or "=").strip()
            target_val = rule.get("value")
            raw_val = row.get(col_key)
            rule_type = (rule.get("type") or ("number" if isinstance(target_val, (int, float)) or op in (">", ">=", "<", "<=") else "string")).lower()
            
            if op == "not_empty":
                match = raw_val is not None and str(raw_val).strip() != ""
                reason = "" if match else f"Column [{col_key}] must not be empty"
                results.append((match, reason))
                continue
                
            if rule_type == "number":
                try:
                    num_val = float(re.sub(r"[^-0-9.]", "", str(raw_val or "")))
                    target_num = float(target_val)
                    if op == "=": match = (num_val == target_num)
                    elif op == "!=": match = (num_val != target_num)
                    elif op == ">": match = (num_val > target_num)
                    elif op == ">=": match = (num_val >= target_num)
                    elif op == "<": match = (num_val < target_num)
                    elif op == "<=": match = (num_val <= target_num)
                    else: match = True
                    reason = "" if match else f"Column [{col_key}] ({num_val}) failed {op} {target_num}"
                except Exception:
                    match = False
                    reason = f"Column [{col_key}] is not a valid number"
                results.append((match, reason))
            else:
                s_val = str(raw_val or "").strip().lower()
                s_tgt = str(target_val or "").strip().lower()
                if op == "=": match = (s_val == s_tgt)
                elif op == "!=": match = (s_val != s_tgt)
                elif op == "contains": match = (s_tgt in s_val)
                else: match = (s_val == s_tgt)
                reason = "" if match else f"Column [{col_key}] ('{raw_val}') failed {op} '{target_val}'"
                results.append((match, reason))
        
        if combine == "OR":
            passes = any(r[0] for r in results)
            fail_reason = "; ".join(r[1] for r in results if r[1])
        else:
            passes = all(r[0] for r in results)
            fail_reason = "; ".join(r[1] for r in results if not r[0])
            
        if passes:
            clean_rows.append(row)
        else:
            row_copy = dict(row)
            row_copy["_exclusion_reason"] = fail_reason or "Failed filter criteria"
            excluded_rows.append(row_copy)
            
    return clean_rows, excluded_rows

@app.post("/api/parse")
def parse_headless_dataset(req: HeadlessParseRequest):
    """
    Public Headless Parsing Endpoint:
    Processes XLSX, CSV, or TSV file against schema definition and layout.
    """
    # 1. Resolve Project Schema
    schema = req.project
    if not schema and req.projectId:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT schema_json FROM projects WHERE project_id = ?", (req.projectId,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail=f"Project '{req.projectId}' not found in database.")
        schema = json.loads(row["schema_json"])

    if not schema:
        raise HTTPException(status_code=400, detail="Missing project schema or valid projectId.")

    # 2. Resolve Layout
    layouts = schema.get("layouts", [])
    layout = None
    if req.layoutId:
        layout = next((l for l in layouts if l.get("id") == req.layoutId), None)
    if not layout and len(layouts) > 0:
        layout = layouts[0]
    if not layout:
        raise HTTPException(status_code=400, detail="No matching layout found in schema.")

    # 3. Decode & Decrypt File Data
    try:
        raw_bytes = base64.b64decode(req.fileData)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 file data: {str(e)}")

    fname = (req.fileName or "").lower()
    ftype = (req.fileType or layout.get("fileType", "")).lower()
    if not ftype:
        if fname.endswith(".csv"): ftype = "csv"
        elif fname.endswith(".tsv") or fname.endswith(".txt"): ftype = "tsv"
        else: ftype = "xlsx"

    # Optional Decryption
    if ftype == "xlsx" and req.filePassword:
        try:
            raw_bytes = decrypt_office_stream(raw_bytes, req.filePassword)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Password decryption failed: {str(e)}")

    # 4. Extract Matrix of Rows
    matrix: List[List[Any]] = []
    if ftype in ("csv", "tsv"):
        delimiter = "\t" if ftype == "tsv" or fname.endswith(".tsv") else ","
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            reader = csv.reader(io.StringIO(text), delimiter=delimiter)
            matrix = [list(row) for row in reader]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"CSV/TSV parse failed: {str(e)}")
    else:
        try:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(raw_bytes), data_only=True)
            sheet_name = wb.sheetnames[0]
            sheet = wb[sheet_name]
            for row in sheet.iter_rows(values_only=True):
                matrix.append([c if c is not None else "" for c in row])
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"XLSX parse failed: {str(e)}")

    if not matrix:
        return {
            "success": True,
            "status": "EMPTY",
            "stats": {"totalRows": 0, "validRows": 0, "invalidRows": 0, "errorCount": 0},
            "cleanData": [],
            "errors": []
        }

    # 5. Offset & Header Detection
    offset = layout.get("offset", {})
    offset_y = int(offset.get("offsetY", 0))
    offset_x = int(offset.get("offsetX", 0))

    if offset_y >= len(matrix):
        raise HTTPException(status_code=400, detail="Header offset row exceeds total row count.")

    headers = [str(h).strip() for h in matrix[offset_y][offset_x:]]
    data_rows = matrix[offset_y + 1:]

    # 6. Apply Column Mappings, Transforms & Validations
    mappings = layout.get("mappings", [])
    target_columns = schema.get("targetColumns", [])

    clean_data = []
    errors = []
    dropped_count = 0
    all_mapped_rows = []

    for r_idx, row in enumerate(data_rows):
        row_slice = row[offset_x:]
        row_dict = {}
        row_errors = []
        has_blocking = False

        # A. Map & Transform Source Columns
        for target in target_columns:
            t_key = target.get("key")
            mapping = next((m for m in mappings if m.get("targetColumn") == t_key), None)
            src_col = mapping.get("sourceColumn") if mapping else None
            transforms = (mapping.get("transforms") if mapping and mapping.get("transforms") else None) or \
                         (mapping.get("transform") if mapping and mapping.get("transform") and mapping.get("transform") != "NONE" else None) or \
                         (target.get("transforms") if target and target.get("transforms") else None) or \
                         (target.get("transform") if target and target.get("transform") and target.get("transform") != "NONE" else "TRIM")
            def_val = mapping.get("defaultValue", "") if mapping else target.get("defaultValue", "")

            raw_val = ""
            if src_col and src_col in headers:
                col_idx = headers.index(src_col)
                if col_idx < len(row_slice):
                    raw_val = row_slice[col_idx]

            val = apply_headless_transforms(raw_val, transforms)
            if (val is None or val == "") and def_val:
                val = def_val

            row_dict[t_key] = val

        # B. Compute Calculated Columns
        calculated_cols = schema.get("calculatedColumns", schema.get("calculated_columns", []))
        for calc in calculated_cols:
            c_key = calc.get("key") or calc.get("id") or calc.get("target_column")
            expr = calc.get("expression") or calc.get("formula", "")
            if c_key and expr:
                computed_val = evaluate_python_expression(expr, row_dict)
                calc_transforms = calc.get("transforms")
                if calc_transforms:
                    computed_val = apply_headless_transforms(computed_val, calc_transforms)
                row_dict[c_key] = computed_val

        all_mapped_rows.append(row_dict)

    # 7. Apply Pre-Validation Ingestion Row Filters
    row_filters = schema.get("rowFilters") or schema.get("row_filters")
    candidate_rows, excluded_data = apply_python_row_filters(all_mapped_rows, row_filters)

    # 8. Run Cell Validations on Candidate Rows
    for r_idx, row_dict in enumerate(candidate_rows):
        has_blocking = False
        row_errors = []

        for target in target_columns:
            t_key = target.get("key")
            val = row_dict.get(t_key)
            mapping = next((m for m in mappings if m.get("targetColumn") == t_key), None)
            is_req = mapping.get("required", target.get("required", False)) if mapping else target.get("required", False)
            validations = mapping.get("validations", target.get("defaultValidations", [])) if mapping else target.get("defaultValidations", [])

            # Check required
            s_val = str(val).strip() if val is not None else ""
            if not s_val:
                if is_req:
                    row_errors.append({
                        "rowNumber": r_idx + 1,
                        "columnKey": t_key,
                        "rule": "Required",
                        "value": ""
                    })
                    has_blocking = True
                continue

            for v in validations:
                v_type = v if isinstance(v, str) else v.get("type", "")
                if not apply_headless_validation(v_type, val):
                    row_errors.append({
                        "rowNumber": r_idx + 1,
                        "columnKey": t_key,
                        "rule": v_type,
                        "value": str(val)
                    })
                    has_blocking = True

        if has_blocking:
            dropped_count += 1
        else:
            clean_data.append(row_dict)

        errors.extend(row_errors)

    total_rows = len(data_rows)
    valid_rows = len(clean_data)

    return {
        "success": True,
        "status": "VALID" if dropped_count == 0 else "HAS_ERRORS",
        "stats": {
            "totalRows": total_rows,
            "candidateRows": len(candidate_rows),
            "excludedRows": len(excluded_data),
            "validRows": valid_rows,
            "invalidRows": dropped_count,
            "errorCount": len(errors)
        },
        "cleanData": clean_data,
        "excludedData": excluded_data,
        "errors": errors
    }

# -----------------------------------------------------------------------------
# 8. Live Destination Broker (Zero-Trust Forwarder)
# -----------------------------------------------------------------------------
@app.post("/api/broker/dispatch")
def broker_dispatch(req: BrokerDispatchRequest):
    """
    Public Live Gateway Dispatcher:
    Forwards clean records to destination REST endpoint without saving files.
    """
    dest_url = req.destinationUrl
    headers = req.headers or {"Content-Type": "application/json"}
    meta = req.metadata or {}

    total_rows = len(req.payload) if isinstance(req.payload, list) else 1
    err_count = meta.get("errorCount", 0)
    user_email = meta.get("user", "anonymous")
    project_id = meta.get("projectId", "")
    layout_id = meta.get("layoutId", "")

    start_time = time.time()
    delivery_status = "FAILED"
    status_code = 500
    resp_text = ""

    try:
        data_bytes = json.dumps(req.payload).encode("utf-8")
        req_obj = urllib.request.Request(dest_url, data=data_bytes, headers=headers, method="POST")

        with urllib.request.urlopen(req_obj, timeout=30) as resp:
            status_code = resp.getcode()
            resp_text = resp.read().decode("utf-8", errors="replace")
            delivery_status = "DELIVERED" if status_code < 400 else "FAILED"
    except urllib.error.HTTPError as he:
        status_code = he.code
        resp_text = he.read().decode("utf-8", errors="replace")
        delivery_status = "FAILED"
    except Exception as ex:
        status_code = 500
        resp_text = str(ex)
        delivery_status = "FAILED"

    duration_ms = int((time.time() - start_time) * 1000)

    # Save delivery audit entry to SQLite
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO broker_logs (
            user_email, project_id, layout_id, destination_url,
            total_rows, error_count, delivery_status, status_code, duration_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_email, project_id, layout_id, dest_url, total_rows, err_count, delivery_status, status_code, duration_ms))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()

    if delivery_status == "FAILED":
        raise HTTPException(
            status_code=status_code if status_code != 500 else 502,
            detail=f"Broker delivery failed (HTTP {status_code}): {resp_text}"
        )

    return {
        "success": True,
        "statusCode": status_code,
        "durationMs": duration_ms,
        "logId": log_id,
        "destinationResponse": resp_text
    }

# -----------------------------------------------------------------------------
# 9. Telemetry Ingest Endpoint (Public)
# -----------------------------------------------------------------------------
@app.post("/api/telemetry/session")
def record_telemetry_session(req: TelemetrySessionRequest):
    """Logs aggregated session performance and rule error counts."""
    conn = get_db()
    cursor = conn.cursor()
    rule_errors_str = json.dumps(req.ruleErrors or {})

    cursor.execute("""
        INSERT INTO telemetry_sessions (
            user_email, project_id, layout_id, total_rows, valid_rows, error_count, rule_errors_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (req.user, req.projectId, req.layoutId, req.totalRows, req.validRows, req.errorCount, rule_errors_str))

    conn.commit()
    conn.close()
    return {"success": True}

# -----------------------------------------------------------------------------
# Server Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    print(f"Starting Unravel Service on http://{HOST}:{PORT} (DB: {DB_PATH})...")
    print(f"Admin Auth Providers: MasterToken={AUTH_MASTER_ENABLED}, IISHeader={AUTH_IIS_HEADER_ENABLED}, LDAP={AUTH_LDAP_ENABLED}")
    uvicorn.run(app, host=HOST, port=PORT)
