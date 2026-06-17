"""
Auth & user management module untuk TempMail.

Schema baru:
  users          — akun (super_admin / admin / user) + password hash + lock state
  user_sessions  — single-device session (1 user = 1 row, login baru kick lama)
  login_fails    — per-username brute-force counter
  audit_log      — admin actions: add/delete/lock/unlock/change_password
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import string
import threading
import time
from datetime import datetime, timezone
from typing import Optional


# ─────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────
ROLE_SUPER = "super_admin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLES = (ROLE_SUPER, ROLE_ADMIN, ROLE_USER)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")

# Password policy: min 8, ≥1 upper, ≥1 digit, ≥1 symbol
_SYMBOL_RE = re.compile(r"[!@#$%^&*()_\-+={}\[\]|\\:;\"'<>,.?/~`]")

PBKDF2_ITERS = 200_000
PBKDF2_HASH = "sha256"

SESSION_TTL_SEC = 7 * 24 * 3600

# Per-user brute-force lockout
USER_FAIL_WINDOW = 600        # 10 min rolling window
USER_FAIL_THRESHOLD = 5       # 5 fails dalam window → lock
USER_LOCKOUT_SEC = 1800       # 30 min auto-lockout (separate dari admin-lock)


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


DEFAULT_INITIAL_PASSWORD = "Babanuki775."


def gen_password(length: int = 14) -> str:
    """Auto-generate password yang lulus policy."""
    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    symbol = secrets.choice("!@#$%^&*-_=+")
    rest_pool = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    rest = "".join(secrets.choice(rest_pool) for _ in range(max(0, length - 4)))
    chars = list(upper + lower + digit + symbol + rest)
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def password_meets_policy(pw: str) -> tuple[bool, str]:
    if len(pw) < 8:
        return False, "Password minimal 8 karakter."
    if not re.search(r"[A-Z]", pw):
        return False, "Password butuh minimal 1 huruf KAPITAL."
    if not re.search(r"\d", pw):
        return False, "Password butuh minimal 1 angka."
    if not _SYMBOL_RE.search(pw):
        return False, "Password butuh minimal 1 simbol (!@#$% dll)."
    return True, ""


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """Return (hex_hash, hex_salt)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(PBKDF2_HASH, password.encode("utf-8"), salt, PBKDF2_ITERS)
    return dk.hex(), salt.hex()


def verify_password(password: str, hex_hash: str, hex_salt: str) -> bool:
    try:
        salt = bytes.fromhex(hex_salt)
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac(PBKDF2_HASH, password.encode("utf-8"), salt, PBKDF2_ITERS)
    return hmac.compare_digest(dk.hex(), hex_hash)


# ─────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────
def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          password_hash TEXT NOT NULL,
          password_salt TEXT NOT NULL,
          role TEXT NOT NULL,
          must_change_password INTEGER NOT NULL DEFAULT 0,
          locked INTEGER NOT NULL DEFAULT 0,
          lock_reason TEXT,
          created_by TEXT,
          created_at TEXT NOT NULL,
          last_login_at TEXT,
          api_token TEXT
        );
        CREATE TABLE IF NOT EXISTS user_sessions (
          username TEXT PRIMARY KEY,
          session_id TEXT NOT NULL UNIQUE,
          ip TEXT,
          user_agent TEXT,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_user_sessions_sid ON user_sessions(session_id);
        CREATE TABLE IF NOT EXISTS login_fails (
          username TEXT PRIMARY KEY,
          fail_count INTEGER NOT NULL DEFAULT 0,
          first_fail_at TEXT,
          locked_until TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          target TEXT,
          reason TEXT,
          meta TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    """)


# ─────────────────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────────────────
def log_action(conn: sqlite3.Connection, actor: str, action: str,
               target: Optional[str] = None, reason: Optional[str] = None,
               meta: Optional[dict] = None) -> None:
    conn.execute(
        "INSERT INTO audit_log(ts, actor, action, target, reason, meta) VALUES(?,?,?,?,?,?)",
        (now_iso(), actor, action, target, reason, json.dumps(meta or {})),
    )


def list_audit(conn: sqlite3.Connection, limit: int = 200,
               action: Optional[str] = None, target: Optional[str] = None,
               user: Optional[str] = None) -> list[dict]:
    q = "SELECT * FROM audit_log WHERE 1=1"
    params: list = []
    if action:
        q += " AND action=?"
        params.append(action)
    if target:
        q += " AND target=?"
        params.append(target)
    if user:
        # "search by user": match semua aktivitas yang melibatkan user ini
        # (substring, case-insensitive) baik sebagai pelaku (actor) maupun target
        like = f"%{user}%"
        q += " AND (actor LIKE ? OR target LIKE ?)"
        params.append(like)
        params.append(like)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(min(int(limit), 1000))
    rows = conn.execute(q, params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["meta"] = json.loads(d.get("meta") or "{}")
        except Exception:
            d["meta"] = {}
        out.append(d)
    return out


# ─────────────────────────────────────────────────────────
# User CRUD
# ─────────────────────────────────────────────────────────
def get_user(conn: sqlite3.Connection, username: str) -> Optional[dict]:
    if not username:
        return None
    r = conn.execute("SELECT * FROM users WHERE username=?", (username.lower(),)).fetchone()
    return dict(r) if r else None


def list_users(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT username, role, must_change_password, locked, lock_reason, "
        "created_by, created_at, last_login_at FROM users ORDER BY "
        "CASE role WHEN 'super_admin' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, "
        "created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def create_user(conn: sqlite3.Connection, *, username: str, password: str,
                role: str, created_by: str,
                must_change: bool = True,
                bypass_policy: bool = False) -> dict:
    username = (username or "").strip().lower()
    if not USERNAME_RE.match(username):
        raise ValueError("Username 3-32 chars, hanya huruf/angka/underscore.")
    if role not in ROLES:
        raise ValueError(f"Role invalid. Pilih: {', '.join(ROLES)}")
    if get_user(conn, username):
        raise ValueError(f"Username '{username}' sudah dipakai.")
    if not bypass_policy:
        ok, msg = password_meets_policy(password)
        if not ok:
            raise ValueError(msg)
    h, s = hash_password(password)
    api_token = secrets.token_hex(32)
    conn.execute(
        "INSERT INTO users(username, password_hash, password_salt, role, "
        "must_change_password, locked, created_by, created_at, api_token) "
        "VALUES(?,?,?,?,?,0,?,?,?)",
        (username, h, s, role, 1 if must_change else 0, created_by, now_iso(), api_token),
    )
    log_action(conn, created_by, "create_user", target=username,
               meta={"role": role, "must_change": must_change})
    return get_user(conn, username) or {}


def delete_user(conn: sqlite3.Connection, *, username: str, actor: str, reason: str) -> None:
    u = get_user(conn, username)
    if not u:
        raise ValueError("User tidak ditemukan.")
    if u["role"] == ROLE_SUPER:
        raise ValueError("super_admin tidak boleh dihapus.")
    if not (reason or "").strip():
        raise ValueError("Alasan delete wajib diisi.")
    conn.execute("DELETE FROM users WHERE username=?", (username.lower(),))
    conn.execute("DELETE FROM user_sessions WHERE username=?", (username.lower(),))
    conn.execute("DELETE FROM login_fails WHERE username=?", (username.lower(),))
    log_action(conn, actor, "delete_user", target=username, reason=reason,
               meta={"role": u["role"]})


def set_lock(conn: sqlite3.Connection, *, username: str, locked: bool,
             actor: str, reason: str) -> None:
    u = get_user(conn, username)
    if not u:
        raise ValueError("User tidak ditemukan.")
    if u["role"] == ROLE_SUPER:
        raise ValueError("super_admin tidak boleh dilock.")
    if locked and not (reason or "").strip():
        raise ValueError("Alasan lock wajib diisi.")
    conn.execute(
        "UPDATE users SET locked=?, lock_reason=? WHERE username=?",
        (1 if locked else 0, reason if locked else None, username.lower()),
    )
    if locked:
        # kick session
        conn.execute("DELETE FROM user_sessions WHERE username=?", (username.lower(),))
    log_action(conn, actor, "lock_user" if locked else "unlock_user",
               target=username, reason=reason or None)


def change_password(conn: sqlite3.Connection, *, username: str, new_password: str,
                    actor: str, clear_must_change: bool = True) -> None:
    u = get_user(conn, username)
    if not u:
        raise ValueError("User tidak ditemukan.")
    ok, msg = password_meets_policy(new_password)
    if not ok:
        raise ValueError(msg)
    h, s = hash_password(new_password)
    conn.execute(
        "UPDATE users SET password_hash=?, password_salt=?, must_change_password=? "
        "WHERE username=?",
        (h, s, 0 if clear_must_change else 1, username.lower()),
    )
    log_action(conn, actor, "change_password", target=username)
    # invalidate semua session lain (force re-login dengan password baru)
    conn.execute("DELETE FROM user_sessions WHERE username=?", (username.lower(),))


# ─────────────────────────────────────────────────────────
# Sessions (single-device per user)
# ─────────────────────────────────────────────────────────
def create_session(conn: sqlite3.Connection, *, username: str,
                   ip: str = "", user_agent: str = "") -> str:
    sid = secrets.token_urlsafe(32)
    expires = datetime.fromtimestamp(time.time() + SESSION_TTL_SEC, tz=timezone.utc).isoformat()
    # 1 user = 1 row → INSERT OR REPLACE → otomatis kick session lama
    conn.execute(
        "INSERT OR REPLACE INTO user_sessions(username, session_id, ip, user_agent, "
        "created_at, expires_at) VALUES(?,?,?,?,?,?)",
        (username.lower(), sid, ip, user_agent[:256], now_iso(), expires),
    )
    conn.execute("UPDATE users SET last_login_at=? WHERE username=?",
                 (now_iso(), username.lower()))
    return sid


def get_session(conn: sqlite3.Connection, session_id: str) -> Optional[dict]:
    """Return {username, role, must_change_password, ...} kalau session valid."""
    if not session_id:
        return None
    r = conn.execute(
        "SELECT s.username, s.session_id, s.expires_at, u.role, "
        "u.must_change_password, u.locked, u.lock_reason "
        "FROM user_sessions s JOIN users u ON u.username=s.username "
        "WHERE s.session_id=?",
        (session_id,),
    ).fetchone()
    if not r:
        return None
    d = dict(r)
    # Cek expiry
    try:
        exp = datetime.fromisoformat(d["expires_at"])
        if exp.timestamp() < time.time():
            conn.execute("DELETE FROM user_sessions WHERE session_id=?", (session_id,))
            return None
    except Exception:
        pass
    if d["locked"]:
        return None
    return d


def revoke_session(conn: sqlite3.Connection, session_id: str) -> None:
    conn.execute("DELETE FROM user_sessions WHERE session_id=?", (session_id,))


def revoke_user_sessions(conn: sqlite3.Connection, username: str) -> None:
    conn.execute("DELETE FROM user_sessions WHERE username=?", (username.lower(),))


# ─────────────────────────────────────────────────────────
# Login + brute-force
# ─────────────────────────────────────────────────────────
def is_user_locked_now(conn: sqlite3.Connection, username: str) -> tuple[bool, int]:
    """Return (locked, retry_after_sec). Combines admin-lock dan auto-lockout."""
    u = get_user(conn, username)
    if not u:
        return False, 0
    if u["locked"]:
        return True, -1  # admin-locked, no auto-unlock
    r = conn.execute("SELECT locked_until FROM login_fails WHERE username=?",
                     (username.lower(),)).fetchone()
    if not r or not r["locked_until"]:
        return False, 0
    try:
        until = datetime.fromisoformat(r["locked_until"]).timestamp()
        retry = int(until - time.time())
        if retry > 0:
            return True, retry
    except Exception:
        pass
    return False, 0


def record_login_fail(conn: sqlite3.Connection, username: str) -> None:
    """Bump fail counter, lockout kalau lewat threshold."""
    username = (username or "").lower()
    if not username:
        return
    r = conn.execute("SELECT * FROM login_fails WHERE username=?", (username,)).fetchone()
    now = time.time()
    if r:
        first = 0
        try:
            first = datetime.fromisoformat(r["first_fail_at"]).timestamp() if r["first_fail_at"] else 0
        except Exception:
            first = 0
        if now - first > USER_FAIL_WINDOW:
            # window expired → reset
            conn.execute(
                "UPDATE login_fails SET fail_count=1, first_fail_at=?, locked_until=NULL "
                "WHERE username=?", (now_iso(), username),
            )
            return
        new_count = (r["fail_count"] or 0) + 1
        if new_count >= USER_FAIL_THRESHOLD:
            until = datetime.fromtimestamp(now + USER_LOCKOUT_SEC, tz=timezone.utc).isoformat()
            conn.execute(
                "UPDATE login_fails SET fail_count=?, locked_until=? WHERE username=?",
                (new_count, until, username),
            )
        else:
            conn.execute(
                "UPDATE login_fails SET fail_count=? WHERE username=?",
                (new_count, username),
            )
    else:
        conn.execute(
            "INSERT INTO login_fails(username, fail_count, first_fail_at) VALUES(?,1,?)",
            (username, now_iso()),
        )


def clear_login_fails(conn: sqlite3.Connection, username: str) -> None:
    conn.execute("DELETE FROM login_fails WHERE username=?", ((username or "").lower(),))


def authenticate(conn: sqlite3.Connection, *, username: str,
                 password: str) -> tuple[Optional[dict], str]:
    """Return (user_dict_atau_None, error_msg)."""
    username = (username or "").strip().lower()
    if not username or not password:
        return None, "Username dan password wajib diisi."
    locked, retry = is_user_locked_now(conn, username)
    if locked:
        if retry < 0:
            u = get_user(conn, username)
            reason = (u or {}).get("lock_reason") or "akun dikunci admin"
            return None, f"Akun terkunci: {reason}. Hubungi admin untuk unlock."
        return None, f"Akun terkunci sementara. Coba lagi dalam {retry} detik."
    u = get_user(conn, username)
    # Konstanta-time-ish: tetap hash dummy biar timing tidak bocor existence
    if not u:
        hash_password(password)  # dummy work
        record_login_fail(conn, username)
        return None, "Username atau password salah."
    if not verify_password(password, u["password_hash"], u["password_salt"]):
        record_login_fail(conn, username)
        return None, "Username atau password salah."
    clear_login_fails(conn, username)
    return u, ""


# ─────────────────────────────────────────────────────────
# Bootstrap super_admin
# ─────────────────────────────────────────────────────────
def ensure_super_admin(conn: sqlite3.Connection, *, username: str, password: str) -> None:
    """Buat super_admin awal kalau tabel users masih kosong."""
    n = conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    if n > 0:
        return
    h, s = hash_password(password)
    conn.execute(
        "INSERT INTO users(username, password_hash, password_salt, role, "
        "must_change_password, locked, created_by, created_at) "
        "VALUES(?,?,?,?,0,0,?,?)",
        (username.lower(), h, s, ROLE_SUPER, "system", now_iso()),
    )
    log_action(conn, "system", "bootstrap_super_admin", target=username)


# ─────────────────────────────────────────────────────────
# Authorization helpers
# ─────────────────────────────────────────────────────────
def can_create_role(actor_role: str, target_role: str) -> bool:
    if actor_role == ROLE_SUPER:
        return target_role in (ROLE_ADMIN, ROLE_USER)
    if actor_role == ROLE_ADMIN:
        return target_role == ROLE_USER
    return False


def can_manage_user(actor_role: str, target_role: str) -> bool:
    """Bisa delete/lock/unlock target user?"""
    if actor_role == ROLE_SUPER:
        return target_role != ROLE_SUPER
    # Admin tidak bisa manage user lain (hanya super yang bisa). Yang Mulia bilang
    # admin hanya bisa ADD user — delete/lock tidak. Ubah ke True kalau mau diizinkan.
    return False


def can_view_all_emails(role: str) -> bool:
    return role == ROLE_SUPER
