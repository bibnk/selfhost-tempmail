"""
Alias & domain management module untuk TempMail.

Schema:
  domains  — daftar domain yang server terima (super_admin yang add)
             mode: 'public' (semua user bisa pakai) | 'private' (hanya super_admin/whitelist)
  aliases  — claim alias unik per user (max 3 custom + unlimited random)
             alias = local@domain (lowercase, unique global)
"""
from __future__ import annotations

import re
import secrets
import sqlite3
import string
from datetime import datetime, timezone
from typing import Optional


# ─────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────
LOCAL_RE = re.compile(r"^[a-z0-9._\-]{1,64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$")

CUSTOM_ALIAS_LIMIT = 3        # max custom alias per user
RANDOM_ALIAS_LEN = 10         # length untuk random generate
RANDOM_ALIAS_CHARS = string.ascii_lowercase + string.digits

DOMAIN_MODE_PUBLIC = "public"
DOMAIN_MODE_PRIVATE = "private"
DOMAIN_MODES = (DOMAIN_MODE_PUBLIC, DOMAIN_MODE_PRIVATE)

EMAIL_RETENTION_HOURS = 48    # auto-delete setelah 48 jam


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────
def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(f"""
        CREATE TABLE IF NOT EXISTS domains (
          domain TEXT PRIMARY KEY,
          mode TEXT NOT NULL DEFAULT '{DOMAIN_MODE_PUBLIC}',
          owner TEXT,
          added_by TEXT NOT NULL,
          added_at TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS aliases (
          alias TEXT PRIMARY KEY,        -- nama@domain lowercase
          local TEXT NOT NULL,
          domain TEXT NOT NULL,
          owner TEXT NOT NULL,           -- username
          kind TEXT NOT NULL DEFAULT 'custom',  -- 'custom' | 'random'
          created_at TEXT NOT NULL,
          FOREIGN KEY(domain) REFERENCES domains(domain)
        );
        CREATE INDEX IF NOT EXISTS idx_aliases_owner ON aliases(owner, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_aliases_domain ON aliases(domain);
    """)


# ─────────────────────────────────────────────────────────
# Domain mgmt (super_admin only)
# ─────────────────────────────────────────────────────────
def add_domain(conn: sqlite3.Connection, *, domain: str, mode: str,
               actor: str, owner: Optional[str] = None) -> dict:
    domain = (domain or "").strip().lower()
    if not DOMAIN_RE.match(domain):
        raise ValueError("Format domain invalid (contoh: bibnk.cloud)")
    if mode not in DOMAIN_MODES:
        raise ValueError(f"Mode harus salah satu: {', '.join(DOMAIN_MODES)}")
    if mode == DOMAIN_MODE_PRIVATE and not owner:
        owner = actor  # default private domain owned by super_admin yang add
    existing = conn.execute("SELECT 1 FROM domains WHERE domain=?", (domain,)).fetchone()
    if existing:
        raise ValueError(f"Domain '{domain}' sudah terdaftar.")
    conn.execute(
        "INSERT INTO domains(domain, mode, owner, added_by, added_at, enabled) "
        "VALUES(?,?,?,?,?,1)",
        (domain, mode, owner, actor, now_iso()),
    )
    return get_domain(conn, domain) or {}


def update_domain(conn: sqlite3.Connection, *, domain: str,
                  mode: Optional[str] = None,
                  enabled: Optional[bool] = None,
                  owner: Optional[str] = None) -> None:
    sets, params = [], []
    if mode is not None:
        if mode not in DOMAIN_MODES:
            raise ValueError("Mode invalid.")
        sets.append("mode=?")
        params.append(mode)
    if enabled is not None:
        sets.append("enabled=?")
        params.append(1 if enabled else 0)
    if owner is not None:
        sets.append("owner=?")
        params.append(owner.lower() or None)
    if not sets:
        return
    params.append(domain.lower())
    conn.execute(f"UPDATE domains SET {', '.join(sets)} WHERE domain=?", params)


def delete_domain(conn: sqlite3.Connection, *, domain: str) -> None:
    domain = domain.lower()
    n = conn.execute("SELECT COUNT(*) n FROM aliases WHERE domain=?", (domain,)).fetchone()["n"]
    if n > 0:
        raise ValueError(f"Domain masih dipakai {n} alias. Hapus alias-nya dulu.")
    conn.execute("DELETE FROM domains WHERE domain=?", (domain,))


def get_domain(conn: sqlite3.Connection, domain: str) -> Optional[dict]:
    r = conn.execute("SELECT * FROM domains WHERE domain=?", (domain.lower(),)).fetchone()
    return dict(r) if r else None


def list_domains(conn: sqlite3.Connection, *, only_enabled: bool = False) -> list[dict]:
    q = "SELECT * FROM domains"
    if only_enabled:
        q += " WHERE enabled=1"
    q += " ORDER BY added_at ASC"
    return [dict(r) for r in conn.execute(q).fetchall()]


def list_visible_domains(conn: sqlite3.Connection, *, role: str,
                         username: str) -> list[dict]:
    """Yang user bisa pilih saat claim alias."""
    rows = list_domains(conn, only_enabled=True)
    out = []
    for d in rows:
        if d["mode"] == DOMAIN_MODE_PUBLIC:
            out.append(d)
        elif d["mode"] == DOMAIN_MODE_PRIVATE:
            # Private: hanya super_admin atau owner-nya yang lihat
            if role == "super_admin" or (d.get("owner") or "").lower() == username.lower():
                out.append(d)
    return out


def domain_is_accepted(conn: sqlite3.Connection, domain: str) -> bool:
    """SMTP check — apakah server harus terima email ke domain ini."""
    r = conn.execute(
        "SELECT 1 FROM domains WHERE domain=? AND enabled=1",
        (domain.lower(),),
    ).fetchone()
    return r is not None


# ─────────────────────────────────────────────────────────
# Alias claim
# ─────────────────────────────────────────────────────────
def _validate_local(local: str) -> str:
    local = (local or "").strip().lower()
    if not LOCAL_RE.match(local):
        raise ValueError("Local part invalid (huruf/angka/dot/underscore/dash, max 64).")
    return local


def _user_can_use_domain(conn: sqlite3.Connection, *, role: str, username: str,
                        domain: str) -> bool:
    d = get_domain(conn, domain)
    if not d or not d["enabled"]:
        return False
    if d["mode"] == DOMAIN_MODE_PUBLIC:
        return True
    if d["mode"] == DOMAIN_MODE_PRIVATE:
        if role == "super_admin":
            return True
        if (d.get("owner") or "").lower() == username.lower():
            return True
    return False


def claim_custom_alias(conn: sqlite3.Connection, *, owner: str, role: str,
                       local: str, domain: str) -> dict:
    local = _validate_local(local)
    domain = (domain or "").strip().lower()
    if not _user_can_use_domain(conn, role=role, username=owner, domain=domain):
        raise ValueError("Domain tidak tersedia / tidak punya akses.")
    # cek limit custom
    custom_count = conn.execute(
        "SELECT COUNT(*) n FROM aliases WHERE owner=? AND kind='custom'",
        (owner.lower(),),
    ).fetchone()["n"]
    if custom_count >= CUSTOM_ALIAS_LIMIT:
        raise ValueError(f"Custom alias sudah maks {CUSTOM_ALIAS_LIMIT}. Hapus salah satu dulu.")
    return _insert_alias(conn, owner=owner, local=local, domain=domain, kind="custom")


def claim_random_alias(conn: sqlite3.Connection, *, owner: str, role: str,
                       domain: str) -> dict:
    domain = (domain or "").strip().lower()
    if not _user_can_use_domain(conn, role=role, username=owner, domain=domain):
        raise ValueError("Domain tidak tersedia / tidak punya akses.")
    # generate sampai unique
    for _ in range(50):
        local = "".join(secrets.choice(RANDOM_ALIAS_CHARS) for _ in range(RANDOM_ALIAS_LEN))
        full = f"{local}@{domain}"
        if not conn.execute("SELECT 1 FROM aliases WHERE alias=?", (full,)).fetchone():
            return _insert_alias(conn, owner=owner, local=local, domain=domain, kind="random")
    raise RuntimeError("Gagal generate random alias unique. Coba lagi.")


def _insert_alias(conn: sqlite3.Connection, *, owner: str, local: str, domain: str,
                  kind: str) -> dict:
    full = f"{local}@{domain}"
    if conn.execute("SELECT 1 FROM aliases WHERE alias=?", (full,)).fetchone():
        raise ValueError(f"Alias '{full}' sudah dipakai user lain.")
    conn.execute(
        "INSERT INTO aliases(alias, local, domain, owner, kind, created_at) "
        "VALUES(?,?,?,?,?,?)",
        (full, local, domain, owner.lower(), kind, now_iso()),
    )
    return {
        "alias": full, "local": local, "domain": domain,
        "owner": owner.lower(), "kind": kind, "created_at": now_iso(),
    }


def delete_alias(conn: sqlite3.Connection, *, alias: str, requester: str,
                 role: str) -> None:
    a = conn.execute("SELECT * FROM aliases WHERE alias=?", (alias.lower(),)).fetchone()
    if not a:
        raise ValueError("Alias tidak ditemukan.")
    if role != "super_admin" and (a["owner"] or "").lower() != requester.lower():
        raise ValueError("Bukan alias kamu.")
    conn.execute("DELETE FROM aliases WHERE alias=?", (alias.lower(),))


def list_aliases(conn: sqlite3.Connection, *, owner: Optional[str] = None) -> list[dict]:
    if owner:
        rows = conn.execute(
            "SELECT * FROM aliases WHERE owner=? ORDER BY kind ASC, created_at DESC",
            (owner.lower(),),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM aliases ORDER BY created_at DESC LIMIT 1000",
        ).fetchall()
    return [dict(r) for r in rows]


def get_alias_owner(conn: sqlite3.Connection, alias: str) -> Optional[str]:
    r = conn.execute("SELECT owner FROM aliases WHERE alias=?",
                     (alias.lower(),)).fetchone()
    return r["owner"] if r else None


# ─────────────────────────────────────────────────────────
# Authorization untuk lihat email
# ─────────────────────────────────────────────────────────
def user_can_access_email(conn: sqlite3.Connection, *, role: str, username: str,
                          rcpt_to: str) -> bool:
    if role == "super_admin":
        return True
    owner = get_alias_owner(conn, rcpt_to)
    if owner is None:
        # alias yang belum di-claim → only super_admin bisa lihat
        return False
    return owner.lower() == username.lower()


# ─────────────────────────────────────────────────────────
# Auto-cleanup: hapus email > 48 jam
# ─────────────────────────────────────────────────────────
def cleanup_old_messages(conn: sqlite3.Connection, *, hours: int = EMAIL_RETENTION_HOURS) -> int:
    """Return jumlah message yang dihapus."""
    cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
    cutoff_iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
    cur = conn.execute(
        "DELETE FROM messages WHERE received_at < ?",
        (cutoff_iso,),
    )
    return cur.rowcount or 0
