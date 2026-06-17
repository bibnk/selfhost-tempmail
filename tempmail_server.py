#!/usr/bin/env python3
from __future__ import annotations

import argparse
import email
import email.header
import html
import json
import os
import random
import re
import signal
import sqlite3
import string
import sys
import threading
import time
from datetime import datetime, timezone
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, unquote

from aiosmtpd.controller import Controller
import dns.resolver
import dns.exception

import auth_users as au
import aliases_domains as ad

BASE = Path(__file__).resolve().parent


def load_env(path: Path = BASE / ".env"):
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()

DOMAIN = os.getenv("DOMAIN", "example.com").lower().strip()
MAIL_HOST = os.getenv("MAIL_HOST", "0.0.0.0")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8787"))
API_TOKEN = os.getenv("API_TOKEN", "")
ACCESS_CODE = os.getenv("ACCESS_CODE", "")
DB_PATH = os.getenv("DB_PATH", str(BASE / "tempmail.sqlite3"))
MAX_MESSAGE_BYTES = int(os.getenv("MAX_MESSAGE_BYTES", "10485760"))

# Bootstrap super_admin awal — username + password.
SUPER_ADMIN_USER = os.getenv("SUPER_ADMIN_USER", "admin").strip().lower()
SUPER_ADMIN_PASS = os.getenv("SUPER_ADMIN_PASS", "6715")
EMAIL_RETENTION_HOURS = int(os.getenv("EMAIL_RETENTION_HOURS", "48"))
SERVER_IP = os.getenv("SERVER_IP", "")

# In-memory session store: {session_id: expires_at_ts}
SESSIONS = {}
SESSION_TTL = 7 * 24 * 3600  # 7 days
SESSION_LOCK = threading.Lock()

# Rate limit untuk login attempts: {ip: [list_of_failed_timestamps]}
LOGIN_FAILS = {}
LOGIN_FAIL_LOCK = threading.Lock()
LOGIN_MAX_FAILS = 5     # max 5 percobaan
LOGIN_FAIL_WINDOW = 300 # dalam 5 menit
LOGIN_LOCKOUT = 900     # lockout 15 menit setelah lewat batas

def _login_check_rate(ip):
    """Return (allowed, retry_after_sec). False = locked out."""
    now = time.time()
    with LOGIN_FAIL_LOCK:
        fails = [t for t in LOGIN_FAILS.get(ip, []) if now - t < LOGIN_FAIL_WINDOW]
        LOGIN_FAILS[ip] = fails
        if len(fails) >= LOGIN_MAX_FAILS:
            oldest = min(fails)
            retry = int(LOGIN_LOCKOUT - (now - oldest))
            if retry > 0:
                return False, retry
        return True, 0

def _login_record_fail(ip):
    with LOGIN_FAIL_LOCK:
        LOGIN_FAILS.setdefault(ip, []).append(time.time())

def _login_clear(ip):
    with LOGIN_FAIL_LOCK:
        LOGIN_FAILS.pop(ip, None)

def _new_session():
    import secrets as _s
    sid = _s.token_urlsafe(24)
    with SESSION_LOCK:
        SESSIONS[sid] = time.time() + SESSION_TTL
    return sid

def _session_valid(sid):
    if not sid:
        return False
    with SESSION_LOCK:
        exp = SESSIONS.get(sid)
        if not exp:
            return False
        if time.time() > exp:
            SESSIONS.pop(sid, None)
            return False
        return True

def _session_revoke(sid):
    with SESSION_LOCK:
        SESSIONS.pop(sid, None)
LOCAL_RE = re.compile(r"^[a-zA-Z0-9._+-]{1,64}$")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _dns_resolve_a(target):
    """Resolve A record of a hostname, return list of IPs or empty list."""
    try:
        answers = dns.resolver.resolve(target, "A", lifetime=5)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []


def verify_domain_dns(domain, server_ip):
    """Verify DNS records for a domain match the expected server_ip.

    Returns dict:
      ok=True  → {"ok": True, "mx": [ips...], "a": [ips...], "checks": [...]}
      ok=False → {"ok": False, "errors": [...], "fixes": [...],
                  "mx": [...], "a": [...], "checks": [...], "steps": [...]}

    "checks" = baris tabel untuk ditampilkan ke user awam, tiap item:
        {"label": str, "ok": bool, "value": str}
    "steps"  = langkah perbaikan bahasa awam (list of str)
    """
    errors = []
    fixes = []
    steps = []
    mx_ips = []
    a_ips = []
    domain_found = True          # apakah domain ada di DNS sama sekali
    mx_found = False             # apakah ada MX record
    mx_points_here = False       # apakah MX mengarah ke server ini

    # ── Check MX records ──
    try:
        mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_hosts = [str(r.exchange).rstrip(".") for r in mx_records]
        for mx_host in mx_hosts:
            ips = _dns_resolve_a(mx_host)
            mx_ips.extend(ips)
        if not mx_ips:
            errors.append("MX record tidak ditemukan")
            fixes.append(
                f"Buat record MX di DNS provider: {domain} → mail.{domain} (priority 10)"
            )
        else:
            mx_found = True
            if server_ip in mx_ips:
                mx_points_here = True
            else:
                errors.append(
                    f"MX record tidak mengarah ke server ini (expected {server_ip})"
                )
                fixes.append(
                    f"Pastikan MX record {domain} mengarah ke mail.{domain} "
                    f"yang resolves ke {server_ip}"
                )
    except dns.resolver.NoAnswer:
        errors.append("MX record tidak ditemukan")
        fixes.append(
            f"Buat record MX di DNS provider: {domain} → mail.{domain} (priority 10)"
        )
    except dns.resolver.NXDOMAIN:
        domain_found = False
        errors.append(f"Domain {domain} tidak ditemukan di DNS")
        fixes.append("Pastikan domain sudah terdaftar dan nameserver sudah propage")
    except dns.exception.Timeout:
        errors.append("DNS query timeout — coba lagi dalam beberapa saat")
        fixes.append("Periksa koneksi DNS server")

    # ── Check A record (INFO ONLY — tidak nge-block) ──
    # Domain di Cloudflare-proxied selalu resolve ke IP Cloudflare, bukan
    # IP server. Mail routing cuma butuh MX, jadi A record di sini hanya
    # dikumpulkan untuk ditampilkan, tidak dipakai sebagai syarat lolos.
    try:
        a_answers = dns.resolver.resolve(domain, "A", lifetime=5)
        a_ips = [str(r) for r in a_answers]
    except Exception:
        a_ips = []

    # ── Susun "checks" (baris tabel, bahasa awam) ──
    checks = [
        {
            "label": "Domain aktif di internet",
            "ok": domain_found,
            "value": "Ya, domain terdaftar" if domain_found
                     else "Belum — domain tidak ditemukan",
        },
        {
            "label": "Pengaturan email (MX) ada",
            "ok": mx_found,
            "value": (", ".join(sorted(set(mx_ips))) if mx_ips else "Belum diatur"),
        },
        {
            "label": "Email diarahkan ke server ini",
            "ok": mx_points_here,
            "value": ("Sudah benar" if mx_points_here
                      else f"Belum mengarah ke {server_ip}"),
        },
    ]

    # ── Susun "steps" (langkah perbaikan bahasa awam) ──
    if not domain_found:
        steps = [
            "Pastikan domain sudah kamu beli dan aktif.",
            "Cek nameserver domain sudah diarahkan ke Cloudflare.",
            "Tunggu 5–30 menit lalu coba lagi.",
        ]
    elif not mx_found:
        steps = [
            "Buka Cloudflare → DNS untuk domain ini.",
            f"Tambah record A: Name = mail, Konten = {server_ip}, Proxy = DNS only (abu-abu).",
            f"Tambah record MX: Name = @, Mail server = mail.{domain}, Priority = 10.",
            "Simpan, tunggu beberapa menit, lalu coba tambah domain lagi.",
        ]
    elif not mx_points_here:
        steps = [
            "Buka Cloudflare → DNS untuk domain ini.",
            f"Cek record A bernama 'mail' kontennya = {server_ip}.",
            "Pastikan record 'mail' itu di-set Proxy = DNS only (awan abu-abu, bukan oranye).",
            "Simpan, tunggu beberapa menit, lalu coba lagi.",
        ]

    if errors:
        # Dedupe sambil jaga urutan — cek MX & A bisa menghasilkan pesan
        # identik (mis. NXDOMAIN/timeout muncul di dua blok)
        def _dedupe(seq):
            seen = set()
            out = []
            for x in seq:
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            return out
        return {"ok": False, "errors": _dedupe(errors), "fixes": _dedupe(fixes),
                "mx": mx_ips, "a": a_ips, "checks": checks, "steps": steps}
    return {"ok": True, "mx": mx_ips, "a": a_ips, "checks": checks, "steps": []}


def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db():
    with db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS addresses (
              address TEXT PRIMARY KEY,
              label TEXT,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              mail_from TEXT,
              rcpt_to TEXT NOT NULL,
              subject TEXT,
              from_header TEXT,
              to_header TEXT,
              date_header TEXT,
              received_at TEXT NOT NULL,
              raw BLOB NOT NULL,
              text_body TEXT,
              html_body TEXT,
              size INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_rcpt_id ON messages(rcpt_to, id DESC);
            CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at DESC);
            """
        )
        # Schema baru: users, sessions, audit, aliases, domains
        au.init_schema(c)
        ad.init_schema(c)
        # Bootstrap super_admin pertama kali
        au.ensure_super_admin(c, username=SUPER_ADMIN_USER, password=SUPER_ADMIN_PASS)
        # Auto-register domain default dari .env kalau belum ada
        if DOMAIN and not ad.get_domain(c, DOMAIN):
            try:
                ad.add_domain(c, domain=DOMAIN, mode=ad.DOMAIN_MODE_PUBLIC,
                              actor="system")
                au.log_action(c, "system", "add_domain", target=DOMAIN,
                              meta={"mode": ad.DOMAIN_MODE_PUBLIC, "source": ".env"})
            except Exception:
                pass


def decode_header_value(v):
    if not v:
        return ""
    out = ""
    for part, enc in email.header.decode_header(v):
        if isinstance(part, bytes):
            out += part.decode(enc or "utf-8", "replace")
        else:
            out += part
    return out


def extract_bodies(msg):
    text_body = ""
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disp:
                continue
            ctype = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            body = payload.decode(charset, "replace")
            if ctype == "text/plain" and not text_body:
                text_body = body
            elif ctype == "text/html" and not html_body:
                html_body = body
    else:
        payload = msg.get_payload(decode=True) or b""
        body = payload.decode(msg.get_content_charset() or "utf-8", "replace")
        if msg.get_content_type() == "text/html":
            html_body = body
        else:
            text_body = body
    return text_body[:200000], html_body[:200000]


def parse_message(raw: bytes):
    msg = email.message_from_bytes(raw, policy=email_policy)
    text_body, html_body = extract_bodies(msg)
    return {
        "subject": decode_header_value(msg.get("Subject", "")),
        "from_header": decode_header_value(msg.get("From", "")),
        "to_header": decode_header_value(msg.get("To", "")),
        "date_header": decode_header_value(msg.get("Date", "")),
        "text_body": text_body,
        "html_body": html_body,
    }


def normalize_addr(addr: str) -> str:
    addr = (addr or "").strip().lower()
    if addr.startswith("<") and addr.endswith(">"):
        addr = addr[1:-1]
    return addr


def is_local_domain(addr: str) -> bool:
    addr = normalize_addr(addr)
    if "@" not in addr:
        return False
    dom = addr.split("@", 1)[1]
    # Cek dynamic — semua domain yang terdaftar di tabel domains (enabled)
    try:
        with db() as c:
            return ad.domain_is_accepted(c, dom)
    except Exception:
        return dom == DOMAIN


def _clean_preview(text_body, html_body, max_len=500):
    """Generate clean preview text, stripping CSS, scripts, HTML tags, and entities."""
    src = text_body or html_body or ""
    if not src:
        return ""
    # Strip <style>, <script>, <head>, comments
    s = re.sub(r"<style[^>]*>[\s\S]*?</style>", " ", src, flags=re.I)
    s = re.sub(r"<script[^>]*>[\s\S]*?</script>", " ", s, flags=re.I)
    s = re.sub(r"<head[^>]*>[\s\S]*?</head>", " ", s, flags=re.I)
    s = re.sub(r"<!--[\s\S]*?-->", " ", s)
    # Strip CSS @-rules (e.g., @media{...}, @font-face{...}, @keyframes{...})
    s = re.sub(r"@(?:media|font-face|keyframes|supports|import|charset|page)[^{]*\{(?:[^{}]|\{[^{}]*\})*\}", " ", s, flags=re.I)
    # Strip raw CSS rules: .selector { props } / #id { props } / tag { props }
    s = re.sub(r"[a-zA-Z_\-#\.\*\[\]:>+~\s,\"'=]{1,80}\{[^{}]*\}", " ", s)
    # Strip remaining HTML tags
    s = re.sub(r"<[^>]+>", " ", s)
    # Decode common entities
    s = (s.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<")
         .replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'"))
    # Collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()
    return s[:max_len]


def row_to_summary(r):
    return {
        "id": r["id"],
        "mail_from": r["mail_from"],
        "rcpt_to": r["rcpt_to"],
        "subject": r["subject"] or "",
        "from": r["from_header"] or r["mail_from"] or "",
        "to": r["to_header"] or r["rcpt_to"],
        "date": r["date_header"] or "",
        "received_at": r["received_at"],
        "size": r["size"],
        "preview": _clean_preview(r["text_body"], r["html_body"], 500),
    }


def row_to_full(r):
    d = row_to_summary(r)
    d.update({
        "text_body": r["text_body"] or "",
        "html_body": r["html_body"] or "",
        "raw": r["raw"].decode("utf-8", "replace"),
    })
    return d


class TempMailSMTP:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        address = normalize_addr(address)
        if not is_local_domain(address):
            return "550 not local domain"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        raw = envelope.content or b""
        if len(raw) > MAX_MESSAGE_BYTES:
            return "552 message too large"
        parsed = parse_message(raw)
        received = now_iso()
        mail_from = normalize_addr(envelope.mail_from or "")
        with db() as c:
            for rcpt in envelope.rcpt_tos:
                c.execute(
                    """INSERT INTO messages
                    (mail_from, rcpt_to, subject, from_header, to_header, date_header, received_at, raw, text_body, html_body, size)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        mail_from,
                        normalize_addr(rcpt),
                        parsed["subject"],
                        parsed["from_header"],
                        parsed["to_header"],
                        parsed["date_header"],
                        received,
                        raw,
                        parsed["text_body"],
                        parsed["html_body"],
                        len(raw),
                    ),
                )
        print(f"[{received}] received from={mail_from} to={','.join(envelope.rcpt_tos)} size={len(raw)}", flush=True)
        return "250 Message accepted"


def json_bytes(obj):
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Veil · Dashboard</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2032%2032%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22g%22%20x1%3D%220%22%20y1%3D%220%22%20x2%3D%221%22%20y2%3D%221%22%3E%3Cstop%20offset%3D%220%22%20stop-color%3D%22%236d6af6%22/%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%238b5cf6%22/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect%20width%3D%2232%22%20height%3D%2232%22%20rx%3D%228%22%20fill%3D%22url%28%23g%29%22/%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22%23fff%22%20stroke-width%3D%222.2%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Crect%20x%3D%227%22%20y%3D%229%22%20width%3D%2218%22%20height%3D%2214%22%20rx%3D%222.5%22/%3E%3Cpath%20d%3D%22m7.5%2011%208.5%206%208.5-6%22/%3E%3C/g%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  /* unified SaaS dark palette */
  --bg-0:#0a0f1a;
  --bg-1:#111827;
  --bg-2:#1f2937;
  --bg-3:#374151;
  --line:rgba(255,255,255,.06);
  --line-2:rgba(255,255,255,.10);
  --line-hot:rgba(99,102,241,.30);
  --txt:#f1f5f9;
  --txt-2:#94a3b8;
  --txt-3:#64748b;
  --txt-4:#475569;
  --accent:#6366f1;
  --accent-dim:rgba(99,102,241,.12);
  --ok:#22c55e;
  --warn:#f59e0b;
  --bad:#ef4444;
  --border:rgba(255,255,255,.06);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:var(--bg-0);
  color:var(--txt);
  font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  font-feature-settings:"cv02","cv03","cv04","cv11";
  letter-spacing:-.011em;
  -webkit-font-smoothing:antialiased;
  overflow-x:hidden;
  position:relative;
}
/* Aurora blobs — fixed full-viewport, blurred for glass to read against */
body::before{display:none!important}
body::after{display:none!important}
button,input{font:inherit;color:inherit;outline:0}
button{cursor:pointer;border:0;background:none}
a{color:inherit;text-decoration:none}

/* === LAYOUT === */
.app{position:relative;z-index:1;min-height:100vh;display:grid;grid-template-columns:240px 1fr;gap:0;padding:0}
.side{
  position:sticky;top:0;height:100vh;display:flex;flex-direction:column;
  padding:24px 16px;
  border-right:1px solid var(--border);
  background:var(--bg-1);
  overflow-y:auto;overflow-x:hidden;
  scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.08) transparent;
}
.side::-webkit-scrollbar{width:6px}
.side::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:99px}
.side:before{display:none!important}
.side:after{display:none!important}
.logo{display:flex;align-items:center;gap:11px;margin-bottom:24px;padding:0 6px;position:relative;z-index:1}
.mark{
  width:38px;height:38px;border-radius:10px;
  background:var(--accent);
  display:grid;place-items:center;color:#fff;font-weight:700;font-size:14px;
  box-shadow:none;
  flex-shrink:0;
}
.brand h1{font-size:15px;font-weight:700;letter-spacing:-.3px}
.brand p{font-size:11px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;margin-top:1px}

.nav{display:flex;flex-direction:column;gap:2px;position:relative;z-index:1}
.navSep{height:1px;background:var(--border);margin:12px 0 8px}
.navGroup{display:flex;flex-direction:column;gap:2px;margin:0 0 8px;padding:8px;border:1px solid var(--border);border-radius:8px;background:var(--bg-0)}
.navGroupLabel{font-size:10px;font-weight:600;color:var(--txt-3);letter-spacing:.06em;padding:0 4px 6px;text-transform:uppercase}
.nav a{
  display:flex;align-items:center;gap:11px;
  padding:9px 12px;border-radius:8px;
  font-size:13px;font-weight:500;color:var(--txt-2);
  border:1px solid transparent;
  transition:all .2s cubic-bezier(.4,0,.2,1);
  position:relative;
}
.nav a span:first-child{font-size:15px;width:18px;text-align:center;opacity:.7}
.nav a svg{flex-shrink:0;opacity:.65;transition:opacity .2s ease}
.nav a:hover{color:var(--txt);background:rgba(255,255,255,.04);border-color:var(--border)}
.nav a:hover span:first-child{opacity:1}
.nav a:hover svg{opacity:1}
.nav a.active{
  background:var(--accent-dim);
  border-color:rgba(99,102,241,.25);
  color:var(--txt);
  box-shadow:none;
}
.nav a.active span:first-child{opacity:1}
.nav a.active svg{opacity:1}
.nav a.active:before{
  content:"";position:absolute;left:-13px;top:50%;transform:translateY(-50%);
  width:3px;height:20px;border-radius:0 3px 3px 0;
  background:var(--accent);
  box-shadow:none;
}
.nav a.logout{margin-top:auto;color:#f87171}
.nav a.logout:hover{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2)}
.nav-spacer{flex:1}

.sidefoot{padding:14px 6px 0;border-top:1px solid var(--border);margin-top:14px;position:relative;z-index:1}
.statusBar{display:flex;align-items:center;gap:8px;padding:9px 11px;border-radius:8px;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.15)}
.statusDot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:none;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.statusBar span{font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--ok)}
.sideMeta{display:grid;gap:6px;margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:11px}
.sideMeta>div{display:flex;justify-content:space-between;padding:7px 11px;border-radius:8px;background:var(--bg-0);border:1px solid var(--border)}
.sideMeta span{color:var(--txt-3);text-transform:uppercase;letter-spacing:.08em;font-size:10px}
.sideMeta b{color:var(--txt);font-weight:500}

/* === USER BADGE (header right) === */
.userBadge{display:flex;align-items:center;gap:11px;padding:9px 14px 9px 9px;border-radius:10px;border:1px solid var(--border);background:var(--bg-2);margin-right:8px}
.ub-avatar{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:var(--accent);color:#fff;font-weight:700;font-size:14px;text-transform:uppercase}
.ub-info{display:flex;flex-direction:column;gap:2px}
.ub-name{font-size:12.5px;font-weight:600;color:var(--txt);font-family:'JetBrains Mono',monospace}
.ub-role{font-size:9.5px;color:var(--accent);text-transform:uppercase;letter-spacing:.1em;font-weight:600}

/* === PASSWORD VALIDATOR === */
.pwRules{list-style:none;padding:10px 0 0;margin:0;display:grid;gap:5px}
.pwRules li{font-size:12px;padding:6px 10px;border-radius:7px;background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.15);color:#fca5a5;font-family:'JetBrains Mono',monospace;transition:all .15s ease;position:relative;padding-left:28px}
.pwRules li:before{content:"✗";position:absolute;left:10px;top:50%;transform:translateY(-50%);font-weight:700;color:var(--bad)}
.pwRules li.ok{background:rgba(34,197,94,.06);border-color:rgba(34,197,94,.20);color:var(--ok)}
.pwRules li.ok:before{content:"✓";color:var(--ok)}
.pwStrength{margin-top:18px;height:8px;border-radius:99px;background:rgba(255,255,255,.05);overflow:hidden;border:1px solid var(--line2);position:relative}
.pwStrength:before{content:"strength";position:absolute;top:-15px;left:0;font-size:9.5px;color:var(--txt-3);letter-spacing:.12em;text-transform:uppercase;font-family:'JetBrains Mono',monospace;font-weight:600}
.pwStrength .bar{height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,var(--bad),var(--warn),var(--ok));transition:width .25s ease}
.actorTag{display:inline-block;padding:2px 9px;margin-left:6px;border-radius:99px;font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:700;letter-spacing:.04em;background:var(--accent);color:#fff;text-transform:uppercase}

/* === MAIN === */
.main{padding:28px 32px 40px;max-width:1400px;width:100%;overflow-x:hidden}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;margin-bottom:26px;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:20px;margin-bottom:26px}
.hero h2{
  font-size:28px;font-weight:600;letter-spacing:-.6px;line-height:1.1;
  color:var(--txt);
}
.hero p{margin-top:6px;color:var(--txt-2);font-size:14px;max-width:600px}
.hero p b{color:var(--accent);font-family:'JetBrains Mono',monospace;font-weight:500;font-size:13px;background:var(--accent-dim);padding:2px 7px;border-radius:5px}

.actions{display:flex;gap:8px;flex-wrap:wrap}
.btn{
  display:inline-flex;align-items:center;gap:7px;
  padding:8px 14px;border-radius:8px;
  font-size:13px;font-weight:500;
  background:var(--bg-2);
  border:1px solid var(--border);
  color:var(--txt);
  transition:all .15s ease;
}
.btn:hover{background:var(--bg-3);border-color:var(--line-2)}
.btn:active{transform:translateY(0)}
.btn.primary{
  background:var(--accent);
  border-color:transparent;color:#fff;
}
.btn.primary:hover{background:#4f46e5}
.btn.green{
  background:var(--ok);
  border-color:transparent;color:#fff;
}
.btn.green:hover{background:#16a34a}

/* === STATS GRID === */
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px}
.stat{
  position:relative;overflow:hidden;
  padding:18px 18px 16px;border-radius:10px;
  background:var(--bg-1);
  border:1px solid var(--border);
  transition:all .2s ease;
}
.stat:hover{border-color:var(--line-2)}
.stat:after{display:none}
.stat .k{font-size:11px;font-weight:600;color:var(--txt-3);text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px}
.stat .v{font-size:22px;font-weight:700;letter-spacing:-.5px;font-family:'JetBrains Mono',monospace;color:var(--txt)}
.stat .s{font-size:11px;color:var(--txt-3);margin-top:4px}

/* === CARDS === */
/* Glass select for inbox alias filter */
.aliasFilter{
  background:var(--bg-2);
  color:var(--txt);border:1px solid var(--line-2);
  padding:8px 32px 8px 14px;border-radius:8px;
  font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;
  cursor:pointer;
  appearance:none;-webkit-appearance:none;
  background-image:
    linear-gradient(45deg,transparent 50%,var(--txt-3) 50%),
    linear-gradient(135deg,var(--txt-3) 50%,transparent 50%);
  background-position:0 0,calc(100% - 16px) 50%,calc(100% - 11px) 50%;
  background-size:100% 100%,5px 5px,5px 5px;
  background-repeat:no-repeat;
  transition:all .15s ease;
}
.aliasFilter:hover{border-color:var(--line-2)}
.aliasFilter:focus{
  outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-dim);
}
.aliasFilter option{background:var(--bg-0);color:var(--txt);padding:8px;font-family:'JetBrains Mono',monospace}

/* Search input for audit user filter */
.auditSearch{
  background:var(--bg-2);
  color:var(--txt);border:1px solid var(--line-2);
  padding:8px 12px 8px 32px;border-radius:8px;
  font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;
  width:170px;transition:all .15s ease;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%23808493' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cline x1='21' y1='21' x2='16.65' y2='16.65'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:11px 50%;
}
.auditSearch::placeholder{color:var(--txt-3);font-weight:500}
.auditSearch:hover{border-color:var(--line-2)}
.auditSearch:focus{
  outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-dim);
}
.auditSearch::-webkit-search-cancel-button{-webkit-appearance:none;appearance:none;height:12px;width:12px;background:var(--txt-3);border-radius:50%;cursor:pointer;-webkit-mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M18 6L6 18M6 6l12 12' stroke='black' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E") center/contain no-repeat;mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M18 6L6 18M6 6l12 12' stroke='black' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E") center/contain no-repeat}

/* === MODAL (glass popout) === */
.modalBackdrop{
  position:fixed;inset:0;z-index:1000;
  background:rgba(0,0,0,.6);backdrop-filter:blur(4px);
  display:none;align-items:center;justify-content:center;padding:20px;
}
.modalBackdrop.show{display:flex}
.modal{
  width:min(480px,100%);
  background:var(--bg-1);
  border:1px solid var(--border);border-radius:12px;
  box-shadow:0 32px 64px -12px rgba(0,0,0,.5);
  overflow:hidden;position:relative;
}
.modal:before{display:none}
.modalHead{
  padding:18px 22px 14px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;gap:12px;
}
.modalIcon{
  width:36px;height:36px;border-radius:10px;display:grid;place-items:center;
  background:var(--accent-dim);border:1px solid rgba(99,102,241,.2);
  font-size:18px;
}
.modal-title{display:flex;align-items:center;gap:12px}
.modal-title h3{font-size:15px;font-weight:700;letter-spacing:-.2px;color:var(--txt)}
.modal-title p{font-size:11.5px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;margin-top:2px}
.modalClose{
  width:32px;height:32px;border-radius:8px;display:grid;place-items:center;
  background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.15);color:#f87171;
  font-size:14px;transition:all .15s ease;
}
.modalClose:hover{background:rgba(239,68,68,.15);transform:rotate(90deg)}
.modalBody{padding:20px 22px;display:grid;gap:16px}
.modalBody label{font-size:10.5px;font-weight:700;color:var(--txt-3);letter-spacing:.18em;text-transform:uppercase;font-family:'JetBrains Mono',monospace;display:block;margin-bottom:6px}
.modalFoot{
  padding:14px 22px;border-top:1px solid var(--border);
  display:flex;gap:10px;justify-content:flex-end;background:var(--bg-0);
}
.modalFoot .btn{font-size:13px;padding:9px 16px}

/* === CLAIM ALIAS MODAL === */
.claimWrap{display:grid;gap:18px}
.claimField label{margin-bottom:9px}
.domChips{display:flex;flex-wrap:wrap;gap:9px}
.domChip{
  position:relative;display:flex;align-items:center;gap:5px;
  padding:11px 15px;border-radius:11px;cursor:pointer;
  border:1.5px solid var(--border);background:var(--bg-2);
  font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--txt-2);
  transition:all .16s ease;user-select:none;
}
.domChip:hover{border-color:var(--accent-2);transform:translateY(-1px)}
.domChip input{position:absolute;opacity:0;pointer-events:none}
.domChip.on{
  border-color:var(--accent);color:var(--txt);
  background:linear-gradient(135deg,var(--accent-dim),rgba(139,92,246,.10));
  box-shadow:0 0 0 3px rgba(109,106,246,.14);
}
.domChip-at{color:var(--accent-2);font-weight:700}
.domChip.on .domChip-name{color:#fff}
.domChip-tag{
  font-size:9px;text-transform:uppercase;letter-spacing:.1em;
  padding:2px 6px;border-radius:5px;background:rgba(255,180,84,.16);color:#ffb454;
}
.aliasInputRow{display:flex;gap:8px;align-items:stretch}
.aliasInputRow .input{
  flex:1;border:1.5px solid var(--border);border-radius:10px;background:var(--bg-2);
}
.aliasInputRow .input:focus-within,.aliasInputRow .input:focus{border-color:var(--accent)}
.aliasInputRow .btn{padding:0 14px;font-size:16px;border-radius:10px}
.claimPreview{
  display:flex;align-items:center;gap:10px;
  padding:13px 15px;border-radius:11px;
  background:linear-gradient(135deg,var(--accent-dim),rgba(139,92,246,.06));
  border:1px dashed rgba(109,106,246,.35);
}
.claimPreview-label{
  font-size:9.5px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;
  color:var(--txt-3);font-family:'JetBrains Mono',monospace;
}
.claimPreview code{
  flex:1;font-family:'JetBrains Mono',monospace;font-size:14px;
  color:var(--accent-2);font-weight:600;word-break:break-all;
}
.claimPreview-copy{
  background:transparent;border:0;color:var(--txt-3);cursor:pointer;
  font-size:16px;padding:2px 6px;border-radius:6px;transition:all .15s ease;
}
.claimPreview-copy:hover{color:var(--accent);background:rgba(109,106,246,.12)}
.claimErr{
  padding:10px 13px;border-radius:9px;font-size:12px;
  background:rgba(255,92,92,.10);border:1px solid rgba(255,92,92,.28);color:#ff8a8a;
  font-family:'JetBrains Mono',monospace;
}

/* === COPY ROW === */
.copyRow{
  display:flex;align-items:center;gap:0;
  border:1px solid var(--border);border-radius:8px;overflow:hidden;
  background:var(--bg-2);
  transition:all .2s ease;
}
.copyRow:hover{border-color:var(--line-2)}
.copyRow code{
  flex:1;padding:11px 14px;font-family:'JetBrains Mono',monospace;font-size:13.5px;font-weight:600;color:var(--accent);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  background:transparent;letter-spacing:.02em;
}
.copyRow button{
  padding:11px 14px;background:var(--bg-3);color:var(--accent);
  border-left:1px solid var(--border);
  font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
  transition:all .15s ease;display:flex;align-items:center;gap:6px;
}
.copyRow button:hover{background:var(--accent);color:#fff}
.copyRow button.ok{background:rgba(34,197,94,.15);color:var(--ok);border-left-color:rgba(34,197,94,.3)}

/* === ALIAS LIST CARDS === */
.aliasGrid{display:grid;gap:10px}
.aliasItem{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:12px 14px;border-radius:10px;
  background:var(--bg-2);
  border:1px solid var(--border);
  transition:all .2s ease;
}
.aliasItem:hover{border-color:var(--line-2)}
.aliasItem .aliasMain{flex:1;min-width:0}
.aliasItem code{font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;color:var(--txt);display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.aliasItem .aliasMeta{font-size:10.5px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;margin-top:3px;display:flex;gap:8px;align-items:center}
.kindTag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:9.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.kindTag.custom{background:var(--accent-dim);color:var(--accent)}
.kindTag.random{background:rgba(168,85,247,.12);color:#a855f7}
.aliasItem .aliasLocal{color:var(--txt)}
.aliasItem .aliasDom{font-weight:700}
.domBadge{
  display:inline-flex;align-items:center;padding:1px 8px;border-radius:99px;
  font-size:9.5px;font-weight:700;letter-spacing:.03em;
  border:1px solid transparent;font-family:'JetBrains Mono',monospace;
}
.iconBtn{
  width:34px;height:34px;border-radius:8px;display:grid;place-items:center;
  background:var(--bg-2);border:1px solid var(--border);
  color:var(--txt-2);font-size:14px;transition:all .15s ease;flex-shrink:0;
}
.iconBtn:hover{background:var(--bg-3);border-color:var(--line-2);color:var(--accent)}
.iconBtn.danger:hover{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2);color:#f87171}

.card{
  position:relative;
  border-radius:12px;
  background:var(--bg-1);
  border:1px solid var(--border);
  overflow:hidden;
  box-shadow:none;
}
.card:before{display:none}
.cardHead{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 20px;border-bottom:1px solid var(--border);
}
.cardHead h3{font-size:14px;font-weight:600;letter-spacing:-.2px}
.cardHead h3:before{content:"";display:none}
.cardBody{padding:18px 20px}
.tabs{display:flex;gap:6px}
.pill{
  display:inline-flex;align-items:center;gap:6px;
  padding:5px 10px;border-radius:999px;
  font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--txt-3);
  background:var(--bg-2);border:1px solid var(--border);
}
.pill .dot{width:6px;height:6px;border-radius:50%;background:var(--ok)}

/* === INBOX LAYOUT === */
.layout{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.layout .inboxTools{grid-column:1 / -1}
@media(max-width:980px){.layout{grid-template-columns:1fr}}

/* === INBOX ADDRESS BAR === */
.inboxAddrBar{
  display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  margin:0 16px 4px;padding:9px 12px;border-radius:10px;
  background:var(--addr-bg,var(--bg-0));
  border:1px solid var(--addr-bd,var(--border));
  animation:addrIn .25s ease;
}
@keyframes addrIn{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:none}}
.inboxAddrBar .addrLabel{
  font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:700;
  letter-spacing:.14em;color:var(--txt-4);
}
.inboxAddrBar .addrValue{
  flex:1;min-width:0;font-family:'JetBrains Mono',monospace;font-size:14px;
  font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  letter-spacing:.01em;
}
.inboxAddrBar .addrValue .aliasLocal{color:var(--txt)}
.inboxAddrBar .addrValue .aliasDom{font-weight:700}
.inboxAddrBar .addrCopy{
  display:inline-flex;align-items:center;gap:6px;flex-shrink:0;
  padding:6px 12px;border-radius:8px;cursor:pointer;
  font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;
  color:var(--addr-fg,var(--accent));
  background:var(--bg-1);
  border:1px solid var(--addr-bd,var(--border));
  transition:all .16s ease;
}
.inboxAddrBar .addrCopy:hover{background:var(--addr-bg,var(--accent-dim));filter:brightness(1.15)}
.inboxAddrBar .addrCopy.ok{color:#34d399;border-color:rgba(52,211,153,.4)}

/* === COMPOSE === */
.bodyPanel{
  padding:16px;border-radius:10px;
  background:var(--bg-0);
  border:1px solid var(--border);
}
.formLabel{
  display:flex;align-items:center;justify-content:space-between;gap:10px;
  font-size:12px;font-weight:500;color:var(--txt-2);
  margin-bottom:8px;
}
.compose{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:stretch}
.inputWrap{
  display:flex;align-items:center;
  border:1px solid var(--border);background:var(--bg-0);
  border-radius:8px;overflow:hidden;
  transition:all .15s ease;
}
.inputWrap:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
.input{flex:1;background:transparent;border:0;padding:12px 14px;color:var(--txt);font-size:14px;font-family:'JetBrains Mono',monospace}
.input::placeholder{color:var(--txt-4)}

.result{
  margin-top:14px;padding:14px;border-radius:8px;
  background:var(--bg-0);border:1px solid var(--border);
  font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.55;
  color:var(--ok);min-height:54px;white-space:pre-wrap;
  position:relative;
}
.result:before{
  content:"⏵ output";display:block;
  font-size:10px;color:var(--txt-3);text-transform:uppercase;letter-spacing:.12em;margin-bottom:8px;
  font-family:'Inter',sans-serif;font-weight:600;
}

/* === INBOX LIST === */
.listShell{
  border:1px solid var(--border);background:var(--bg-0);
  border-radius:8px;padding:6px;min-height:540px;max-height:70vh;overflow-y:auto;
}
.listShell::-webkit-scrollbar{width:8px}
.listShell::-webkit-scrollbar-track{background:transparent}
.listShell::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:4px}
.listShell::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.15)}

.list{display:flex;flex-direction:column;gap:4px}
.msg{
  padding:13px 14px;border-radius:8px;cursor:pointer;
  background:transparent;border:1px solid transparent;
  transition:all .15s ease;
}
.msg:hover{background:rgba(255,255,255,.03);border-color:var(--border)}
.msg.selected{background:var(--accent-dim);border-color:rgba(59,130,256,.25)}
.msgTop{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:6px}
.subject{font-size:13.5px;font-weight:600;color:var(--txt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;display:flex;align-items:center;gap:7px}
.htmlTag{font-size:9px;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:.04em;padding:2px 6px;border-radius:4px;background:var(--accent-dim);color:var(--accent);flex-shrink:0}
.time{font-size:10.5px;font-family:'JetBrains Mono',monospace;color:var(--txt-3);flex-shrink:0}
.meta{font-size:11.5px;color:var(--txt-3);line-height:1.5;margin-bottom:6px;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis}
.preview{font-size:12.5px;color:var(--txt-2);line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}

/* === DETAIL === */
.previewShell{
  border:1px solid var(--border);background:var(--bg-0);
  border-radius:8px;padding:18px;min-height:540px;max-height:70vh;overflow-y:auto;
}
.previewShell::-webkit-scrollbar{width:8px}
.previewShell::-webkit-scrollbar-track{background:transparent}
.previewShell::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:4px}
.empty{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:100%;min-height:240px;gap:14px;
  border:1px dashed var(--line-2);border-radius:10px;
  color:var(--txt-3);font-size:13px;font-family:'JetBrains Mono',monospace;
  background:transparent;text-align:center;padding:24px;
}
.empty .emptyIcon{
  width:54px;height:54px;border-radius:14px;
  background:var(--bg-2);border:1px solid var(--border);
  display:grid;place-items:center;font-size:24px;
  color:var(--txt-3);
}
.empty.bad{color:var(--bad);border-color:rgba(239,68,68,.2);background:rgba(239,68,68,.04)}

.mailTitle{
  font-size:20px;font-weight:700;letter-spacing:-.4px;margin-bottom:14px;
  color:var(--txt);line-height:1.3;
}
.mailMeta{
  display:grid;gap:5px;padding:12px 14px;
  background:var(--bg-0);border:1px solid var(--border);border-radius:8px;
  font-size:12px;font-family:'JetBrains Mono',monospace;color:var(--txt-2);margin-bottom:14px;
}
.mailMeta b{color:var(--accent);font-weight:500;display:inline-block;min-width:75px}

.bodyTabs{display:flex;gap:4px;margin-bottom:10px;padding:4px;background:var(--bg-0);border:1px solid var(--border);border-radius:8px;width:fit-content}
.bodyTab{
  padding:6px 14px;border-radius:6px;
  font-size:11.5px;font-weight:600;letter-spacing:.04em;color:var(--txt-3);
  transition:all .12s ease;font-family:'JetBrains Mono',monospace;
}
.bodyTab:hover{color:var(--txt-2)}
.bodyTab.active{
  background:var(--accent);
  color:#fff;
}
.bodybox,.bodyText,.bodyRaw{
  padding:14px;border-radius:8px;border:1px solid var(--border);
  background:var(--bg-0);
  max-height:60vh;overflow:auto;
}
.bodyText{
  white-space:pre-wrap;word-wrap:break-word;line-height:1.6;font-size:13.5px;color:#dde2eb;
  font-family:'Inter',-apple-system,sans-serif;
}
.bodyText a{color:var(--accent);word-break:break-all;text-decoration:underline;text-decoration-color:rgba(99,102,241,.3)}
.bodyText a:hover{text-decoration-color:var(--accent)}
.bodyRaw{
  white-space:pre-wrap;word-wrap:break-word;
  font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11.5px;color:#9ba3b3;
}
.bodyFrame{
  width:100%;min-height:480px;max-height:75vh;
  border:1px solid var(--border);border-radius:8px;background:#fff;
}

/* === TOAST === */
.toast{position:fixed;bottom:24px;right:24px;z-index:50;display:flex;flex-direction:column-reverse;gap:8px;pointer-events:none}
.toast div{
  pointer-events:auto;
  padding:11px 16px;border-radius:10px;
  background:var(--bg-1);border:1px solid var(--border);
  color:var(--txt);font-size:13px;font-weight:500;
  box-shadow:0 14px 40px rgba(0,0,0,.5);
  animation:toastIn .25s ease-out;
  max-width:340px;
}
@keyframes toastIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}

/* === PAGE TRANSITIONS === */
.page{display:none;animation:fadeIn .2s ease-out}
.page.active{display:block}
.page.active.grid{display:grid}
.page.active.layout{display:grid}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* === RESPONSIVE === */
@media(max-width:880px){
  .app{grid-template-columns:1fr}
  /* Sidebar becomes off-canvas drawer */
  .side{
    position:fixed;top:0;left:0;bottom:0;
    width:78vw;max-width:300px;height:100vh;
    transform:translateX(-100%);
    transition:transform .22s ease;
    z-index:120;
    border-right:1px solid var(--border);
    box-shadow:0 0 0 0 rgba(0,0,0,0);
    padding:20px 14px;
    will-change:transform;
  }
  body.drawer-open .side{transform:translateX(0);box-shadow:0 12px 40px -8px rgba(0,0,0,.55)}
  /* Backdrop */
  .drawer-backdrop{
    position:fixed;inset:0;background:rgba(5,8,15,.55);
    backdrop-filter:blur(2px);-webkit-backdrop-filter:blur(2px);
    opacity:0;pointer-events:none;transition:opacity .22s ease;
    z-index:110;
  }
  body.drawer-open .drawer-backdrop{opacity:1;pointer-events:auto}
  /* Hamburger button visible on mobile */
  .menuBtn{
    display:inline-flex;align-items:center;justify-content:center;
    width:38px;height:38px;border-radius:10px;
    background:var(--bg-1);border:1px solid var(--border);
    color:var(--fg-1);cursor:pointer;
    margin-right:4px;flex-shrink:0;
  }
  .menuBtn:hover{background:var(--bg-2)}
  .menuBtn svg{width:18px;height:18px}
  .main{padding:18px 16px}
  .mobileBar{
    display:flex;align-items:center;gap:10px;
    margin:-4px 0 14px;
  }
  .mobileBar .mbBrand{
    display:flex;align-items:center;gap:8px;
    font-weight:600;font-size:14px;color:var(--fg-1);
  }
  .mobileBar .mbBrand .mark{
    width:26px;height:26px;border-radius:7px;
    background:linear-gradient(135deg,#8b5cf6,#6d28d9);
    display:flex;align-items:center;justify-content:center;
  }
  .mobileBar .mbBrand .mark svg{width:14px;height:14px}
  .hero h2{font-size:22px}
  .grid{grid-template-columns:repeat(2,1fr)}
  .compose{grid-template-columns:1fr}
}
@media(min-width:881px){
  .menuBtn,.drawer-backdrop,.mobileBar{display:none}
}
@media(max-width:600px){
  .main{padding:14px 12px;}
  .hero{flex-direction:column;align-items:flex-start;gap:10px;}
  .hero h2{font-size:19px;}
  .grid{grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:12px;}
  .stat{padding:12px;}
  .stat .v{font-size:20px;}
  .stat .k{font-size:10px;}
  .layout{grid-template-columns:1fr;gap:10px;}
  .listShell{min-height:auto;max-height:none;}
  .previewShell{min-height:300px;max-height:none;padding:14px;}
  .inboxAddrBar{margin:0 0 8px;}
  .inboxTools{flex-wrap:wrap;gap:8px;}
  .compose{grid-template-columns:1fr;}
  .aliasInputRow{flex-direction:column;align-items:stretch;gap:8px;}
  .aliasItem{flex-wrap:wrap;gap:8px;}
  .aliasMain{min-width:0;}
  .aliasLocal,.aliasDom{font-size:13px;word-break:break-all;}
  .btn{font-size:14px;}
  .input{font-size:16px;}
  .modalBackdrop{padding:0;align-items:flex-end;}
  .modal{width:100%;max-width:100%;max-height:92vh;border-radius:16px 16px 0 0;}
  .modalBody{padding:18px;max-height:74vh;overflow-y:auto;}
  .modalHead{padding:16px 18px;}
  .modalFoot{padding:14px 18px;flex-direction:column-reverse;gap:8px;}
  .modalFoot .btn{width:100%;justify-content:center;}
  .apiHead{padding:10px 12px;flex-wrap:wrap;gap:6px;}
  .apiPath{font-size:12px;word-break:break-all;}
  .apiDesc{flex-basis:100%;font-size:11px;}
  .apiCode{font-size:10px;padding:10px;}
  .apiResp{font-size:10px;word-break:break-all;}
  .bodyFrame{min-height:360px;max-height:60vh;}
  .mailTitle{font-size:16px;}
  .mailMeta{font-size:12px;}
  .bodyTabs{flex-wrap:wrap;}
  .toast{bottom:12px;right:12px;left:12px;align-items:stretch;}
  .toast>div{width:auto;}
  .copyRow{flex-direction:column;align-items:stretch;gap:8px;}
  .addrValue{word-break:break-all;font-size:13px;}
  .side{width:84vw;max-width:320px;}
}
@media(max-width:380px){
  .grid{grid-template-columns:1fr 1fr;}
  .hero h2{font-size:17px;}
  .side{width:88vw;}
}
</style>
</head>
<body>
<div class="app">
  <div class="drawer-backdrop" id="drawerBackdrop" aria-hidden="true"></div>
  <aside class="side" id="sideDrawer">
    <div class="logo"><div class="mark"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m3.5 7 8.5 6 8.5-6"/></svg></div><div class="brand"><h1>Veil</h1><p>temporary mail</p></div></div>
    <nav class="nav">
      <a class="active" href="#inbox" data-page="inbox"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h5l2 3h4l2-3h5"/><path d="M5 5h14a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Z"/></svg> Inbox</a>
      <a href="#aliases" data-page="aliases"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.5 7 8.5 6 8.5-6"/></svg> Aliases</a>
      <a href="#api" data-page="api"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="m8 9-3 3 3 3"/><path d="m16 9 3 3-3 3"/><path d="m13.5 7-3 10"/></svg> Bot API</a>
      <a href="#status" data-page="status"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2 6 4-14 2 8h6"/></svg> Status</a>
      <div class="navGroup" data-need="admin">
        <div class="navGroupLabel">Admin</div>
        <a href="#users-add" data-page="users-add"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/></svg> Add User</a>
        <a href="#users-manage" data-page="users-manage"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></svg> Lock / Delete</a>
        <a href="#users-log" data-page="users-log"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8M8 17h6"/></svg> Audit Log</a>
      </div>
      <a href="#domains" data-page="domains" data-need="super"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg> Domains</a>
      <div class="navSep"></div>
      <a href="#change-pw" data-page="change-pw"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="m10.85 12.15 8.15-8.15M16 5l3 3M14 7l3 3"/></svg> Change Password</a>
      <div class="nav-spacer"></div>
      <a class="logout" href="/logout"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg> Logout</a>
    </nav>
    <div class="sidefoot">
      <div class="statusBar"><span class="statusDot"></span><span>SYSTEM ONLINE</span></div>
      <div class="sideMeta">
        <div><span>SMTP</span><b id="sideSmtp">—</b></div>
        <div><span>MSG</span><b id="sideMsg">—</b></div>
        <div><span>HOST</span><b id="sideHost">bibnk.cloud</b></div>
      </div>
    </div>
  </aside>
  <main class="main">
    <div class="mobileBar">
      <button class="menuBtn" id="menuBtn" aria-label="Open menu" aria-controls="sideDrawer" aria-expanded="false">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="7" x2="20" y2="7"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="17" x2="20" y2="17"/></svg>
      </button>
      <div class="mbBrand">
        <div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m3.5 7 8.5 6 8.5-6"/></svg></div>
        <span>Veil</span>
      </div>
    </div>
    <section class="top">
      <div class="hero">
        <h2 id="pageTitle">Inbox</h2>
        <p id="pageSubtitle">Tangkap email ke <b id="domainInline">*@domain</b>, baca isinya, ambil OTP via API.</p>
      </div>
      <div class="userBadge">
        <div class="ub-avatar" id="ubAvatar">?</div>
        <div class="ub-info">
          <div class="ub-name" id="ubName">—</div>
          <div class="ub-role" id="ubRole">—</div>
        </div>
      </div>
      <div class="actions">
        <button class="btn" onclick="refresh()">↻ Refresh</button>
        <button class="btn primary" onclick="openClaimAliasModal()">✦ New Address</button>
      </div>
    </section>

    <section class="grid page" id="status" data-page="status">
      <div class="stat"><div class="k">Domain</div><div class="v" id="stDomain">—</div><div class="s">wildcard catch-all</div></div>
      <div class="stat"><div class="k">Messages</div><div class="v" id="stMessages">—</div><div class="s">stored in SQLite</div></div>
      <div class="stat"><div class="k">SMTP</div><div class="v" id="stSmtp">—</div><div class="s">receiver port</div></div>
      <div class="stat"><div class="k">API Auth</div><div class="v" id="stAuth">—</div><div class="s">x-api-token</div></div>
    </section>

    <section class="layout page" id="inbox" data-page="inbox">
      <div class="card">
        <div class="cardHead">
          <h3 id="inboxTitle">Inbox</h3>
          <div class="tabs">
            <select id="aliasFilter" class="aliasFilter" onchange="onAliasFilterChange()">
              <option value="">All incoming</option>
            </select>
            <button class="btn" onclick="refresh()" title="Refresh">↻</button>
          </div>
        </div>
        <div id="inboxAddrBar" class="inboxAddrBar" style="display:none"></div>
        <div class="cardBody">
          <div class="listShell">
            <div id="list" class="list">
              <div class="empty"><div class="emptyIcon">📭</div><div>Loading inbox...</div></div>
            </div>
          </div>
        </div>
      </div>
      <div class="card detail">
        <div class="cardHead"><h3>Message</h3><span class="pill" id="selectedPill">—</span></div>
        <div class="cardBody"><div class="previewShell"><div id="detail" class="empty"><div class="emptyIcon">✉</div><div>Pilih email dari list<br><span style="font-size:11px;color:var(--txt-4)">Klik salah satu pesan di kiri untuk membaca</span></div></div></div></div>
      </div>
    </section>

    <section class="layout page" id="aliases" data-page="aliases">
      <div class="card inboxTools">
        <div class="cardHead"><h3>Aliases</h3><span class="pill"><span class="dot"></span> max 3 custom + ∞ random</span></div>
        <div class="cardBody">
          <div class="bodyPanel" style="text-align:center;padding:24px 20px">
            <p style="font-size:13px;color:var(--txt-3);max-width:420px;margin:0 auto 18px;line-height:1.6">Claim alias kustom (max 3) atau generate random unlimited. Setiap alias unik global, hanya pemiliknya yang bisa lihat email.</p>
            <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
              <button class="btn green" onclick="openClaimAliasModal()">➕ Claim Custom</button>
              <button class="btn" onclick="openClaimAliasModal('random')">🎲 Generate Random</button>
            </div>
          </div>
        </div>
      </div>
      <div class="card" style="grid-column:1/-1">
        <div class="cardHead"><h3>My Aliases</h3><button class="btn" onclick="loadAliases()">↻</button></div>
        <div class="cardBody"><div id="aliasList" class="list"><div class="empty"><div class="emptyIcon">⏳</div><div>Loading...</div></div></div></div>
      </div>
      <select id="aliasDomain" style="display:none"></select>
    </section>

    <section class="layout page" id="users-add" data-page="users-add">
      <div class="card inboxTools">
        <div class="cardHead"><h3>Add User</h3><span class="pill" id="rolePill"><span class="dot"></span> —</span></div>
        <div class="cardBody">
          <div class="bodyPanel" style="text-align:center;padding:32px 20px">
            <div style="font-size:54px;margin-bottom:14px;line-height:1;display:inline-block">👤</div>
            <h4 style="font-size:18px;font-weight:600;letter-spacing:-.3px;margin-bottom:6px">Buat user baru</h4>
            <p style="font-size:12.5px;color:var(--txt-3);max-width:360px;margin:0 auto 20px;line-height:1.55">Password default <b style="color:var(--accent);font-family:'JetBrains Mono',monospace">Baba...</b> akan otomatis di-set. User wajib ganti saat first login.</p>
            <button class="btn green" style="font-size:14px;padding:11px 22px" onclick="openAddUserModal()">➕ Add User</button>
          </div>
        </div>
      </div>
    </section>

    <section class="card page" id="users-manage" data-page="users-manage">
      <div class="cardHead"><h3>Lock / Delete</h3><button class="btn" onclick="loadUsers()">↻</button></div>
      <div class="cardBody"><div id="userList" class="list"><div class="empty"><div class="emptyIcon">⏳</div><div>Loading...</div></div></div></div>
    </section>

    <section class="card page" id="users-log" data-page="users-log">
      <div class="cardHead">
        <h3>User Log</h3>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <input id="auditUser" class="auditSearch" type="search" list="auditUserList"
                 placeholder="Search user…" autocomplete="off"
                 oninput="onAuditUserInput()" onsearch="loadAudit()" title="Filter by user (actor or target)">
          <datalist id="auditUserList"></datalist>
          <select id="auditAction" class="aliasFilter" onchange="loadAudit()" title="Filter by activity">
            <option value="">All activity</option>
            <option value="create_user">Create user</option>
            <option value="delete_user">Delete user</option>
            <option value="lock_user">Lock user</option>
            <option value="unlock_user">Unlock user</option>
            <option value="change_password">Change password</option>
            <option value="reset_password">Reset password</option>
            <option value="regen_token">Regen token</option>
            <option value="add_domain">Add domain</option>
            <option value="update_domain">Update domain</option>
            <option value="delete_domain">Delete domain</option>
            <option value="delete_alias">Delete alias</option>
          </select>
          <button class="btn" onclick="clearAuditFilter()" title="Clear filters">Clear</button>
          <button class="btn" onclick="loadAudit()" title="Refresh">↻</button>
        </div>
      </div>
      <div class="cardBody"><div id="auditList" class="list"><div class="empty"><div class="emptyIcon">⏳</div><div>Loading...</div></div></div></div>
    </section>

    <section class="layout page" id="change-pw" data-page="change-pw">
      <div class="card inboxTools" style="grid-column:1/-1">
        <div class="cardHead"><h3>Change Password</h3><span class="pill"><span class="dot"></span> self-service</span></div>
        <div class="cardBody">
          <div class="bodyPanel">
            <label class="formLabel">Current password</label>
            <div class="inputWrap"><input class="input" id="cpCurrent" type="password" placeholder="••••••••"></div>
            <label class="formLabel" style="margin-top:12px">New password</label>
            <div class="inputWrap"><input class="input" id="cpNew" type="password" placeholder="••••••••" oninput="validatePw('cpNew','cpRules','cpStrength')"></div>
            <ul id="cpRules" class="pwRules">
              <li data-rule="len">Minimal 8 karakter</li>
              <li data-rule="upper">1 huruf KAPITAL</li>
              <li data-rule="digit">1 angka</li>
              <li data-rule="symbol">1 simbol (!@#$% dll)</li>
            </ul>
            <div id="cpStrength" class="pwStrength"><div class="bar"></div></div>
            <label class="formLabel" style="margin-top:12px">Confirm new password</label>
            <div class="inputWrap"><input class="input" id="cpConfirm" type="password" placeholder="••••••••"></div>
            <div style="margin-top:14px;display:flex;gap:8px">
              <button class="btn green" onclick="submitChangePw()">🔑 Update Password</button>
            </div>
            <div id="cpResult" class="result">Password baru harus berbeda dari yang lama dan memenuhi semua syarat.</div>
          </div>
        </div>
      </div>
    </section>

    <section class="layout page" id="domains" data-page="domains">
      <div class="card inboxTools">
        <div class="cardHead"><h3>Add Domain</h3><span class="pill"><span class="dot"></span> super_admin only</span></div>
        <div class="cardBody">
          <div class="bodyPanel">
            <label class="formLabel">Domain</label>
            <div class="compose">
              <div class="inputWrap"><input class="input" id="newDomain" placeholder="example.com"></div>
              <select class="input" id="newDomainMode" style="max-width:200px">
                <option value="public">public (semua bisa pakai)</option>
                <option value="private">private (owner only)</option>
              </select>
              <button class="btn green" onclick="addDomain()">+ Add</button>
            </div>
            <label class="formLabel" style="margin-top:10px">Owner (optional, untuk mode private)</label>
            <div class="inputWrap"><input class="input" id="newDomainOwner" placeholder="username (kosongi = self)"></div>
            <div id="newDomainResult" class="result">Pastikan MX & A record di Cloudflare sudah di-set ke server ini sebelum add.</div>
          </div>
        </div>
      </div>
      <div class="card" style="grid-column:1/-1">
        <div class="cardHead"><h3>Domains</h3><button class="btn" onclick="loadDomains()">↻</button></div>
        <div class="cardBody"><div id="domainList" class="list"><div class="empty"><div class="emptyIcon">⏳</div><div>Loading...</div></div></div></div>
      </div>
    </section>

    <section class="card page" id="api" data-page="api">
      <div class="cardHead"><h3>🤖 Bot API</h3></div>
      <div class="cardBody">
        <!-- TOKEN SECTION -->
        <div style="margin-bottom:20px;padding:16px;background:var(--bg-2);border:1px solid var(--border);border-radius:12px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <div style="font-size:11px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:1px">🔑 Your API Token</div>
            <div style="display:flex;gap:6px">
              <button class="btn" onclick="toggleTokenVis()" style="font-size:11px;padding:4px 10px" id="btnToggleEye">👁 Show</button>
              <button class="btn" onclick="copyToken()" style="font-size:11px;padding:4px 10px">⎘ Copy</button>
              <button class="btn" onclick="regenToken()" style="font-size:11px;padding:4px 10px;color:var(--violet)">⟳ Regen</button>
            </div>
          </div>
          <div id="apiTokenBox" style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px;font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--cyan);word-break:break-all;user-select:all;letter-spacing:1px" onclick="copyToken()">●●●●●●●●●●●●●●●●●●●●●●●●</div>
          <div style="font-size:11px;color:var(--txt-3);margin-top:8px">⚠️ Regenerate = token lama langsung mati. Update di bot/script kamu.</div>
        </div>
        <!-- USAGE SECTION -->
        <div style="margin-bottom:20px">
          <div style="font-size:11px;color:var(--txt-3);margin-bottom:8px;font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:1px">📋 Usage</div>
          <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:8px;padding:14px;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:2">
            <div style="color:var(--txt-3)"># Set variable (bash)</div>
            <div><span style="color:var(--violet)">export</span> <span style="color:var(--cyan)">TOKEN</span>=<span style="color:var(--green)">"your-token-here"</span></div>
            <div><span style="color:var(--violet)">export</span> <span style="color:var(--cyan)">BASE</span>=<span style="color:var(--green)">"https://mail.bibnk.cloud"</span></div>
            <div style="margin-top:4px;color:var(--txt-3)"># Auth header</div>
            <div><span style="color:var(--cyan)">H</span>=<span style="color:var(--green)">"-H \"x-api-token: <span style="color:var(--violet)">$TOKEN</span>\""</span></div>
            <div><span style="color:var(--cyan)">J</span>=<span style="color:var(--green)">"-H \"content-type: application/json\""</span></div>
          </div>
        </div>
        <!-- ENDPOINTS -->
        <div style="margin-bottom:8px">
          <div style="font-size:11px;color:var(--txt-3);margin-bottom:8px;font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:1px">🚀 Endpoints</div>
        </div>
        <!-- WHOAMI -->
        <div class="apiSection" id="apiSec1">
          <div class="apiHead" onclick="toggleSec('apiSec1')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/whoami</span><span class="apiDesc">Cek info user yang login</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl $H "$BASE/api/whoami" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "username": "6715", "role": "super_admin", "api_token": "..." }</div>
          </div>
        </div>
        <!-- STATUS -->
        <div class="apiSection" id="apiSec2">
          <div class="apiHead" onclick="toggleSec('apiSec2')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/status</span><span class="apiDesc">Status server (domain, smtp, messages)</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl $H "$BASE/api/status" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "domain": "bibnk.cloud", "smtp_port": 25, "messages": 12, ... }</div>
          </div>
        </div>
        <!-- MESSAGES -->
        <div class="apiSection" id="apiSec3">
          <div class="apiHead" onclick="toggleSec('apiSec3')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/messages</span><span class="apiDesc">List inbox email</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode"># Semua email milikmu
curl $H "$BASE/api/messages?limit=20" | jq

# Filter per alias
curl $H "$BASE/api/messages?user=hello&limit=10" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "messages": [{ "id": 1, "from": "...", "subject": "...", ... }] }</div>
          </div>
        </div>
        <!-- SINGLE MESSAGE -->
        <div class="apiSection" id="apiSec4">
          <div class="apiHead" onclick="toggleSec('apiSec4')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/messages/:id</span><span class="apiDesc">Detail email (body + headers)</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl $H "$BASE/api/messages/123" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "id": 123, "from": "...", "subject": "...", "body": "...", "headers": {...} }</div>
          </div>
        </div>
        <!-- LATEST / POLL -->
        <div class="apiSection" id="apiSec5">
          <div class="apiHead" onclick="toggleSec('apiSec5')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/latest</span><span class="apiDesc">Long-poll email terbaru (untuk OTP)</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode"># Tunggu email baru max 30 detik
curl $H "$BASE/api/latest?user=hello&wait=30" | jq

# Tunggu email baru dari ID tertentu
curl $H "$BASE/api/latest?user=hello&since_id=5&wait=30" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "id": 124, "from": "...", "subject": "Your OTP: 1234", ... }
// { "message": null } // timeout, tidak ada email baru</div>
          </div>
        </div>
        <!-- ALIASES LIST -->
        <div class="apiSection" id="apiSec6">
          <div class="apiHead" onclick="toggleSec('apiSec6')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/aliases</span><span class="apiDesc">List alias yang kamu punya</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl $H "$BASE/api/aliases" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "aliases": [{ "alias": "hello@bibnk.cloud", "kind": "custom", ... }], "custom_limit": 3 }</div>
          </div>
        </div>
        <!-- CREATE ALIAS -->
        <div class="apiSection" id="apiSec7">
          <div class="apiHead" onclick="toggleSec('apiSec7')">
            <span class="apiMethod post">POST</span><span class="apiPath">/api/aliases</span><span class="apiDesc">Buat alias baru (random/custom)</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode"># Random alias (pilih domain dari /api/status → "domains")
curl -X POST $H $J "$BASE/api/aliases" \
  -d '{"kind":"random","domain":"bibnk.cloud"}' | jq

# Custom alias di domain lain
curl -X POST $H $J "$BASE/api/aliases" \
  -d '{"kind":"custom","local":"hello","domain":"b1bnk.site"}' | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// domain = salah satu dari /api/status."domains". { "alias": "xK9mBp2qZw@bibnk.cloud", "domain": "bibnk.cloud", "kind": "random", ... }</div>
          </div>
        </div>
        <!-- DELETE MESSAGE -->
        <div class="apiSection" id="apiSec8">
          <div class="apiHead" onclick="toggleSec('apiSec8')">
            <span class="apiMethod del">DEL</span><span class="apiPath">/api/messages/:id</span><span class="apiDesc">Hapus email</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl -X DELETE $H "$BASE/api/messages/123" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "ok": true }</div>
          </div>
        </div>
        <!-- DOMAINS (super_admin) -->
        <div class="apiSection" id="apiSec9">
          <div class="apiHead" onclick="toggleSec('apiSec9')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/domains</span><span class="apiDesc">List semua domain <span class="apiBadge">super</span></span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl $H "$BASE/api/domains" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "domains": [{ "domain": "bibnk.cloud", "mode": "public", ... }] }</div>
          </div>
        </div>
        <!-- ADD DOMAIN -->
        <div class="apiSection" id="apiSec10">
          <div class="apiHead" onclick="toggleSec('apiSec10')">
            <span class="apiMethod post">POST</span><span class="apiPath">/api/domains</span><span class="apiDesc">Tambah domain <span class="apiBadge">super</span></span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl -X POST $H $J "$BASE/api/domains" \
  -d '{"domain":"alt.example","mode":"public"}' | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
          </div>
        </div>
        <!-- TOGGLE DOMAIN -->
        <div class="apiSection" id="apiSec11">
          <div class="apiHead" onclick="toggleSec('apiSec11')">
            <span class="apiMethod post">POST</span><span class="apiPath">/api/domains/:domain</span><span class="apiDesc">Toggle/delete domain <span class="apiBadge">super</span></span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode"># Disable domain
curl -X POST $H $J "$BASE/api/domains/alt.example" \
  -d '{"enabled":false}' | jq

# Set mode
curl -X POST $H $J "$BASE/api/domains/alt.example" \
  -d '{"mode":"private"}' | jq

# Delete
curl -X DELETE $H "$BASE/api/domains/alt.example" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
          </div>
        </div>
        <!-- USERS (admin) -->
        <div class="apiSection" id="apiSec12">
          <div class="apiHead" onclick="toggleSec('apiSec12')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/users</span><span class="apiDesc">List semua user <span class="apiBadge">admin+</span></span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl $H "$BASE/api/users" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
          </div>
        </div>
        <!-- CREATE USER -->
        <div class="apiSection" id="apiSec13">
          <div class="apiHead" onclick="toggleSec('apiSec13')">
            <span class="apiMethod post">POST</span><span class="apiPath">/api/users</span><span class="apiDesc">Buat user baru <span class="apiBadge">admin+</span></span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl -X POST $H $J "$BASE/api/users" \
  -d '{"username":"alice","role":"user"}' | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// Password awal: Babanuki775. (wajib ganti saat first login)</div>
          </div>
        </div>
        <!-- LOCK/UNLOCK/DELETE USER -->
        <div class="apiSection" id="apiSec14">
          <div class="apiHead" onclick="toggleSec('apiSec14')">
            <span class="apiMethod post">POST</span><span class="apiPath">/api/users/:name/(lock|unlock)</span><span class="apiDesc">Lock/unlock/delete user <span class="apiBadge">super</span></span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode"># Lock
curl -X POST $H $J "$BASE/api/users/alice/lock" \
  -d '{"reason":"abuse"}' | jq

# Unlock
curl -X POST $H $J "$BASE/api/users/alice/unlock" \
  -d '{"reason":"cleared"}' | jq

# Delete
curl -X DELETE $H $J "$BASE/api/users/alice" \
  -d '{"reason":"offboard"}' | jq

# Reset password → Babanuki775.
curl -X POST $H $J "$BASE/api/users/alice/password" -d '{}' | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
          </div>
        </div>
        <!-- AUDIT LOG -->
        <div class="apiSection" id="apiSec15">
          <div class="apiHead" onclick="toggleSec('apiSec15')">
            <span class="apiMethod get">GET</span><span class="apiPath">/api/audit</span><span class="apiDesc">Audit log admin actions <span class="apiBadge">super</span></span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode># Semua log
curl $H "$BASE/api/audit?limit=100" | jq

# Filter by action
curl $H "$BASE/api/audit?action=create_user" | jq

# Filter by target
curl $H "$BASE/api/audit?target=alice" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
          </div>
        </div>
        <!-- REGEN TOKEN -->
        <div class="apiSection" id="apiSec16">
          <div class="apiHead" onclick="toggleSec('apiSec16')">
            <span class="apiMethod post">POST</span><span class="apiPath">/api/regen-token</span><span class="apiDesc">Generate API token baru</span><span class="apiArrow">▾</span>
          </div>
          <div class="apiBody">
            <pre class="apiCode">curl -X POST $H "$BASE/api/regen-token" | jq</pre>
            <button class="btnCopy" onclick="copyBlock(this)">⎘</button>
            <div class="apiResp">// { "api_token": "new-token-here" }</div>
          </div>
        </div>
        <!-- SMTP TIP -->
        <div style="margin-top:20px;padding:14px;background:var(--bg-2);border:1px solid var(--border);border-radius:8px;font-size:12px;color:var(--txt-2)">
          <div style="color:var(--cyan);font-weight:bold;margin-bottom:6px">📬 SMTP Receiver</div>
          <div style="color:var(--txt-3);line-height:1.8">
            Server menerima email ke <b style="color:var(--txt-2)">*</b>@bibnk.cloud via port 25.<br>
            Test: <code style="color:var(--green)">swaks --to test@bibnk.cloud --server 43.134.130.236 --port 25</code>
          </div>
        </div>
      </div>
    </section>
    <!-- API PAGE STYLES -->
    <style>
      .apiSection{margin-bottom:8px;border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--bg-2)}
      .apiHead{display:flex;align-items:center;gap:8px;padding:10px 14px;cursor:pointer;transition:background .15s}
      .apiHead:hover{background:var(--bg-3,#222)}
      .apiMethod{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;min-width:34px;text-align:center;letter-spacing:0.5px}
      .apiMethod.get{background:#0f3a2e;color:#34d399}
      .apiMethod.post{background:#2d1f4e;color:#a78bfa}
      .apiMethod.del{background:#3b1515;color:#f87171}
      .apiPath{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan);font-weight:600}
      .apiDesc{font-size:12px;color:var(--txt-3);flex:1}
      .apiArrow{color:var(--txt-3);font-size:10px;transition:transform .2s}
      .apiSection.open .apiArrow{transform:rotate(180deg)}
      .apiBody{display:none;padding:0 14px 12px;position:relative}
      .apiSection.open .apiBody{display:block}
      .apiCode{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--green);line-height:1.8;white-space:pre-wrap;word-break:break-all;margin:0}
      .apiResp{margin-top:8px;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--txt-3);line-height:1.7;white-space:pre-wrap}
      .apiBadge{display:inline-block;font-size:9px;background:var(--violet);color:#fff;padding:1px 5px;border-radius:3px;margin-left:4px;vertical-align:middle;font-weight:600}
      .btnCopy{position:absolute;top:16px;right:20px;background:var(--bg-2);border:1px solid var(--border);border-radius:4px;padding:3px 8px;font-size:11px;color:var(--txt-3);cursor:pointer;transition:all .15s}
      .btnCopy:hover{color:var(--cyan);border-color:var(--cyan)}
    </style>
  </main>
</div>
<div id="modalRoot" class="modalBackdrop" onclick="if(event.target===this)closeModal()"></div>
<div id="toast" class="toast"></div>
<script>
const qs=new URLSearchParams(location.search); let token=qs.get('token')||localStorage.token||'';
if(qs.get('token')){history.replaceState(null,'',location.pathname+location.hash)}
let domain='';
async function api(path,opt={}){opt.credentials='same-origin';opt.headers=Object.assign({'content-type':'application/json'},opt.headers||{});if(token)opt.headers['x-api-token']=token;let r=await fetch(path,opt);if(r.status===401){location.href='/login';return}let j=await r.json();if(!r.ok){const err=new Error(j.error||JSON.stringify(j));err.data=j;err.status=r.status;throw err;}return j}
function esc(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
// Warna konsisten per-domain: hash nama → hue HSL. Domain baru otomatis dapat warna sendiri.
function domainColor(dom){
  let h=0; const s=String(dom||'');
  for(let i=0;i<s.length;i++){h=(h*31+s.charCodeAt(i))>>>0}
  const hue=h%360;
  return {
    fg:`hsl(${hue},70%,72%)`,
    bg:`hsla(${hue},70%,55%,.13)`,
    bd:`hsla(${hue},70%,60%,.32)`,
  };
}
// Render alamat email dengan domain diwarnai sesuai domainColor. Aman untuk esc.
function colorAddr(addr){
  const a=String(addr||'');
  const at=a.lastIndexOf('@');
  if(at<0)return esc(a);
  const local=a.slice(0,at), dom=a.slice(at+1);
  const c=domainColor(dom);
  return `${esc(local)}<span style="color:${c.fg};font-weight:600">@${esc(dom)}</span>`;
}

// === MODAL SYSTEM (glass popout) ===
function openModal({icon='✨',title='',sub='',body='',foot='',onClose}){
  const r=document.getElementById('modalRoot');
  // Cancel pending close clear (race-condition safe)
  if(r._closeTimer){clearTimeout(r._closeTimer);r._closeTimer=null}
  r.innerHTML=`<div class="modal" onclick="event.stopPropagation()">
    <div class="modalHead">
      <div class="modal-title">
        <div class="modalIcon">${icon}</div>
        <div><h3>${esc(title)}</h3>${sub?`<p>${esc(sub)}</p>`:''}</div>
      </div>
      <button class="modalClose" onclick="closeModal()">✕</button>
    </div>
    <div class="modalBody">${body}</div>
    ${foot?`<div class="modalFoot">${foot}</div>`:''}
  </div>`;
  r.classList.add('show');
  r._onClose=onClose||null;
  document.addEventListener('keydown',escClose);
}
function closeModal(){
  const r=document.getElementById('modalRoot');
  if(r._onClose){try{r._onClose()}catch(e){}}
  r._onClose=null;
  r.classList.remove('show');
  if(r._closeTimer)clearTimeout(r._closeTimer);
  r._closeTimer=setTimeout(()=>{r.innerHTML='';r._closeTimer=null},180);
  document.removeEventListener('keydown',escClose);
}
function escClose(e){if(e.key==='Escape')closeModal()}

async function copyText(text,btn){
  try{
    await navigator.clipboard.writeText(text);
    if(btn){
      const old=btn.innerHTML;
      btn.classList.add('ok');
      btn.innerHTML='✓ Copied';
      setTimeout(()=>{btn.classList.remove('ok');btn.innerHTML=old},1400);
    }
    toast('Copied: '+text);
  }catch(e){toast('Copy failed')}
}

function copyRow(value,label){
  return `<div class="copyRow">
    <code>${esc(value)}</code>
    <button onclick="copyText('${esc(value).replace(/'/g,"\\'")}',this)">📋 ${esc(label||'Copy')}</button>
  </div>`;
}

// === ALIAS FILTER (inbox dropdown) ===
let myAliases=[];
async function loadMyAliasesIntoFilter(){
  try{
    const j=await api('/api/aliases');
    myAliases=j.aliases||[];
    const sel=document.getElementById('aliasFilter');
    if(!sel)return;
    const cur=sel.value;
    const opts=['<option value="">All incoming</option>'];
    if(me.role==='super_admin')opts.push('<option value="__all__">All system mail (super)</option>');
    myAliases.forEach(a=>opts.push(`<option value="${esc(a.alias)}">${esc(a.alias)}</option>`));
    sel.innerHTML=opts.join('');
    if(cur)sel.value=cur;
  }catch(e){console.warn('alias filter load failed',e)}
}

function onAliasFilterChange(){
  const v=document.getElementById('aliasFilter').value;
  refresh(v);
}
// Address bar di inbox: highlight address aktif + tombol copy
function renderInboxAddr(addr){
  const bar=document.getElementById('inboxAddrBar');
  if(!bar)return;
  if(!addr || addr==='__all__'){bar.style.display='none';bar.innerHTML='';return;}
  const local=addr.split('@')[0]||addr;
  const dom=addr.split('@')[1]||'';
  const c=domainColor(dom);
  bar.style.display='flex';
  bar.style.setProperty('--addr-fg',c.fg);
  bar.style.setProperty('--addr-bg',c.bg);
  bar.style.setProperty('--addr-bd',c.bd);
  bar.innerHTML=`<span class="addrLabel">ADDRESS</span>`
    +`<code class="addrValue"><span class="aliasLocal">${esc(local)}</span><span class="aliasDom" style="color:${c.fg}">@${esc(dom)}</span></code>`
    +`<button class="addrCopy" onclick="copyText('${esc(addr).replace(/'/g,"\\'")}',this)" title="Copy address">`
    +`<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`
    +`<span>Copy</span></button>`;
}
function toast(s){let el=document.createElement('div');el.textContent=s;document.getElementById('toast').appendChild(el);setTimeout(()=>el.remove(),3300)}
function fmtTime(s){try{return new Date(s).toLocaleString()}catch(e){return s||''}}
function stripHtml(s){return String(s||'').replace(/<style[^>]*>[\s\S]*?<\/style>/gi,'').replace(/<script[^>]*>[\s\S]*?<\/script>/gi,'').replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/[a-zA-Z0-9_\-,.\s#:>*\[\]="']{2,80}\{[^{}]*\}/g,' ').replace(/@(media|font-face|keyframes|supports|import|charset)[^{]*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/gi,' ').replace(/\s+/g,' ').trim()}
async function status(){let s=await api('/api/status');domain=s.domain;let di=document.getElementById('domainInline'); if(di) di.textContent='*@'+s.domain;let e1=document.getElementById('stDomain');if(e1)e1.textContent=s.domain;let e2=document.getElementById('stMessages');if(e2)e2.textContent=s.messages;let e3=document.getElementById('stSmtp');if(e3)e3.textContent=s.smtp_port;let e4=document.getElementById('stAuth');if(e4)e4.textContent=s.auth?'ON':'OFF';let sm=document.getElementById('sideSmtp');if(sm)sm.textContent=':'+s.smtp_port;let smg=document.getElementById('sideMsg');if(smg)smg.textContent=s.messages;let sh=document.getElementById('sideHost');if(sh)sh.textContent=s.domain;return s}
function currentTo(){
  const sel=document.getElementById('aliasFilter');
  if(!sel)return '';
  const v=sel.value;
  if(v==='__all__')return '__SUPER_ALL__';
  return v;
}
async function refresh(filterOverride){
  try{
    await status();
    await loadMyAliasesIntoFilter();
    // Empty state: user belum punya alias dan bukan super_admin
    if(myAliases.length===0 && me.role!=='super_admin'){
      document.getElementById('inboxTitle').textContent='Inbox';
      renderInboxAddr('');
      document.getElementById('list').innerHTML=`<div class="empty">
        <div class="emptyIcon" style="font-size:36px">📭</div>
        <div style="font-size:15px;font-weight:600;color:var(--txt);margin:8px 0 4px">Belum punya alias</div>
        <div style="font-size:12px;color:var(--txt-3);max-width:340px;margin:0 auto 16px">Buat alias kustom atau generate random alias untuk mulai terima email.</div>
        <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
          <button class="btn green" onclick="openClaimAliasModal()">➕ Add Alias</button>
          <button class="btn" onclick="openClaimAliasModal('random')">🎲 Generate Random</button>
        </div>
      </div>`;
      return;
    }
    let sel=filterOverride!==undefined?filterOverride:currentTo();
    let qs='/api/messages?limit=80';
    let title='All incoming';
    if(sel && sel!=='__SUPER_ALL__'){qs+='&to='+encodeURIComponent(sel);title='Inbox: '+sel;}
    if(sel==='__SUPER_ALL__'){title='All system mail';}
    renderInboxAddr((sel && sel!=='__SUPER_ALL__')?sel:'');
    let j=await api(qs);
    document.getElementById('inboxTitle').textContent=title;
    document.getElementById('list').innerHTML=j.messages.map(m=>{
      const raw=m.preview||'';
      const isHtml=/<\/?[a-z][^>]*>/i.test(raw)||/\{[^{}]*:[^{}]*\}/.test(raw)||/@(media|keyframes|font-face)/i.test(raw);
      const cleanPreview=isHtml?stripHtml(raw):raw;
      const tag=isHtml?'<span class="htmlTag">HTML</span>':'';
      return `<article class="msg" data-id="${m.id}" onclick="loadMsg(${m.id})"><div class="msgTop"><div class="subject">${esc(m.subject||'(no subject)')}${tag}</div><div class="time">#${m.id}</div></div><div class="meta">${esc(m.from)} → ${colorAddr(m.rcpt_to)}<br>${esc(fmtTime(m.received_at))}</div><div class="preview">${esc(cleanPreview)}</div></article>`;
    }).join('')||'<div class="empty"><div class="emptyIcon">📭</div><div>Belum ada email masuk<br><span style="font-size:11px;color:var(--txt-4)">Email akan muncul di sini secara real-time</span></div></div>';
  }catch(e){
    document.getElementById('list').innerHTML='<div class="empty bad"><div class="emptyIcon">⚠</div><div>'+esc(e.message)+'</div></div>';
    toast('Error: '+e.message);
  }
}
function linkify(s){return String(s||'').replace(/(https?:\/\/[^\s<>"']+)/g,m=>`<a href="${m}" target="_blank" rel="noopener noreferrer">${m}</a>`)}
function injectBaseTarget(html){
  // Force semua link di HTML email buka di tab baru, bukan replace iframe.
  const base='<base target="_blank">';
  if(/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i,m=>m+base);
  if(/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i,m=>m+'<head>'+base+'</head>');
  return base+html;
}
function renderBody(m,mode){
  if(mode==='raw'){return `<pre class="bodybox bodyRaw">${esc(m.raw||'')}</pre>`}
  if(mode==='text'&&m.text_body){return `<div class="bodybox bodyText">${linkify(esc(m.text_body))}</div>`}
  if(m.html_body){const srcdoc=injectBaseTarget(m.html_body).replace(/&/g,'&amp;').replace(/"/g,'&quot;');return `<iframe class="bodyFrame" sandbox="allow-popups allow-popups-to-escape-sandbox" srcdoc="${srcdoc}"></iframe>`}
  if(m.text_body){return `<div class="bodybox bodyText">${linkify(esc(m.text_body))}</div>`}
  return `<div class="empty">No body content.</div>`;
}
let currentMsg=null;
function setBodyMode(mode){
  if(!currentMsg) return;
  document.getElementById('bodySlot').innerHTML=renderBody(currentMsg,mode);
  document.querySelectorAll('.bodyTab').forEach(b=>b.classList.toggle('active',b.dataset.mode===mode));
}
async function loadMsg(id){
  try{
    document.querySelectorAll('.msg').forEach(el=>el.classList.toggle('selected',el.dataset.id==String(id)));
    const m=await api('/api/messages/'+id);
    currentMsg=m;
    document.getElementById('selectedPill').textContent='#'+m.id;
    const detail=document.getElementById('detail');
    detail.className='';
    const hasHtml=!!m.html_body, hasText=!!m.text_body;
    const defaultMode=hasHtml?'html':(hasText?'text':'raw');
    const tabsHtml=`<div class="bodyTabs">${hasHtml?'<button type="button" class="bodyTab" data-mode="html">HTML</button>':''}${hasText?'<button type="button" class="bodyTab" data-mode="text">Text</button>':''}<button type="button" class="bodyTab" data-mode="raw">Raw</button></div>`;
    detail.innerHTML=`<h2 class="mailTitle">${esc(m.subject||'(no subject)')}</h2><div class="mailMeta"><div><b>From</b> ${esc(m.from)}</div><div><b>To</b> ${colorAddr(m.rcpt_to)}</div><div><b>Received</b> ${esc(fmtTime(m.received_at))}</div></div>${tabsHtml}<div id="bodySlot"></div>`;
    detail.querySelectorAll('.bodyTab').forEach(b=>b.addEventListener('click',()=>setBodyMode(b.dataset.mode)));
    setBodyMode(defaultMode);
  }catch(e){
    document.getElementById('detail').innerHTML='<div class="empty bad">'+esc(e.message)+'</div>';
  }
}
async function copyToken(){
  const t=me.api_token||'';
  if(!t){toast('No token');return}
  try{await navigator.clipboard.writeText(t);toast('Token copied!')}catch(e){
    const el=document.createElement('textarea');el.value=t;document.body.appendChild(el);el.select();document.execCommand('copy');document.body.removeChild(el);toast('Token copied!')
  }
}
function showToken(){
  const t=me.api_token||'';
  const box=document.getElementById('apiTokenBox');
  if(box) box.textContent = tokenVisible ? t : (t ? '●'.repeat(t.length) : '— no token —');
}
async function regenToken(){
  if(!confirm('Generate new token? Token lama langsung mati.'))return;
  try{
    const r=await api('/api/regen-token',{method:'POST'});
    me.api_token=r.api_token;
    showToken();
    toast('New token generated!');
  }catch(e){toast('Error: '+e.message)}
}
let tokenVisible=false;
function toggleTokenVis(){
  tokenVisible=!tokenVisible;
  const box=document.getElementById('apiTokenBox');
  const btn=document.getElementById('btnToggleEye');
  if(box&&me.api_token){
    box.textContent=tokenVisible?me.api_token:'●'.repeat(me.api_token.length);
    if(btn)btn.textContent=tokenVisible?'🙈 Hide':'👁 Show';
  }
}
function toggleSec(id){
  const el=document.getElementById(id);
  if(el)el.classList.toggle('open');
}
function copyBlock(btn){
  const pre=btn.parentElement.querySelector('.apiCode');
  if(!pre)return;
  navigator.clipboard.writeText(pre.textContent).then(()=>toast('Copied!')).catch(()=>{
    const t=document.createElement('textarea');t.value=pre.textContent;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);toast('Copied!')
  });
}

// === ROLE & DOMAIN STATE ===
let me={username:'',role:''};
let availDomains=[];
async function loadMe(){try{me=await api('/api/whoami')}catch(e){me={username:'?',role:'user'}}return me}
function applyRoleVisibility(){
  const r=me.role;
  document.querySelectorAll('[data-need]').forEach(el=>{
    const need=el.dataset.need;
    let ok=false;
    if(need==='super')ok=(r==='super_admin');
    else if(need==='admin')ok=(r==='super_admin'||r==='admin');
    el.style.display=ok?'':'none';
  });
  // role pill text
  const rp=document.getElementById('rolePill');
  if(rp)rp.innerHTML='<span class="dot"></span> '+r;
  // user badge di header
  const un=document.getElementById('ubName'); if(un) un.textContent=me.username||'?';
  const ur=document.getElementById('ubRole'); if(ur) ur.textContent=(me.role||'').replace('_',' ');
  const ua=document.getElementById('ubAvatar'); if(ua) ua.textContent=(me.username||'?')[0]||'?';
  // hide admin option in role select kalau bukan super
  const ru=document.getElementById('newUserRole');
  if(ru){
    [...ru.options].forEach(o=>{ if(o.value==='admin'){o.disabled=(r!=='super_admin');o.hidden=(r!=='super_admin')} });
  }
}
function refreshDomainSelect(){
  const sel=document.getElementById('aliasDomain'); if(!sel) return;
  sel.innerHTML=availDomains.map(d=>`<option value="${d.domain}">${d.domain}${d.mode==='private'?' (private)':''}</option>`).join('');
}

// === ALIAS PAGE ===
// mode: 'custom' (default) atau 'random' — cuma beda default focus & tombol utama
function openClaimAliasModal(mode){
  // Kumpulkan domain yang tersedia (dari availDomains, fallback global domain)
  const doms = (availDomains&&availDomains.length)?availDomains:[{domain:domain,mode:'public'}];
  const chips = doms.map((d,i)=>`
    <label class="domChip${i===0?' on':''}">
      <input type="radio" name="aliasDom" value="${esc(d.domain)}"${i===0?' checked':''} onchange="syncDomChips()">
      <span class="domChip-at">@</span><span class="domChip-name">${esc(d.domain)}</span>
      ${d.mode==='private'?'<span class="domChip-tag">private</span>':''}
    </label>`).join('');
  openModal({
    icon:'✦',title:'New Email Address',sub:'pilih domain, lalu random atau custom',
    body:`<div class="claimWrap">
      <div class="claimField">
        <label>Domain</label>
        <div class="domChips" id="domChips">${chips}</div>
      </div>
      <div class="claimField">
        <label>Nama alias <span style="color:var(--txt-3);font-weight:400">— kosongkan untuk random</span></label>
        <div class="aliasInputRow">
          <input class="input" id="mAliasLocal" placeholder="contoh: telegram, otp, belanja" autocomplete="off" oninput="updatePreview()">
          <button class="btn" type="button" onclick="genRandomLocal()" title="Acak nama">🎲</button>
        </div>
      </div>
      <div class="claimPreview" id="aliasPreview">
        <span class="claimPreview-label">Preview</span>
        <code id="aliasPreviewVal">—</code>
        <button class="claimPreview-copy" type="button" onclick="copyPreview()" title="Copy">⧉</button>
      </div>
      <div id="mAliasErr" class="claimErr" style="display:none"></div>
    </div>`,
    foot:`
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn green" onclick="claimAliasFromModal()">✓ Buat Alias</button>
    `,
  });
  syncDomChips();
  updatePreview();
  if(mode!=='random') setTimeout(()=>document.getElementById('mAliasLocal')?.focus(),120);
}

function selectedAliasDomain(){
  const r=document.querySelector('input[name="aliasDom"]:checked');
  return r?r.value:(domain||'');
}
function syncDomChips(){
  document.querySelectorAll('#domChips .domChip').forEach(l=>{
    const on=l.querySelector('input').checked;
    l.classList.toggle('on',on);
  });
  updatePreview();
}
function genRandomLocal(){
  const c='abcdefghijklmnopqrstuvwxyz0123456789';
  let s='';for(let i=0;i<10;i++)s+=c[Math.floor(Math.random()*c.length)];
  const el=document.getElementById('mAliasLocal'); if(el){el.value=s;updatePreview()}
}
function updatePreview(){
  const local=(document.getElementById('mAliasLocal')?.value||'').trim().toLowerCase();
  const dom=selectedAliasDomain();
  const shown=local?local:'(random saat dibuat)';
  const el=document.getElementById('aliasPreviewVal');
  if(el) el.textContent=shown+'@'+dom;
}
function copyPreview(){
  const local=(document.getElementById('mAliasLocal')?.value||'').trim().toLowerCase();
  if(!local){toast('Isi nama alias dulu untuk copy');return}
  navigator.clipboard?.writeText(local+'@'+selectedAliasDomain());
  toast('Copied');
}

async function claimAliasFromModal(){
  const local=(document.getElementById('mAliasLocal')?.value||'').trim().toLowerCase();
  const domain=selectedAliasDomain();
  const err=document.getElementById('mAliasErr');
  err.style.display='none';
  const kind=local?'custom':'random';
  try{
    const body=kind==='random'?{kind:'random',domain}:{kind:'custom',local,domain};
    const j=await api('/api/aliases',{method:'POST',body:JSON.stringify(body)});
    closeModal();
    showAliasCreatedModal(j.alias,kind);
    loadAliases();
    if(typeof loadMyAliasesIntoFilter==='function')loadMyAliasesIntoFilter();
  }catch(e){err.textContent=e.message;err.style.display='block'}
}

function showAliasCreatedModal(alias,kind){
  openModal({
    icon:'✨',title:'Alias Created',sub:kind==='random'?'auto-generated 10 char':'custom alias',
    body:`<div>
      <label>Your new email address</label>
      ${copyRow(alias,'Copy')}
    </div>
    <div style="font-size:11.5px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;line-height:1.6">
      Email yang dikirim ke <b style="color:var(--accent)">${esc(alias)}</b> akan masuk ke inbox kamu otomatis.
    </div>`,
    foot:`<button class="btn green" onclick="closeModal();window.location.hash='#inbox'">📥 Go to Inbox</button>`,
  });
}

function deleteAliasIt(alias){
  openModal({
    icon:'🗑',title:'Delete Alias?',sub:'aksi tidak dapat dibatalkan',
    body:`<div style="padding:11px 14px;border-radius:11px;background:rgba(255,92,92,.06);border:1px solid rgba(255,92,92,.20);color:#ff9a9a;font-size:13px">
      Alias <b style="font-family:'JetBrains Mono',monospace;color:#ff8a8a">${esc(alias)}</b> akan dihapus permanen. Email yang sudah masuk tetap di inbox.
    </div>`,
    foot:`
      <button class="btn" onclick="closeModal()">Batal</button>
      <button class="btn" style="background:linear-gradient(135deg,rgba(255,92,92,.30),rgba(255,61,139,.18));color:#fff;border-color:rgba(255,92,92,.45)" onclick="confirmDeleteAlias('${esc(alias).replace(/'/g,"\\'")}')">🗑 Hapus</button>
    `,
  });
}

async function confirmDeleteAlias(alias){
  try{
    await api('/api/aliases/'+encodeURIComponent(alias),{method:'DELETE'});
    closeModal();
    toast('Deleted '+alias);
    loadAliases();
    if(typeof loadMyAliasesIntoFilter==='function')loadMyAliasesIntoFilter();
  }catch(e){toast('Error: '+e.message)}
}

async function loadAliases(){
  try{
    const j=await api('/api/aliases');
    const lim=j.custom_limit||3;
    const used=(j.aliases||[]).filter(a=>a.kind==='custom').length;
    const tot=(j.aliases||[]).length;
    const meta=`<div style="display:flex;gap:14px;align-items:center;padding:0 0 14px;font-family:'JetBrains Mono',monospace;font-size:11.5px"><span style="color:var(--txt-3)">CUSTOM <b style="color:${used>=lim?'var(--warn)':'var(--accent)'}">${used}/${lim}</b></span><span style="color:var(--txt-3)">TOTAL <b style="color:var(--accent)">${tot}</b></span></div>`;
    const list=(j.aliases||[]).map(a=>{
      const dom=a.domain||(a.alias.split('@')[1]||'');
      const local=a.alias.split('@')[0]||a.alias;
      const c=domainColor(dom);
      const badge=`<span class="domBadge" style="color:${c.fg};background:${c.bg};border-color:${c.bd}">@${esc(dom)}</span>`;
      return `<div class="aliasItem">
      <div class="aliasMain">
        <code><span class="aliasLocal">${esc(local)}</span><span class="aliasDom" style="color:${c.fg}">@${esc(dom)}</span></code>
        <div class="aliasMeta"><span class="kindTag ${a.kind}">${a.kind}</span>${badge}<span>${esc(a.created_at||'').replace('T',' ').slice(0,19)}</span></div>
      </div>
      <button class="iconBtn" onclick="copyText('${esc(a.alias).replace(/'/g,"\\'")}',this)" title="Copy">📋</button>
      <button class="iconBtn danger" onclick="deleteAliasIt('${esc(a.alias).replace(/'/g,"\\'")}')" title="Delete">🗑</button>
    </div>`;}).join('')||'<div class="empty"><div class="emptyIcon">📭</div><div>Belum punya alias.<br><span style="font-size:11px;color:var(--txt-4)">Klik tombol di atas untuk claim.</span></div></div>';
    document.getElementById('aliasList').innerHTML=meta+'<div class="aliasGrid">'+list+'</div>';
  }catch(e){document.getElementById('aliasList').innerHTML='<div class="empty bad">'+esc(e.message)+'</div>'}
}

// === USERS PAGE ===
function openAddUserModal(){
  const roleOpts=me.role==='super_admin'?'<option value="user">user</option><option value="admin">admin</option>':'<option value="user">user</option>';
  openModal({
    icon:'➕',title:'Add User',sub:'password default = Baba...',
    body:`<div>
      <label>Username</label>
      <input class="input" id="mUserName" placeholder="username (lowercase)" autocomplete="off">
    </div>
    <div>
      <label>Role</label>
      <select id="mUserRole" class="input" style="cursor:pointer">${roleOpts}</select>
    </div>
    <div style="padding:9px 12px;border-radius:8px;background:var(--accent-dim);border:1px solid rgba(99,102,241,.15);color:var(--accent);font-size:11.5px;font-family:'JetBrains Mono',monospace;line-height:1.55">
      ⓘ User akan dapat password default <b style="color:var(--accent)">Baba...</b> dan WAJIB ganti saat first login.
    </div>
    <div id="mUserErr" style="display:none;padding:9px 12px;border-radius:8px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#fca5a5;font-size:12px;font-family:'JetBrains Mono',monospace"></div>`,
    foot:`
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn green" onclick="submitAddUser()">✓ Create User</button>
    `,
  });
  setTimeout(()=>document.getElementById('mUserName')?.focus(),120);
}

async function submitAddUser(){
  const username=(document.getElementById('mUserName')?.value||'').trim().toLowerCase();
  const role=document.getElementById('mUserRole')?.value||'user';
  const err=document.getElementById('mUserErr');
  err.style.display='none';
  if(!username){err.textContent='Username wajib diisi.';err.style.display='block';return}
  try{
    const j=await api('/api/users',{method:'POST',body:JSON.stringify({username,role})});
    closeModal();
    showUserCreatedModal(j);
    loadUsers();
  }catch(e){err.textContent=e.message;err.style.display='block'}
}

function showUserCreatedModal(j){
  openModal({
    icon:'🎉',title:'User Created',sub:`role: ${j.role}`,
    body:`<div>
      <label>Username</label>
      ${copyRow(j.username,'Copy')}
    </div>
    <div>
      <label>Initial Password</label>
      ${copyRow(j.initial_password,'Copy')}
    </div>
    <div>
      <label>Login URL</label>
      ${copyRow(location.origin+'/login','Copy')}
    </div>
    <div style="padding:11px 14px;border-radius:11px;background:rgba(255,180,84,.07);border:1px solid rgba(255,180,84,.22);color:#ffb454;font-size:11.5px;font-family:'JetBrains Mono',monospace;line-height:1.55">
      ⚠ User ini WAJIB ganti password saat first login. Password tidak akan ditampilkan lagi setelah modal ditutup.
    </div>`,
    foot:`
      <button class="btn" onclick="copyText('Login: ${location.origin}/login\\nUsername: ${esc(j.username)}\\nPassword: ${esc(j.initial_password)}',this)">📋 Copy All</button>
      <button class="btn green" onclick="closeModal()">✓ Done</button>
    `,
  });
}

async function loadUsers(){
  try{
    const j=await api('/api/users');
    document.getElementById('userList').innerHTML=(j.users||[]).map(u=>{
      const lockBtn=(me.role==='super_admin'&&u.role!=='super_admin')?(u.locked?`<button class="iconBtn" onclick="openUnlockModal('${esc(u.username).replace(/'/g,"\\'")}')" title="Unlock">🔓</button>`:`<button class="iconBtn" onclick="openLockModal('${esc(u.username).replace(/'/g,"\\'")}')" title="Lock">🔒</button>`):'';
      const delBtn=(me.role==='super_admin'&&u.role!=='super_admin')?`<button class="iconBtn danger" onclick="openDeleteUserModal('${esc(u.username).replace(/'/g,"\\'")}')" title="Delete">🗑</button>`:'';
      const pwBtn=(me.role==='super_admin'&&u.role!=='super_admin')?`<button class="iconBtn" onclick="openResetPwModal('${esc(u.username).replace(/'/g,"\\'")}')" title="Reset password">🔑</button>`:'';
      const tag=u.locked?'<span class="htmlTag" style="background:rgba(255,92,92,.18);color:#ff8a8a;border-color:rgba(255,92,92,.4)">LOCKED</span>':(u.must_change_password?'<span class="htmlTag" style="background:rgba(255,180,84,.15);color:#ffb454">MUST CHANGE PW</span>':'');
      const reason=u.lock_reason?`<br>Lock reason: <i>${esc(u.lock_reason)}</i>`:'';
      return `<article class="msg"><div class="msgTop"><div class="subject">${esc(u.username)} <span class="htmlTag">${u.role}</span>${tag}</div><div style="display:flex;gap:6px">${pwBtn}${lockBtn}${delBtn}</div></div><div class="meta">created ${esc(u.created_at)} · by ${esc(u.created_by||'-')} · last login ${esc(u.last_login_at||'never')}${reason}</div></article>`;
    }).join('')||'<div class="empty"><div class="emptyIcon">👥</div><div>No users</div></div>';
  }catch(e){document.getElementById('userList').innerHTML='<div class="empty bad">'+esc(e.message)+'</div>'}
}

function openLockModal(u){
  openModal({
    icon:'🔒',title:'Lock User',sub:u,
    body:`<div>
      <label>Alasan lock (wajib)</label>
      <input class="input" id="mLockReason" placeholder="contoh: suspicious activity" autocomplete="off">
    </div>`,
    foot:`<button class="btn" onclick="closeModal()">Batal</button><button class="btn green" onclick="submitLock('${esc(u).replace(/'/g,"\\'")}')">🔒 Lock</button>`,
  });
  setTimeout(()=>document.getElementById('mLockReason')?.focus(),120);
}
async function submitLock(u){
  const reason=(document.getElementById('mLockReason')?.value||'').trim();
  if(!reason){toast('Alasan wajib');return}
  try{await api('/api/users/'+u+'/lock',{method:'POST',body:JSON.stringify({reason})});closeModal();toast('Locked '+u);loadUsers()}catch(e){toast('Error: '+e.message)}
}
function openUnlockModal(u){
  openModal({
    icon:'🔓',title:'Unlock User',sub:u,
    body:`<div>
      <label>Alasan unlock (opsional)</label>
      <input class="input" id="mUnlockReason" placeholder="manual unlock" autocomplete="off">
    </div>`,
    foot:`<button class="btn" onclick="closeModal()">Batal</button><button class="btn green" onclick="submitUnlock('${esc(u).replace(/'/g,"\\'")}')">🔓 Unlock</button>`,
  });
}
async function submitUnlock(u){
  const reason=(document.getElementById('mUnlockReason')?.value||'').trim()||'manual unlock';
  try{await api('/api/users/'+u+'/unlock',{method:'POST',body:JSON.stringify({reason})});closeModal();toast('Unlocked '+u);loadUsers()}catch(e){toast('Error: '+e.message)}
}
function openDeleteUserModal(u){
  openModal({
    icon:'🗑',title:'Delete User?',sub:u,
    body:`<div style="padding:11px 14px;border-radius:11px;background:rgba(255,92,92,.06);border:1px solid rgba(255,92,92,.20);color:#ff9a9a;font-size:13px;line-height:1.55">
      User <b>${esc(u)}</b> akan dihapus permanen — alias, session, dan email yang dia miliki ikut hilang.
    </div>
    <div>
      <label>Alasan delete (wajib)</label>
      <input class="input" id="mDelReason" placeholder="contoh: tidak aktif lagi" autocomplete="off">
    </div>`,
    foot:`<button class="btn" onclick="closeModal()">Batal</button><button class="btn" style="background:linear-gradient(135deg,rgba(255,92,92,.30),rgba(255,61,139,.18));color:#fff;border-color:rgba(255,92,92,.45)" onclick="submitDelete('${esc(u).replace(/'/g,"\\'")}')">🗑 Delete</button>`,
  });
}
async function submitDelete(u){
  const reason=(document.getElementById('mDelReason')?.value||'').trim();
  if(!reason){toast('Alasan wajib');return}
  try{await api('/api/users/'+u,{method:'DELETE',body:JSON.stringify({reason})});closeModal();toast('Deleted '+u);loadUsers()}catch(e){toast('Error: '+e.message)}
}
function openResetPwModal(u){
  openModal({
    icon:'🔑',title:'Reset Password?',sub:u,
    body:`<div style="padding:11px 14px;border-radius:8px;background:var(--accent-dim);border:1px solid rgba(99,102,241,.15);color:var(--accent);font-size:12.5px;line-height:1.55">
      Password ${esc(u)} akan direset ke <b style="color:var(--accent)">Baba...</b> dan dia harus ganti saat next login.
    </div>`,
    foot:`<button class="btn" onclick="closeModal()">Batal</button><button class="btn green" onclick="submitResetPw('${esc(u).replace(/'/g,"\\'")}')">🔑 Reset</button>`,
  });
}
async function submitResetPw(u){
  try{
    const j=await api('/api/users/'+u+'/password',{method:'POST',body:JSON.stringify({})});
    closeModal();
    openModal({
      icon:'🎉',title:'Password Reset',sub:u,
      body:`<div>
        <label>New Password</label>
        ${copyRow(j.new_password,'Copy')}
      </div>
      <div style="padding:9px 12px;border-radius:9px;background:rgba(255,180,84,.07);border:1px solid rgba(255,180,84,.22);color:#ffb454;font-size:11.5px;font-family:'JetBrains Mono',monospace">
        ⚠ User wajib ganti password saat next login.
      </div>`,
      foot:`<button class="btn green" onclick="closeModal()">✓ Done</button>`,
    });
    loadUsers();
  }catch(e){toast('Error: '+e.message)}
}

// === DOMAINS PAGE ===
async function addDomain(){
  const domain=(document.getElementById('newDomain').value||'').trim();
  const mode=document.getElementById('newDomainMode').value;
  const owner=(document.getElementById('newDomainOwner').value||'').trim();
  const result=document.getElementById('newDomainResult');
  if(!domain){result.innerHTML='<span style="color:#ff8a8a">⚠ Masukkan nama domain</span>';return}
  result.innerHTML='<span style="color:var(--accent)">⏳ Memverifikasi DNS...</span>';
  try{
    const j=await api('/api/domains',{method:'POST',body:JSON.stringify({domain,mode,owner})});
    result.innerHTML='<span style="color:#6be585">✓ Domain <b>'+esc(j.domain)+'</b> berhasil ditambahkan</span>';
    document.getElementById('newDomain').value='';
    document.getElementById('newDomainOwner').value='';
    toast('Domain '+j.domain+' added');
    loadDomains();status();
  }catch(e){
    let msg=e.message||'Unknown error';
    const j=e.data||{};
    if(j.checks||j.steps||j.details){
      const ck=j.checks||[];
      const st=j.steps||[];
      let html='<div style="border:1px solid rgba(255,92,92,.22);border-radius:10px;overflow:hidden;font-size:12.5px">';
      html+='<div style="padding:10px 14px;background:rgba(255,92,92,.10);color:#ff8a8a;font-weight:600">⚠ '+esc(j.error||'Domain belum siap dipakai')+'</div>';
      if(ck.length){
        html+='<table style="width:100%;border-collapse:collapse">';
        ck.forEach(c=>{
          const icon=c.ok?'<span style="color:#6be585">✓</span>':'<span style="color:#ff8a8a">✕</span>';
          const vcol=c.ok?'rgba(255,255,255,.55)':'#ffb454';
          html+='<tr style="border-top:1px solid rgba(255,255,255,.06)">'
              +'<td style="padding:8px 14px;width:24px;text-align:center">'+icon+'</td>'
              +'<td style="padding:8px 6px;color:rgba(255,255,255,.78)">'+esc(c.label)+'</td>'
              +'<td style="padding:8px 14px;text-align:right;color:'+vcol+'">'+esc(c.value)+'</td>'
              +'</tr>';
        });
        html+='</table>';
      } else if(j.details&&j.details.length){
        html+='<div style="padding:8px 14px">';
        j.details.forEach(d=>{html+='<div style="color:#ffb454">• '+esc(d)+'</div>'});
        html+='</div>';
      }
      if(st.length){
        html+='<div style="padding:10px 14px;border-top:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.02)">';
        html+='<div style="font-weight:600;color:#ffd27a;margin-bottom:6px">Cara memperbaiki:</div>';
        html+='<ol style="margin:0;padding-left:18px;color:rgba(255,255,255,.72);line-height:1.7">';
        st.forEach(s=>{html+='<li>'+esc(s)+'</li>'});
        html+='</ol></div>';
      } else if(j.fixes&&j.fixes.length){
        html+='<div style="padding:10px 14px;border-top:1px solid rgba(255,255,255,.08)">';
        j.fixes.forEach(f=>{html+='<div style="color:#ffb454">→ '+esc(f)+'</div>'});
        html+='</div>';
      }
      html+='</div>';
      result.innerHTML=html;
      toast('Error: '+(j.error||msg));
      return;
    }
    result.innerHTML='<span style="color:#ff8a8a">⚠ '+esc(msg)+'</span>';
    toast('Error: '+msg);
  }
}
async function loadDomains(){
  try{
    const j=await api('/api/domains');
    document.getElementById('domainList').innerHTML=(j.domains||[]).map(d=>{
      const tag=`<span class="htmlTag">${d.mode}</span>${d.enabled?'':'<span class="htmlTag" style="background:rgba(255,92,92,.18);color:#ff8a8a">DISABLED</span>'}`;
      const toggle=`<button class="btn" onclick="toggleDomain('${esc(d.domain)}',${!d.enabled})">${d.enabled?'⏸ Disable':'▶ Enable'}</button>`;
      const modeBtn=d.mode==='public'?`<button class="btn" onclick="setDomainMode('${esc(d.domain)}','private')">→ Private</button>`:`<button class="btn" onclick="setDomainMode('${esc(d.domain)}','public')">→ Public</button>`;
      const del=`<button class="btn" onclick="delDomain('${esc(d.domain)}')">🗑</button>`;
      return `<article class="msg"><div class="msgTop"><div class="subject">${esc(d.domain)} ${tag}</div><div>${modeBtn} ${toggle} ${del}</div></div><div class="meta">added ${esc(d.added_at)} · by ${esc(d.added_by||'-')} · owner ${esc(d.owner||'-')}</div></article>`;
    }).join('')||'<div class="empty"><div class="emptyIcon">🌐</div><div>No domains</div></div>';
  }catch(e){document.getElementById('domainList').innerHTML='<div class="empty bad">'+esc(e.message)+'</div>'}
}
async function toggleDomain(d,enabled){try{await api('/api/domains/'+d,{method:'POST',body:JSON.stringify({enabled})});toast(d+' '+(enabled?'enabled':'disabled'));loadDomains()}catch(e){toast(e.message)}}
async function setDomainMode(d,mode){try{await api('/api/domains/'+d,{method:'POST',body:JSON.stringify({mode})});toast(d+' → '+mode);loadDomains()}catch(e){toast(e.message)}}
async function delDomain(d){if(!confirm('Hapus domain '+d+' ? (Alias-nya harus kosong dulu)')) return;try{await api('/api/domains/'+d,{method:'DELETE'});toast('Deleted '+d);loadDomains()}catch(e){toast('Error: '+e.message)}}

// === AUDIT PAGE ===
let _auditUsersLoaded=false;
let _auditDebounce=null;
async function fillAuditUsers(){
  // isi <datalist> saran nama user dari /api/users (sekali saja)
  const dl=document.getElementById('auditUserList');
  if(!dl || _auditUsersLoaded) return;
  try{
    const j=await api('/api/users');
    const names=(j.users||[]).map(u=>u.username).sort();
    dl.innerHTML=names.map(n=>`<option value="${esc(n)}">`).join('');
    _auditUsersLoaded=true;
  }catch(e){/* non-super admin bisa gagal di /api/users, abaikan */}
}
function onAuditUserInput(){
  // debounce 300ms biar nggak spam request tiap ketik
  clearTimeout(_auditDebounce);
  _auditDebounce=setTimeout(loadAudit,300);
}
async function loadAudit(){
  fillAuditUsers();
  const user=((document.getElementById('auditUser')||{}).value||'').trim();
  const action=(document.getElementById('auditAction')||{}).value||'';
  const qp=new URLSearchParams({limit:'200'});
  if(user) qp.set('user',user);
  if(action) qp.set('action',action);
  try{
    const j=await api('/api/audit?'+qp.toString());
    document.getElementById('auditList').innerHTML=(j.audit||[]).map(r=>{
      const meta=Object.keys(r.meta||{}).length?` <span class="htmlTag" style="background:rgba(255,255,255,.04)">${esc(JSON.stringify(r.meta))}</span>`:'';
      const reason=r.reason?`<br>reason: <i>${esc(r.reason)}</i>`:'';
      const actorTag=`<span class="actorTag" title="actor">${esc(r.actor)}</span>`;
      return `<article class="msg"><div class="msgTop"><div class="subject"><b>${esc(r.action)}</b> → ${esc(r.target||'-')} ${actorTag}</div><div class="time">#${r.id}</div></div><div class="meta">${esc(r.ts)}${meta}${reason}</div></article>`;
    }).join('')||`<div class="empty"><div class="emptyIcon">📜</div><div>No audit entries${(user||action)?' match the filter':''}</div></div>`;
  }catch(e){document.getElementById('auditList').innerHTML='<div class="empty bad">'+esc(e.message)+'</div>'}
}
function clearAuditFilter(){
  const u=document.getElementById('auditUser'); if(u) u.value='';
  const a=document.getElementById('auditAction'); if(a) a.value='';
  loadAudit();
}

// === PASSWORD VALIDATOR ===
function _checkPw(pw){
  return {
    len: pw.length>=8,
    upper: /[A-Z]/.test(pw),
    digit: /\d/.test(pw),
    symbol: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw)
  };
}
function validatePw(inputId, rulesId, strengthId){
  const pw=document.getElementById(inputId).value;
  const c=_checkPw(pw);
  const ul=document.getElementById(rulesId);
  if(ul){
    [...ul.children].forEach(li=>{ const k=li.dataset.rule; li.classList.toggle('ok', !!c[k]) });
  }
  const score=Object.values(c).filter(Boolean).length;
  const bar=document.querySelector('#'+strengthId+' .bar');
  if(bar){
    bar.style.width=(score*25)+'%';
    bar.style.background=score<2?'var(--danger)':score<4?'var(--warning)':'var(--success)';
  }
  return Object.values(c).every(Boolean);
}

async function submitChangePw(){
  const cur=document.getElementById('cpCurrent').value;
  const npw=document.getElementById('cpNew').value;
  const conf=document.getElementById('cpConfirm').value;
  const div=document.getElementById('cpResult');
  if(!validatePw('cpNew','cpRules','cpStrength')){
    div.textContent='Password baru belum memenuhi semua syarat.'; toast('Belum valid'); return;
  }
  if(npw!==conf){ div.textContent='Konfirmasi password tidak cocok.'; toast('Tidak cocok'); return; }
  // first-login flow tidak butuh current pw, tapi self-service butuh
  const body=me.must_change_password?{new:npw,confirm:conf}:{current:cur,new:npw,confirm:conf};
  try{
    const r=await fetch('/change-password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    if(r.redirected||r.ok){
      div.textContent='✓ Password updated. Silakan re-login.';
      toast('Password berhasil diganti');
      setTimeout(()=>location.href='/login',1200);
    }else{
      const t=await r.text();
      const m=t.match(/class="err"[^>]*>([^<]+)/);
      div.textContent=m?m[1]:'Update gagal.'; toast(m?m[1]:'Update gagal');
    }
  }catch(e){ div.textContent=e.message; toast('Error: '+e.message) }
}

const pageMeta={
  inbox:['Inbox','Tangkap email ke <b>*@DOMAIN</b>, baca isinya, ambil OTP via API.'],
  aliases:['Aliases','Claim alias kustom (max 3) atau random unlimited. 1 alias = 1 owner.'],
  'users-add':['Add User','Tambah user baru. Password default <b>Baba...</b>, wajib ganti saat login pertama.'],
  'users-manage':['Lock / Delete','Kelola user — lock/unlock dengan alasan, hapus akun, reset password.'],
  'users-log':['User Log','Jejak admin: add/delete/lock/unlock dengan actor di-highlight & timestamp.'],
  domains:['Domains','Tambah domain custom. public = semua bisa pakai · private = owner only.'],
  'change-pw':['Change Password','Ganti password sendiri. Syarat: 8+ chars, 1 KAPITAL, 1 angka, 1 simbol.'],
  api:['Bot API','Endpoint siap pakai: ready email, list inbox, wait latest OTP.'],
  status:['Status','Realtime SMTP receiver, total messages, retention, dan domain config.']
};
function route(){
  let page=(location.hash||'#inbox').replace('#','')||'inbox';
  if(page==='create') page='inbox';
  if(page==='users') page='users-add'; // backward compat
  if(page==='audit') page='users-log';
  if(!pageMeta[page]) page='inbox';
  // Block akses page yang butuh role lebih tinggi
  if(page.startsWith('users-')&&!(me.role==='super_admin'||me.role==='admin')) page='inbox';
  if(page==='domains'&&me.role!=='super_admin') page='inbox';
  document.querySelectorAll('.page').forEach(el=>el.classList.toggle('active',el.dataset.page===page));
  document.querySelectorAll('.nav a[data-page]').forEach(a=>a.classList.toggle('active',a.dataset.page===page));
  let meta=pageMeta[page];
  document.getElementById('pageTitle').textContent=meta[0];
  document.getElementById('pageSubtitle').innerHTML=meta[1].replace('DOMAIN',(domain||'domain'));
  if(page==='inbox') refresh();
  else if(page==='aliases') loadAliases();
  else if(page==='users-add'){/* no fetch needed */}
  else if(page==='users-manage') loadUsers();
  else if(page==='users-log') loadAudit();
  else if(page==='domains') loadDomains();
  else if(page==='change-pw'){
    // Self-service: butuh current. Force-change: hide current field
    const showCurrent=!me.must_change_password;
    document.getElementById('cpCurrent').parentElement.parentElement.style.display=showCurrent?'':'none';
    document.getElementById('cpResult').textContent=me.must_change_password?'⚠ Wajib ganti password (first login). Tidak perlu masukkan password lama.':'Password baru harus berbeda dari yang lama dan memenuhi semua syarat.';
  }
  else status().catch(e=>toast(e.message));
}
window.addEventListener('hashchange',route);
(async()=>{
  await loadMe();
  showToken();
  applyRoleVisibility();
  const s=await status().catch(e=>{toast(e.message);return{}});
  availDomains=s.domains||[{domain:domain}];
  refreshDomainSelect();
  route();
  refresh();
})();
setInterval(()=>{((location.hash||'#inbox').replace('#','')==='inbox')?refresh():status()},15000);

// === Mobile sidebar drawer ===
(function(){
  const btn = document.getElementById('menuBtn');
  const backdrop = document.getElementById('drawerBackdrop');
  const side = document.getElementById('sideDrawer');
  if(!btn||!backdrop||!side) return;
  const open = ()=>{document.body.classList.add('drawer-open'); btn.setAttribute('aria-expanded','true');};
  const close = ()=>{document.body.classList.remove('drawer-open'); btn.setAttribute('aria-expanded','false');};
  const toggle = ()=>document.body.classList.contains('drawer-open')?close():open();
  btn.addEventListener('click', toggle);
  backdrop.addEventListener('click', close);
  document.addEventListener('keydown', e=>{ if(e.key==='Escape') close(); });
  // Close drawer when a nav link is clicked on mobile
  side.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{
    if(window.matchMedia('(max-width:880px)').matches) close();
  }));
  // Reset on resize back to desktop
  window.addEventListener('resize',()=>{
    if(!window.matchMedia('(max-width:880px)').matches) close();
  });
})();
</script>
</body>
</html>
"""


LANDING_HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Veil · Disposable Email That Disappears</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2032%2032%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22g%22%20x1%3D%220%22%20y1%3D%220%22%20x2%3D%221%22%20y2%3D%221%22%3E%3Cstop%20offset%3D%220%22%20stop-color%3D%22%236d6af6%22/%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%238b5cf6%22/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect%20width%3D%2232%22%20height%3D%2232%22%20rx%3D%228%22%20fill%3D%22url%28%23g%29%22/%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22%23fff%22%20stroke-width%3D%222.2%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Crect%20x%3D%227%22%20y%3D%229%22%20width%3D%2218%22%20height%3D%2214%22%20rx%3D%222.5%22/%3E%3Cpath%20d%3D%22m7.5%2011%208.5%206%208.5-6%22/%3E%3C/g%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080b12;--bg-card:#0f1420;--bg-elevated:#161d2c;
  --border:#1c2536;--border-hover:#2c3a52;
  --text:#f4f6fb;--text-secondary:#9aa6bd;--text-muted:#5d6880;
  --accent:#6d6af6;--accent-2:#8b5cf6;--accent-hover:#5957e6;--accent-dim:rgba(109,106,246,.12);
  --success:#34d399;--warning:#fbbf24;--danger:#f87171;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
html,body{min-height:100%}
body{
  background:var(--bg);color:var(--text);position:relative;overflow-x:hidden;
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  -webkit-font-smoothing:antialiased;
}
.bg-glow{
  position:fixed;top:-280px;left:50%;transform:translateX(-50%);
  width:900px;height:700px;pointer-events:none;z-index:0;
  background:radial-gradient(circle at 50% 40%,rgba(109,106,246,.22),rgba(139,92,246,.10) 35%,transparent 68%);
  filter:blur(20px);
}
body>*{position:relative;z-index:1}
a{color:var(--accent);text-decoration:none}
/* NAV */
nav{
  display:flex;align-items:center;justify-content:space-between;
  max-width:1040px;margin:0 auto;padding:24px 24px;
}
.nav-logo{display:flex;align-items:center;gap:11px}
.nav-logo .mark{
  width:38px;height:38px;border-radius:11px;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  display:grid;place-items:center;
  box-shadow:0 6px 20px -6px rgba(109,106,246,.6);
}
.nav-logo h1{font-size:19px;font-weight:700;letter-spacing:-.4px}
.nav-btn{
  display:inline-flex;align-items:center;gap:6px;
  padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;
  background:rgba(255,255,255,.04);color:var(--text);
  border:1px solid var(--border);cursor:pointer;
  transition:all .18s ease;
}
.nav-btn:hover{background:rgba(255,255,255,.08);border-color:var(--border-hover);transform:translateY(-1px)}

/* HERO */
.hero{max-width:760px;margin:0 auto;padding:64px 24px 40px;text-align:center}
.badge{
  display:inline-flex;align-items:center;gap:8px;
  padding:7px 15px;border-radius:99px;margin-bottom:28px;
  background:rgba(255,255,255,.04);border:1px solid var(--border);
  font-size:12.5px;font-weight:500;color:var(--text-secondary);
  font-family:'JetBrains Mono',monospace;letter-spacing:-.2px;
}
.pulse{width:7px;height:7px;border-radius:50%;background:var(--success);box-shadow:0 0 0 0 rgba(52,211,153,.6);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.5)}70%{box-shadow:0 0 0 7px rgba(52,211,153,0)}100%{box-shadow:0 0 0 0 rgba(52,211,153,0)}}
.hero h2{
  font-size:54px;font-weight:800;letter-spacing:-2px;line-height:1.05;
  margin-bottom:20px;
  background:linear-gradient(180deg,#fff 30%,#b8bdd0);
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
}
.hero p{font-size:18px;color:var(--text-secondary);max-width:580px;margin:0 auto 34px;line-height:1.62}
.hero-cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.hero-btn{
  display:inline-flex;align-items:center;gap:8px;
  padding:15px 30px;border-radius:12px;font-size:15px;font-weight:700;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;border:none;cursor:pointer;
  box-shadow:0 10px 30px -10px rgba(109,106,246,.7);transition:all .18s ease;
}
.hero-btn:hover{transform:translateY(-2px);box-shadow:0 16px 36px -10px rgba(109,106,246,.8)}
.ghost-btn{
  display:inline-flex;align-items:center;gap:8px;
  padding:15px 26px;border-radius:12px;font-size:15px;font-weight:600;
  background:transparent;color:var(--text-secondary);border:1px solid var(--border);transition:all .18s ease;
}
.ghost-btn:hover{color:var(--text);border-color:var(--border-hover)}

/* INBOX PREVIEW */
.preview{
  max-width:560px;margin:56px auto 0;text-align:left;
  background:var(--bg-card);border:1px solid var(--border);border-radius:16px;
  overflow:hidden;box-shadow:0 30px 70px -30px rgba(0,0,0,.8);
}
.preview-bar{display:flex;align-items:center;gap:7px;padding:13px 16px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.015)}
.preview-bar .dot{width:11px;height:11px;border-radius:50%}
.dot.r{background:#ff5f57}.dot.y{background:#febc2e}.dot.g{background:#28c840}
.preview-addr{
  display:flex;align-items:center;gap:7px;margin-left:10px;
  font-family:'JetBrains Mono',monospace;font-size:12.5px;color:var(--text-secondary);
}
.preview-addr .dom{color:var(--accent)}
.copy-pill{margin-left:auto;font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--text-muted);border:1px solid var(--border);border-radius:6px;padding:3px 9px}
.preview-body{padding:6px}
.mail{display:flex;gap:13px;padding:14px 14px;border-radius:11px;transition:background .15s ease;cursor:default}
.mail+.mail{margin-top:2px}
.mail:hover{background:rgba(255,255,255,.025)}
.mail.unread{background:rgba(109,106,246,.06)}
.mail.unread .mail-sub{color:var(--text)}
.mail.unread .mail-from{font-weight:700}
.avatar{width:38px;height:38px;border-radius:10px;flex-shrink:0;display:grid;place-items:center;font-weight:700;font-size:15px;color:#fff}
.avatar.a1{background:linear-gradient(135deg,#6366f1,#8b5cf6)}
.avatar.a2{background:linear-gradient(135deg,#635bff,#4f46e5)}
.avatar.a3{background:linear-gradient(135deg,#10b981,#059669)}
.mail-txt{min-width:0;flex:1}
.mail-from{font-size:13.5px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px}
.mail-from .time{margin-left:auto;font-size:11px;color:var(--text-muted);font-weight:500}
.mail-sub{font-size:13px;color:var(--text-secondary);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mail-pre{font-size:12px;color:var(--text-muted);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* FEATURES */
.features{max-width:1040px;margin:0 auto;padding:60px 24px 50px;display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.feature{padding:30px 26px;border-radius:16px;background:var(--bg-card);border:1px solid var(--border);transition:all .2s ease}
.feature:hover{border-color:var(--border-hover);transform:translateY(-3px)}
.feature .icon{width:46px;height:46px;border-radius:12px;margin-bottom:18px;background:var(--accent-dim);display:grid;place-items:center;color:var(--accent)}
.feature h3{font-size:17px;font-weight:700;margin-bottom:9px;letter-spacing:-.3px}
.feature p{font-size:14px;color:var(--text-secondary);line-height:1.6}

/* HOW IT WORKS */
.how{max-width:1040px;margin:0 auto;padding:40px 24px 80px;text-align:center}
.how h3{font-size:32px;font-weight:800;letter-spacing:-1px;margin-bottom:44px}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.step{padding:30px 26px;border-radius:16px;background:var(--bg-card);border:1px solid var(--border);text-align:left}
.step .num{width:38px;height:38px;border-radius:11px;margin-bottom:18px;background:linear-gradient(135deg,var(--accent),var(--accent-2));display:grid;place-items:center;color:#fff;font-weight:800;font-size:15px}
.step h4{font-size:16px;font-weight:700;margin-bottom:8px;letter-spacing:-.3px}
.step p{font-size:13.5px;color:var(--text-secondary);line-height:1.6}

/* FOOTER */
footer{text-align:center;padding:36px 24px;border-top:1px solid var(--border);color:var(--text-muted);font-size:13px}
.foot-logo{display:inline-flex;align-items:center;gap:7px;font-weight:700;color:var(--text-secondary);font-size:14px;margin-bottom:8px}

@media(max-width:760px){
  nav{padding:18px 20px;}
  .nav-logo h1{font-size:18px;}
  .nav-btn{padding:8px 14px;font-size:13px;}
  .hero{padding:60px 20px 40px;}
  .badge{font-size:11px;padding:5px 12px;}
  .hero h2{font-size:34px;letter-spacing:-1px;line-height:1.1;}
  .hero h2 br{display:none;}
  .hero p{font-size:15px;max-width:100%;}
  .hero-cta{flex-direction:column;gap:10px;width:100%;}
  .hero-btn,.ghost-btn{width:100%;justify-content:center;padding:14px 20px;font-size:15px;}
  .preview{margin:36px auto 0;max-width:100%;border-radius:14px;}
  .preview-bar{padding:10px 12px;flex-wrap:wrap;gap:8px;}
  .preview-addr{font-size:11.5px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .preview-addr .dom{font-size:11.5px;}
  .copy-pill{font-size:10.5px;padding:3px 9px;}
  .preview-body{padding:6px;}
  .mail{padding:12px 10px;gap:10px;}
  .avatar{width:34px;height:34px;font-size:13px;flex-shrink:0;}
  .mail-from{font-size:13px;}
  .mail-sub{font-size:13px;}
  .mail-pre{font-size:12px;}
  .time{font-size:10.5px;}
  .features{padding:48px 20px;gap:14px;grid-template-columns:1fr;}
  .feature{padding:22px;}
  .feature h3{font-size:17px;}
  .feature p{font-size:14px;}
  .how{padding:48px 20px 64px;}
  .how h3{font-size:26px;letter-spacing:-0.6px;}
  .steps{grid-template-columns:1fr;gap:14px;}
  .step{padding:22px;}
  .step h4{font-size:16px;}
  footer{padding:32px 20px;font-size:12px;text-align:center;flex-direction:column;gap:12px;}
}
@media(max-width:380px){
  .hero h2{font-size:28px;}
  .preview-addr{font-size:11px;}
  .preview-addr svg{display:none;}
}
</style>
</head>
<body>
<div class="bg-glow"></div>
<nav>
  <div class="nav-logo">
    <div class="mark"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m3.5 7 8.5 6 8.5-6"/></svg></div>
    <h1>Veil</h1>
  </div>
  <a href="/login" class="nav-btn">Sign in</a>
</nav>

<section class="hero">
  <div class="badge"><span class="pulse"></span> Live SMTP · real inbox, real time</div>
  <h2>Email that vanishes<br>the moment you're done.</h2>
  <p>Spin up a throwaway address in one click. Catch the verification code, the confirmation link, the receipt — then walk away. No sign-up, no inbox to clean, nothing tied back to you.</p>
  <div class="hero-cta">
    <a href="/login" class="hero-btn">Open your inbox</a>
    <a href="#how" class="ghost-btn">How it works</a>
  </div>

  <div class="preview">
    <div class="preview-bar">
      <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
      <div class="preview-addr"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.5 7 8.5 6 8.5-6"/></svg> quiet-fox42@<span class="dom">bibnk.cloud</span></div>
      <span class="copy-pill">copy</span>
    </div>
    <div class="preview-body">
      <div class="mail unread">
        <div class="avatar a1">G</div>
        <div class="mail-txt"><div class="mail-from">GitHub <span class="time">now</span></div><div class="mail-sub">[GitHub] Please verify your device</div><div class="mail-pre">Your one-time code is 824 193. It expires in 10 minutes…</div></div>
      </div>
      <div class="mail">
        <div class="avatar a2">S</div>
        <div class="mail-txt"><div class="mail-from">Stripe <span class="time">1m</span></div><div class="mail-sub">Confirm your email address</div><div class="mail-pre">Tap the button below to finish setting up your account…</div></div>
      </div>
      <div class="mail">
        <div class="avatar a3">N</div>
        <div class="mail-txt"><div class="mail-from">Newsletter <span class="time">3m</span></div><div class="mail-sub">Welcome aboard 👋</div><div class="mail-pre">Thanks for signing up. Here's everything you need to get…</div></div>
      </div>
    </div>
  </div>
</section>

<section class="features">
  <div class="feature">
    <div class="icon"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z"/></svg></div>
    <h3>Lands instantly</h3>
    <p>A real SMTP server pushes mail straight into your inbox the second it arrives. No refresh button, no polling delay.</p>
  </div>
  <div class="feature">
    <div class="icon"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m8 9-3 3 3 3"/><path d="m16 9 3 3-3 3"/><path d="m13.5 7-3 10"/></svg></div>
    <h3>Built for automation</h3>
    <p>A clean REST API with token auth. Wire it into bots, test suites, and scripts — JSON in, JSON out.</p>
  </div>
  <div class="feature">
    <div class="icon"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg></div>
    <h3>Nothing left behind</h3>
    <p>No account, no profile, no tracking pixels following you around. Use an alias, read it, let it disappear.</p>
  </div>
</section>

<section class="how" id="how">
  <h3>Three steps. That's the whole thing.</h3>
  <div class="steps">
    <div class="step">
      <div class="num">1</div>
      <h4>Grab an address</h4>
      <p>Generate a random alias or pick your own — across any connected domain.</p>
    </div>
    <div class="step">
      <div class="num">2</div>
      <h4>Use it anywhere</h4>
      <p>Drop it into any sign-up form. Mail routes in over real SMTP in real time.</p>
    </div>
    <div class="step">
      <div class="num">3</div>
      <h4>Read & move on</h4>
      <p>Catch the code or link from a clean dashboard, then forget it ever existed.</p>
    </div>
  </div>
</section>

<footer>
  <div class="foot-logo"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m3.5 7 8.5 6 8.5-6"/></svg> Veil</div>
  <div>Disposable email · self-hosted · private by default</div>
</footer>
</body>
</html>
"""


LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · Veil</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2032%2032%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22g%22%20x1%3D%220%22%20y1%3D%220%22%20x2%3D%221%22%20y2%3D%221%22%3E%3Cstop%20offset%3D%220%22%20stop-color%3D%22%236d6af6%22/%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%238b5cf6%22/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect%20width%3D%2232%22%20height%3D%2232%22%20rx%3D%228%22%20fill%3D%22url%28%23g%29%22/%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22%23fff%22%20stroke-width%3D%222.2%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Crect%20x%3D%227%22%20y%3D%229%22%20width%3D%2218%22%20height%3D%2214%22%20rx%3D%222.5%22/%3E%3Cpath%20d%3D%22m7.5%2011%208.5%206%208.5-6%22/%3E%3C/g%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080b12;--bg-card:#0f1420;--bg-elevated:#161d2c;
  --border:#1c2536;--border-hover:#2c3a52;
  --text:#f4f6fb;--text-secondary:#9aa6bd;--text-muted:#5d6880;
  --accent:#6d6af6;--accent-2:#8b5cf6;--accent-hover:#5957e6;--accent-dim:rgba(109,106,246,.12);
  --success:#34d399;--warning:#fbbf24;--danger:#f87171;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:var(--bg);
  color:var(--text);
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  display:grid;place-items:center;padding:20px;position:relative;overflow:hidden;
  -webkit-font-smoothing:antialiased;
}
body:before{
  content:"";position:fixed;top:-200px;left:50%;transform:translateX(-50%);
  width:700px;height:600px;pointer-events:none;
  background:radial-gradient(circle at 50% 40%,rgba(109,106,246,.18),transparent 65%);filter:blur(20px);
}
.box{
  position:relative;z-index:1;
  width:100%;max-width:400px;
  padding:36px 32px 32px;
  background:var(--bg-card);
  border:1px solid var(--border);
  border-radius:16px;
}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:24px}
.mark{
  width:42px;height:42px;border-radius:11px;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  display:grid;place-items:center;box-shadow:0 6px 20px -6px rgba(109,106,246,.6);
}
h1{font-size:17px;font-weight:700;letter-spacing:-.3px}
.sub{margin-top:2px;font-size:12px;color:var(--text-muted);font-family:'JetBrains Mono',monospace}
form{margin-top:24px;display:grid;gap:14px}
label{font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.1em}
.inputWrap{
  margin-top:8px;border:1px solid var(--border);background:var(--bg);border-radius:10px;
  overflow:hidden;transition:all .15s ease;
}
.inputWrap:focus-within{
  border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-dim);
}
input{
  width:100%;border:0;background:transparent;
  padding:14px 16px;color:#fff;
  font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:500;
  letter-spacing:.5px;outline:0;
}
input::placeholder{color:var(--text-muted)}
.field+.field{margin-top:14px}
button{
  cursor:pointer;border:0;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  color:#fff;
  padding:14px 20px;border-radius:10px;
  font-weight:700;font-size:13px;letter-spacing:.5px;text-transform:uppercase;
  box-shadow:0 8px 24px -10px rgba(109,106,246,.7);transition:all .15s ease;
}
button:hover{transform:translateY(-1px);box-shadow:0 12px 28px -10px rgba(109,106,246,.8)}
button:active{transform:translateY(0)}
.err{
  margin-top:4px;padding:11px 14px;
  background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);
  border-radius:9px;color:var(--danger);font-size:12.5px;text-align:center;
  font-family:'JetBrains Mono',monospace;
}
.foot{
  margin-top:20px;padding-top:18px;border-top:1px solid var(--border);
  text-align:center;color:var(--text-muted);font-size:11px;font-family:'JetBrains Mono',monospace;
}
.foot span{color:var(--success)}
@media (max-width: 640px){
  body{padding:0;align-items:flex-start;background:var(--bg);}
  .box{margin:0;border-radius:0;border:none;border-bottom:1px solid var(--border);padding:32px 22px 28px;min-height:100vh;width:100%;max-width:100%;box-shadow:none;}
  .logo{margin-bottom:24px;}
  .logo .mark{width:36px;height:36px;}
  .logo .name{font-size:18px;}
  h1{font-size:22px!important;margin:0 0 6px;}
  .sub{font-size:13px;margin-bottom:22px;}
  .field{margin-bottom:14px;}
  .input{font-size:16px;padding:13px 14px;}
  .field label{font-size:11px;}
  button[type=submit],.btn{font-size:15px;padding:13px;}
  .foot{font-size:10.5px;}
}
</style>
</head>
<body>
<div class="box">
  <div class="logo">
    <div class="mark"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m3.5 7 8.5 6 8.5-6"/></svg></div>
    <div>
      <h1>Veil</h1>
      <p class="sub">welcome back</p>
    </div>
  </div>
  <form method="POST" action="/login" autocomplete="off">
    <div class="field">
      <label for="username">Username</label>
      <div class="inputWrap"><input id="username" name="username" type="text" autocomplete="username" placeholder="Enter your username" autofocus required></div>
    </div>
    <div class="field">
      <label for="password">Password</label>
      <div class="inputWrap"><input id="password" name="password" type="password" autocomplete="current-password" placeholder="••••••••" required></div>
    </div>
    <button type="submit">Authenticate →</button>
    __ERROR__
  </form>
  <div class="foot">Session 7 days · <span>encrypted</span> · single device</div>
</div>
<script>document.getElementById('username').focus();</script>
</body>
</html>
"""


CHANGE_PW_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Change Password · Veil</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2032%2032%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22g%22%20x1%3D%220%22%20y1%3D%220%22%20x2%3D%221%22%20y2%3D%221%22%3E%3Cstop%20offset%3D%220%22%20stop-color%3D%22%236d6af6%22/%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%238b5cf6%22/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect%20width%3D%2232%22%20height%3D%2232%22%20rx%3D%228%22%20fill%3D%22url%28%23g%29%22/%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22%23fff%22%20stroke-width%3D%222.2%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Crect%20x%3D%227%22%20y%3D%229%22%20width%3D%2218%22%20height%3D%2214%22%20rx%3D%222.5%22/%3E%3Cpath%20d%3D%22m7.5%2011%208.5%206%208.5-6%22/%3E%3C/g%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080b12;--bg-card:#0f1420;--bg-elevated:#161d2c;
  --border:#1c2536;--border-hover:#2c3a52;
  --text:#f4f6fb;--text-secondary:#9aa6bd;--text-muted:#5d6880;
  --accent:#6d6af6;--accent-2:#8b5cf6;--accent-hover:#5957e6;--accent-dim:rgba(109,106,246,.12);
  --success:#34d399;--warning:#fbbf24;--danger:#f87171;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;
  display:grid;place-items:center;padding:20px;
}
.box{width:100%;max-width:440px;padding:30px 28px 26px;background:var(--bg-card);border:1px solid var(--border);border-radius:16px}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.mark{width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,var(--accent),var(--accent-2));display:grid;place-items:center;box-shadow:0 6px 20px -6px rgba(109,106,246,.6)}
h1{font-size:17px;font-weight:700}
.sub{margin-top:2px;font-size:12px;color:var(--text-muted);font-family:'JetBrains Mono',monospace}
.notice{margin-top:14px;padding:11px 14px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);border-radius:9px;color:var(--warning);font-size:12.5px;line-height:1.5}
.notice b{color:#fbbf24}
form{margin-top:14px;display:grid;gap:10px}
label{font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.1em}
.inputWrap{margin-top:5px;border:1px solid var(--border);background:var(--bg);border-radius:10px;overflow:hidden;transition:all .15s ease}
.inputWrap:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
input{width:100%;border:0;background:transparent;padding:12px 14px;color:#fff;font-family:'JetBrains Mono',monospace;font-size:14px;outline:0}
input::placeholder{color:var(--text-muted)}
button{cursor:pointer;border:0;background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;padding:13px 20px;border-radius:10px;font-weight:700;font-size:13px;letter-spacing:.5px;text-transform:uppercase;margin-top:6px;box-shadow:0 8px 24px -10px rgba(109,106,246,.7);transition:all .15s ease}
button:hover{transform:translateY(-1px);box-shadow:0 12px 28px -10px rgba(109,106,246,.8)}
button:active{transform:translateY(0)}
.err{margin-top:4px;padding:11px 14px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:9px;color:var(--danger);font-size:12.5px;text-align:center}

.pwRules{list-style:none;padding:8px 0 0;margin:0;display:grid;gap:4px}
.pwRules li{font-size:11.5px;padding:6px 10px;border-radius:7px;background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.18);color:#fca5a5;font-family:'JetBrains Mono',monospace;transition:all .15s ease;position:relative;padding-left:28px}
.pwRules li:before{content:"✗";position:absolute;left:10px;top:50%;transform:translateY(-50%);font-weight:700;color:var(--danger)}
.pwRules li.ok{background:rgba(34,197,94,.06);border-color:rgba(34,197,94,.25);color:var(--success)}
.pwRules li.ok:before{content:"✓";color:var(--success)}
.pwStrength{margin-top:8px;height:5px;border-radius:99px;background:rgba(255,255,255,.05);overflow:hidden;border:1px solid var(--border)}
.pwStrength .bar{height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,var(--danger),var(--warning),var(--success));transition:width .25s ease}
@media (max-width: 640px){
  body{padding:0;align-items:flex-start;background:var(--bg);}
  .box{margin:0;border-radius:0;border:none;border-bottom:1px solid var(--border);padding:32px 22px 28px;min-height:100vh;width:100%;max-width:100%;box-shadow:none;}
  .logo{margin-bottom:20px;}
  .logo .mark{width:36px;height:36px;}
  .logo .name{font-size:18px;}
  h1{font-size:22px!important;margin:0 0 6px;}
  .sub{font-size:13px;margin-bottom:18px;}
  .notice{font-size:12px;padding:10px 12px;margin-bottom:14px;}
  .inputWrap{margin-bottom:12px;}
  .input{font-size:16px;padding:13px 14px;}
  label{font-size:11px;}
  button[type=submit],.btn{font-size:15px;padding:13px;}
  .pwRules{font-size:11px;}
}
</style>
</head>
<body>
<div class="box">
  <div class="logo"><div class="mark"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m3.5 7 8.5 6 8.5-6"/></svg></div><div><h1>Set new password</h1><p class="sub">first login · required</p></div></div>
  <div class="notice">⚠ <b>Mandatory.</b> Password default <b>Baba...</b> harus diganti sebelum lanjut. Tidak perlu masukkan password lama.</div>
  <form method="POST" action="/change-password" autocomplete="off" id="cpForm">
    <div>
      <label for="new">New password</label>
      <div class="inputWrap"><input id="new" name="new" type="password" autocomplete="new-password" required oninput="checkPw()"></div>
      <ul class="pwRules" id="rules">
        <li data-rule="len">Minimal 8 karakter</li>
        <li data-rule="upper">1 huruf KAPITAL</li>
        <li data-rule="digit">1 angka</li>
        <li data-rule="symbol">1 simbol (!@#$% dll)</li>
      </ul>
      <div class="pwStrength" id="strength"><div class="bar"></div></div>
    </div>
    <div>
      <label for="confirm">Confirm new password</label>
      <div class="inputWrap"><input id="confirm" name="confirm" type="password" autocomplete="new-password" required></div>
    </div>
    <button type="submit">Save new password →</button>
    __ERROR__
  </form>
</div>
<script>
function checkPw(){
  const pw=document.getElementById('new').value;
  const c={
    len: pw.length>=8,
    upper: /[A-Z]/.test(pw),
    digit: /\\d/.test(pw),
    symbol: /[!@#$%^&*()_+\\-=\\[\\]{};':"\\\\|,.<>\\/?]/.test(pw)
  };
  const ul=document.getElementById('rules');
  [...ul.children].forEach(li=>{ const k=li.dataset.rule; li.classList.toggle('ok', !!c[k]) });
  const score=Object.values(c).filter(Boolean).length;
  const bar=document.querySelector('#strength .bar');
  bar.style.width=(score*25)+'%';
  bar.style.background=score<2?'var(--danger)':score<4?'var(--warning)':'var(--success)';
}
document.getElementById('new').focus();
</script>
</body>
</html>
"""


# ─────────────────────── PWA: manifest + service worker ───────────────────────
PWA_ICONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")

# Digital Asset Links for the Android TWA (app: cloud.bibnk.veil).
# Fingerprint = SHA256 of the release signing keystore (alias "veil").
# Override via env if you re-sign with a different key.
ASSETLINKS_PACKAGE = os.environ.get("TWA_PACKAGE", "cloud.bibnk.veil")
ASSETLINKS_FINGERPRINTS = [
    f.strip() for f in os.environ.get(
        "TWA_FINGERPRINTS",
        "46:ED:BC:FC:A0:78:7C:93:73:DA:2D:D2:10:D9:23:3E:1D:8B:A9:0A:B8:4A:41:A3:C0:90:CB:60:23:41:75:F8",
    ).split(",") if f.strip()
]

PWA_MANIFEST = {
    "name": "Veil — Disposable Email",
    "short_name": "Veil",
    "description": "Self-hosted disposable email by Bibnk.",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "orientation": "portrait",
    "background_color": "#0a0f1a",
    "theme_color": "#8b5cf6",
    "lang": "en",
    "categories": ["productivity", "utilities"],
    "icons": [
        {"src": "/icons/icon-96.png",            "sizes": "96x96",   "type": "image/png", "purpose": "any"},
        {"src": "/icons/icon-192.png",           "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/icons/icon-512.png",           "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {"src": "/icons/icon-192-maskable.png",  "sizes": "192x192", "type": "image/png", "purpose": "maskable"},
        {"src": "/icons/icon-512-maskable.png",  "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
    ],
    "shortcuts": [
        {
            "name": "Inbox",
            "short_name": "Inbox",
            "description": "Open inbox",
            "url": "/#/inbox",
            "icons": [{"src": "/icons/icon-192.png", "sizes": "192x192"}],
        },
        {
            "name": "New alias",
            "short_name": "New",
            "description": "Create a new alias",
            "url": "/#/aliases",
            "icons": [{"src": "/icons/icon-192.png", "sizes": "192x192"}],
        },
    ],
}

# Service worker — network-first for API, cache-first for static.
# Bump SW_VERSION whenever this string changes so old clients pick up the update.
SW_VERSION = "veil-pwa-v1"
SW_JS = r"""// Veil PWA service worker
const VERSION = '__VERSION__';
const STATIC_CACHE = 'veil-static-' + VERSION;
const STATIC_ASSETS = [
  '/manifest.webmanifest',
  '/icons/icon-96.png',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(STATIC_CACHE).then(c => c.addAll(STATIC_ASSETS).catch(()=>null)));
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k.startsWith('veil-') && !k.endsWith(VERSION)).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // API, auth, login, change-pw, regen-token: always network, never cache
  if (url.pathname.startsWith('/api/') ||
      url.pathname === '/login' ||
      url.pathname === '/logout' ||
      url.pathname === '/change-password') {
    return; // let the browser handle it
  }

  // Static icons + manifest: cache-first
  if (url.pathname.startsWith('/icons/') || url.pathname === '/manifest.webmanifest') {
    e.respondWith((async () => {
      const cache = await caches.open(STATIC_CACHE);
      const hit = await cache.match(req);
      if (hit) return hit;
      try {
        const res = await fetch(req);
        if (res.ok) cache.put(req, res.clone());
        return res;
      } catch { return hit || Response.error(); }
    })());
    return;
  }

  // HTML shell ('/'): network-first with cache fallback so the app still opens offline
  if (req.mode === 'navigate' || (url.pathname === '/' && req.destination === 'document')) {
    e.respondWith((async () => {
      try {
        const res = await fetch(req);
        const cache = await caches.open(STATIC_CACHE);
        cache.put('/', res.clone());
        return res;
      } catch {
        const cache = await caches.open(STATIC_CACHE);
        const cached = await cache.match('/');
        if (cached) return cached;
        return new Response('<h1>Offline</h1><p>Veil is unreachable.</p>',
          { headers: {'content-type': 'text/html; charset=utf-8'}, status: 503 });
      }
    })());
    return;
  }
});

// Notification click — focus the app or open it.
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if (c.url.includes(self.location.origin)) { return c.focus(); }
    }
    return self.clients.openWindow('/');
  })());
});
""".replace("__VERSION__", SW_VERSION)

# Tags to inject into each HTML <head> right after the <link rel="icon" ...> line.
PWA_HEAD_TAGS = """
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#8b5cf6">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Veil">
<meta name="mobile-web-app-capable" content="yes">
<meta name="application-name" content="Veil">
<link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',function(){navigator.serviceWorker.register('/sw.js',{scope:'/'}).catch(function(){});});}</script>
"""


def inject_pwa_tags(html_str: str) -> str:
    """Inject PWA <head> tags right after the existing <link rel="icon" ...> line.
    Falls back to inserting after <head> if no icon line is found. No-op if tags already present."""
    if "/manifest.webmanifest" in html_str:
        return html_str
    # Try to inject after the existing favicon line for stable placement.
    marker = '<link rel="icon"'
    i = html_str.find(marker)
    if i != -1:
        end = html_str.find(">", i)
        if end != -1:
            return html_str[: end + 1] + PWA_HEAD_TAGS + html_str[end + 1 :]
    # Fallback: inject right after <head>
    j = html_str.find("<head>")
    if j != -1:
        return html_str[: j + len("<head>")] + PWA_HEAD_TAGS + html_str[j + len("<head>") :]
    return html_str


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), file=sys.stderr)

    def _read_cookie(self, name):
        ck = self.headers.get("cookie") or ""
        for part in ck.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name)+1:]
        return ""

    def current_user(self):
        """Return user dict {username, role, must_change_password, ...} atau None.

        Order:
          1. per-user API token via x-api-token (per-user level)
          2. master API token via x-api-token (super_admin power, untuk script/bot)
          3. session cookie (per-user dari users table)
        """
        api_token = self.headers.get("x-api-token")
        if api_token:
            # 1. Check per-user API token first
            with db() as c:
                row = c.execute("SELECT username, role, must_change_password FROM users WHERE api_token=?", (api_token,)).fetchone()
                if row:
                    return {"username": row["username"], "role": row["role"],
                            "must_change_password": row["must_change_password"], "via": "api_token"}
            # 2. Master API token = super_admin level
            if API_TOKEN and api_token == API_TOKEN:
                return {"username": "_api_token", "role": au.ROLE_SUPER,
                        "must_change_password": 0, "via": "api_token"}
        # 3. Session cookie
        sid = self._read_cookie("tm_sid")
        if sid:
            with db() as c:
                u = au.get_session(c, sid)
                if u:
                    u["via"] = "cookie"
                    return u
        # 3. Backward-compat: ?token= di URL
        if API_TOKEN:
            qs = parse_qs(urlparse(self.path).query)
            if qs.get("token", [""])[0] == API_TOKEN:
                return {"username": "_api_token", "role": au.ROLE_SUPER,
                        "must_change_password": 0, "via": "api_token_qs"}
        return None

    def authed(self):
        return self.current_user() is not None

    def require_role(self, *roles):
        u = self.current_user()
        if not u:
            self.send_json({"error": "unauthorized"}, 401)
            return None
        if u["role"] not in roles:
            self.send_json({"error": "forbidden"}, 403)
            return None
        return u

    def send_json(self, obj, status=200):
        data = json_bytes(obj)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_landing_html(self):
        data = inject_pwa_tags(LANDING_HTML).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_html(self):
        data = inject_pwa_tags(INDEX_HTML).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_login_html(self, error=""):
        err_html = f'<div class="err">{html.escape(error)}</div>' if error else ''
        page = inject_pwa_tags(LOGIN_HTML.replace("__ERROR__", err_html))
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_change_pw_html(self, error=""):
        err_html = f'<div class="err">{html.escape(error)}</div>' if error else ''
        page = inject_pwa_tags(CHANGE_PW_HTML.replace("__ERROR__", err_html))
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # ── PWA static handlers ──
    def send_assetlinks(self):
        # Digital Asset Links — verifies the TWA owns this domain so Chrome
        # opens the app fullscreen (no address bar). Fingerprint = SHA256 of
        # the release signing keystore (alias "veil").
        payload = [{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": ASSETLINKS_PACKAGE,
                "sha256_cert_fingerprints": ASSETLINKS_FINGERPRINTS,
            },
        }]
        data = json_bytes(payload)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(data)

    def send_manifest(self):
        data = json_bytes(PWA_MANIFEST)
        self.send_response(200)
        self.send_header("Content-Type", "application/manifest+json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(data)

    def send_sw(self):
        data = SW_JS.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        # SW must not be cached aggressively or updates won't roll out
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.send_header("Service-Worker-Allowed", "/")
        self.end_headers()
        self.wfile.write(data)

    def send_icon(self, path):
        # Resolve safely under PWA_ICONS_DIR; reject path traversal.
        name = os.path.basename(path)
        fp = os.path.join(PWA_ICONS_DIR, name)
        if not os.path.isfile(fp) or os.path.commonpath([os.path.abspath(fp), PWA_ICONS_DIR]) != PWA_ICONS_DIR:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with open(fp, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400, immutable")
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, set_cookie=None, clear_cookie=None):
        self.send_response(302)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        if clear_cookie:
            self.send_header("Set-Cookie", clear_cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def body(self):
        n = int(self.headers.get("content-length") or 0)
        if not n:
            return {}
        return json.loads(self.rfile.read(n).decode("utf-8"))


    def requested_address(self, qs=None, body=None):
        """Return full address from ?to=full@domain or ?user=local / JSON user/local."""
        qs = qs or {}
        body = body or {}
        raw = ""
        for key in ("to", "address", "email"):
            if key in qs and qs.get(key, [""])[0]:
                raw = qs.get(key, [""])[0]
                break
            if body.get(key):
                raw = body.get(key)
                break
        if not raw:
            for key in ("user", "local", "alias"):
                if key in qs and qs.get(key, [""])[0]:
                    raw = qs.get(key, [""])[0]
                    break
                if body.get(key):
                    raw = body.get(key)
                    break
        raw = str(raw or "").strip().lower()
        if not raw:
            return "", ""
        if "@" in raw:
            local, dom = raw.split("@", 1)
            # Multi-domain: cek apakah dom terdaftar di tabel domains, fallback ke DOMAIN
            with db() as c:
                if not ad.domain_is_accepted(c, dom):
                    raise RuntimeError(f"domain '{dom}' tidak terdaftar")
            target_domain = dom
        else:
            local = raw
            target_domain = DOMAIN
        if not LOCAL_RE.match(local):
            raise RuntimeError("user/alias invalid. Pakai huruf/angka/dot/underscore/plus/minus max 64 char")
        return local, f"{local}@{target_domain}"

    def _assert_can_use_address(self, user, addr):
        """Raise PermissionError kalau user tidak boleh akses alias addr.

        super_admin & API token = bypass.
        Selain itu: user hanya boleh akses alias yang dia claim.
        """
        if not user:
            raise PermissionError("unauthorized")
        if user["role"] == au.ROLE_SUPER:
            return
        with db() as c:
            owner = ad.get_alias_owner(c, addr)
        if owner is None:
            raise PermissionError(f"Alias '{addr}' belum di-claim. Claim dulu di /api/aliases.")
        if owner.lower() != (user.get("username") or "").lower():
            raise PermissionError(f"Alias '{addr}' milik user lain.")

    def do_GET(self):
        path = urlparse(self.path).path
        # ── PWA public routes (no auth required) ──
        if path == "/manifest.webmanifest":
            return self.send_manifest()
        if path == "/.well-known/assetlinks.json":
            return self.send_assetlinks()
        if path == "/sw.js":
            return self.send_sw()
        if path.startswith("/icons/"):
            return self.send_icon(path)
        if path == "/login":
            return self.send_login_html()
        if path == "/change-password":
            u = self.current_user()
            if not u:
                return self.redirect("/login")
            return self.send_change_pw_html()
        if path == "/logout":
            sid = self._read_cookie("tm_sid")
            if sid:
                with db() as c:
                    au.revoke_session(c, sid)
            return self.redirect("/login", clear_cookie="tm_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        if path == "/":
            u = self.current_user()
            if not u:
                return self.send_landing_html()
            if u.get("must_change_password"):
                return self.redirect("/change-password")
            return self.send_html()
        if not self.authed():
            return self.send_json({"error": "unauthorized"}, 401)
        try:
            return self._handle_get(path)
        except PermissionError as e:
            return self.send_json({"error": str(e) or "forbidden"}, 403)
        except ValueError as e:
            return self.send_json({"error": str(e)}, 400)
        except Exception as e:
            return self.send_json({"error": str(e)}, 500)

    def _handle_get(self, path):
        u = self.current_user()
        qs = parse_qs(urlparse(self.path).query)
        # ── Status / whoami ──
        if path == "/api/status":
            with db() as c:
                if u["role"] == au.ROLE_SUPER:
                    mc = c.execute("SELECT COUNT(*) n FROM messages").fetchone()["n"]
                else:
                    mc = c.execute(
                        "SELECT COUNT(*) n FROM messages m JOIN aliases a ON a.alias=m.rcpt_to "
                        "WHERE a.owner=?", (u["username"],)
                    ).fetchone()["n"]
                ac = c.execute("SELECT COUNT(*) n FROM aliases WHERE owner=?",
                               (u["username"],)).fetchone()["n"] if u["role"] != au.ROLE_SUPER \
                     else c.execute("SELECT COUNT(*) n FROM aliases").fetchone()["n"]
                domains = ad.list_visible_domains(c, role=u["role"], username=u["username"])
            return self.send_json({
                "domain": DOMAIN, "smtp_port": SMTP_PORT, "web_port": WEB_PORT,
                "messages": mc, "addresses": ac,
                "auth": True,
                "user": {"username": u["username"], "role": u["role"]},
                "domains": domains,
                "retention_hours": EMAIL_RETENTION_HOURS,
            })
        if path == "/api/whoami":
            with db() as c:
                row = c.execute("SELECT api_token FROM users WHERE username=?", (u["username"],)).fetchone()
                api_token = row["api_token"] if row else None
            return self.send_json({
                "username": u["username"], "role": u["role"],
                "must_change_password": bool(u.get("must_change_password")),
                "api_token": api_token,
            })

        # ── Aliases ──
        if path == "/api/aliases":
            with db() as c:
                owner = u["username"] if u["role"] != au.ROLE_SUPER else qs.get("owner", [None])[0]
                rows = ad.list_aliases(c, owner=owner)
            return self.send_json({"aliases": rows,
                                   "custom_limit": ad.CUSTOM_ALIAS_LIMIT})

        # ── Domains ──
        if path == "/api/domains":
            with db() as c:
                if u["role"] == au.ROLE_SUPER:
                    rows = ad.list_domains(c)
                else:
                    rows = ad.list_visible_domains(c, role=u["role"], username=u["username"])
            return self.send_json({"domains": rows})

        # ── Users (super_admin & admin lihat list) ──
        if path == "/api/users":
            actor = self.require_role(au.ROLE_SUPER, au.ROLE_ADMIN)
            if not actor:
                return
            with db() as c:
                rows = au.list_users(c)
            return self.send_json({"users": rows})

        # ── Audit log (super_admin only) ──
        if path == "/api/audit":
            actor = self.require_role(au.ROLE_SUPER)
            if not actor:
                return
            with db() as c:
                rows = au.list_audit(
                    c,
                    limit=int(qs.get("limit", ["200"])[0]),
                    action=qs.get("action", [None])[0],
                    target=qs.get("target", [None])[0],
                    user=qs.get("user", [None])[0],
                )
            return self.send_json({"audit": rows})

        # ── Ready (compat) ──
        if path == "/api/ready":
            local, addr = self.requested_address(qs=qs)
            if not addr:
                raise ValueError("isi parameter user/local/to, contoh /api/ready?user=telegram")
            self._assert_can_use_address(u, addr)
            label = qs.get("label", [""])[0].strip()
            with db() as c:
                c.execute("INSERT OR IGNORE INTO addresses(address,label,created_at) VALUES(?,?,?)",
                          (addr, label, now_iso()))
                count = c.execute("SELECT COUNT(*) n FROM messages WHERE rcpt_to=?", (addr,)).fetchone()["n"]
                latest = c.execute("SELECT * FROM messages WHERE rcpt_to=? ORDER BY id DESC LIMIT 1", (addr,)).fetchone()
            return self.send_json({
                "ready": True, "user": local, "address": addr, "messages": count,
                "latest": row_to_summary(latest) if latest else None,
                "api": {"list": f"/api/messages?user={local}&limit=20",
                        "latest": f"/api/latest?user={local}&wait=30"}
            })

        # ── Messages list ──
        if path == "/api/messages":
            _local, to = self.requested_address(qs=qs)
            limit = min(int(qs.get("limit", ["50"])[0]), 200)
            with db() as c:
                if to:
                    self._assert_can_use_address(u, to)
                    rows = c.execute(
                        "SELECT * FROM messages WHERE rcpt_to=? ORDER BY id DESC LIMIT ?",
                        (to, limit),
                    ).fetchall()
                else:
                    if u["role"] == au.ROLE_SUPER:
                        rows = c.execute(
                            "SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)
                        ).fetchall()
                    else:
                        rows = c.execute(
                            "SELECT m.* FROM messages m JOIN aliases a ON a.alias=m.rcpt_to "
                            "WHERE a.owner=? ORDER BY m.id DESC LIMIT ?",
                            (u["username"], limit),
                        ).fetchall()
            return self.send_json({"address": to or None,
                                   "messages": [row_to_summary(r) for r in rows]})

        # ── Latest (poll) ──
        if path == "/api/latest":
            _local, to = self.requested_address(qs=qs)
            if to:
                self._assert_can_use_address(u, to)
            since_id = int(qs.get("since_id", ["0"])[0])
            wait = min(int(qs.get("wait", ["0"])[0]), 60)
            deadline = time.time() + wait
            while True:
                with db() as c:
                    if to:
                        r = c.execute(
                            "SELECT * FROM messages WHERE rcpt_to=? AND id>? ORDER BY id DESC LIMIT 1",
                            (to, since_id),
                        ).fetchone()
                    else:
                        if u["role"] == au.ROLE_SUPER:
                            r = c.execute(
                                "SELECT * FROM messages WHERE id>? ORDER BY id DESC LIMIT 1",
                                (since_id,),
                            ).fetchone()
                        else:
                            r = c.execute(
                                "SELECT m.* FROM messages m JOIN aliases a ON a.alias=m.rcpt_to "
                                "WHERE a.owner=? AND m.id>? ORDER BY m.id DESC LIMIT 1",
                                (u["username"], since_id),
                            ).fetchone()
                if r:
                    return self.send_json(row_to_full(r))
                if time.time() >= deadline:
                    return self.send_json({"message": None})
                time.sleep(1)

        # ── Single message ──
        m = re.match(r"^/api/messages/(\d+)$", path)
        if m:
            mid = int(m.group(1))
            with db() as c:
                r = c.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
            if not r:
                return self.send_json({"error": "not found"}, 404)
            if u["role"] != au.ROLE_SUPER:
                # owner check
                with db() as c:
                    owner = ad.get_alias_owner(c, r["rcpt_to"])
                if not owner or owner.lower() != u["username"].lower():
                    return self.send_json({"error": "forbidden"}, 403)
            return self.send_json(row_to_full(r))

        if path == "/api/addresses":
            # Legacy — return aliases yang user punya
            with db() as c:
                owner = None if u["role"] == au.ROLE_SUPER else u["username"]
                rows = ad.list_aliases(c, owner=owner)
            return self.send_json({"addresses": [{"address": r["alias"],
                                                  "label": r.get("kind"),
                                                  "created_at": r["created_at"]}
                                                 for r in rows]})

        return self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        # Login endpoint — public, no auth required
        if path == "/login":
            ip = self.client_address[0]
            ok, retry = _login_check_rate(ip)
            if not ok:
                return self.send_login_html(error=f"Terlalu banyak percobaan dari IP ini. Coba lagi dalam {retry} detik.")
            n = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(n).decode("utf-8") if n else ""
            ctype = self.headers.get("content-type") or ""
            username = ""
            password = ""
            if "application/json" in ctype:
                try:
                    j = json.loads(raw or "{}")
                    username = (j.get("username") or "").strip()
                    password = j.get("password") or ""
                except Exception:
                    pass
            else:
                form = parse_qs(raw)
                username = (form.get("username", [""])[0] or "").strip()
                password = form.get("password", [""])[0] or ""
            with db() as c:
                user, err = au.authenticate(c, username=username, password=password)
                if err or not user:
                    _login_record_fail(ip)
                    return self.send_login_html(error=err or "Login gagal.")
                _login_clear(ip)
                ua = self.headers.get("user-agent", "")
                sid = au.create_session(c, username=user["username"], ip=ip, user_agent=ua)
            cookie = f"tm_sid={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={au.SESSION_TTL_SEC}"
            # User wajib ganti password kalau flag must_change_password
            target = "/change-password" if user.get("must_change_password") else "/"
            return self.redirect(target, set_cookie=cookie)
        # Change password endpoint — wajib login dulu
        if path == "/change-password":
            u = self.current_user()
            if not u:
                return self.redirect("/login")
            n = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(n).decode("utf-8") if n else ""
            ctype = self.headers.get("content-type") or ""
            cur_pw = new_pw = confirm_pw = ""
            if "application/json" in ctype:
                try:
                    j = json.loads(raw or "{}")
                    cur_pw = j.get("current") or ""
                    new_pw = j.get("new") or ""
                    confirm_pw = j.get("confirm") or ""
                except Exception:
                    pass
            else:
                form = parse_qs(raw)
                cur_pw = form.get("current", [""])[0]
                new_pw = form.get("new", [""])[0]
                confirm_pw = form.get("confirm", [""])[0]
            if new_pw != confirm_pw:
                return self.send_change_pw_html(error="Konfirmasi password tidak cocok.")
            with db() as c:
                user_row = au.get_user(c, u["username"])
                if not user_row:
                    return self.send_change_pw_html(error="User tidak ditemukan.")
                # First-login flow (must_change_password=1) → skip current password check
                # Self-service flow → wajib verify current password
                first_login = bool(user_row.get("must_change_password"))
                if not first_login:
                    if not au.verify_password(cur_pw, user_row["password_hash"], user_row["password_salt"]):
                        return self.send_change_pw_html(error="Password lama salah.")
                ok, msg = au.password_meets_policy(new_pw)
                if not ok:
                    return self.send_change_pw_html(error=msg)
                au.change_password(c, username=u["username"], new_password=new_pw,
                                   actor=u["username"])
                # change_password() invalidate semua session — buat session baru
                ua = self.headers.get("user-agent", "")
                sid = au.create_session(c, username=u["username"],
                                        ip=self.client_address[0], user_agent=ua)
            cookie = f"tm_sid={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={au.SESSION_TTL_SEC}"
            return self.redirect("/", set_cookie=cookie)
        if not self.authed():
            return self.send_json({"error": "unauthorized"}, 401)
        try:
            return self._handle_post(path)
        except PermissionError as e:
            return self.send_json({"error": str(e) or "forbidden"}, 403)
        except ValueError as e:
            return self.send_json({"error": str(e)}, 400)
        except Exception as e:
            return self.send_json({"error": str(e)}, 500)

    def _handle_post(self, path):
        u = self.current_user()
        b = self.body()
        # ── Regenerate API token ──
        if path == "/api/regen-token":
            import secrets
            new_token = secrets.token_hex(32)
            with db() as c:
                c.execute("UPDATE users SET api_token=? WHERE username=?", (new_token, u["username"]))
            au.log_action(c, u["username"], "regen_token", target=u["username"])
            return self.send_json({"api_token": new_token})
        # ── Existing endpoints (compat) ──
        if path == "/api/ready":
            local, addr = self.requested_address(body=b)
            if not addr:
                raise ValueError("isi JSON user/local/to")
            self._assert_can_use_address(u, addr)
            label = (b.get("label") or "").strip()
            with db() as c:
                c.execute("INSERT OR IGNORE INTO addresses(address,label,created_at) VALUES(?,?,?)",
                          (addr, label, now_iso()))
                count = c.execute("SELECT COUNT(*) n FROM messages WHERE rcpt_to=?", (addr,)).fetchone()["n"]
                latest = c.execute("SELECT * FROM messages WHERE rcpt_to=? ORDER BY id DESC LIMIT 1", (addr,)).fetchone()
            return self.send_json({"ready": True, "user": local, "address": addr,
                                   "messages": count,
                                   "latest": row_to_summary(latest) if latest else None,
                                   "api": {"list": f"/api/messages?user={local}&limit=20",
                                           "latest": f"/api/latest?user={local}&wait=30"}})

        # ── Alias claim ──
        if path == "/api/aliases":
            local = (b.get("local") or "").strip().lower()
            domain = (b.get("domain") or DOMAIN).strip().lower()
            kind = (b.get("kind") or ("random" if not local else "custom")).lower()
            owner = u["username"] if u["role"] != au.ROLE_SUPER else (b.get("owner") or u["username"])
            with db() as c:
                if kind == "random":
                    a = ad.claim_random_alias(c, owner=owner, role=u["role"], domain=domain)
                else:
                    a = ad.claim_custom_alias(c, owner=owner, role=u["role"],
                                              local=local, domain=domain)
            return self.send_json(a)

        # ── User management ──
        if path == "/api/users":
            actor = self.require_role(au.ROLE_SUPER, au.ROLE_ADMIN)
            if not actor:
                return
            target_role = (b.get("role") or au.ROLE_USER).lower()
            if not au.can_create_role(actor["role"], target_role):
                raise PermissionError(f"Role '{actor['role']}' tidak boleh buat '{target_role}'")
            username = (b.get("username") or "").strip().lower()
            # Default initial password = Baba.... Bypass policy karena user
            # WAJIB ganti saat first login (yang baru harus comply policy).
            pw = au.DEFAULT_INITIAL_PASSWORD
            with db() as c:
                au.create_user(c, username=username, password=pw, role=target_role,
                               created_by=actor["username"], must_change=True,
                               bypass_policy=True)
            return self.send_json({
                "username": username, "role": target_role,
                "initial_password": pw,
                "must_change_password": True,
                "note": f"Password default: {pw}. User wajib ganti saat login pertama."
            })

        m = re.match(r"^/api/users/([\w]+)/(lock|unlock|password)$", path)
        if m:
            actor = self.require_role(au.ROLE_SUPER)
            if not actor:
                return
            target = m.group(1).lower()
            action = m.group(2)
            reason = (b.get("reason") or "").strip()
            with db() as c:
                if action == "lock":
                    au.set_lock(c, username=target, locked=True,
                                actor=actor["username"], reason=reason)
                elif action == "unlock":
                    au.set_lock(c, username=target, locked=False,
                                actor=actor["username"], reason=reason or "manual unlock")
                elif action == "password":
                    new_pw = au.DEFAULT_INITIAL_PASSWORD
                    # bypass policy lewat raw update — initial password Baba...
                    # tidak lulus policy tapi user wajib ganti saat next login
                    h, s = au.hash_password(new_pw)
                    c.execute(
                        "UPDATE users SET password_hash=?, password_salt=?, "
                        "must_change_password=1 WHERE username=?",
                        (h, s, target),
                    )
                    c.execute("DELETE FROM user_sessions WHERE username=?", (target,))
                    au.log_action(c, actor["username"], "reset_password", target=target)
                    return self.send_json({"username": target, "new_password": new_pw,
                                           "must_change_password": True})
            return self.send_json({"username": target, "action": action, "ok": True})

        # ── Domain management (super_admin only) ──
        if path == "/api/domains":
            actor = self.require_role(au.ROLE_SUPER)
            if not actor:
                return
            domain_name = (b.get("domain") or "").strip().lower()
            if not domain_name:
                return self.send_json({"error": "domain is required"}, 400)

            # ── Validasi format domain DULU (sebelum DNS) supaya input ngawur
            #    tidak meledak jadi 500 saat di-resolve ──
            if not ad.DOMAIN_RE.match(domain_name):
                return self.send_json({
                    "error": "Format domain invalid",
                    "details": [f"'{domain_name}' bukan nama domain yang valid"],
                    "fixes": ["Gunakan format seperti: example.com (huruf kecil, tanpa spasi/simbol)"],
                }, 400)

            mode_in = (b.get("mode") or "public").lower()
            if mode_in not in ad.DOMAIN_MODES:
                return self.send_json({
                    "error": "Mode invalid",
                    "details": [f"mode '{mode_in}' tidak dikenal"],
                    "fixes": [f"Pilih salah satu: {', '.join(ad.DOMAIN_MODES)}"],
                }, 400)

            # ── DNS verification ──
            if SERVER_IP:
                try:
                    dns_result = verify_domain_dns(domain_name, SERVER_IP)
                except Exception as e:
                    return self.send_json({
                        "error": "DNS verification failed",
                        "details": ["Gagal mengecek DNS untuk domain ini"],
                        "fixes": ["Pastikan domain valid & nameserver sudah aktif, lalu coba lagi"],
                    }, 400)
                if not dns_result["ok"]:
                    return self.send_json({
                        "error": "DNS verification failed",
                        "details": dns_result["errors"],
                        "fixes": dns_result["fixes"],
                        "checks": dns_result.get("checks", []),
                        "steps": dns_result.get("steps", []),
                        "mx": dns_result.get("mx", []),
                        "a": dns_result.get("a", []),
                        "domain": domain_name,
                        "server_ip": SERVER_IP,
                    }, 400)

            with db() as c:
                d = ad.add_domain(c, domain=domain_name,
                                  mode=mode_in,
                                  actor=actor["username"],
                                  owner=(b.get("owner") or "").strip().lower() or None)
                au.log_action(c, actor["username"], "add_domain",
                              target=d["domain"], meta={"mode": d["mode"]})
            return self.send_json(d)

        m = re.match(r"^/api/domains/([\w\.\-]+)$", path)
        if m:
            actor = self.require_role(au.ROLE_SUPER)
            if not actor:
                return
            domain = m.group(1).lower()
            with db() as c:
                ad.update_domain(
                    c, domain=domain,
                    mode=(b.get("mode") or "").lower() or None,
                    enabled=b.get("enabled"),
                    owner=(b.get("owner") or "").strip().lower() or None,
                )
                au.log_action(c, actor["username"], "update_domain",
                              target=domain, meta={k: v for k, v in b.items() if k in ("mode", "enabled", "owner")})
            return self.send_json({"domain": domain, "ok": True})

        # ── Legacy: /api/address (deprecated, redirect to /api/aliases) ──
        if path == "/api/address":
            local = (b.get("local") or "").strip().lower()
            kind = "custom" if local else "random"
            domain = DOMAIN
            owner = u["username"] if u["role"] != au.ROLE_SUPER else (b.get("owner") or u["username"])
            with db() as c:
                if kind == "random":
                    a = ad.claim_random_alias(c, owner=owner, role=u["role"], domain=domain)
                else:
                    a = ad.claim_custom_alias(c, owner=owner, role=u["role"],
                                              local=local, domain=domain)
            return self.send_json({"address": a["alias"], "kind": a["kind"]})

        return self.send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        path = urlparse(self.path).path
        u = self.current_user()
        if not u:
            return self.send_json({"error": "unauthorized"}, 401)
        try:
            return self._handle_delete(path, u)
        except PermissionError as e:
            return self.send_json({"error": str(e) or "forbidden"}, 403)
        except ValueError as e:
            return self.send_json({"error": str(e)}, 400)
        except Exception as e:
            return self.send_json({"error": str(e)}, 500)

    def _handle_delete(self, path, u):
        b = self.body() if int(self.headers.get("content-length") or 0) else {}
        # ── Delete message ──
        m = re.match(r"^/api/messages/(\d+)$", path)
        if m:
            mid = int(m.group(1))
            with db() as c:
                r = c.execute("SELECT rcpt_to FROM messages WHERE id=?", (mid,)).fetchone()
                if r and u["role"] != au.ROLE_SUPER:
                    owner = ad.get_alias_owner(c, r["rcpt_to"])
                    if not owner or owner.lower() != u["username"].lower():
                        return self.send_json({"error": "forbidden"}, 403)
                c.execute("DELETE FROM messages WHERE id=?", (mid,))
            return self.send_json({"deleted": mid})

        # ── Delete user (super only) ──
        m = re.match(r"^/api/users/([\w]+)$", path)
        if m:
            actor = self.require_role(au.ROLE_SUPER)
            if not actor:
                return
            target = m.group(1).lower()
            reason = (b.get("reason") or "").strip()
            with db() as c:
                au.delete_user(c, username=target, actor=actor["username"], reason=reason)
            return self.send_json({"deleted_user": target})

        # ── Delete alias ──
        m = re.match(r"^/api/aliases/(.+)$", path)
        if m:
            alias = unquote(m.group(1)).lower()
            with db() as c:
                ad.delete_alias(c, alias=alias, requester=u["username"], role=u["role"])
                au.log_action(c, u["username"], "delete_alias", target=alias)
            return self.send_json({"deleted_alias": alias})

        # ── Delete domain (super only) ──
        m = re.match(r"^/api/domains/([\w\.\-]+)$", path)
        if m:
            actor = self.require_role(au.ROLE_SUPER)
            if not actor:
                return
            domain = m.group(1).lower()
            with db() as c:
                ad.delete_domain(c, domain=domain)
                au.log_action(c, actor["username"], "delete_domain", target=domain)
            return self.send_json({"deleted_domain": domain})

        return self.send_json({"error": "not found"}, 404)


def cleanup_loop(stop_event):
    """Background thread: hapus email > EMAIL_RETENTION_HOURS jam, jalan tiap 1 jam."""
    while not stop_event.is_set():
        try:
            with db() as c:
                n = ad.cleanup_old_messages(c, hours=EMAIL_RETENTION_HOURS)
                if n:
                    print(f"[cleanup] removed {n} emails older than {EMAIL_RETENTION_HOURS}h", flush=True)
                # Bersihkan session expired juga
                c.execute(
                    "DELETE FROM user_sessions WHERE expires_at < ?",
                    (now_iso(),),
                )
        except Exception as e:
            print(f"[cleanup] error: {e}", flush=True)
        # tidur 1 jam atau sampai stop
        stop_event.wait(3600)


def run_web():
    srv = ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler)
    print(f"Dashboard/API: http://{WEB_HOST}:{WEB_PORT}/", flush=True)
    print(f"  super_admin login: {SUPER_ADMIN_USER} / (password from .env or default)", flush=True)
    srv.serve_forever()


def main():
    init_db()
    smtp = Controller(TempMailSMTP(), hostname=MAIL_HOST, port=SMTP_PORT)
    smtp.start()
    print(f"SMTP receiver: {MAIL_HOST}:{SMTP_PORT} accepting *@{DOMAIN} (+ tambahan dari /api/domains)", flush=True)
    stop = threading.Event()

    # Cleanup thread untuk auto-delete email lama
    cleaner = threading.Thread(target=cleanup_loop, args=(stop,), daemon=True)
    cleaner.start()
    print(f"Cleanup thread: messages older than {EMAIL_RETENTION_HOURS}h auto-deleted", flush=True)

    def shutdown(signum, frame):
        stop.set()
        try:
            smtp.stop()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    run_web()


if __name__ == "__main__":
    main()
