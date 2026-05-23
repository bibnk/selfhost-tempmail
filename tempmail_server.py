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
SUPER_ADMIN_USER = os.getenv("SUPER_ADMIN_USER", "6715").strip().lower()
SUPER_ADMIN_PASS = os.getenv("SUPER_ADMIN_PASS", "6715")
EMAIL_RETENTION_HOURS = int(os.getenv("EMAIL_RETENTION_HOURS", "48"))

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
<title>TempMail · self-hosted</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  /* black dope palette */
  --bg-0:#000000;
  --bg-1:#050608;
  --bg-2:#0a0c10;
  --bg-3:#0f1218;
  --line:rgba(255,255,255,.06);
  --line-2:rgba(255,255,255,.10);
  --line-hot:rgba(0,229,255,.35);
  --txt:#f3f4f7;
  --txt-2:#aab1bd;
  --txt-3:#6b7280;
  --txt-4:#3a4150;
  --neon:#00e5ff;
  --neon-2:#7c5cff;
  --neon-3:#ff3d8b;
  --ok:#22d995;
  --warn:#ffb454;
  --bad:#ff5c5c;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:#04060a;
  color:var(--txt);
  font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  font-feature-settings:"cv02","cv03","cv04","cv11";
  letter-spacing:-.011em;
  -webkit-font-smoothing:antialiased;
  overflow-x:hidden;
  position:relative;
}
/* Aurora blobs — fixed full-viewport, blurred for glass to read against */
body:before{
  content:"";position:fixed;inset:-20vh;pointer-events:none;z-index:0;
  background:
    radial-gradient(circle 700px at 0% 0%,    #7c5cff 0%, transparent 50%),
    radial-gradient(circle 600px at 15% 55%,  #ff3d8b 0%, transparent 50%),
    radial-gradient(circle 750px at 50% 20%,  #5a3eff 0%, transparent 50%),
    radial-gradient(circle 650px at 80% 60%,  #00e5ff 0%, transparent 50%),
    radial-gradient(circle 580px at 100% 100%, #22d995 0%, transparent 50%),
    radial-gradient(circle 500px at 35% 100%, #ff6b9d 0%, transparent 50%);
  filter:blur(20px) saturate(180%);
  opacity:1;
  animation:floaty 22s ease-in-out infinite alternate;
}
@keyframes floaty{
  0%{transform:translate(0,0) rotate(0deg) scale(1)}
  50%{transform:translate(-30px,20px) rotate(2deg) scale(1.05)}
  100%{transform:translate(20px,-30px) rotate(-2deg) scale(.98)}
}
body:after{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:
    linear-gradient(rgba(255,255,255,.022) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.022) 1px,transparent 1px);
  background-size:32px 32px;
  mask-image:radial-gradient(ellipse at center,#000 30%,transparent 80%);
}
button,input{font:inherit;color:inherit;outline:0}
button{cursor:pointer;border:0;background:none}
a{color:inherit;text-decoration:none}

/* === LAYOUT === */
.app{position:relative;z-index:1;min-height:100vh;display:grid;grid-template-columns:280px 1fr;gap:22px;padding:22px}
.side{
  position:sticky;top:22px;height:calc(100vh - 44px);display:flex;flex-direction:column;
  padding:24px 20px;
  border:1px solid rgba(255,255,255,.10);
  border-radius:22px;
  background:linear-gradient(165deg,rgba(20,22,30,.10),rgba(8,10,16,.20));
  backdrop-filter:blur(32px) saturate(200%) brightness(.85);
  -webkit-backdrop-filter:blur(32px) saturate(200%) brightness(.85);
  box-shadow:
    0 24px 48px -12px rgba(0,0,0,.6),
    0 8px 24px rgba(124,92,255,.12),
    inset 0 1px 0 rgba(255,255,255,.08),
    inset 0 0 0 1px rgba(255,255,255,.02);
  overflow-y:auto;overflow-x:hidden;
  scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.1) transparent;
}
.side::-webkit-scrollbar{width:6px}
.side::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:99px}
.side:before{
  content:"";position:absolute;inset:0;border-radius:22px;pointer-events:none;
  background:
    linear-gradient(180deg,rgba(124,92,255,.06),transparent 35%,transparent 65%,rgba(0,229,255,.05)),
    linear-gradient(180deg,rgba(255,255,255,.04) 0,transparent 1px);
  opacity:.85;
}
.side:after{
  content:"";position:absolute;top:0;left:24px;right:24px;height:1px;
  background:linear-gradient(90deg,transparent,rgba(124,92,255,.6),rgba(0,229,255,.5),transparent);
  opacity:.7;
}
.logo{display:flex;align-items:center;gap:11px;margin-bottom:24px;padding:0 6px;position:relative;z-index:1}
.mark{
  width:38px;height:38px;border-radius:11px;
  background:conic-gradient(from 200deg,var(--neon),var(--neon-2),var(--neon-3),var(--neon));
  display:grid;place-items:center;color:#000;font-weight:800;font-size:16px;
  box-shadow:0 0 32px rgba(0,229,255,.5),inset 0 0 12px rgba(0,0,0,.3);
  animation:spin 8s linear infinite;
}
@keyframes spin{to{filter:hue-rotate(360deg)}}
.brand h1{font-size:15px;font-weight:700;letter-spacing:-.3px}
.brand p{font-size:11px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;margin-top:1px}

.nav{display:flex;flex-direction:column;gap:3px;position:relative;z-index:1}
.navGroup{display:flex;flex-direction:column;gap:3px;margin:10px 0 6px;padding:12px 8px 10px;border:1px solid rgba(255,255,255,.06);border-radius:13px;background:linear-gradient(180deg,rgba(255,255,255,.025),rgba(255,255,255,.005));backdrop-filter:blur(10px)}
.navGroupLabel{font-size:9.5px;font-weight:700;color:var(--txt-3);letter-spacing:.22em;padding:0 6px 8px;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;gap:8px}
.navGroupLabel:before{content:"";flex:1;height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.08))}
.navGroupLabel:after{content:"";flex:1;height:1px;background:linear-gradient(90deg,rgba(255,255,255,.08),transparent)}
.nav a{
  display:flex;align-items:center;gap:11px;
  padding:11px 13px;border-radius:11px;
  font-size:13.5px;font-weight:500;color:var(--txt-2);
  border:1px solid transparent;
  transition:all .2s cubic-bezier(.4,0,.2,1);
  position:relative;
}
.nav a span:first-child{font-size:15px;width:18px;text-align:center;filter:saturate(80%)}
.nav a:hover{color:var(--txt);background:linear-gradient(135deg,rgba(255,255,255,.05),rgba(255,255,255,.02));transform:translateX(3px);border-color:rgba(255,255,255,.05)}
.nav a:hover span:first-child{filter:saturate(120%);transform:scale(1.1)}
.nav a.active{
  background:linear-gradient(135deg,rgba(124,92,255,.22),rgba(0,229,255,.08));
  border-color:rgba(124,92,255,.45);
  color:var(--txt);
  box-shadow:
    inset 0 1px 0 rgba(255,255,255,.08),
    0 6px 20px rgba(124,92,255,.22),
    0 0 0 1px rgba(124,92,255,.15);
}
.nav a.active span:first-child{filter:saturate(140%) drop-shadow(0 0 6px rgba(0,229,255,.5))}
.nav a.active:before{
  content:"";position:absolute;left:-13px;top:50%;transform:translateY(-50%);
  width:4px;height:22px;border-radius:0 4px 4px 0;
  background:linear-gradient(180deg,var(--neon),var(--neon-2));
  box-shadow:0 0 16px var(--neon);
}
.nav a.logout{margin-top:auto;color:#ff8a8a}
.nav a.logout:hover{background:linear-gradient(135deg,rgba(255,92,92,.14),rgba(255,92,92,.04));border-color:rgba(255,92,92,.3)}
.nav-spacer{flex:1}

.sidefoot{padding:14px 6px 0;border-top:1px solid rgba(255,255,255,.06);margin-top:14px;position:relative;z-index:1}
.statusBar{display:flex;align-items:center;gap:8px;padding:9px 11px;border-radius:10px;background:rgba(34,217,149,.07);border:1px solid rgba(34,217,149,.22);backdrop-filter:blur(8px)}
.statusDot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 12px var(--ok);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.statusBar span{font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--ok)}
.sideMeta{display:grid;gap:6px;margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:11px}
.sideMeta>div{display:flex;justify-content:space-between;padding:7px 11px;border-radius:8px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.05);backdrop-filter:blur(8px)}
.sideMeta span{color:var(--txt-3);text-transform:uppercase;letter-spacing:.08em;font-size:10px}
.sideMeta b{color:var(--neon);font-weight:500}

/* === USER BADGE (header right) === */
.userBadge{display:flex;align-items:center;gap:11px;padding:9px 14px 9px 9px;border-radius:13px;border:1px solid rgba(255,255,255,.10);background:linear-gradient(135deg,rgba(124,92,255,.18),rgba(0,229,255,.06));backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);margin-right:8px;box-shadow:0 8px 22px rgba(124,92,255,.18),inset 0 1px 0 rgba(255,255,255,.06)}
.ub-avatar{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(135deg,var(--neon-2),var(--neon-3));color:#fff;font-weight:800;font-size:14px;text-transform:uppercase;box-shadow:0 4px 14px rgba(124,92,255,.4),inset 0 1px 0 rgba(255,255,255,.2)}
.ub-info{display:flex;flex-direction:column;gap:2px}
.ub-name{font-size:12.5px;font-weight:600;color:var(--txt);font-family:'JetBrains Mono',monospace}
.ub-role{font-size:9.5px;color:var(--neon);text-transform:uppercase;letter-spacing:.1em;font-weight:600}

/* === PASSWORD VALIDATOR === */
.pwRules{list-style:none;padding:10px 0 0;margin:0;display:grid;gap:5px}
.pwRules li{font-size:12px;padding:6px 10px;border-radius:7px;background:rgba(255,92,92,.06);border:1px solid rgba(255,92,92,.18);color:#ff9a9a;font-family:'JetBrains Mono',monospace;transition:all .15s ease;position:relative;padding-left:28px}
.pwRules li:before{content:"✗";position:absolute;left:10px;top:50%;transform:translateY(-50%);font-weight:700;color:#ff5c5c}
.pwRules li.ok{background:rgba(34,217,149,.06);border-color:rgba(34,217,149,.25);color:var(--ok)}
.pwRules li.ok:before{content:"✓";color:var(--ok)}
.pwStrength{margin-top:18px;height:8px;border-radius:99px;background:rgba(255,255,255,.05);overflow:hidden;border:1px solid var(--line2);position:relative}
.pwStrength:before{content:"strength";position:absolute;top:-15px;left:0;font-size:9.5px;color:var(--txt-3);letter-spacing:.12em;text-transform:uppercase;font-family:'JetBrains Mono',monospace;font-weight:600}
.pwStrength .bar{height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,var(--bad),var(--warn),var(--ok));transition:width .25s ease;box-shadow:0 0 12px currentColor}
.actorTag{display:inline-block;padding:2px 9px;margin-left:6px;border-radius:99px;font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:700;letter-spacing:.04em;background:linear-gradient(135deg,var(--neon-2),var(--neon-3));color:#fff;box-shadow:0 2px 8px rgba(124,92,255,.35);text-transform:uppercase}

/* === MAIN === */
.main{padding:28px 32px 40px;max-width:1400px;width:100%}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;margin-bottom:26px;flex-wrap:wrap}
.hero h2{
  font-size:36px;font-weight:700;letter-spacing:-1.2px;line-height:1.05;
  background:linear-gradient(135deg,#fff 30%,#a8b0bd 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.hero p{margin-top:6px;color:var(--txt-2);font-size:14px;max-width:600px}
.hero p b{color:var(--neon);font-family:'JetBrains Mono',monospace;font-weight:500;font-size:13px;background:rgba(0,229,255,.08);padding:2px 7px;border-radius:5px;border:1px solid rgba(0,229,255,.2)}

.actions{display:flex;gap:8px;flex-wrap:wrap}
.btn{
  display:inline-flex;align-items:center;gap:7px;
  padding:9px 14px;border-radius:9px;
  font-size:13px;font-weight:600;
  background:rgba(255,255,255,.03);
  border:1px solid var(--line-2);
  color:var(--txt);
  transition:all .15s ease;
}
.btn:hover{background:rgba(255,255,255,.06);border-color:rgba(255,255,255,.18);transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn.primary{
  background:linear-gradient(135deg,var(--neon-2),#5a3eff);
  border-color:transparent;color:#fff;
  box-shadow:0 6px 20px rgba(124,92,255,.35),inset 0 1px 0 rgba(255,255,255,.18);
}
.btn.primary:hover{box-shadow:0 10px 28px rgba(124,92,255,.5),inset 0 1px 0 rgba(255,255,255,.25)}
.btn.green{
  background:linear-gradient(135deg,#22d995,#11a06b);
  border-color:transparent;color:#fff;
  box-shadow:0 6px 20px rgba(34,217,149,.3),inset 0 1px 0 rgba(255,255,255,.18);
}
.btn.green:hover{box-shadow:0 10px 28px rgba(34,217,149,.45)}

/* === STATS GRID === */
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px}
.stat{
  position:relative;overflow:hidden;
  padding:18px 18px 16px;border-radius:14px;
  background:linear-gradient(180deg,rgba(15,18,24,.8),rgba(8,10,14,.9));
  border:1px solid var(--line);
  transition:all .2s ease;
}
.stat:hover{border-color:var(--line-2);transform:translateY(-2px);box-shadow:0 12px 30px rgba(0,0,0,.4)}
.stat:after{
  content:"";position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--neon-2),transparent);
  opacity:.5;
}
.stat .k{font-size:11px;font-weight:600;color:var(--txt-3);text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px}
.stat .v{font-size:22px;font-weight:700;letter-spacing:-.5px;font-family:'JetBrains Mono',monospace;color:var(--txt)}
.stat .s{font-size:11px;color:var(--txt-3);margin-top:4px}

/* === CARDS === */
/* Glass select for inbox alias filter */
.aliasFilter{
  background:linear-gradient(135deg,rgba(124,92,255,.10),rgba(0,229,255,.04));
  color:var(--txt);border:1px solid rgba(255,255,255,.12);
  padding:8px 32px 8px 14px;border-radius:10px;
  font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;
  letter-spacing:.04em;cursor:pointer;
  appearance:none;-webkit-appearance:none;
  background-image:
    linear-gradient(135deg,rgba(124,92,255,.10),rgba(0,229,255,.04)),
    linear-gradient(45deg,transparent 50%,var(--neon-2) 50%),
    linear-gradient(135deg,var(--neon-2) 50%,transparent 50%);
  background-position:0 0,calc(100% - 16px) 50%,calc(100% - 11px) 50%;
  background-size:100% 100%,5px 5px,5px 5px;
  background-repeat:no-repeat;
  backdrop-filter:blur(16px) saturate(160%);
  -webkit-backdrop-filter:blur(16px) saturate(160%);
  transition:all .15s ease;
  box-shadow:
    0 4px 14px rgba(0,229,255,.10),
    inset 0 1px 0 rgba(255,255,255,.08);
}
.aliasFilter:hover{
  border-color:rgba(0,229,255,.40);
  box-shadow:0 6px 18px rgba(0,229,255,.20),inset 0 1px 0 rgba(255,255,255,.10);
}
.aliasFilter:focus{
  outline:none;border-color:rgba(124,92,255,.55);
  box-shadow:0 0 0 3px rgba(124,92,255,.18),0 6px 20px rgba(124,92,255,.22);
}
.aliasFilter option{background:#0a0d14;color:var(--txt);padding:8px;font-family:'JetBrains Mono',monospace}

/* === MODAL (glass popout) === */
.modalBackdrop{
  position:fixed;inset:0;z-index:1000;
  background:rgba(2,3,7,.55);backdrop-filter:blur(8px) saturate(120%);-webkit-backdrop-filter:blur(8px) saturate(120%);
  display:none;align-items:center;justify-content:center;padding:20px;
  animation:mdFade .18s ease-out;
}
.modalBackdrop.show{display:flex}
@keyframes mdFade{from{opacity:0}to{opacity:1}}
.modal{
  width:min(480px,100%);
  background:linear-gradient(165deg,rgba(20,22,30,.55),rgba(8,10,16,.72));
  backdrop-filter:blur(40px) saturate(200%);-webkit-backdrop-filter:blur(40px) saturate(200%);
  border:1px solid rgba(255,255,255,.12);border-radius:20px;
  box-shadow:
    0 32px 64px -12px rgba(0,0,0,.7),
    0 12px 36px rgba(124,92,255,.22),
    inset 0 1px 0 rgba(255,255,255,.10);
  overflow:hidden;position:relative;
  animation:mdRise .22s cubic-bezier(.22,1,.36,1);
}
@keyframes mdRise{from{opacity:0;transform:translateY(16px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
.modal:before{
  content:"";position:absolute;top:0;left:24px;right:24px;height:1px;
  background:linear-gradient(90deg,transparent,rgba(124,92,255,.7),rgba(0,229,255,.6),transparent);
}
.modalHead{
  padding:18px 22px 14px;border-bottom:1px solid rgba(255,255,255,.06);
  display:flex;align-items:center;justify-content:space-between;gap:12px;
}
.modalIcon{
  width:36px;height:36px;border-radius:11px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--neon-2),var(--neon-3));
  font-size:18px;box-shadow:0 6px 18px rgba(124,92,255,.4),inset 0 1px 0 rgba(255,255,255,.2);
}
.modal-title{display:flex;align-items:center;gap:12px}
.modal-title h3{font-size:15px;font-weight:700;letter-spacing:-.2px;color:var(--txt)}
.modal-title p{font-size:11.5px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;margin-top:2px}
.modalClose{
  width:32px;height:32px;border-radius:9px;display:grid;place-items:center;
  background:rgba(255,92,92,.10);border:1px solid rgba(255,92,92,.22);color:#ff8a8a;
  font-size:14px;transition:all .15s ease;
}
.modalClose:hover{background:rgba(255,92,92,.18);transform:rotate(90deg)}
.modalBody{padding:20px 22px;display:grid;gap:16px}
.modalBody label{font-size:10.5px;font-weight:700;color:var(--txt-3);letter-spacing:.18em;text-transform:uppercase;font-family:'JetBrains Mono',monospace;display:block;margin-bottom:6px}
.modalFoot{
  padding:14px 22px;border-top:1px solid rgba(255,255,255,.06);
  display:flex;gap:10px;justify-content:flex-end;background:rgba(0,0,0,.18);
}
.modalFoot .btn{font-size:13px;padding:9px 16px}

/* === COPY ROW === */
.copyRow{
  display:flex;align-items:center;gap:0;
  border:1px solid rgba(124,92,255,.30);border-radius:11px;overflow:hidden;
  background:linear-gradient(135deg,rgba(124,92,255,.10),rgba(0,229,255,.04));
  backdrop-filter:blur(10px);
  transition:all .2s ease;
}
.copyRow:hover{border-color:rgba(124,92,255,.55);box-shadow:0 6px 18px rgba(124,92,255,.18)}
.copyRow code{
  flex:1;padding:11px 14px;font-family:'JetBrains Mono',monospace;font-size:13.5px;font-weight:600;color:var(--neon);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  background:transparent;letter-spacing:.02em;
}
.copyRow button{
  padding:11px 14px;background:rgba(124,92,255,.16);color:var(--neon);
  border-left:1px solid rgba(124,92,255,.25);
  font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
  transition:all .15s ease;display:flex;align-items:center;gap:6px;
}
.copyRow button:hover{background:rgba(124,92,255,.28);color:#fff}
.copyRow button.ok{background:rgba(34,217,149,.22);color:var(--ok);border-left-color:rgba(34,217,149,.35)}

/* === ALIAS LIST CARDS === */
.aliasGrid{display:grid;gap:10px}
.aliasItem{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:12px 14px;border-radius:12px;
  background:linear-gradient(135deg,rgba(124,92,255,.08),rgba(0,229,255,.03));
  backdrop-filter:blur(10px);
  border:1px solid rgba(255,255,255,.07);
  transition:all .2s ease;
}
.aliasItem:hover{border-color:rgba(124,92,255,.30);transform:translateY(-1px);box-shadow:0 8px 22px rgba(124,92,255,.18)}
.aliasItem .aliasMain{flex:1;min-width:0}
.aliasItem code{font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;color:var(--txt);display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.aliasItem .aliasMeta{font-size:10.5px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;margin-top:3px;display:flex;gap:8px;align-items:center}
.kindTag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:9.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.kindTag.custom{background:rgba(124,92,255,.18);color:var(--neon)}
.kindTag.random{background:rgba(0,229,255,.14);color:var(--neon-2)}
.iconBtn{
  width:34px;height:34px;border-radius:9px;display:grid;place-items:center;
  background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
  color:var(--txt-2);font-size:14px;transition:all .15s ease;flex-shrink:0;
}
.iconBtn:hover{background:rgba(124,92,255,.16);border-color:rgba(124,92,255,.35);color:var(--neon);transform:scale(1.05)}
.iconBtn.danger:hover{background:rgba(255,92,92,.14);border-color:rgba(255,92,92,.35);color:#ff8a8a}

.card{
  position:relative;
  border-radius:18px;
  background:linear-gradient(180deg,rgba(15,18,24,.18),rgba(8,10,14,.30));
  backdrop-filter:blur(24px) saturate(180%) brightness(.9);
  -webkit-backdrop-filter:blur(24px) saturate(180%) brightness(.9);
  border:1px solid rgba(255,255,255,.10);
  overflow:hidden;
  box-shadow:
    0 16px 36px -12px rgba(0,0,0,.5),
    inset 0 1px 0 rgba(255,255,255,.06);
}
.card:before{
  content:"";position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent 10%,rgba(124,92,255,.4) 50%,transparent 90%);
  opacity:.3;
}
.cardHead{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:16px 20px;border-bottom:1px solid var(--line);
}
.cardHead h3{font-size:14px;font-weight:600;letter-spacing:-.2px}
.cardHead h3:before{content:"› ";color:var(--neon);font-family:'JetBrains Mono',monospace;font-weight:400}
.cardBody{padding:18px 20px}
.tabs{display:flex;gap:6px}
.pill{
  display:inline-flex;align-items:center;gap:6px;
  padding:5px 10px;border-radius:999px;
  font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--txt-3);
  background:rgba(255,255,255,.025);border:1px solid var(--line);
}
.pill .dot{width:6px;height:6px;border-radius:50%;background:var(--neon);box-shadow:0 0 8px var(--neon)}

/* === INBOX LAYOUT === */
.layout{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.layout .inboxTools{grid-column:1 / -1}
@media(max-width:980px){.layout{grid-template-columns:1fr}}

/* === COMPOSE === */
.bodyPanel{
  padding:16px;border-radius:12px;
  background:radial-gradient(600px 200px at 0 0,rgba(0,229,255,.04),transparent 60%),rgba(0,0,0,.3);
  border:1px solid var(--line);
}
.formLabel{
  display:flex;align-items:center;justify-content:space-between;gap:10px;
  font-size:11px;font-weight:600;color:var(--txt-2);
  text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px;
}
.hint{font-size:11px;color:var(--txt-3);text-transform:none;letter-spacing:0;font-weight:500;font-family:'JetBrains Mono',monospace}
.compose{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:stretch}
.inputWrap{
  display:flex;align-items:center;
  border:1px solid var(--line-2);background:#000;
  border-radius:10px;overflow:hidden;
  transition:all .15s ease;
}
.inputWrap:focus-within{border-color:var(--neon);box-shadow:0 0 0 3px rgba(0,229,255,.12),0 8px 22px rgba(0,229,255,.06)}
.inputPrefix{padding:0 4px 0 14px;color:var(--neon);font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:500}
.input{flex:1;background:transparent;border:0;padding:12px 14px;color:var(--txt);font-size:14px;font-family:'JetBrains Mono',monospace}
.input::placeholder{color:var(--txt-4)}
.quick{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.quick button{
  padding:6px 11px;border-radius:7px;
  font-size:11.5px;font-weight:500;font-family:'JetBrains Mono',monospace;
  background:rgba(255,255,255,.025);border:1px solid var(--line);
  color:var(--txt-2);transition:all .15s ease;
}
.quick button:hover{background:rgba(0,229,255,.08);border-color:rgba(0,229,255,.3);color:var(--neon)}

.result{
  margin-top:14px;padding:14px;border-radius:10px;
  background:#000;border:1px solid var(--line);
  font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.55;
  color:#7fe7c0;min-height:54px;white-space:pre-wrap;
  position:relative;
}
.result:before{
  content:"⏵ output";display:block;
  font-size:10px;color:var(--txt-3);text-transform:uppercase;letter-spacing:.12em;margin-bottom:8px;
  font-family:'Inter',sans-serif;font-weight:600;
}

/* === INBOX LIST === */
.listShell{
  border:1px solid var(--line);background:rgba(0,0,0,.4);
  border-radius:12px;padding:6px;min-height:540px;max-height:70vh;overflow-y:auto;
}
.listShell::-webkit-scrollbar{width:8px}
.listShell::-webkit-scrollbar-track{background:transparent}
.listShell::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:4px}
.listShell::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.15)}

.list{display:flex;flex-direction:column;gap:4px}
.msg{
  padding:13px 14px;border-radius:9px;cursor:pointer;
  background:rgba(255,255,255,.018);border:1px solid transparent;
  transition:all .15s ease;
}
.msg:hover{background:rgba(255,255,255,.04);border-color:var(--line)}
.msg.selected{background:rgba(124,92,255,.08);border-color:rgba(124,92,255,.3)}
.msgTop{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:6px}
.subject{font-size:13.5px;font-weight:600;color:var(--txt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;display:flex;align-items:center;gap:7px}
.htmlTag{font-size:9px;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:.04em;padding:2px 6px;border-radius:4px;background:rgba(124,92,255,.12);color:var(--neon-2);border:1px solid rgba(124,92,255,.25);flex-shrink:0}
.time{font-size:10.5px;font-family:'JetBrains Mono',monospace;color:var(--txt-3);flex-shrink:0}
.meta{font-size:11.5px;color:var(--txt-3);line-height:1.5;margin-bottom:6px;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis}
.preview{font-size:12.5px;color:var(--txt-2);line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}

/* === DETAIL === */
.previewShell{
  border:1px solid var(--line);background:rgba(0,0,0,.4);
  border-radius:12px;padding:18px;min-height:540px;max-height:70vh;overflow-y:auto;
}
.previewShell::-webkit-scrollbar{width:8px}
.previewShell::-webkit-scrollbar-track{background:transparent}
.previewShell::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:4px}
.empty{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:100%;min-height:240px;gap:14px;
  border:1px dashed var(--line-2);border-radius:10px;
  color:var(--txt-3);font-size:13px;font-family:'JetBrains Mono',monospace;
  background:rgba(0,0,0,.2);text-align:center;padding:24px;
}
.empty .emptyIcon{
  width:54px;height:54px;border-radius:14px;
  background:radial-gradient(circle at 30% 30%,rgba(124,92,255,.18),transparent 60%),rgba(0,0,0,.4);
  border:1px solid var(--line-2);
  display:grid;place-items:center;font-size:24px;
  color:var(--neon-2);
  box-shadow:inset 0 0 20px rgba(124,92,255,.08);
}
.empty.bad{color:var(--bad);border-color:rgba(255,92,92,.3);background:rgba(255,92,92,.04)}

.mailTitle{
  font-size:20px;font-weight:700;letter-spacing:-.4px;margin-bottom:14px;
  color:var(--txt);line-height:1.3;
}
.mailMeta{
  display:grid;gap:5px;padding:12px 14px;
  background:rgba(0,0,0,.4);border:1px solid var(--line);border-radius:10px;
  font-size:12px;font-family:'JetBrains Mono',monospace;color:var(--txt-2);margin-bottom:14px;
}
.mailMeta b{color:var(--neon);font-weight:500;display:inline-block;min-width:75px}

.bodyTabs{display:flex;gap:4px;margin-bottom:10px;padding:4px;background:rgba(0,0,0,.5);border:1px solid var(--line);border-radius:9px;width:fit-content}
.bodyTab{
  padding:6px 14px;border-radius:6px;
  font-size:11.5px;font-weight:600;letter-spacing:.04em;color:var(--txt-3);
  transition:all .12s ease;font-family:'JetBrains Mono',monospace;
}
.bodyTab:hover{color:var(--txt-2)}
.bodyTab.active{
  background:linear-gradient(135deg,var(--neon-2),#5a3eff);
  color:#fff;
  box-shadow:0 4px 14px rgba(124,92,255,.35);
}
.bodybox,.bodyText,.bodyRaw{
  padding:14px;border-radius:10px;border:1px solid var(--line);
  background:rgba(0,0,0,.4);
  max-height:60vh;overflow:auto;
}
.bodyText{
  white-space:pre-wrap;word-wrap:break-word;line-height:1.6;font-size:13.5px;color:#dde2eb;
  font-family:'Inter',-apple-system,sans-serif;
}
.bodyText a{color:var(--neon);word-break:break-all;text-decoration:underline;text-decoration-color:rgba(0,229,255,.3)}
.bodyText a:hover{text-decoration-color:var(--neon)}
.bodyRaw{
  white-space:pre-wrap;word-wrap:break-word;
  font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11.5px;color:#9ba3b3;
}
.bodyFrame{
  width:100%;min-height:480px;max-height:75vh;
  border:1px solid var(--line);border-radius:10px;background:#fff;
}

/* === API PAGE === */
.apiBox{
  position:relative;border:1px solid var(--line);border-radius:12px;
  background:#000;overflow:hidden;
}
.apiToolbar{
  display:flex;align-items:center;gap:6px;
  padding:10px 14px;border-bottom:1px solid var(--line);
  background:rgba(255,255,255,.02);
}
.apiDot{width:11px;height:11px;border-radius:50%;background:#ff5f57}
.apiDot:nth-child(2){background:#febc2e}
.apiDot:nth-child(3){background:#28c840}
.api{
  margin:0;padding:18px 20px;max-height:480px;overflow:auto;
  font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12.5px;line-height:1.65;
  color:#bcd9c8;
}
.api::-webkit-scrollbar{width:8px;height:8px}
.api::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:4px}

/* === TOAST === */
.toast{position:fixed;bottom:24px;right:24px;z-index:50;display:flex;flex-direction:column-reverse;gap:8px;pointer-events:none}
.toast div{
  pointer-events:auto;
  padding:11px 16px;border-radius:10px;
  background:linear-gradient(180deg,rgba(15,18,24,.95),rgba(8,10,14,.98));
  border:1px solid var(--line-hot);
  color:var(--txt);font-size:13px;font-weight:500;
  box-shadow:0 14px 40px rgba(0,0,0,.6),0 0 24px rgba(0,229,255,.12);
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
  .side{position:relative;height:auto;flex-direction:row;padding:14px 18px;align-items:center;gap:14px}
  .side .logo{margin:0}
  .nav{flex-direction:row;gap:4px;margin-left:auto}
  .nav a:before{display:none}
  .sidefoot{display:none}
  .nav-spacer{display:none}
  .main{padding:20px 16px}
  .hero h2{font-size:26px}
  .grid{grid-template-columns:repeat(2,1fr)}
  .compose{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="logo"><div class="mark">B</div><div class="brand"><h1>TempMail</h1><p>self-hosted</p></div></div>
    <nav class="nav">
      <a class="active" href="#inbox" data-page="inbox"><span>📥</span> Inbox</a>
      <a href="#aliases" data-page="aliases"><span>✉️</span> Aliases</a>

      <div class="navGroup" data-need="admin">
        <div class="navGroupLabel">USERS</div>
        <a href="#users-add" data-page="users-add"><span>➕</span> Add User</a>
        <a href="#users-manage" data-page="users-manage"><span>🛡️</span> Lock / Delete</a>
        <a href="#users-log" data-page="users-log"><span>📜</span> User Log</a>
      </div>

      <a href="#domains" data-page="domains" data-need="super"><span>🌐</span> Domains</a>
      <a href="#change-pw" data-page="change-pw"><span>🔑</span> Change Password</a>
      <a href="#api" data-page="api"><span>🤖</span> Bot API</a>
      <a href="#status" data-page="status"><span>📊</span> Status</a>
      <div class="nav-spacer"></div>
      <a class="logout" href="/logout"><span>🚪</span> Logout</a>
    </nav>
    <div class="sidefoot">
      <div class="statusBar"><span class="statusDot"></span><span>SYSTEM ONLINE</span></div>
      <div class="sideMeta">
        <div><span>SMTP</span><b id="sideSmtp">—</b></div>
        <div><span>MSG</span><b id="sideMsg">—</b></div>
        <div><span>HOST</span><b id="sideHost">your-domain.com</b></div>
      </div>
    </div>
  </aside>
  <main class="main">
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
        <button class="btn primary" onclick="location.hash='inbox'; setTimeout(()=>createAddress(),50)">+ Random</button>
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
              <button class="btn" onclick="claimAlias('random')">🎲 Generate Random</button>
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
            <div style="font-size:54px;margin-bottom:14px;background:linear-gradient(135deg,var(--neon),var(--neon-2));-webkit-background-clip:text;background-clip:text;color:transparent;line-height:1;display:inline-block">👤</div>
            <h4 style="font-size:18px;font-weight:600;letter-spacing:-.3px;margin-bottom:6px">Buat user baru</h4>
            <p style="font-size:12.5px;color:var(--txt-3);max-width:360px;margin:0 auto 20px;line-height:1.55">Password default <b style="color:var(--neon);font-family:'JetBrains Mono',monospace">EJFamily</b> akan otomatis di-set. User wajib ganti saat first login.</p>
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
      <div class="cardHead"><h3>User Log</h3><button class="btn" onclick="loadAudit()">↻</button></div>
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
      <div class="cardHead"><h3>Bot API</h3><button class="btn" onclick="copyApi()">⎘ Copy</button></div>
      <div class="cardBody"><div class="apiBox"><div class="apiToolbar"><span class="apiDot"></span><span class="apiDot"></span><span class="apiDot"></span><span style="margin-left:10px;font-size:11px;color:var(--txt-3);font-family:'JetBrains Mono',monospace">curl-examples.sh</span></div><pre id="apihelp" class="api"></pre></div></div>
    </section>
  </main>
</div>
<div id="modalRoot" class="modalBackdrop" onclick="if(event.target===this)closeModal()"></div>
<div id="toast" class="toast"></div>
<script>
const qs=new URLSearchParams(location.search); let token=qs.get('token')||localStorage.token||'';
if(qs.get('token')){history.replaceState(null,'',location.pathname+location.hash)}
let domain=''; let lastApiText='';
async function api(path,opt={}){opt.credentials='same-origin';opt.headers=Object.assign({'content-type':'application/json'},opt.headers||{});if(token)opt.headers['x-api-token']=token;let r=await fetch(path,opt);if(r.status===401){location.href='/login';return}let j=await r.json();if(!r.ok)throw new Error(j.error||JSON.stringify(j));return j}
function esc(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}

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
function toast(s){let el=document.createElement('div');el.textContent=s;document.getElementById('toast').appendChild(el);setTimeout(()=>el.remove(),3300)}
function fmtTime(s){try{return new Date(s).toLocaleString()}catch(e){return s||''}}
function stripHtml(s){return String(s||'').replace(/<style[^>]*>[\s\S]*?<\/style>/gi,'').replace(/<script[^>]*>[\s\S]*?<\/script>/gi,'').replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/[a-zA-Z0-9_\-,.\s#:>*\[\]="']{2,80}\{[^{}]*\}/g,' ').replace(/@(media|font-face|keyframes|supports|import|charset)[^{]*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/gi,' ').replace(/\s+/g,' ').trim()}
async function status(){let s=await api('/api/status');domain=s.domain;let di=document.getElementById('domainInline'); if(di) di.textContent='*@'+s.domain;document.getElementById('stDomain').textContent=s.domain;document.getElementById('stMessages').textContent=s.messages;document.getElementById('stSmtp').textContent=s.smtp_port;document.getElementById('stAuth').textContent=s.auth?'ON':'OFF';let sm=document.getElementById('sideSmtp');if(sm)sm.textContent=':'+s.smtp_port;let smg=document.getElementById('sideMsg');if(smg)smg.textContent=s.messages;let sh=document.getElementById('sideHost');if(sh)sh.textContent=s.domain;lastApiText=`TOKEN='${token||'TOKEN'}'\nBASE='${location.origin}'\n\n# ready/open requested user email\ncurl -s "$BASE/api/ready?user=telegram" -H "x-api-token: $TOKEN" | jq\n\n# create random address\ncurl -s -X POST "$BASE/api/address" -H "x-api-token: $TOKEN" -H "content-type: application/json" -d '{}' | jq\n\n# create specific alias\ncurl -s -X POST "$BASE/api/address" -H "x-api-token: $TOKEN" -H "content-type: application/json" -d '{"local":"telegram"}' | jq\n\n# wait latest email for requested user max 30 sec\ncurl -s "$BASE/api/latest?user=telegram&wait=30" -H "x-api-token: $TOKEN" | jq\n\n# list inbox only requested user\ncurl -s "$BASE/api/messages?user=telegram&limit=20" -H "x-api-token: $TOKEN" | jq`;document.getElementById('apihelp').textContent=lastApiText;return s}
async function createAddress(){let local=document.getElementById('local').value.trim();try{let j=await api('/api/address',{method:'POST',body:JSON.stringify({local})});document.getElementById('result').textContent=JSON.stringify(j,null,2);document.getElementById('local').value=j.address.split('@')[0];toast('Ready: '+j.address);refresh();}catch(e){document.getElementById('result').textContent=e.message;toast('Error: '+e.message)}}
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
      document.getElementById('list').innerHTML=`<div class="empty">
        <div class="emptyIcon" style="font-size:36px;background:linear-gradient(135deg,var(--neon),var(--neon-2));-webkit-background-clip:text;background-clip:text;color:transparent">📭</div>
        <div style="font-size:15px;font-weight:600;color:var(--txt);margin:8px 0 4px">Belum punya alias</div>
        <div style="font-size:12px;color:var(--txt-3);max-width:340px;margin:0 auto 16px">Buat alias kustom atau generate random alias untuk mulai terima email.</div>
        <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
          <button class="btn green" onclick="openClaimAliasModal()">➕ Add Alias</button>
          <button class="btn" onclick="claimAlias('random')">🎲 Generate Random</button>
        </div>
      </div>`;
      return;
    }
    let sel=filterOverride!==undefined?filterOverride:currentTo();
    let qs='/api/messages?limit=80';
    let title='All incoming';
    if(sel && sel!=='__SUPER_ALL__'){qs+='&to='+encodeURIComponent(sel);title='Inbox: '+sel;}
    if(sel==='__SUPER_ALL__'){title='All system mail';}
    let j=await api(qs);
    document.getElementById('inboxTitle').textContent=title;
    document.getElementById('list').innerHTML=j.messages.map(m=>{
      const raw=m.preview||'';
      const isHtml=/<\/?[a-z][^>]*>/i.test(raw)||/\{[^{}]*:[^{}]*\}/.test(raw)||/@(media|keyframes|font-face)/i.test(raw);
      const cleanPreview=isHtml?stripHtml(raw):raw;
      const tag=isHtml?'<span class="htmlTag">HTML</span>':'';
      return `<article class="msg" data-id="${m.id}" onclick="loadMsg(${m.id})"><div class="msgTop"><div class="subject">${esc(m.subject||'(no subject)')}${tag}</div><div class="time">#${m.id}</div></div><div class="meta">${esc(m.from)} → ${esc(m.rcpt_to)}<br>${esc(fmtTime(m.received_at))}</div><div class="preview">${esc(cleanPreview)}</div></article>`;
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
    detail.innerHTML=`<h2 class="mailTitle">${esc(m.subject||'(no subject)')}</h2><div class="mailMeta"><div><b>From</b> ${esc(m.from)}</div><div><b>To</b> ${esc(m.rcpt_to)}</div><div><b>Received</b> ${esc(fmtTime(m.received_at))}</div></div>${tabsHtml}<div id="bodySlot"></div>`;
    detail.querySelectorAll('.bodyTab').forEach(b=>b.addEventListener('click',()=>setBodyMode(b.dataset.mode)));
    setBodyMode(defaultMode);
  }catch(e){
    document.getElementById('detail').innerHTML='<div class="empty bad">'+esc(e.message)+'</div>';
  }
}
async function copyApi(){try{await navigator.clipboard.writeText(lastApiText);toast('API examples copied')}catch(e){toast('Copy failed')}}

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
function openClaimAliasModal(){
  // Pakai dropdown domain dari aliasDomain kalau ada, fallback ke current
  const dEl=document.getElementById('aliasDomain');
  const opts=dEl?Array.from(dEl.options).map(o=>`<option value="${esc(o.value)}">${esc(o.textContent)}</option>`).join(''):`<option value="${esc(domain)}">${esc(domain)}</option>`;
  openModal({
    icon:'➕',title:'Claim Custom Alias',sub:'maks 3 alias custom per user',
    body:`<div>
      <label>Local part</label>
      <input class="input" id="mAliasLocal" placeholder="contoh: telegram, otp, kerjaan" autocomplete="off">
    </div>
    <div>
      <label>Domain</label>
      <select id="mAliasDomain" class="input" style="cursor:pointer">${opts}</select>
    </div>
    <div id="mAliasErr" style="display:none;padding:9px 12px;border-radius:9px;background:rgba(255,92,92,.10);border:1px solid rgba(255,92,92,.28);color:#ff8a8a;font-size:12px;font-family:'JetBrains Mono',monospace"></div>`,
    foot:`
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn" onclick="claimAliasFromModal('random')">🎲 Random</button>
      <button class="btn green" onclick="claimAliasFromModal('custom')">✓ Claim</button>
    `,
  });
  setTimeout(()=>document.getElementById('mAliasLocal')?.focus(),120);
}

async function claimAliasFromModal(kind){
  const local=(document.getElementById('mAliasLocal')?.value||'').trim();
  const domain=document.getElementById('mAliasDomain')?.value||'';
  const err=document.getElementById('mAliasErr');
  err.style.display='none';
  if(kind==='custom'&&!local){err.textContent='Local part wajib diisi.';err.style.display='block';return}
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
      Email yang dikirim ke <b style="color:var(--neon)">${esc(alias)}</b> akan masuk ke inbox kamu otomatis.
    </div>`,
    foot:`<button class="btn green" onclick="closeModal();window.location.hash='#inbox'">📥 Go to Inbox</button>`,
  });
}

// Backward compat: claimAlias('random') dipanggil dari empty state inbox
async function claimAlias(kind){
  if(kind==='random'){
    try{
      const j=await api('/api/aliases',{method:'POST',body:JSON.stringify({kind:'random',domain})});
      showAliasCreatedModal(j.alias,'random');
      loadAliases();
      if(typeof loadMyAliasesIntoFilter==='function')loadMyAliasesIntoFilter();
    }catch(e){toast('Error: '+e.message)}
    return;
  }
  // custom dari form aliases page
  const local=(document.getElementById('aliasLocal')?.value||'').trim();
  const dom=document.getElementById('aliasDomain')?.value||domain;
  try{
    const j=await api('/api/aliases',{method:'POST',body:JSON.stringify({kind:'custom',local,domain:dom})});
    if(document.getElementById('aliasLocal'))document.getElementById('aliasLocal').value='';
    showAliasCreatedModal(j.alias,'custom');
    loadAliases();
    if(typeof loadMyAliasesIntoFilter==='function')loadMyAliasesIntoFilter();
  }catch(e){toast('Error: '+e.message)}
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
    const meta=`<div style="display:flex;gap:14px;align-items:center;padding:0 0 14px;font-family:'JetBrains Mono',monospace;font-size:11.5px"><span style="color:var(--txt-3)">CUSTOM <b style="color:${used>=lim?'var(--warn)':'var(--neon)'}">${used}/${lim}</b></span><span style="color:var(--txt-3)">TOTAL <b style="color:var(--neon-2)">${tot}</b></span></div>`;
    const list=(j.aliases||[]).map(a=>`<div class="aliasItem">
      <div class="aliasMain">
        <code>${esc(a.alias)}</code>
        <div class="aliasMeta"><span class="kindTag ${a.kind}">${a.kind}</span><span>${esc(a.created_at||'').replace('T',' ').slice(0,19)}</span></div>
      </div>
      <button class="iconBtn" onclick="copyText('${esc(a.alias).replace(/'/g,"\\'")}',this)" title="Copy">📋</button>
      <button class="iconBtn danger" onclick="deleteAliasIt('${esc(a.alias).replace(/'/g,"\\'")}')" title="Delete">🗑</button>
    </div>`).join('')||'<div class="empty"><div class="emptyIcon">📭</div><div>Belum punya alias.<br><span style="font-size:11px;color:var(--txt-4)">Klik tombol di atas untuk claim.</span></div></div>';
    document.getElementById('aliasList').innerHTML=meta+'<div class="aliasGrid">'+list+'</div>';
  }catch(e){document.getElementById('aliasList').innerHTML='<div class="empty bad">'+esc(e.message)+'</div>'}
}

// === USERS PAGE ===
function openAddUserModal(){
  const roleOpts=me.role==='super_admin'?'<option value="user">user</option><option value="admin">admin</option>':'<option value="user">user</option>';
  openModal({
    icon:'➕',title:'Add User',sub:'password default = EJFamily',
    body:`<div>
      <label>Username</label>
      <input class="input" id="mUserName" placeholder="username (lowercase)" autocomplete="off">
    </div>
    <div>
      <label>Role</label>
      <select id="mUserRole" class="input" style="cursor:pointer">${roleOpts}</select>
    </div>
    <div style="padding:9px 12px;border-radius:9px;background:rgba(0,229,255,.06);border:1px solid rgba(0,229,255,.20);color:var(--neon-2);font-size:11.5px;font-family:'JetBrains Mono',monospace;line-height:1.55">
      ⓘ User akan dapat password default <b style="color:var(--neon)">EJFamily</b> dan WAJIB ganti saat first login.
    </div>
    <div id="mUserErr" style="display:none;padding:9px 12px;border-radius:9px;background:rgba(255,92,92,.10);border:1px solid rgba(255,92,92,.28);color:#ff8a8a;font-size:12px;font-family:'JetBrains Mono',monospace"></div>`,
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
    body:`<div style="padding:11px 14px;border-radius:11px;background:rgba(0,229,255,.06);border:1px solid rgba(0,229,255,.22);color:var(--neon-2);font-size:12.5px;line-height:1.55">
      Password ${esc(u)} akan direset ke <b style="color:var(--neon)">EJFamily</b> dan dia harus ganti saat next login.
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
  try{
    const j=await api('/api/domains',{method:'POST',body:JSON.stringify({domain,mode,owner})});
    document.getElementById('newDomainResult').textContent='✓ Added: '+JSON.stringify(j);
    document.getElementById('newDomain').value='';
    document.getElementById('newDomainOwner').value='';
    toast('Domain '+j.domain+' added');
    loadDomains();status();
  }catch(e){document.getElementById('newDomainResult').textContent=e.message;toast('Error: '+e.message)}
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
async function loadAudit(){
  try{
    const j=await api('/api/audit?limit=200');
    document.getElementById('auditList').innerHTML=(j.audit||[]).map(r=>{
      const meta=Object.keys(r.meta||{}).length?` <span class="htmlTag" style="background:rgba(255,255,255,.04)">${esc(JSON.stringify(r.meta))}</span>`:'';
      const reason=r.reason?`<br>reason: <i>${esc(r.reason)}</i>`:'';
      const actorTag=`<span class="actorTag" title="actor">${esc(r.actor)}</span>`;
      return `<article class="msg"><div class="msgTop"><div class="subject"><b>${esc(r.action)}</b> → ${esc(r.target||'-')} ${actorTag}</div><div class="time">#${r.id}</div></div><div class="meta">${esc(r.ts)}${meta}${reason}</div></article>`;
    }).join('')||'<div class="empty"><div class="emptyIcon">📜</div><div>No audit entries</div></div>';
  }catch(e){document.getElementById('auditList').innerHTML='<div class="empty bad">'+esc(e.message)+'</div>'}
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
    bar.style.background=score<2?'var(--bad)':score<4?'var(--warn)':'var(--ok)';
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
  'users-add':['Add User','Tambah user baru. Password default <b>EJFamily</b>, wajib ganti saat login pertama.'],
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
  applyRoleVisibility();
  const s=await status().catch(e=>{toast(e.message);return{}});
  availDomains=s.domains||[{domain:domain}];
  refreshDomainSelect();
  route();
  refresh();
})();
setInterval(()=>{((location.hash||'#inbox').replace('#','')==='inbox')?refresh():status()},15000);
</script>
</body>
</html>
"""


LOGIN_HTML = """<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login · TempMail</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#000;--card:#0a0c10;--line:rgba(255,255,255,.06);--line2:rgba(255,255,255,.10);--neon:#00e5ff;--neon-2:#7c5cff;--neon-3:#ff3d8b;--ok:#22d995;--text:#f3f4f7;--sub:#aab1bd;--muted:#6b7280;--bad:#ff5c5c}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:
    radial-gradient(1200px 700px at 20% -10%,rgba(124,92,255,.14),transparent 60%),
    radial-gradient(900px 500px at 100% 110%,rgba(0,229,255,.08),transparent 60%),
    radial-gradient(700px 500px at 0% 100%,rgba(255,61,139,.06),transparent 60%),
    var(--bg);
  color:var(--text);
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  display:grid;place-items:center;padding:20px;
  -webkit-font-smoothing:antialiased;
  overflow:hidden;
}
body:before{
  content:"";position:fixed;inset:0;pointer-events:none;
  background-image:
    linear-gradient(rgba(255,255,255,.014) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.014) 1px,transparent 1px);
  background-size:48px 48px;
  mask-image:radial-gradient(ellipse at center,#000 30%,transparent 80%);
}
.box{
  position:relative;z-index:1;
  width:100%;max-width:400px;
  padding:36px 32px 32px;
  background:linear-gradient(180deg,rgba(15,18,24,.85),rgba(8,10,14,.95));
  border:1px solid var(--line);
  border-radius:18px;
  box-shadow:0 30px 80px rgba(0,0,0,.6),0 0 0 1px rgba(255,255,255,.02) inset;
  backdrop-filter:blur(20px);
}
.box:before{
  content:"";position:absolute;top:0;left:20px;right:20px;height:1px;
  background:linear-gradient(90deg,transparent,var(--neon-2),transparent);
  opacity:.5;
}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:24px}
.mark{
  width:42px;height:42px;border-radius:11px;
  background:conic-gradient(from 200deg,var(--neon),var(--neon-2),var(--neon-3),var(--neon));
  display:grid;place-items:center;color:#000;font-weight:800;font-size:18px;
  box-shadow:0 0 28px rgba(0,229,255,.45),inset 0 0 14px rgba(0,0,0,.3);
  animation:spin 8s linear infinite;
}
@keyframes spin{to{filter:hue-rotate(360deg)}}
h1{font-size:17px;font-weight:700;letter-spacing:-.3px}
.sub{margin-top:2px;font-size:12px;color:var(--muted);font-family:'JetBrains Mono',monospace}
form{margin-top:24px;display:grid;gap:14px}
label{font-size:11px;font-weight:600;color:var(--sub);text-transform:uppercase;letter-spacing:.1em}
.inputWrap{
  margin-top:8px;border:1px solid var(--line2);background:#000;border-radius:10px;
  overflow:hidden;transition:all .15s ease;
}
.inputWrap:focus-within{
  border-color:var(--neon);
  box-shadow:0 0 0 3px rgba(0,229,255,.12),0 8px 22px rgba(0,229,255,.08);
}
input{
  width:100%;border:0;background:transparent;
  padding:14px 16px;color:#fff;
  font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:500;
  letter-spacing:.5px;outline:0;
}
input::placeholder{color:rgba(255,255,255,.18)}
.field+.field{margin-top:14px}
button{
  cursor:pointer;border:0;
  background:linear-gradient(135deg,var(--neon-2),#5a3eff);
  color:#fff;
  padding:14px 20px;border-radius:10px;
  font-weight:700;font-size:13px;letter-spacing:.5px;text-transform:uppercase;
  transition:all .15s ease;
  box-shadow:0 8px 24px rgba(124,92,255,.35),inset 0 1px 0 rgba(255,255,255,.18);
}
button:hover{transform:translateY(-1px);box-shadow:0 12px 32px rgba(124,92,255,.5),inset 0 1px 0 rgba(255,255,255,.25)}
button:active{transform:translateY(0)}
.err{
  margin-top:4px;padding:11px 14px;
  background:rgba(255,92,92,.08);border:1px solid rgba(255,92,92,.25);
  border-radius:9px;color:var(--bad);font-size:12.5px;text-align:center;
  font-family:'JetBrains Mono',monospace;
}
.foot{
  margin-top:20px;padding-top:18px;border-top:1px solid var(--line);
  text-align:center;color:var(--muted);font-size:11px;font-family:'JetBrains Mono',monospace;
}
.foot span{color:var(--ok)}
</style>
</head>
<body>
<div class="box">
  <div class="logo">
    <div class="mark">B</div>
    <div>
      <h1>TempMail</h1>
      <p class="sub">self-hosted · access required</p>
    </div>
  </div>
  <form method="POST" action="/login" autocomplete="off">
    <div class="field">
      <label for="username">Username</label>
      <div class="inputWrap"><input id="username" name="username" type="text" autocomplete="username" placeholder="6715" autofocus required></div>
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
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Change Password · TempMail</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#000;--card:#0a0c10;--line:rgba(255,255,255,.06);--line2:rgba(255,255,255,.10);--neon:#00e5ff;--neon-2:#7c5cff;--neon-3:#ff3d8b;--ok:#22d995;--text:#f3f4f7;--sub:#aab1bd;--muted:#6b7280;--bad:#ff5c5c;--warn:#ffb454}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:radial-gradient(1200px 700px at 20% -10%,rgba(124,92,255,.14),transparent 60%),radial-gradient(900px 500px at 100% 110%,rgba(0,229,255,.08),transparent 60%),var(--bg);
  color:var(--text);font-family:'Inter',sans-serif;display:grid;place-items:center;padding:20px;
}
.box{width:100%;max-width:440px;padding:30px 28px 26px;background:linear-gradient(180deg,rgba(15,18,24,.85),rgba(8,10,14,.95));border:1px solid var(--line);border-radius:18px;box-shadow:0 30px 80px rgba(0,0,0,.6);backdrop-filter:blur(20px)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.mark{width:42px;height:42px;border-radius:11px;background:conic-gradient(from 200deg,var(--neon),var(--neon-2),var(--neon-3),var(--neon));display:grid;place-items:center;color:#000;font-weight:800;box-shadow:0 0 28px rgba(0,229,255,.45)}
h1{font-size:17px;font-weight:700}
.sub{margin-top:2px;font-size:12px;color:var(--muted);font-family:'JetBrains Mono',monospace}
.notice{margin-top:14px;padding:11px 14px;background:rgba(255,180,84,.08);border:1px solid rgba(255,180,84,.25);border-radius:9px;color:var(--warn);font-size:12.5px;line-height:1.5}
.notice b{color:#ffd28c}
form{margin-top:14px;display:grid;gap:10px}
label{font-size:11px;font-weight:600;color:var(--sub);text-transform:uppercase;letter-spacing:.1em}
.inputWrap{margin-top:5px;border:1px solid var(--line2);background:#000;border-radius:10px;overflow:hidden;transition:all .15s ease}
.inputWrap:focus-within{border-color:var(--neon);box-shadow:0 0 0 3px rgba(0,229,255,.12)}
input{width:100%;border:0;background:transparent;padding:12px 14px;color:#fff;font-family:'JetBrains Mono',monospace;font-size:14px;outline:0}
button{cursor:pointer;border:0;background:linear-gradient(135deg,var(--neon-2),#5a3eff);color:#fff;padding:13px 20px;border-radius:10px;font-weight:700;font-size:13px;letter-spacing:.5px;text-transform:uppercase;box-shadow:0 8px 24px rgba(124,92,255,.35);margin-top:6px}
button:hover{transform:translateY(-1px)}
.err{margin-top:4px;padding:11px 14px;background:rgba(255,92,92,.08);border:1px solid rgba(255,92,92,.25);border-radius:9px;color:var(--bad);font-size:12.5px;text-align:center}

.pwRules{list-style:none;padding:8px 0 0;margin:0;display:grid;gap:4px}
.pwRules li{font-size:11.5px;padding:6px 10px;border-radius:7px;background:rgba(255,92,92,.06);border:1px solid rgba(255,92,92,.18);color:#ff9a9a;font-family:'JetBrains Mono',monospace;transition:all .15s ease;position:relative;padding-left:28px}
.pwRules li:before{content:"✗";position:absolute;left:10px;top:50%;transform:translateY(-50%);font-weight:700;color:#ff5c5c}
.pwRules li.ok{background:rgba(34,217,149,.06);border-color:rgba(34,217,149,.25);color:var(--ok)}
.pwRules li.ok:before{content:"✓";color:var(--ok)}
.pwStrength{margin-top:8px;height:5px;border-radius:99px;background:rgba(255,255,255,.05);overflow:hidden;border:1px solid var(--line)}
.pwStrength .bar{height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,var(--bad),var(--warn),var(--ok));transition:width .25s ease}
</style>
</head>
<body>
<div class="box">
  <div class="logo"><div class="mark">B</div><div><h1>Set new password</h1><p class="sub">first login · required</p></div></div>
  <div class="notice">⚠ <b>Mandatory.</b> Password default <b>EJFamily</b> harus diganti sebelum lanjut. Tidak perlu masukkan password lama.</div>
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
  bar.style.background=score<2?'var(--bad)':score<4?'var(--warn)':'var(--ok)';
}
document.getElementById('new').focus();
</script>
</body>
</html>
"""


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
          1. master API token via x-api-token (super_admin power, untuk script/bot)
          2. session cookie (per-user dari users table)
        """
        # 1. Master API token = super_admin level
        if API_TOKEN and self.headers.get("x-api-token") == API_TOKEN:
            return {"username": "_api_token", "role": au.ROLE_SUPER,
                    "must_change_password": 0, "via": "api_token"}
        # 2. Session cookie
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

    def send_html(self):
        data = INDEX_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_login_html(self, error=""):
        err_html = f'<div class="err">{html.escape(error)}</div>' if error else ''
        page = LOGIN_HTML.replace("__ERROR__", err_html)
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_change_pw_html(self, error=""):
        err_html = f'<div class="err">{html.escape(error)}</div>' if error else ''
        page = CHANGE_PW_HTML.replace("__ERROR__", err_html)
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
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
                return self.redirect("/login")
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
            return self.send_json({
                "username": u["username"], "role": u["role"],
                "must_change_password": bool(u.get("must_change_password")),
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
            # Default initial password = EJFamily. Bypass policy karena user
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
                    # bypass policy lewat raw update — initial password EJFamily
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
            with db() as c:
                d = ad.add_domain(c, domain=b.get("domain") or "",
                                  mode=(b.get("mode") or "public").lower(),
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
