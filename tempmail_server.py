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
from urllib.parse import parse_qs, urlparse

from aiosmtpd.controller import Controller

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
    return addr.endswith("@" + DOMAIN)


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
<title>TempMail</title>
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
  background:
    radial-gradient(1200px 700px at 15% -10%,rgba(124,92,255,.10),transparent 60%),
    radial-gradient(900px 500px at 110% 0%,rgba(0,229,255,.06),transparent 55%),
    radial-gradient(800px 600px at 90% 110%,rgba(255,61,139,.05),transparent 60%),
    var(--bg-0);
  color:var(--txt);
  font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  font-feature-settings:"cv02","cv03","cv04","cv11";
  letter-spacing:-.011em;
  -webkit-font-smoothing:antialiased;
  overflow-x:hidden;
}
/* Subtle grid texture overlay */
body:before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:
    linear-gradient(rgba(255,255,255,.012) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.012) 1px,transparent 1px);
  background-size:48px 48px;
  mask-image:radial-gradient(ellipse at center,#000 30%,transparent 80%);
}
button,input{font:inherit;color:inherit;outline:0}
button{cursor:pointer;border:0;background:none}
a{color:inherit;text-decoration:none}

/* === LAYOUT === */
.app{position:relative;z-index:1;min-height:100vh;display:grid;grid-template-columns:260px 1fr}
.side{
  position:sticky;top:0;height:100vh;display:flex;flex-direction:column;
  padding:22px 18px;
  border-right:1px solid var(--line);
  background:linear-gradient(180deg,rgba(5,6,8,.8),rgba(0,0,0,.95));
  backdrop-filter:blur(20px);
}
.logo{display:flex;align-items:center;gap:11px;margin-bottom:32px;padding:0 6px}
.mark{
  width:36px;height:36px;border-radius:10px;
  background:conic-gradient(from 200deg,var(--neon),var(--neon-2),var(--neon-3),var(--neon));
  display:grid;place-items:center;color:#000;font-weight:800;font-size:16px;
  box-shadow:0 0 24px rgba(0,229,255,.4),inset 0 0 12px rgba(0,0,0,.3);
  animation:spin 8s linear infinite;
}
@keyframes spin{to{filter:hue-rotate(360deg)}}
.brand h1{font-size:15px;font-weight:700;letter-spacing:-.3px}
.brand p{font-size:11px;color:var(--txt-3);font-family:'JetBrains Mono',monospace;margin-top:1px}

.nav{display:flex;flex-direction:column;gap:3px}
.nav a{
  display:flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:9px;
  font-size:13.5px;font-weight:500;color:var(--txt-2);
  border:1px solid transparent;
  transition:all .15s ease;
  position:relative;
}
.nav a:hover{color:var(--txt);background:rgba(255,255,255,.025)}
.nav a.active{
  background:linear-gradient(135deg,rgba(124,92,255,.12),rgba(0,229,255,.04));
  border-color:rgba(124,92,255,.25);
  color:var(--txt);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.04),0 4px 14px rgba(124,92,255,.12);
}
.nav a.active:before{
  content:"";position:absolute;left:-19px;top:50%;transform:translateY(-50%);
  width:3px;height:18px;border-radius:0 3px 3px 0;
  background:linear-gradient(180deg,var(--neon),var(--neon-2));
  box-shadow:0 0 12px var(--neon);
}
.nav a.logout{margin-top:auto;color:#ff8a8a}
.nav a.logout:hover{background:rgba(255,92,92,.08);border-color:rgba(255,92,92,.2)}
.nav-spacer{flex:1}

.sidefoot{padding:14px 6px 0;border-top:1px solid var(--line);margin-top:14px}
.statusBar{display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:8px;background:rgba(34,217,149,.06);border:1px solid rgba(34,217,149,.18)}
.statusDot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 10px var(--ok);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.statusBar span{font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--ok)}
.sideMeta{display:grid;gap:6px;margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:11px}
.sideMeta>div{display:flex;justify-content:space-between;padding:6px 10px;border-radius:7px;background:rgba(255,255,255,.018);border:1px solid var(--line)}
.sideMeta span{color:var(--txt-3);text-transform:uppercase;letter-spacing:.08em;font-size:10px}
.sideMeta b{color:var(--neon);font-weight:500}

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
.card{
  position:relative;
  border-radius:16px;
  background:linear-gradient(180deg,rgba(15,18,24,.7),rgba(8,10,14,.85));
  border:1px solid var(--line);
  overflow:hidden;
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
    <div class="logo"><div class="mark">B</div><div class="brand"><h1>TempMail</h1><p>example.com</p></div></div>
    <nav class="nav">
      <a class="active" href="#inbox" data-page="inbox"><span>📥</span> Inbox</a>
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
        <div><span>HOST</span><b id="sideHost">example.com</b></div>
      </div>
    </div>
  </aside>
  <main class="main">
    <section class="top">
      <div class="hero">
        <h2 id="pageTitle">Inbox</h2>
        <p id="pageSubtitle">Tangkap email ke <b id="domainInline">*@domain</b>, baca isinya, ambil OTP via API.</p>
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
      <div class="card inboxTools">
        <div class="cardHead"><h3>Ready Email</h3><span class="pill"><span class="dot"></span> choose alias</span></div>
        <div class="cardBody">
          <div class="bodyPanel">
            <label class="formLabel" for="local">User / alias <span class="hint">contoh: telegram → telegram@example.com</span></label>
            <div class="compose">
              <div class="inputWrap"><span class="inputPrefix">@</span><input class="input" id="local" placeholder="telegram / otp / akun1"></div>
              <button class="btn green" onclick="createAddress()">+ Ready</button>
            </div>
            <div class="quick">
              <button onclick="document.getElementById('local').value='otp';createAddress()">otp</button>
              <button onclick="document.getElementById('local').value='telegram';createAddress()">telegram</button>
              <button onclick="document.getElementById('local').value='discord';createAddress()">discord</button>
              <button onclick="document.getElementById('local').value='kiro';createAddress()">kiro</button>
              <button onclick="document.getElementById('local').value='';createAddress()">random</button>
            </div>
            <div id="result" class="result">Isi alias di atas lalu klik Ready. Inbox akan otomatis filter ke alamat itu.</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="cardHead"><h3 id="inboxTitle">Inbox</h3><div class="tabs"><button class="btn" onclick="refresh()">↻</button><button class="btn" onclick="document.getElementById('local').value='';refresh()">All</button></div></div>
        <div class="cardBody"><div class="listShell"><div id="list" class="list"><div class="empty"><div class="emptyIcon">📭</div><div>Loading inbox...</div></div></div></div></div>
      </div>
      <div class="card detail">
        <div class="cardHead"><h3>Message</h3><span class="pill" id="selectedPill">—</span></div>
        <div class="cardBody"><div class="previewShell"><div id="detail" class="empty"><div class="emptyIcon">✉</div><div>Pilih email dari list<br><span style="font-size:11px;color:var(--txt-4)">Klik salah satu pesan di kiri untuk membaca</span></div></div></div></div>
      </div>
    </section>

    <section class="card page" id="api" data-page="api">
      <div class="cardHead"><h3>Bot API</h3><button class="btn" onclick="copyApi()">⎘ Copy</button></div>
      <div class="cardBody"><div class="apiBox"><div class="apiToolbar"><span class="apiDot"></span><span class="apiDot"></span><span class="apiDot"></span><span style="margin-left:10px;font-size:11px;color:var(--txt-3);font-family:'JetBrains Mono',monospace">curl-examples.sh</span></div><pre id="apihelp" class="api"></pre></div></div>
    </section>
  </main>
</div>
<div id="toast" class="toast"></div>
<script>
const qs=new URLSearchParams(location.search); let token=qs.get('token')||localStorage.token||'';
if(qs.get('token')){history.replaceState(null,'',location.pathname+location.hash)}
let domain=''; let lastApiText='';
async function api(path,opt={}){opt.credentials='same-origin';opt.headers=Object.assign({'content-type':'application/json'},opt.headers||{});if(token)opt.headers['x-api-token']=token;let r=await fetch(path,opt);if(r.status===401){location.href='/login';return}let j=await r.json();if(!r.ok)throw new Error(j.error||JSON.stringify(j));return j}
function esc(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function toast(s){let el=document.createElement('div');el.textContent=s;document.getElementById('toast').appendChild(el);setTimeout(()=>el.remove(),3300)}
function fmtTime(s){try{return new Date(s).toLocaleString()}catch(e){return s||''}}
function stripHtml(s){return String(s||'').replace(/<style[^>]*>[\s\S]*?<\/style>/gi,'').replace(/<script[^>]*>[\s\S]*?<\/script>/gi,'').replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/[a-zA-Z0-9_\-,.\s#:>*\[\]="']{2,80}\{[^{}]*\}/g,' ').replace(/@(media|font-face|keyframes|supports|import|charset)[^{]*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/gi,' ').replace(/\s+/g,' ').trim()}
async function status(){let s=await api('/api/status');domain=s.domain;let di=document.getElementById('domainInline'); if(di) di.textContent='*@'+s.domain;document.getElementById('stDomain').textContent=s.domain;document.getElementById('stMessages').textContent=s.messages;document.getElementById('stSmtp').textContent=s.smtp_port;document.getElementById('stAuth').textContent=s.auth?'ON':'OFF';let sm=document.getElementById('sideSmtp');if(sm)sm.textContent=':'+s.smtp_port;let smg=document.getElementById('sideMsg');if(smg)smg.textContent=s.messages;let sh=document.getElementById('sideHost');if(sh)sh.textContent=s.domain;lastApiText=`TOKEN='${token||'TOKEN'}'\nBASE='${location.origin}'\n\n# ready/open requested user email\ncurl -s "$BASE/api/ready?user=telegram" -H "x-api-token: $TOKEN" | jq\n\n# create random address\ncurl -s -X POST "$BASE/api/address" -H "x-api-token: $TOKEN" -H "content-type: application/json" -d '{}' | jq\n\n# create specific alias\ncurl -s -X POST "$BASE/api/address" -H "x-api-token: $TOKEN" -H "content-type: application/json" -d '{"local":"telegram"}' | jq\n\n# wait latest email for requested user max 30 sec\ncurl -s "$BASE/api/latest?user=telegram&wait=30" -H "x-api-token: $TOKEN" | jq\n\n# list inbox only requested user\ncurl -s "$BASE/api/messages?user=telegram&limit=20" -H "x-api-token: $TOKEN" | jq`;document.getElementById('apihelp').textContent=lastApiText;return s}
async function createAddress(){let local=document.getElementById('local').value.trim();try{let j=await api('/api/address',{method:'POST',body:JSON.stringify({local})});document.getElementById('result').textContent=JSON.stringify(j,null,2);document.getElementById('local').value=j.address.split('@')[0];toast('Ready: '+j.address);refresh();}catch(e){document.getElementById('result').textContent=e.message;toast('Error: '+e.message)}}
function currentTo(){let v=document.getElementById('local').value.trim(); if(!v) return ''; return v.includes('@')?v:v+'@'+domain}
async function refresh(){try{await status();let to=currentTo();let path='/api/messages?limit=80'+(to?'&to='+encodeURIComponent(to):'');let j=await api(path);let title=to?`Inbox: ${to}`:'All incoming';document.getElementById('inboxTitle').textContent=title;document.getElementById('list').innerHTML=j.messages.map(m=>{const raw=m.preview||'';const isHtml=/<\/?[a-z][^>]*>/i.test(raw)||/\{[^{}]*:[^{}]*\}/.test(raw)||/@(media|keyframes|font-face)/i.test(raw);const cleanPreview=isHtml?stripHtml(raw):raw;const tag=isHtml?'<span class="htmlTag">HTML</span>':'';return `<article class="msg" data-id="${m.id}" onclick="loadMsg(${m.id})"><div class="msgTop"><div class="subject">${esc(m.subject||'(no subject)')}${tag}</div><div class="time">#${m.id}</div></div><div class="meta">${esc(m.from)} → ${esc(m.rcpt_to)}<br>${esc(fmtTime(m.received_at))}</div><div class="preview">${esc(cleanPreview)}</div></article>`}).join('')||'<div class="empty"><div class="emptyIcon">📭</div><div>Belum ada email masuk<br><span style="font-size:11px;color:var(--txt-4)">Email akan muncul di sini secara real-time</span></div></div>'; }catch(e){document.getElementById('list').innerHTML='<div class="empty bad"><div class="emptyIcon">⚠</div><div>'+esc(e.message)+'</div></div>';toast('Error: '+e.message)}}
function linkify(s){return String(s||'').replace(/(https?:\/\/[^\s<>"']+)/g,m=>`<a href="${m}" target="_blank" rel="noopener noreferrer">${m}</a>`)}
function renderBody(m,mode){
  if(mode==='raw'){return `<pre class="bodybox bodyRaw">${esc(m.raw||'')}</pre>`}
  if(mode==='html' && m.html_body){
    const srcdoc=m.html_body.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
    return `<iframe class="bodyFrame" sandbox="allow-popups allow-popups-to-escape-sandbox" srcdoc="${srcdoc}"></iframe>`;
  }
  if(m.text_body){return `<div class="bodybox bodyText">${linkify(esc(m.text_body))}</div>`}
  if(m.html_body){const srcdoc=m.html_body.replace(/&/g,'&amp;').replace(/"/g,'&quot;');return `<iframe class="bodyFrame" sandbox="allow-popups allow-popups-to-escape-sandbox" srcdoc="${srcdoc}"></iframe>`}
  return `<pre class="bodybox bodyRaw">${esc(m.raw||'')}</pre>`;
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

const pageMeta={
  inbox:['Inbox','Tangkap email ke <b>*@DOMAIN</b>, baca isinya, ambil OTP via API.'],
  api:['Bot API','Endpoint siap pakai: ready email, list inbox, wait latest OTP.'],
  status:['Status','Realtime SMTP receiver, total messages, dan domain config.']
};
function route(){
  let page=(location.hash||'#inbox').replace('#','')||'inbox';
  if(page==='create') page='inbox'; if(!pageMeta[page]) page='inbox';
  document.querySelectorAll('.page').forEach(el=>el.classList.toggle('active',el.dataset.page===page));
  document.querySelectorAll('.nav a[data-page]').forEach(a=>a.classList.toggle('active',a.dataset.page===page));
  let meta=pageMeta[page];
  document.getElementById('pageTitle').textContent=meta[0];
  document.getElementById('pageSubtitle').innerHTML=meta[1].replace('DOMAIN',(domain||'domain'));
  if(page==='inbox') refresh(); else status().catch(e=>toast(e.message));
}
window.addEventListener('hashchange',route);
status().then(()=>{route();refresh()}).catch(e=>toast(e.message));
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
  padding:15px 16px;color:#fff;
  font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:600;
  letter-spacing:8px;text-align:center;outline:0;
}
input::placeholder{letter-spacing:6px;color:rgba(255,255,255,.12)}
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
      <p class="sub">example.com · access required</p>
    </div>
  </div>
  <form method="POST" action="/login" autocomplete="off">
    <div>
      <label for="code">Access code</label>
      <div class="inputWrap"><input id="code" name="code" type="password" inputmode="numeric" autocomplete="off" placeholder="••••" autofocus required></div>
    </div>
    <button type="submit">Authenticate →</button>
    __ERROR__
  </form>
  <div class="foot">Session 7 days · <span>encrypted</span> · self-hosted</div>
</div>
<script>document.getElementById('code').focus();</script>
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

    def authed(self):
        # 1. API token via header (untuk script/bot)
        if API_TOKEN and self.headers.get("x-api-token") == API_TOKEN:
            return True
        # 2. Session cookie (untuk dashboard browser)
        sid = self._read_cookie("tm_sid")
        if _session_valid(sid):
            return True
        # 3. Backward-compat: ?token= di URL (deprecated, masih jalan)
        if API_TOKEN:
            qs = parse_qs(urlparse(self.path).query)
            if qs.get("token", [""])[0] == API_TOKEN:
                return True
        # 4. Kalau auth tidak dikonfigurasi sama sekali, allow (mode dev)
        if not API_TOKEN and not ACCESS_CODE:
            return True
        return False

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
            if dom.lower() != DOMAIN:
                raise RuntimeError(f"domain harus {DOMAIN}")
        else:
            local = raw
        if not LOCAL_RE.match(local):
            raise RuntimeError("user/alias invalid. Pakai huruf/angka/dot/underscore/plus/minus max 64 char")
        return local, f"{local}@{DOMAIN}"

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/login":
            return self.send_login_html()
        if path == "/logout":
            sid = self._read_cookie("tm_sid")
            if sid:
                _session_revoke(sid)
            return self.redirect("/login", clear_cookie="tm_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        if path == "/":
            # If access code is set and user is not authed, redirect to login
            if ACCESS_CODE and not self.authed():
                return self.redirect("/login")
            return self.send_html()
        if not self.authed():
            return self.send_json({"error": "unauthorized"}, 401)
        try:
            if path == "/api/status":
                with db() as c:
                    mc = c.execute("SELECT COUNT(*) n FROM messages").fetchone()["n"]
                    ac = c.execute("SELECT COUNT(*) n FROM addresses").fetchone()["n"]
                return self.send_json({"domain": DOMAIN, "smtp_port": SMTP_PORT, "web_port": WEB_PORT, "messages": mc, "addresses": ac, "auth": bool(API_TOKEN)})
            if path == "/api/ready":
                qs = parse_qs(urlparse(self.path).query)
                local, addr = self.requested_address(qs=qs)
                if not addr:
                    raise RuntimeError("isi parameter user/local/to, contoh /api/ready?user=telegram")
                label = qs.get("label", [""])[0].strip()
                with db() as c:
                    c.execute("INSERT OR IGNORE INTO addresses(address,label,created_at) VALUES(?,?,?)", (addr, label, now_iso()))
                    count = c.execute("SELECT COUNT(*) n FROM messages WHERE rcpt_to=?", (addr,)).fetchone()["n"]
                    latest = c.execute("SELECT * FROM messages WHERE rcpt_to=? ORDER BY id DESC LIMIT 1", (addr,)).fetchone()
                return self.send_json({"ready": True, "user": local, "address": addr, "messages": count, "latest": row_to_summary(latest) if latest else None, "api": {"list": f"/api/messages?user={local}&limit=20", "latest": f"/api/latest?user={local}&wait=30"}})
            if path == "/api/messages":
                qs = parse_qs(urlparse(self.path).query)
                _local, to = self.requested_address(qs=qs)
                limit = min(int(qs.get("limit", ["50"])[0]), 200)
                with db() as c:
                    if to:
                        rows = c.execute("SELECT * FROM messages WHERE rcpt_to=? ORDER BY id DESC LIMIT ?", (to, limit)).fetchall()
                    else:
                        rows = c.execute("SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
                return self.send_json({"address": to or None, "messages": [row_to_summary(r) for r in rows]})
            if path == "/api/latest":
                qs = parse_qs(urlparse(self.path).query)
                _local, to = self.requested_address(qs=qs)
                since_id = int(qs.get("since_id", ["0"])[0])
                wait = min(int(qs.get("wait", ["0"])[0]), 60)
                deadline = time.time() + wait
                while True:
                    with db() as c:
                        if to:
                            r = c.execute("SELECT * FROM messages WHERE rcpt_to=? AND id>? ORDER BY id DESC LIMIT 1", (to, since_id)).fetchone()
                        else:
                            r = c.execute("SELECT * FROM messages WHERE id>? ORDER BY id DESC LIMIT 1", (since_id,)).fetchone()
                    if r:
                        return self.send_json(row_to_full(r))
                    if time.time() >= deadline:
                        return self.send_json({"message": None})
                    time.sleep(1)
            m = re.match(r"^/api/messages/(\d+)$", path)
            if m:
                mid = int(m.group(1))
                with db() as c:
                    r = c.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
                if not r:
                    return self.send_json({"error": "not found"}, 404)
                return self.send_json(row_to_full(r))
            if path == "/api/addresses":
                with db() as c:
                    rows = c.execute("SELECT * FROM addresses ORDER BY created_at DESC LIMIT 500").fetchall()
                return self.send_json({"addresses": [dict(r) for r in rows]})
            return self.send_json({"error": "not found"}, 404)
        except Exception as e:
            return self.send_json({"error": str(e)}, 500)

    def do_POST(self):
        path = urlparse(self.path).path
        # Login endpoint — public, no auth required
        if path == "/login":
            ip = self.client_address[0]
            ok, retry = _login_check_rate(ip)
            if not ok:
                return self.send_login_html(error=f"Terlalu banyak percobaan. Coba lagi dalam {retry} detik.")
            n = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(n).decode("utf-8") if n else ""
            ctype = self.headers.get("content-type") or ""
            code = ""
            if "application/x-www-form-urlencoded" in ctype:
                code = parse_qs(raw).get("code", [""])[0].strip()
            elif "application/json" in ctype:
                try:
                    code = (json.loads(raw or "{}").get("code") or "").strip()
                except Exception:
                    code = ""
            else:
                code = parse_qs(raw).get("code", [""])[0].strip()
            if not ACCESS_CODE:
                return self.send_login_html(error="Login dimatikan: ACCESS_CODE belum di-set di .env")
            if code != ACCESS_CODE:
                _login_record_fail(ip)
                return self.send_login_html(error="Access code salah. Coba lagi.")
            # Success: clear fail counter, issue session
            _login_clear(ip)
            sid = _new_session()
            cookie = f"tm_sid={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
            return self.redirect("/", set_cookie=cookie)
        if not self.authed():
            return self.send_json({"error": "unauthorized"}, 401)
        try:
            if path == "/api/ready":
                b = self.body()
                local, addr = self.requested_address(body=b)
                if not addr:
                    raise RuntimeError("isi JSON user/local/to, contoh {\"user\":\"telegram\"}")
                label = (b.get("label") or "").strip()
                with db() as c:
                    c.execute("INSERT OR IGNORE INTO addresses(address,label,created_at) VALUES(?,?,?)", (addr, label, now_iso()))
                    count = c.execute("SELECT COUNT(*) n FROM messages WHERE rcpt_to=?", (addr,)).fetchone()["n"]
                    latest = c.execute("SELECT * FROM messages WHERE rcpt_to=? ORDER BY id DESC LIMIT 1", (addr,)).fetchone()
                return self.send_json({"ready": True, "user": local, "address": addr, "messages": count, "latest": row_to_summary(latest) if latest else None, "api": {"list": f"/api/messages?user={local}&limit=20", "latest": f"/api/latest?user={local}&wait=30"}})
            if path == "/api/address":
                b = self.body()
                local = (b.get("local") or "").strip().lower()
                label = (b.get("label") or "").strip()
                if not local:
                    local = "tmp" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
                if "@" in local:
                    local, dom = local.split("@", 1)
                    if dom.lower() != DOMAIN:
                        raise RuntimeError(f"domain harus {DOMAIN}")
                if not LOCAL_RE.match(local):
                    raise RuntimeError("alias invalid. Pakai huruf/angka/dot/underscore/plus/minus max 64 char")
                addr = f"{local}@{DOMAIN}"
                with db() as c:
                    c.execute("INSERT OR IGNORE INTO addresses(address,label,created_at) VALUES(?,?,?)", (addr, label, now_iso()))
                return self.send_json({"address": addr})
            return self.send_json({"error": "not found"}, 404)
        except Exception as e:
            return self.send_json({"error": str(e)}, 500)

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not self.authed():
            return self.send_json({"error": "unauthorized"}, 401)
        m = re.match(r"^/api/messages/(\d+)$", path)
        if not m:
            return self.send_json({"error": "not found"}, 404)
        with db() as c:
            c.execute("DELETE FROM messages WHERE id=?", (int(m.group(1)),))
        return self.send_json({"deleted": int(m.group(1))})


def run_web():
    srv = ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler)
    print(f"Dashboard/API: http://{WEB_HOST}:{WEB_PORT}/" + (f"?token={API_TOKEN}" if API_TOKEN else ""), flush=True)
    srv.serve_forever()


def main():
    init_db()
    smtp = Controller(TempMailSMTP(), hostname=MAIL_HOST, port=SMTP_PORT)
    smtp.start()
    print(f"SMTP receiver: {MAIL_HOST}:{SMTP_PORT} accepting *@{DOMAIN}", flush=True)
    stop = threading.Event()

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
