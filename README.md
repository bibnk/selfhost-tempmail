# Self-hosted TempMail

Self-hosted disposable / temporary email server with SMTP receiver + web dashboard + bot API. Multi-user, multi-domain, role-based.

## Features

### Mail engine
- **SMTP receiver** on port 25 via `aiosmtpd`. Catches `*@your-domain` wildcard.
- **Multi-domain** — add domains at runtime via dashboard (super_admin).
- **Domain modes** — `public` (any user can claim aliases) or `private` (owner only).
- **Auto-cleanup** — emails older than 48 hours auto-deleted (configurable).

### Auth & roles
- **Three roles**: `super_admin`, `admin`, `user`.
  - `super_admin` — manages everyone, sees all email, manages domains.
  - `admin` — adds users only.
  - `user` — claims own aliases, reads own inbox.
- **Username + password login** — PBKDF2 (200k iters, sha256) + per-user salt.
- **Password policy** — min 8 chars, ≥1 uppercase, ≥1 digit, ≥1 symbol.
- **First-login enforcement** — auto-generated initial password, user must change before accessing dashboard.
- **Single-device session** — new login auto-kicks the old session.
- **Brute-force protection** — per-IP + per-username lockout.

### Aliases
- Users **claim** aliases — no one else can read your inbox.
- **Custom aliases** — up to 3 per user (configurable).
- **Random aliases** — unlimited, 10-char unique alphanumeric.
- Duplicate prevention — global unique across all users.

### Audit log
- Every admin action (create/delete/lock/unlock user, add/update/delete domain, password change) is logged with actor, timestamp, target, and reason.
- Super_admin can view via `/api/audit` or dashboard.

### Bot API
- Master API token (super_admin level) for scripts/bots.
- Endpoints: `/api/ready`, `/api/messages`, `/api/latest`, `/api/messages/{id}`.
- `/api/latest?wait=30` — long-poll for OTP automation.

### Dashboard UI
- Black-dope theme — dark, neon cyan/violet accents, JetBrains Mono.
- Pages: Inbox, Aliases, Users (admin+), Domains (super), Audit Log (super), Bot API, Status.
- HTML email rendered in sandboxed iframe with `<base target="_blank">`.

## Quick install (1-shot)

```bash
curl -fsSL https://raw.githubusercontent.com/bibnk/selfhost-tempmail/main/setup.sh | sudo bash
```

The installer asks for: domain, super_admin username, super_admin password, port. It handles deps, venv, systemd unit, ufw, Caddy + Let's Encrypt SSL.

## Manual setup

```bash
git clone https://github.com/bibnk/selfhost-tempmail.git
cd selfhost-tempmail
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
# Edit .env — set DOMAIN, SUPER_ADMIN_USER, SUPER_ADMIN_PASS, API_TOKEN
.venv/bin/python tempmail_server.py
```

Visit `http://YOUR_VPS_IP:8787/`. Login with `SUPER_ADMIN_USER` / `SUPER_ADMIN_PASS`.

## DNS setup

Required records on your domain:

```
A      mail.your-domain.com    → YOUR_VPS_IP
MX     @                       → mail.your-domain.com  (priority 10)
TXT    @                       → "v=spf1 mx ~all"
TXT    _dmarc                  → "v=DMARC1; p=none; rua=mailto:postmaster@your-domain.com"
```

If using Cloudflare: **disable proxy** (gray cloud) for `mail` subdomain — Cloudflare doesn't proxy SMTP. Also disable Cloudflare Email Routing or it'll hijack your MX.

## Bot API examples

```bash
TOKEN='YOUR_API_TOKEN'
BASE='https://mail.your-domain.com'

# Create a random alias
curl -X POST "$BASE/api/aliases" -H "x-api-token: $TOKEN" \
  -H "content-type: application/json" -d '{"kind":"random","domain":"your-domain.com"}'

# Wait for next email to alias (up to 30s)
curl "$BASE/api/latest?user=hello&wait=30" -H "x-api-token: $TOKEN"

# List inbox of an alias
curl "$BASE/api/messages?user=hello&limit=20" -H "x-api-token: $TOKEN"
```

## Schema

- `users` — accounts + role + lock state
- `user_sessions` — single-device sessions
- `login_fails` — per-username brute-force counter
- `audit_log` — admin action history
- `domains` — accepted SMTP domains + mode
- `aliases` — claimed alias → owner mapping
- `messages` — received emails (auto-cleaned 48h)
- `addresses` — legacy table (kept for compat)

## Security notes

- Passwords hashed with PBKDF2-HMAC-SHA256, 200k iters, 16-byte salt.
- Sessions stored server-side, cookies are HttpOnly + SameSite=Lax.
- Rate limit on login: 5 fails per 5 min per IP, then 15-min lockout. Per-username: 5 fails per 10 min, then 30-min lockout.
- Locked accounts cannot self-unlock — must be unlocked by super_admin.
- API token is super_admin-equivalent — keep it out of git.

## License

MIT — see LICENSE.
