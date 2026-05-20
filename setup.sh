#!/usr/bin/env bash
# Self-host TempMail one-shot installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/bibnk/selfhost-tempmail/main/setup.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/bibnk/selfhost-tempmail/main/setup.sh | sudo DOMAIN=mail.example.com bash
#
# Env vars (optional, asked interactively if missing):
#   DOMAIN          - Mail domain (e.g. mail.example.com). Required.
#   ACCESS_CODE     - Login code for dashboard (e.g. 6715). Random if empty.
#   ENABLE_HTTPS    - "yes" to install Caddy + Let's Encrypt SSL. Default: yes.
#   INSTALL_DIR     - Where to put files. Default: /opt/selfhost-tempmail.
#   REPO_URL        - Repo to clone. Default: https://github.com/bibnk/selfhost-tempmail.git
#
# What it does:
#   1. Install OS deps (python3-venv, git, curl, ufw)
#   2. Clone repo into INSTALL_DIR
#   3. Create .venv and pip install requirements
#   4. Generate .env with random API_TOKEN
#   5. Open ports 25, 80, 443 (or 8787 if no HTTPS)
#   6. Install systemd service (auto-start on boot, auto-restart on crash)
#   7. (optional) Install Caddy + auto-issue Let's Encrypt SSL for DOMAIN
#   8. Print final URL + access code

set -euo pipefail

# ============ helpers ============
log()   { echo -e "\033[1;36m[+]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[!]\033[0m $*" >&2; }
err()   { echo -e "\033[1;31m[x]\033[0m $*" >&2; }
die()   { err "$*"; exit 1; }
need_root() { [ "$EUID" -eq 0 ] || die "Run as root (use sudo)."; }
have()  { command -v "$1" >/dev/null 2>&1; }

# ============ config ============
INSTALL_DIR="${INSTALL_DIR:-/opt/selfhost-tempmail}"
REPO_URL="${REPO_URL:-https://github.com/bibnk/selfhost-tempmail.git}"
ENABLE_HTTPS="${ENABLE_HTTPS:-yes}"
SERVICE_NAME="tempmail"
SERVICE_USER="root"

need_root

# ============ banner ============
cat <<'EOF'

  ╔════════════════════════════════════════╗
  ║   Self-Host TempMail · 1-shot setup    ║
  ║   github.com/bibnk/selfhost-tempmail   ║
  ╚════════════════════════════════════════╝

EOF

# ============ collect inputs ============
if [ -z "${DOMAIN:-}" ]; then
  if [ -t 0 ]; then
    read -r -p "→ Mail domain (e.g. mail.example.com): " DOMAIN
  else
    die "DOMAIN env var required when running non-interactively. Re-run with: curl ... | sudo DOMAIN=mail.example.com bash"
  fi
fi
[ -n "$DOMAIN" ] || die "DOMAIN cannot be empty."

if [ -z "${ACCESS_CODE:-}" ]; then
  if [ -t 0 ]; then
    read -r -p "→ Dashboard access code (Enter for random 6 digits): " ACCESS_CODE
  fi
fi
if [ -z "${ACCESS_CODE:-}" ]; then
  ACCESS_CODE=$(python3 -c "import secrets; print(secrets.randbelow(900000)+100000)")
  log "Generated random access code: $ACCESS_CODE"
fi

if [ "$ENABLE_HTTPS" = "yes" ] && [ -t 0 ]; then
  read -r -p "→ Install Caddy + auto-SSL Let's Encrypt? (Y/n): " ans
  case "$ans" in
    n|N) ENABLE_HTTPS="no" ;;
  esac
fi

API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32 | tr -d '=+/' | head -c 43)

# ============ 1. OS dependencies ============
log "Installing OS dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl ufw ca-certificates >/dev/null

# ============ 2. clone or update repo ============
if [ -d "$INSTALL_DIR/.git" ]; then
  log "Repo already exists at $INSTALL_DIR, pulling latest..."
  git -C "$INSTALL_DIR" fetch --quiet origin
  git -C "$INSTALL_DIR" reset --hard origin/main --quiet
else
  log "Cloning $REPO_URL into $INSTALL_DIR..."
  rm -rf "$INSTALL_DIR"
  git clone --quiet --depth=1 "$REPO_URL" "$INSTALL_DIR"
fi

# ============ 3. venv + deps ============
log "Setting up Python venv..."
cd "$INSTALL_DIR"
python3 -m venv .venv
# shellcheck source=/dev/null
. .venv/bin/activate
pip install -q -U pip
pip install -q -r requirements.txt
deactivate

# ============ 4. write .env ============
log "Writing .env..."
DB_PATH="$INSTALL_DIR/tempmail.sqlite3"
if [ "$ENABLE_HTTPS" = "yes" ]; then
  WEB_HOST="127.0.0.1"   # behind Caddy
else
  WEB_HOST="0.0.0.0"     # exposed directly
fi

cat > "$INSTALL_DIR/.env" <<EOF
DOMAIN=$DOMAIN
MAIL_HOST=0.0.0.0
SMTP_PORT=25
WEB_HOST=$WEB_HOST
WEB_PORT=8787
API_TOKEN=$API_TOKEN
ACCESS_CODE=$ACCESS_CODE
DB_PATH=$DB_PATH
MAX_MESSAGE_BYTES=10485760
EOF
chmod 600 "$INSTALL_DIR/.env"

# ============ 5. firewall ============
log "Configuring firewall (ufw)..."
ufw allow 22/tcp >/dev/null 2>&1 || true   # don't lock yourself out
ufw allow 25/tcp >/dev/null 2>&1
if [ "$ENABLE_HTTPS" = "yes" ]; then
  ufw allow 80/tcp  >/dev/null 2>&1
  ufw allow 443/tcp >/dev/null 2>&1
else
  ufw allow 8787/tcp >/dev/null 2>&1
fi
log "Firewall rules applied (ufw status: $(ufw status | head -1 | awk '{print $2}'))"

# ============ 6. systemd service ============
log "Creating systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Self-host TempMail SMTP+Web server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python3 $INSTALL_DIR/tempmail_server.py
Restart=always
RestartSec=5
# Allow binding to port 25 without running as root if possible
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${SERVICE_NAME}.service >/dev/null 2>&1 || true

# Wait briefly and verify
sleep 2
if ! systemctl is-active --quiet ${SERVICE_NAME}.service; then
  err "Service failed to start. Logs:"
  journalctl -u ${SERVICE_NAME}.service --no-pager -n 20 || true
  die "Setup aborted."
fi
log "Service '${SERVICE_NAME}' is running."

# ============ 7. Caddy + HTTPS (optional) ============
if [ "$ENABLE_HTTPS" = "yes" ]; then
  log "Installing Caddy..."
  if ! have caddy; then
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https >/dev/null
    curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy >/dev/null
  fi

  log "Writing Caddyfile for $DOMAIN..."
  mkdir -p /var/log/caddy
  chown -R caddy:caddy /var/log/caddy 2>/dev/null || true
  cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    encode gzip zstd

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }

    reverse_proxy 127.0.0.1:8787

    log {
        output file /var/log/caddy/${DOMAIN}.log
        format json
    }
}
EOF

  systemctl enable caddy >/dev/null 2>&1 || true
  systemctl restart caddy
  log "Caddy is running. Let's Encrypt certificate will be issued on first request to $DOMAIN."
fi

# ============ 8. summary ============
PUBLIC_IP=$(curl -s --max-time 4 https://api.ipify.org || curl -s --max-time 4 https://ifconfig.me || echo "<your-server-ip>")

cat <<EOF


╔══════════════════════════════════════════════════════════╗
║                  ✅ INSTALL COMPLETE                     ║
╚══════════════════════════════════════════════════════════╝

📡 Domain:        $DOMAIN
🌐 Public IP:     $PUBLIC_IP

📥 SMTP receiver:  port 25 (terima email *@$DOMAIN)
🖥  Dashboard:     $( [ "$ENABLE_HTTPS" = "yes" ] && echo "https://$DOMAIN" || echo "http://$PUBLIC_IP:8787" )
🔑 Access code:    $ACCESS_CODE
🤖 API token:      $API_TOKEN

📋 DNS records yang HARUS Yang Mulia tambahkan di Cloudflare/DNS provider:

   A     ${DOMAIN%%.*}    $PUBLIC_IP                       (DNS only / non-proxied)
   MX    @                $DOMAIN          priority 10
   TXT   @                "v=spf1 mx ~all"
   TXT   _dmarc           "v=DMARC1; p=none;"

⚙️  Service control:
   systemctl status $SERVICE_NAME       # status
   systemctl restart $SERVICE_NAME      # restart
   journalctl -u $SERVICE_NAME -f       # live logs

📁 Install dir:    $INSTALL_DIR
🔐 .env file:      $INSTALL_DIR/.env  (chmod 600, jangan share)

⚠️  Catatan: pastikan provider VPS Yang Mulia membuka inbound port 25 dan 80/443.
   Banyak provider (AWS, GCP, Tencent) memblokir port 25 by default — submit ticket jika perlu.

EOF
