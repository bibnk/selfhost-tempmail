# Self-host TempMail

Catch-all temp mail server dengan dashboard web modern dan API untuk bot. Self-hosted, tanpa Cloudflare Email Routing.

**Fitur:**
- Terima semua email `*@DOMAIN` lewat SMTP port 25
- Simpan email ke SQLite (lightweight, no external DB)
- Dashboard web modern (black theme, neon accent) dengan login access code
- API token untuk script/bot (curl-friendly)
- Render HTML email aman di iframe sandbox
- Auto-extract OTP dari subject/body
- Generate alias random atau custom (`telegram@`, `otp@`, dll)

## 🚀 1-shot install (recommended)

Satu perintah, semua otomatis: dependencies, venv, .env, firewall, systemd service, dan Caddy + auto-SSL Let's Encrypt.

```bash
curl -fsSL https://raw.githubusercontent.com/bibnk/selfhost-tempmail/main/setup.sh | sudo bash
```

Atau dengan domain langsung dari env (non-interactive):

```bash
curl -fsSL https://raw.githubusercontent.com/bibnk/selfhost-tempmail/main/setup.sh | sudo DOMAIN=mail.example.com bash
```

Script akan tanya:
- 📡 **Mail domain** (e.g. `mail.example.com`)
- 🔑 **Access code** (untuk login dashboard, kosongkan untuk random 6 digit)
- 🔒 **Install Caddy + SSL?** (Y/n) — auto Let's Encrypt

Setelah selesai, dashboard live di `https://DOMAIN` dan SMTP siap di port 25.

### Setelah install, set DNS records:

| Type | Name | Content | Note |
|------|------|---------|------|
| A | mail | `IP_VPS` | DNS only (jangan proxied) |
| MX | @ | `mail.example.com` | priority 10 |
| TXT | @ | `v=spf1 mx ~all` | |
| TXT | _dmarc | `v=DMARC1; p=none;` | |

⚠️ **Hapus Cloudflare Email Routing kalau aktif** (route1/2/3.mx.cloudflare.net), kalau tidak email tidak akan masuk ke VPS.

⚠️ **Pastikan provider VPS membuka port 25 inbound.** Banyak provider (AWS, GCP, Tencent, Alibaba) memblokir port 25 secara default — submit ticket unblock kalau perlu.

## ⚙️ Service control (setelah install)

```bash
systemctl status tempmail      # cek status
systemctl restart tempmail     # restart
journalctl -u tempmail -f      # live logs
```

File penting:
- Install dir: `/opt/selfhost-tempmail`
- Config: `/opt/selfhost-tempmail/.env` (chmod 600, jangan share)
- Database: `/opt/selfhost-tempmail/tempmail.sqlite3`
- Caddyfile: `/etc/caddy/Caddyfile`

## 🤖 API untuk bot

Token tersimpan di `.env` dengan key `API_TOKEN`. Pakai header `x-api-token`:

```bash
TOKEN='YOUR_API_TOKEN'
BASE='https://mail.example.com'

# Create alias spesifik
curl -s -X POST "$BASE/api/address" \
  -H "x-api-token: $TOKEN" \
  -H "content-type: application/json" \
  -d '{"local":"telegram"}' | jq

# Create alias random
curl -s -X POST "$BASE/api/address" \
  -H "x-api-token: $TOKEN" \
  -H "content-type: application/json" \
  -d '{}' | jq

# List email untuk user (filter by alias)
curl -s "$BASE/api/messages?user=telegram&limit=20" \
  -H "x-api-token: $TOKEN" | jq

# Wait email terbaru max 30 detik (long-polling)
curl -s "$BASE/api/latest?user=telegram&wait=30" \
  -H "x-api-token: $TOKEN" | jq

# Get detail email by ID
curl -s "$BASE/api/messages/1" \
  -H "x-api-token: $TOKEN" | jq

# Delete email
curl -s -X DELETE "$BASE/api/messages/1" \
  -H "x-api-token: $TOKEN" | jq
```

## 🧪 Test SMTP receiver

Dari VPS sendiri:

```bash
apt install -y swaks
swaks --to test@example.com --from sender@gmail.com --server 127.0.0.1 --port 25 --body 'hello'
```

Lalu cek dashboard atau:

```bash
curl -s "$BASE/api/messages?to=test@example.com" -H "x-api-token: $TOKEN" | jq
```

Dari luar (setelah DNS propagate):

```bash
swaks --to test@example.com --from sender@gmail.com --server mail.example.com --port 25 --body 'hello from outside'
```

## 🛠 Manual install (alternatif)

Kalau Yang Mulia tidak mau pakai installer otomatis:

```bash
# 1. Dependencies
sudo apt update && sudo apt install -y python3 python3-venv git ufw

# 2. Clone
git clone https://github.com/bibnk/selfhost-tempmail.git
cd selfhost-tempmail

# 3. Venv + deps
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip && pip install -r requirements.txt

# 4. Config
cp .env.example .env
# Edit .env: set DOMAIN, ACCESS_CODE, generate API_TOKEN
python3 -c "import secrets; print(secrets.token_urlsafe(32))"  # untuk API_TOKEN

# 5. Firewall
sudo ufw allow 25/tcp
sudo ufw allow 8787/tcp

# 6. Run (foreground untuk test)
sudo .venv/bin/python3 tempmail_server.py
```

Untuk persistent, bikin systemd unit di `/etc/systemd/system/tempmail.service` (lihat contoh di [setup.sh](./setup.sh) bagian `systemd service`).

## 📋 .env reference

| Variable | Default | Keterangan |
|----------|---------|------------|
| `DOMAIN` | — | Mail domain (wajib) |
| `MAIL_HOST` | `0.0.0.0` | SMTP listen address |
| `SMTP_PORT` | `25` | SMTP port |
| `WEB_HOST` | `0.0.0.0` | Web listen address (`127.0.0.1` kalau di belakang Caddy) |
| `WEB_PORT` | `8787` | Web port |
| `API_TOKEN` | — | Token panjang untuk akses API (header `x-api-token`) |
| `ACCESS_CODE` | — | Kode pendek untuk login dashboard browser. Kosongkan untuk dev mode |
| `DB_PATH` | `./tempmail.sqlite3` | Path SQLite |
| `MAX_MESSAGE_BYTES` | `10485760` | Max ukuran satu email (10 MB) |

## 🔒 Catatan keamanan

- File `.env` di-chmod `600` oleh installer (cuma root yang bisa baca)
- Dashboard ada **rate limit login** (5 fail / 5 menit → lockout 15 menit per IP)
- Session cookie `HttpOnly`, `SameSite=Lax`, expire 7 hari
- HTML email dirender di iframe `sandbox` (script di dalam email tidak bisa akses dashboard)
- SSL otomatis via Let's Encrypt (Caddy) — auto-renew tiap 60 hari
- HSTS aktif di Caddyfile bawaan

## 🐛 Troubleshooting

**Email dari luar tidak masuk?**
- Cek MX sudah ke `mail.example.com` (bukan Cloudflare routing)
- Cek A record `mail` DNS only (abu-abu, jangan oranye)
- Test port 25 dari luar: `nc -vz mail.example.com 25`
- Cek log: `journalctl -u tempmail -n 50`
- Banyak provider VPS blokir port 25 — submit ticket unblock

**Dashboard tidak bisa diakses?**
- Cek service: `systemctl status tempmail`
- Cek port 80/443 (atau 8787 kalau tanpa SSL): `ss -tlnp`
- Cek Caddy log kalau pakai SSL: `journalctl -u caddy -n 50`
- Browser hard refresh (`Ctrl+Shift+R`) kalau JS lama ke-cache

**Lupa access code?**
```bash
sudo grep ACCESS_CODE /opt/selfhost-tempmail/.env
```

## 📜 License

MIT — see [LICENSE](./LICENSE)

## 🙏 Credits

Built with `aiosmtpd`, vanilla Python `http.server`, vanilla JS, Caddy untuk reverse proxy + SSL otomatis. No bloat, no framework.
