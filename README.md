# Self-host Temp Mail + Dashboard + API

Ini untuk membuat temp mail pakai domain sendiri tanpa Cloudflare Email Routing.

Fitur:
- Terima semua email `*@DOMAIN` via SMTP port 25
- Simpan email ke SQLite
- Dashboard web untuk baca email
- API untuk bot mengambil email/OTP
- Generate alamat random/alias via API

## Syarat

- VPS dengan IP publik
- Port `25` terbuka dari internet
- Port dashboard `8787` dibuka kalau mau akses browser
- Cloudflare DNS record `mail` harus **DNS only**, bukan proxied/orange cloud

## DNS Cloudflare untuk `example.com`

Ganti `IP_VPS` dengan IP VPS kamu:

```text
A     mail      IP_VPS                 DNS only
MX    @         mail.example.com       priority 10
TXT   @         v=spf1 mx ~all
TXT   _dmarc    v=DMARC1; p=none; rua=mailto:postmaster@example.com
```

Hapus/disable Cloudflare Email Routing MX kalau masih ada:

```text
route1.mx.cloudflare.net
route2.mx.cloudflare.net
route3.mx.cloudflare.net
```

Karena kalau MX masih Cloudflare, email tidak masuk ke VPS kamu.

## Install VPS

```bash
apt update && apt install -y python3 python3-venv screen ufw

cd /root
tar -xzf /tmp/selfhost-tempmail.tar.gz -C /root
cd ~/selfhost-tempmail

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

cp .env.example .env
nano .env
```

Isi `.env` contoh:

```bash
DOMAIN=example.com
MAIL_HOST=0.0.0.0
SMTP_PORT=25
WEB_HOST=0.0.0.0
WEB_PORT=8787
API_TOKEN=buat-token-random-panjang
DB_PATH=~/selfhost-tempmail/tempmail.sqlite3
MAX_MESSAGE_BYTES=10485760
```

Buka port:

```bash
ufw allow 25/tcp
ufw allow 8787/tcp
```

Kalau `ufw` belum aktif tidak masalah. Pastikan firewall provider VPS juga buka port 25 dan 8787.

## Run manual

```bash
cd ~/selfhost-tempmail
source .venv/bin/activate
python3 tempmail_server.py
```

Buka dashboard:

```text
http://IP_VPS:8787/?token=buat-token-random-panjang
```

## Run permanent pakai screen

```bash
screen -S tempmail -dm bash -lc 'cd ~/selfhost-tempmail && source .venv/bin/activate && python3 tempmail_server.py 2>&1 | tee -a /tmp/tempmail.log'
```

Cek log:

```bash
tail -f /tmp/tempmail.log
```

Stop:

```bash
screen -S tempmail -X quit
```

## API untuk bot

Set token:

```bash
TOKEN='buat-token-random-panjang'
BASE='http://IP_VPS:8787'
```

Create address random:

```bash
curl -s -X POST "$BASE/api/address" \
  -H "x-api-token: $TOKEN" \
  -H "content-type: application/json" \
  -d '{}' | jq
```

Create alias spesifik:

```bash
curl -s -X POST "$BASE/api/address" \
  -H "x-api-token: $TOKEN" \
  -H "content-type: application/json" \
  -d '{"local":"telegram"}' | jq
```

List email untuk alamat:

```bash
curl -s "$BASE/api/messages?to=telegram@example.com&limit=20" \
  -H "x-api-token: $TOKEN" | jq
```

Ambil email terbaru, tunggu max 30 detik:

```bash
curl -s "$BASE/api/latest?to=telegram@example.com&wait=30" \
  -H "x-api-token: $TOKEN" | jq
```

Ambil detail email by ID:

```bash
curl -s "$BASE/api/messages/1" \
  -H "x-api-token: $TOKEN" | jq
```

Delete email:

```bash
curl -s -X DELETE "$BASE/api/messages/1" \
  -H "x-api-token: $TOKEN" | jq
```

## Test kirim lokal dari VPS

```bash
apt install -y swaks
swaks --to test@example.com --from tester@example.com --server 127.0.0.1 --port 25 --body 'hello tempmail'
```

Lalu cek dashboard/API.

## Catatan penting

- Ini fokus untuk **receive/temp mail + API**, bukan SMTP outbound.
- Tidak perlu bikin user email satu-satu; semua `*@example.com` diterima.
- Kalau email dari luar tidak masuk, cek:
  - MX sudah ke `mail.example.com`, bukan Cloudflare routing
  - `mail.example.com` DNS only
  - port 25 VPS terbuka
  - proses `tempmail_server.py` jalan sebagai root atau pakai port 25
