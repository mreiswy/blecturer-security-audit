# Audit Keamanan — bLecturer (`diksy.ilkom.unej.ac.id`)

Laporan bug bounty untuk mata kuliah **Dasar-Dasar Keamanan Informasi (DDKI)**.
Pengujian dilakukan dengan izin pemilik akun, pada 27 Oktober 2026.

| | |
|---|---|
| Target | `https://diksy.ilkom.unej.ac.id` (aplikasi bLecturer) |
| IP | `103.241.206.254` |
| Stack | PHP + framework internal `bFramework`, openresty di depan |
| Cookie sesi | `BLSESSID` |
| Cakupan | Aplikasi utama (anonim + terautentikasi sebagai mahasiswa) dan port `8080` pada host yang sama |
| Metode | Manual + skrip Python (`requests`), reverse-engineer framework dari repo publik, enumerasi rute, uji otorisasi/CSRF/validasi |

## Ringkasan temuan

| # | Temuan | Tingkat | Status |
|---|---|---|---|
| 1 | Panel Termix di port 8080 terbuka tanpa TLS | **High** | Terkonfirmasi |
| 2 | CORS port 8080 mencerminkan Origin apa pun + `credentials: true` | **High** | Terkonfirmasi |
| 3 | Kegagalan CSRF dibalas HTTP 500, bukan 419 | **Medium** | Terkonfirmasi |
| 4 | `X-Forwarded-Proto` dipercaya → flag `secure` & HSTS hilang | **Medium** | Terkonfirmasi |
| 5 | Redirect aset membocorkan port internal dan menurunkan skema ke HTTP | **Medium** | Terkonfirmasi |
| 6 | Enumerasi akun lewat pesan registrasi & NIM | **Low** | Terkonfirmasi |
| 7 | Akun dibuat sebelum email diverifikasi (pre-verification squatting) | **Low** | Terkonfirmasi |
| 8 | Tidak ada alur reset password | **Low** | Terkonfirmasi |
| 9 | Header keamanan terpasang ganda | **Info** | Terkonfirmasi |
| 10 | Parameter `_csrf` ganda (HPP) diterima → HTTP 500, bukan 400/419 | **Medium** | Terkonfirmasi |
| 11 | Kuota login ~10 percobaan per IP, tanpa header `Retry-After` | **Low** | Terkonfirmasi |

Tidak ditemukan: RCE, SQL injection, IDOR, auth bypass, XSS, CSRF bypass,
session fixation, path traversal, request smuggling, cache poisoning, race
condition pada rate limiter, BFLA, mass assignment, SSRF, JWT/algorithm
confusion, excessive data exposure.

**Catatan: F10 adalah perluasan dari F3.** Keduanya punya akar yang sama —
framework tidak membedakan "token tidak valid" dari "permintaan rusak" dan
membalas keduanya dengan 500. Perbaikan F3 sekaligus menutup sebagian F10.

---

## 1. Panel Termix di port 8080 terbuka tanpa TLS — High

Host yang sama menjalankan **Termix** — aplikasi manajemen SSH dan remote desktop
(self-hosted). Aplikasi ini dapat diakses publik lewat **HTTP polos**, sementara
port yang sama menolak HTTPS.

```
$ curl -s -m 20 -D - -o /dev/null http://diksy.ilkom.unej.ac.id:8080/
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html
Content-Length: 3164
Last-Modified: Sun, 23 Aug 2026 00:48:37 GMT

$ curl -sk -m 10 -o /dev/null -w "%{http_code}\n" https://diksy.ilkom.unej.ac.id:8080/
000        # TLS tidak tersedia

$ curl -s http://diksy.ilkom.unej.ac.id:8080/manifest.json
{ "name": "Termix",
  "description": "Self-hosted SSH and remote desktop management.", ... }
```

**Dampak.** Termix menyimpan kredensial SSH dan sesi terminal ke server lain.
Tanpa TLS, semua trafik — termasuk token sesi dan password saat login — dapat
dibaca siapa pun di jalur jaringan yang sama (Wi-Fi kampus, ISP, proxy). Ini
adalah panel yang, bila berhasil dimasuki, memberi akses shell ke infrastruktur.

**Bukti:** `evidence/f1_8080_http_headers.txt`, `evidence/f1_8080_manifest.txt`,
`evidence/f1_8080_tls_refused.txt`

**Perbaikan.** Tutup port 8080 dari internet (firewall/security group), atau
pasang TLS + autentikasi di depannya. Jika panel ini hanya untuk admin,
batasi ke VPN atau allowlist IP.

---

## 2. CORS port 8080 mencerminkan Origin apa pun + `credentials: true` — High

Server mengembalikan `Access-Control-Allow-Origin` berisi **nilai Origin yang
dikirim penyerang**, disertai `Access-Control-Allow-Credentials: true`.
Termasuk untuk `Origin: null` dan untuk respons error 401.

```
$ curl -D - -o /dev/null -H "Origin: https://evil.example" \
       http://diksy.ilkom.unej.ac.id:8080/users/me
HTTP/1.1 401 Unauthorized
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true

$ curl -D - -o /dev/null -H "Origin: null" http://...:8080/users/me
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

Preflight juga mengizinkan metode tulis dan header internal:

```
$ curl -D - -o /dev/null -X OPTIONS \
    -H "Origin: https://evil.example" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: authorization,content-type" \
    http://diksy.ilkom.unej.ac.id:8080/users/login
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET,POST,PUT,PATCH,DELETE,OPTIONS
Access-Control-Allow-Headers: Origin,X-Requested-With,Content-Type,Accept,Authorization,
  User-Agent,X-Electron-App,X-Termix-Device-ID,Cache-Control,x-admin-target-user
```

**Dampak.** Pola `reflect-any-origin` + `credentials: true` adalah kombinasi
paling berbahaya di CORS: situs mana pun yang dikunjungi korban dapat membaca
respons API Termix **dengan kredensial korban**. `Origin: null` juga diterima —
artinya halaman dari `file://`, `data:`, atau iframe sandbox bisa ikut serta.
Header `x-admin-target-user` di daftar izin menunjukkan ada endpoint yang
menerima target user dari header; jika ada endpoint impersonasi, CORS ini
membukanya untuk lintas-origin.

**Bukti:** `evidence/f2_cors_reflect.txt`, `evidence/f2_cors_null.txt`,
`evidence/f2_cors_preflight.txt`, `evidence/f2_unauth_json.txt`

**Perbaikan.** Ganti pencerminan dengan allowlist origin eksplisit:

```js
const ALLOW = new Set(['https://termix.example.go.id']);
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o && ALLOW.has(o)) {
    res.set('Access-Control-Allow-Origin', o);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```
Jangan pernah mengizinkan `null`. Hapus `x-admin-target-user` dari
`Access-Control-Allow-Headers` bila tidak benar-benar dipakai.

---

## 3. Kegagalan CSRF dibalas HTTP 500, bukan 419 — Medium

Setiap POST tanpa `_csrf` yang valid mengembalikan **HTTP 500**, padahal body
responsnya adalah halaman "419 Sesi kedaluwarsa" yang benar.

```
$ for p in login register email/verify/resend; do
    curl -s -D - -X POST "https://diksy.ilkom.unej.ac.id/$p" -d "email=a@b.c&password=x" | head -1
  done
POST /login               → HTTP/1.1 500 Internal Server Error
POST /register            → HTTP/1.1 500 Internal Server Error
POST /email/verify/resend → HTTP/1.1 500 Internal Server Error
```

Berlaku juga pada endpoint terautentikasi (`/profile/name`, `/quests/{id}/submit`,
`/marketplace/purchase`, `/bug-bounty`, `/api/marketplace/purchase`) dan pada
token yang dipalsukan.

**Dampak.** Dua akibat nyata:

1. **Penanganan sesi kedaluwarsa rusak.** `marketplace.js` baris 26 memeriksa
   `r.status === 419 || r.status === 401` untuk mengarahkan user ke `/login`.
   Karena server mengirim 500, cabang itu tidak pernah jalan — user hanya
   mendapat toast generik dan tidak pernah diminta login ulang.
2. **Monitoring buta.** Semua CSRF kedaluwarsa tercatat sebagai server error,
   menutupi error 500 yang sungguhan di log dan alerting.

Penyebabnya hampir pasti di `bFramework`: `Kernel::guard()` melempar ulang
`HttpException` 419 sebagai error generik sehingga `ErrorHandler` memetakannya
ke 500.

**Bukti:** `evidence/f4_csrf_500.txt`

**Perbaikan.** Satu perubahan di titik tengah, memperbaiki semua endpoint
sekaligus — jangan tambal per-route:

```php
// Kernel::guard() — teruskan status asli, jangan ditelan ErrorHandler
if (!$this->csrf->validate($token)) {
    throw new HttpException(419, 'Sesi formulir kedaluwarsa, silakan muat ulang halaman.');
}
```

---

## 4. `X-Forwarded-Proto` dipercaya → flag `secure` & HSTS hilang — Medium

Menambahkan header `X-Forwarded-Proto: http` membuat cookie sesi kehilangan
atribut `secure`, dan HSTS hilang dari respons.

```
=== normal
Strict-Transport-Security: max-age=31536000; includeSubDomains
Set-Cookie: BLSESSID=…; path=/; secure; HttpOnly; SameSite=Lax
Vary: Accept-Encoding,X-Forwarded-Proto

=== dengan X-Forwarded-Proto: http
(Strict-Transport-Security tidak ada)
Set-Cookie: BLSESSID=…; path=/; HttpOnly; SameSite=Lax      ← secure hilang
Vary: Accept-Encoding,X-Forwarded-Proto
```

**Dampak.** Header ini menentukan apakah aplikasi menganggap dirinya berjalan
di HTTPS. Siapa pun yang bisa menyisipkan header tersebut — proxy longgar,
CDN yang salah konfigurasi, atau request langsung ke origin — memaksa aplikasi
mengeluarkan cookie tanpa `secure`, sehingga cookie sesi dapat dikirim lewat
HTTP polos dan disadap. Kehadiran `X-Forwarded-Proto` di header `Vary` juga
menunjukkan nilai ini masuk ke cache key.

**Bukti:** `evidence/f5_xfp_cookie.txt`

**Perbaikan.** Batasi kepercayaan proxy ke IP yang benar-benar milik load
balancer, dan paksa `secure` tanpa syarat:

```php
// hanya percaya header dari proxy yang dikenal
$trusted = ['10.0.0.0/8', '172.16.0.0/12'];
$isHttps = in_array($remoteAddr, $trusted, true)
    ? ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'
    : !empty($_SERVER['HTTPS']);

// cookie: secure selalu true untuk aplikasi yang hanya boleh diakses via HTTPS
session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
```

---

## 5. Redirect aset membocorkan port internal dan menurunkan skema ke HTTP — Medium

```
$ for p in uploads assets assets/js assets/css; do curl -D - -o /dev/null "https://diksy.ilkom.unej.ac.id/$p"; done

GET /uploads      → 301  Location: http://diksy.ilkom.unej.ac.id:8080/uploads/
GET /assets       → 301  Location: http://diksy.ilkom.unej.ac.id:8080/assets/
GET /assets/js    → 301  Location: http://diksy.ilkom.unej.ac.id:8080/assets/js/
GET /assets/css   → 301  Location: http://diksy.ilkom.unej.ac.id:8080/assets/css/
```

**Dampak.** Tiga masalah sekaligus: (a) membocorkan topologi internal
(port 8080), (b) menurunkan skema dari HTTPS ke HTTP — bertentangan dengan HSTS
yang dikirim aplikasi, dan (c) mengarahkan pengunjung ke aplikasi yang sama
sekali berbeda (Termix), bukan ke aset bLecturer. Ini juga memperkuat temuan #1:
alamat panel Termix "diiklankan" oleh aplikasi utama.

**Bukti:** `evidence/f3_redirect_8080.txt`

**Perbaikan.** Perbaiki aturan rewrite/regex di openresty agar tidak
menambahkan `:8080`, dan gunakan path relatif atau `$scheme`:

```nginx
location /assets/ { try_files $uri $uri/ =404; }
# jangan: rewrite ^/assets/(.*)$ http://host:8080/assets/$1 permanent;
```

---

## 6. Enumerasi akun lewat pesan registrasi & NIM — Low

Endpoint `/register` membedakan "email sudah dipakai" dari "email tersedia",
sehingga daftar akun dapat dipanen tanpa login.

```
email sudah terdaftar → 302 /register        (dengan pesan "email sudah terdaftar")
email baru            → 302 /email/verify
NIM sudah terdaftar   → "NIM sudah terdaftar."
NIM acak              → lolos ke /email/verify
```

Terverifikasi pada akun nyata milik penguji: alamat `@mail.unej.ac.id` yang
sudah terdaftar ditolak saat registrasi (berarti ada di DB), meski login
mengembalikan "Email atau password salah" — akun tanpa password lokal
(dibuat lewat Google OAuth).

**Dampak.** Penyerang dapat memetakan mahasiswa mana yang punya akun, dan
mengaitkannya dengan NIM. Berguna untuk phishing bertarget dan untuk mengisi
slot sebelum korban mendaftar (lihat #7).

**Bukti.** Bukti mentah tidak disertakan karena responsnya memuat email nyata;
potongan di atas cukup untuk reproduksi. Uji ulang dengan akun milik sendiri.

**Perbaikan.** Selalu balas dengan pesan netral dan status yang sama:
"Jika email tersebut valid dan belum terdaftar, kami telah mengirim tautan
verifikasi." Lakukan pengecekan duplikat di dalam alur verifikasi email,
bukan di halaman form.

---

## 7. Akun dibuat sebelum email diverifikasi — Low

POST `/register` dengan email `@unej.ac.id` apa pun langsung membuat baris user
di database dan mengalihkan ke `/email/verify` — sebelum inbox dibuktikan.

```
x@unej.ac.id          → 302 /email/verify   (akun dibuat)
x@UNEJ.AC.ID          → 302 /email/verify   (case-insensitive, tak dinormalisasi)
x+tag@unej.ac.id      → 302 /email/verify
x@student.unej.ac.id  → ditolak
x@sub.unej.ac.id      → ditolak
x@unej.ac.id.evil.com → ditolak   (validasi domain benar, bukan pencocokan substring)
```

**Dampak.** *Pre-verification squatting*: siapa pun dapat mendaftarkan alamat
email dosen atau staf sebelum pemiliknya sadar, memblokir pendaftaran asli
(pesan "email sudah terdaftar"). Karena akun ada sebelum verifikasi, kuota
dan rate limit per-akun juga bisa dihabiskan lebih dulu. Validasi domainnya
sendiri sudah benar — ini murni soal urutan pembuatan baris.

**Perbaikan.** Tulis ke tabel `pending_registrations` (email, NIM, token,
kedaluwarsa), dan baru buat baris `users` setelah token diverifikasi.

---

## 8. Tidak ada alur reset password — Low

```
/auth/forgot       404
/forgot-password   404
/password/reset    404
/auth/reset        404
/reset             404
/lupa-password     404
Tautan "lupa/forgot" di halaman login: 0
```

**Dampak.** User dengan password lokal yang lupa tidak punya jalan pulih
selain menghubungi admin. Ini juga berarti tidak ada vektor reset-token untuk
diserang — sisi positifnya — tapi menandakan alur akun belum lengkap.
(Sebagai catatan: user yang masuk lewat Google **dapat** membuat password
dari `/profile`, form "Buat password".)

**Bukti:** `evidence/f8_no_reset.txt`

**Perbaikan.** Tambahkan alur reset dengan token acak sekali-pakai, masa
berlaku 30–60 menit, dan respons netral (jangan bocorkan apakah email terdaftar).

---

## 9. Header keamanan terpasang ganda — Info

```
$ curl -D - -o /dev/null https://diksy.ilkom.unej.ac.id/login | grep -iE "strict-transport|x-content-type"
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**Dampak.** Tidak berbahaya langsung, tapi menandakan dua lapis konfigurasi
(aplikasi + openresty) yang tidak sinkron. Menyulitkan audit karena perubahan
di satu lapis tidak terlihat efeknya.

**Bukti:** `evidence/f6_dup_headers.txt`

**Perbaikan.** Pasang header hanya di satu tempat — idealnya di openresty untuk
semua respons, termasuk halaman error.

---

## 10. Parameter `_csrf` ganda (HPP) diterima parser, gagal sebagai 500 — Medium

Framework menerima parameter ganda untuk field keamanan `_csrf` tanpa menolaknya,
dan setiap varian ganda berakhir di `500 Internal Server Error` — bukan `400`
(permintaan rusak) atau `419` (CSRF gagal).

```
$ # baseline: satu token valid
POST /profile/name   _csrf=<valid>&name=second
HTTP/1.1 302   Location: /profile        (tersimpan)

$ # token valid DIIKUTI nilai sampah
POST /profile/name   _csrf=<valid>&_csrf=deadbeef&name=second
HTTP/1.1 500   (halaman "Sesi kedaluwarsa")   (TIDAK tersimpan)

$ # nilai sampah DIIKUTI token valid
POST /profile/name   _csrf=deadbeef&_csrf=<valid>&name=second
HTTP/1.1 500   (TIDAK tersimpan)

$ # bentuk array
POST /profile/name   _csrf[]=<valid>&name=second
HTTP/1.1 500
```

**Apa yang TIDAK terbukti.** Saya sempat menduga ada bypass posisional (nilai
pertama sampah, nilai kedua valid → diterima). Pengujian membantahnya: semua
varian tanpa token valid di posisi pertama tetap ditolak. Tidak ada bypass CSRF
di sini, dan laporan ini tidak mengklaimnya.

**Apa yang terbukti.** Dua hal:

1. **Parser tidak menolak duplikat field keamanan.** Kontrol di depan aplikasi
   (openresty, WAF, aturan proxy) bisa membaca nilai `_csrf` yang berbeda dari
   yang dipakai aplikasi. Ini kelas bug *layer diff*: server ini punya tiga
   lapisan (openresty → framework → authz) yang bisa berbeda tafsir atas
   parameter yang sama.
2. **500 alih-alih 419.** Sama seperti temuan #3: kegagalan CSRF dilaporkan
   sebagai error server. Setiap 500 masuk ke metrik error dan notifikasi
   on-call, jadi masukan remeh bisa membanjiri monitoring dan menyembunyikan
   kegagalan sungguhan.

**Dampak.** Tidak langsung memberi akses. Nilainya adalah jalur divergensi
tafsir antar lapisan, plus noise error-rate.

**Bukti:** `evidence/f10_hpp_csrf.txt`

**Perbaikan.** Tolak body dengan parameter ganda untuk field keamanan
(`_csrf`) dengan `400`. Ambil token dari satu sumber saja setelah memvalidasi
jumlah kemunculan, dan kembalikan `419` untuk semua kegagalan CSRF — lihat #3.

---

## 11. Kuota login ~10 percobaan per IP, tanpa `Retry-After` — Low

Limiter login menghitung **per-IP**, bukan per-akun. Email berbeda-beda dari
satu IP tetap kena batasnya. Kuotanya bergulir (rolling window ~1 menit), jadi
jumlah persisnya bervariasi antara 8 dan 10 tergantung sisa jendela:

```
$ # satu cookie jar, token _csrf diambil ulang tiap percobaan, email SELALU beda
$ # hasil dua run terpisah:
302 302 302 302 302 302 302 302 429 429          (429 di percobaan ke-9)
302 302 302 302 302 302 302 302 302 302 429      (429 di percobaan ke-11)
```

Halaman 429 menyebut jendela waktu di HTML, tetapi **tidak mengirim header
`Retry-After`**:

```
HTTP/1.1 429
Body: Terlalu banyak percobaan masuk. Coba lagi dalam 1 menit (sekitar pukul 20:58 WIB).
```

Catatan metodologi: percobaan dengan `_csrf` tidak valid dibalas `500` **sebelum**
limiter menghitung, jadi uji ini wajib memakai token asli + cookie jar yang sama.
Percobaan pertama saya salah karena itu.

**Dampak.** Dua arah, keduanya kecil:

- **Terlalu ketat untuk pengguna sah.** Satu laboratorium atau satu NAT kampus
  berbagi satu IP. Delapan salah ketik dari orang berbeda akan mengunci seluruh
  lab selama satu menit. Ini masalah ketersediaan, bukan kebocoran.
- **Tidak ada `Retry-After`.** Klien otomatis (aplikasi mobile, skrip) tidak
  punya cara terprogram untuk tahu kapan boleh mencoba lagi; mereka hanya bisa
  menebak atau mem-parse HTML.

Karena pembatasnya per-IP, penyerang dengan banyak IP tetap bisa menyebar
percobaan. Ini **bukan** temuan kritis — dicatat karena memengaruhi pengguna
nyata dan mudah diperbaiki.

**Bukti:** `evidence/f13_rate_limit.txt`

**Perbaikan.** Kirim `Retry-After` (detik) bersama `429`. Tambahkan juga
penghitung per-akun di samping per-IP, atau longgarkan kuota IP untuk rentang
kampus, supaya satu laboratorium tidak saling mengunci.

---

## Area yang diuji dan bersih

Kejujuran laporan sama pentingnya dengan temuannya. Berikut yang **diuji dan
tidak ditemukan masalah**:

| Area | Uji | Hasil |
|---|---|---|
| IDOR | `/quests/{1..7}`, `/submissions/{n}`, `/files/{n}`, `/courses/{n}`, `/marketplace/purchases/{n}` | 404 — tidak ada objek yang bisa diakses lintas user |
| IDOR aksi | POST `/quests/3..8/submit` (quest bukan milik sendiri) | 404 — route terikat kepemilikan |
| Otorisasi admin | `/admin/{quests,levels,courses,transactions,submissions,rewards}` dengan GET, POST, `_method`, `X-HTTP-Method-Override`, `Accept: application/json` | 403 konsisten di semua varian |
| Mass assignment | `is_admin`, `role`, `exp`, `coins`, `level_id` pada `/profile/name` | Diabaikan; hanya field yang di-whitelist yang diproses |
| XSS | `/login`, `/profile/name`, `/bug-bounty` (title/description/history), `/quests` | Semua di-escape; `"><svg/onload=…>` tampil sebagai `&quot;&gt;` |
| Skema URL | `javascript:`, `data:`, `vbscript:`, `//evil.com` pada `submission_url` dan `evidence_url` | Ditolak dengan pesan validasi eksplisit |
| CSRF | Token terikat sesi; token dari sesi lain; token hilang | Ditolak (walau dengan status 500 — lihat #3) |
| Session fixation | SID sebelum vs sesudah register & login; SID setelah logout | Diregenerasi; SID lama mati |
| SQL injection | `/leaderboard?course=` dengan `4'`, `4)`, `4 AND 1=1`, `4 UNION SELECT 1`, `4;--` | 404 — parameter di-cast ke integer |
| Rate limit | Login, register, resend verifikasi; bypass via `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `X-Client-IP`, `CF-Connecting-IP` | 429 aktif (lihat #11 untuk kuota sebenarnya), header tidak mem-bypass |
| Ekonomi koin | POST `/marketplace/purchase` `reward_id=6` (60 koin) dengan saldo 0 | Ditolak server-side: "Koin kamu tidak cukup", saldo tetap 0, riwayat kosong |
| API JSON | `/api/{quests,leaderboard,profile,me,users,marketplace,rewards,dashboard,notifications,submissions}` dengan `Accept: application/json` | 404 dengan envelope JSON konsisten — tidak ada API yang tidak terautentikasi |
| Panel Termix | `/version`, `/metrics` (anonim), `/api/health`, `/debug`, `/api/users`, `/api/hosts` | `/version` + `/metrics` → 401; `/health` + `/users/sso-providers` → JSON kecil non-sensitif; sisanya SPA catch-all 3164 B (bukan endpoint). Tidak ada kebocoran konfigurasi |
| Duplikasi submit | POST ulang quest yang sudah dikirim | "Kamu sudah mengirim quest ini." |
| Path traversal | `..%2f`, `%2e%2e/`, `%00`, `//etc/passwd`, `/index.php/.env` | 400/403/404 konsisten |
| File sensitif | `.env`, `.git/config`, `storage/logs/laravel.log`, `phpinfo.php`, `backup.zip`, `db.sql`, `_ignition/health-check` | 403/404 |
| Metode HTTP | `PUT`/`DELETE`/`PATCH`/`TRACE` pada halaman | 404, bukan 405 |
| Header aplikasi utama | CSP, X-Frame-Options, Referrer-Policy, Cache-Control | CSP ketat tanpa `unsafe-inline`, `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` pada halaman terautentikasi |
| PII di leaderboard | `/leaderboard?course=4` | Hanya nama + level, tanpa email/NIM |

---

## Urutan prioritas perbaikan

1. **Tutup port 8080 dari internet** — atau pasang TLS + batasi akses. Ini satu-satunya temuan yang langsung memberi jalan masuk ke infrastruktur.
2. **Perbaiki CORS di Termix** — allowlist origin eksplisit, tolak `null`, hapus `x-admin-target-user` bila tak dipakai.
3. **Perbaiki status CSRF** — satu perubahan di `Kernel::guard()`, memperbaiki semua endpoint sekaligus dan mengembalikan penanganan sesi kedaluwarsa di frontend.
4. **Kunci `TRUSTED_PROXIES`** dan paksa `secure` pada cookie tanpa syarat.
5. **Perbaiki redirect `/assets`** agar tidak menurunkan skema dan tidak membocorkan port internal.
6. **Samakan pesan registrasi** dan pindahkan pembuatan user ke setelah verifikasi email.
7. **Tambahkan alur reset password.**
8. **Dedup header keamanan** di satu lapis saja.

---

## Struktur repo

```
.
├── README.md                      laporan ini
├── reproduce.sh                   reproduksi temuan #1–#5, #8–#11 (anonim, tanpa kredensial)
└── evidence/
    ├── f1_8080_http_headers.txt   header port 8080 (200, nginx, tanpa TLS)
    ├── f1_8080_manifest.txt       manifest.json → "Termix"
    ├── f1_8080_tls_refused.txt    HTTPS di 8080/8443 → kode 000
    ├── f2_cors_reflect.txt        ACAO mencerminkan https://evil.example
    ├── f2_cors_null.txt           ACAO: null + credentials true
    ├── f2_cors_preflight.txt      preflight mengizinkan metode tulis + header internal
    ├── f2_unauth_json.txt         401 {"error":"Missing authentication token"}
    ├── f3_redirect_8080.txt       /assets → http://…:8080/
    ├── f3_csrf_500.txt            POST tanpa _csrf → HTTP 500 (empat endpoint)
    ├── f4_csrf_500.txt            POST tanpa _csrf → HTTP 500
    ├── f5_xfp_cookie.txt          X-Forwarded-Proto: http → cookie tanpa `secure`
    ├── f6_dup_headers.txt         HSTS & nosniff terpasang dua kali
    ├── f8_no_reset.txt            semua path reset password → 404
    ├── f10_hpp_csrf.txt           _csrf ganda → 500; bypass posisional TIDAK terbukti
    ├── f13_rate_limit.txt         limiter per-IP ~10 percobaan, tanpa Retry-After
    ├── n_csrf_cross_session.txt   token lintas sesi ditolak (uji negatif)
    ├── n_negative_surface.txt     ekonomi koin, envelope API JSON, jalur Termix
    ├── quests_before.html         snapshot Quest Board sebelum pengujian (data disamarkan)
    ├── marketplace.html           snapshot Marketplace (data disamarkan)
    └── *.js                       api.js, quests.js, marketplace.js, layout.js
```

## Etika & batasan

- Pengujian dilakukan atas izin pemilik akun. Tidak ada data user lain yang
  diakses, diunduh, atau diubah.
- Kredensial, cookie sesi, nama, NIM, dan token CSRF di seluruh artefak repo
  ini sudah disamarkan (`[REDACTED]`, `[NIM]`, `[NAMA_MAHASISWA]`).
- Tidak ada eksploitasi yang mengubah data, menulis file, atau menjalankan
  perintah di server.
- Beberapa berkas uji sempat tertulis ke akun pemilik saat pengujian dan sudah
  dilaporkan terpisah untuk dibersihkan.
- `reproduce.sh` hanya menjalankan permintaan HTTP baca-saja (GET/OPTIONS) dan
  POST tanpa kredensial ke endpoint publik. Bukti yang butuh sesi (F10, dan
  uji negatif lintas sesi) diambil sekali dengan sesi pemilik akun, lalu
  disamarkan — skrip tidak memuat cookie apa pun.
- Temuan #11 mengirim beberapa percobaan login dengan email karangan
  (`probe1@unej.ac.id` dan sejenisnya) dan password salah. Tidak ada akun
  nyata yang dicoba, dan tidak ada kredensial yang ditebak.

---

**Penulis:** Mohammad Reihan Islami Wijaya (252410102080)
**Mata kuliah:** Dasar-Dasar Keamanan Informasi — Semester 3
**Tanggal:** 27 Oktober 2026
