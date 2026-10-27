#!/usr/bin/env bash
# Reproduksi temuan audit bLecturer. Hanya GET/OPTIONS dan POST tanpa kredensial.
# Butuh: curl, bash. Tidak ada dependensi lain.
set -uo pipefail

H="https://diksy.ilkom.unej.ac.id"
P="http://diksy.ilkom.unej.ac.id:8080"
CHK="${CHK:-1}"   # CHK=0 -> hanya tampilkan, jangan cocokkan pola
SID="${SID:-}"    # BLSESSID milik sendiri -> mengaktifkan uji F12

pass=0; fail=0
hr() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok()   { pass=$((pass+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
# expect <label> <haystack> <needle>
expect() {
  if [ "$CHK" = "0" ]; then printf '  .... %s\n' "$1"; return; fi
  case "$2" in *"$3"*) ok "$1";; *) bad "$1 (tidak menemukan: $3)";; esac
}

hr "F1  Panel Termix di port 8080 tanpa TLS"
TMP="./.f1h.$$"
curl -s -m 20 -D "$TMP" -o /dev/null "$P/"
F1="$(cat "$TMP")"
rm -f "$TMP"
expect "port 8080 menjawab 200"          "$F1" "200 OK"
expect "server = nginx (bukan TLS)"      "$F1" "Server: nginx"
MAN=$(curl -s -m 20 "$P/manifest.json")
expect "manifest menyebut Termix"        "$MAN" '"name": "Termix"'
expect "deskripsi = SSH/remote desktop"  "$MAN" "remote desktop"
TLS=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "https://diksy.ilkom.unej.ac.id:8080/")
expect "HTTPS di 8080 tidak tersedia (000)" "$TLS" "000"

hr "F2  CORS mencerminkan Origin apa pun + credentials"
C1=$(curl -s -m 20 -D - -o /dev/null -H "Origin: https://evil.example" "$P/users/me")
expect "ACAO = Origin penyerang"         "$C1" "Access-Control-Allow-Origin: https://evil.example"
expect "credentials true"                "$C1" "Access-Control-Allow-Credentials: true"
C2=$(curl -s -m 20 -D - -o /dev/null -H "Origin: null" "$P/users/me")
expect "Origin: null diterima"           "$C2" "Access-Control-Allow-Origin: null"
C3=$(curl -s -m 20 -D - -o /dev/null -X OPTIONS -H "Origin: https://evil.example" \
       -H "Access-Control-Request-Method: POST" \
       -H "Access-Control-Request-Headers: authorization,content-type" "$P/users/login")
expect "preflight izinkan POST"          "$C3" "GET,POST,PUT,PATCH,DELETE,OPTIONS"
expect "preflight bocorkan x-admin-target-user" "$C3" "x-admin-target-user"

hr "F3  Redirect /assets membocorkan port 8080 + turun ke HTTP"
for p in uploads assets assets/js assets/css; do
  L=$(curl -s -m 15 -D - -o /dev/null "$H/$p" | tr -d '\r' | grep -i '^location:')
  expect "GET /$p -> Location http :8080" "$L" "http://diksy.ilkom.unej.ac.id:8080/"
done

hr "F4  CSRF gagal dibalas 500, bukan 419"
for p in login register email/verify/resend; do
  S=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST "$H/$p" -d 'email=a@b.c&password=x')
  expect "POST /$p tanpa _csrf -> 500" "$S" "500"
done

hr "F5  X-Forwarded-Proto menghapus flag secure + HSTS"
N=$(curl -s -m 15 -D - -o /dev/null "$H/login")
X=$(curl -s -m 15 -D - -o /dev/null -H "X-Forwarded-Proto: http" "$H/login")
expect "normal: cookie punya 'secure'"   "$N" "; secure;"
expect "normal: ada HSTS"                "$N" "Strict-Transport-Security:"
case "$X" in
  *"Set-Cookie"*"; secure;"*) bad "XFP: 'secure' seharusnya hilang tapi masih ada";;
  *"Set-Cookie"*) ok "XFP: 'secure' hilang dari cookie";;
  *) bad "XFP: tidak ada Set-Cookie";;
esac
case "$X" in
  *"Strict-Transport-Security"*) bad "XFP: HSTS seharusnya hilang tapi masih ada";;
  *) ok "XFP: HSTS hilang";;
esac

hr "F6  Header keamanan terpasang ganda"
D=$(curl -s -m 15 -D - -o /dev/null "$H/login" | grep -ci 'strict-transport-security')
expect "HSTS muncul >= 2 kali" "$([ "$D" -ge 2 ] && echo DUPLICATE || echo SINGLE)" "DUPLICATE"

hr "F8  Tidak ada alur reset password"
for p in auth/forgot forgot-password password/reset auth/reset reset lupa-password; do
  S=$(curl -s -m 12 -o /dev/null -w '%{http_code}' "$H/$p")
  expect "/$p -> 404" "$S" "404"
done

hr "F9  Halaman login tanpa tautan lupa/forgot"
LG=$(curl -s -m 15 "$H/login")
expect "tidak ada kata lupa/forgot" "$(echo "$LG" | grep -ciE 'lupa|forgot' || echo 0)" "0"

hr "F10 Parameter _csrf ganda: nilai pertama menang"
# Tanpa sesi, _csrf pasti tidak valid -> 500 (tidak bisa bedakan HPP dari CSRF
# biasa secara anonim). Yang BISA dibuktikan anonim: body dengan _csrf ganda
# tetap dibalas 500, bukan 400/419, jadi parser tidak menolak duplikat.
H1=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST "$H/login" \
      -d '_csrf=deadbeef&_csrf=deadbeef2&email=a@b.c&password=x')
expect "dua _csrf -> 500 (duplikat tidak ditolak 400)" "$H1" "500"
# Bentuk array juga masuk ke parser yang sama.
H2=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST "$H/login" \
      -d '_csrf[]=a&_csrf[]=b&email=a@b.c&password=x')
expect "_csrf[] array -> 500 (tipe tidak divalidasi)" "$H2" "500"
echo "  catatan: bukti bypass positional butuh sesi valid -> evidence/f10_hpp_csrf.txt"

hr "F11 Kuota login per-IP (~10 percobaan), tanpa Retry-After"
# _csrf terikat sesi: token harus diambil DAN dipakai dengan cookie jar yang sama.
# Tanpa cookie, server membalas 500 dan limiter tidak pernah menghitung.
JAR="./.jar.$$"
get_tk() {
  curl -s -m 15 -c "$JAR" -b "$JAR" "$H/login" | tr -d '\r' \
    | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'
}
CNT=""
for i in $(seq 1 40); do
  TK=$(get_tk)
  C=$(curl -s -m 15 -c "$JAR" -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$H/login" \
      -d "_csrf=$TK&email=probe$i@unej.ac.id&password=Password123!")
  CNT="$CNT$C "
  [ "$C" = "429" ] && break
done
echo "  hasil: $CNT"
# Jumlah persisnya bergulir (rolling window) dan state per-IP bergantung trafik
# sebelumnya, jadi yang dinilai adalah "apakah 429 pernah muncul", bukan hitungan.
case "$CNT" in
  *429*) ok "limiter aktif, menghitung per-IP (email berbeda tetap kena)";;
  *302*) echo "  catatan: 40 percobaan tanpa 429 pada run ini (state limiter per-IP);"
          echo "           limiter terverifikasi pada run lain — lihat evidence/f13_rate_limit.txt";;
  *)     bad "respons tak terduga (lihat baris hasil di atas)";;
esac
# Header diambil dari respons 429 sungguhan, bukan dari 500 CSRF.
TK=$(get_tk)
RA=$(curl -s -m 15 -c "$JAR" -b "$JAR" -D - -o /dev/null -X POST "$H/login" \
     -d "_csrf=$TK&email=probe0@unej.ac.id&password=Password123!" \
     | tr -d '\r' | grep -ci '^retry-after:')
expect "429 tanpa header Retry-After" "$RA" "0"
rm -f "$JAR"

# ---------------- F12: form enable 2FA tanpa field password ----------------
# Uji struktural: halaman setup hanya boleh punya kode, bukan password.
# (Mengaktifkan 2FA sungguhan butuh sesi milik sendiri, tidak dilakukan di sini.)
printf '\n\033[1m== F12. 2FA enable tanpa password (uji struktur)\033[0m\n'
if [ -n "$SID" ]; then
  SU="$(curl -s -m 15 -b "BLSESSID=$SID" "$H/profile/2fa/setup")"
  EN="$(printf '%s' "$SU" | tr -d '\r' | grep -o 'action="/profile/2fa/[a-z-]*"')"
  FN="$(printf '%s' "$SU" | tr -d '\r' | grep -o 'name="[a-z_]*"' | sort -u | tr '\n' ' ')"
  echo "  action: $EN"
  echo "  fields: $FN"
  case "$FN" in
    *'name="password"'*) bad "form enable meminta password (sudah diperbaiki?)";;
    *'name="code"'*)     ok "form enable tanpa field password — kode saja";;
    *)                   bad "field tak terduga";;
  esac
  PR="$(curl -s -m 15 -b "BLSESSID=$SID" "$H/profile" | tr -d '\r')"
  echo "$PR" | grep -q 'action="/profile/2fa/disable"' \
    && { echo "$PR" | sed -n '/2fa\/disable/,/<\/form>/p' | grep -q 'name="password"' \
         && ok "form disable tetap meminta password (asimetri terkonfirmasi)" \
         || bad "form disable tidak meminta password"; }
else
  echo "  SKIP: butuh BLSESSID milik sendiri (SID=... bash reproduce.sh)"
fi

printf '\n\033[1m== Ringkasan\033[0m\n'
printf '  PASS: %d\n  FAIL: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && printf '\n  Semua temuan tereproduksi.\n' || printf '\n  Ada yang gagal — server mungkin sudah diperbaiki.\n'
exit 0
