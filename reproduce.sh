#!/usr/bin/env bash
# Reproduksi temuan audit bLecturer. Hanya GET/OPTIONS dan POST tanpa kredensial.
# Butuh: curl, bash. Tidak ada dependensi lain.
set -uo pipefail

H="https://diksy.ilkom.unej.ac.id"
P="http://diksy.ilkom.unej.ac.id:8080"
CHK="${CHK:-1}"   # CHK=0 -> hanya tampilkan, jangan cocokkan pola

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

printf '\n\033[1m== Ringkasan\033[0m\n'
printf '  PASS: %d\n  FAIL: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && printf '\n  Semua temuan tereproduksi.\n' || printf '\n  Ada yang gagal — server mungkin sudah diperbaiki.\n'
exit 0
