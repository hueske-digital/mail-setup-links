#!/usr/bin/env bash
# End-to-end test: the service obtains a certificate from Pebble via HTTP-01 and delivers a
# profile whose CMS signature verifies against Pebble's root certificate.
set -euo pipefail
cd "$(dirname "$0")/.."

LINK_SECRET="$(openssl rand -base64 32)"
export LINK_SECRET
work="$(mktemp -d)"
cleanup() {
  docker compose down --volumes --remove-orphans >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT

base="http://mobileconfig.test:5002"
request() { curl --silent --show-error --resolve mobileconfig.test:5002:127.0.0.1 "$@"; }

docker compose up --build --detach --wait

link="$(request --fail --data-urlencode "email=kunde@example.com" --data-urlencode "displayName=Max Mustermann" "$base/links" |
  grep --only-matching --extended-regexp "$base/e/[A-Za-z0-9_-]+" | head -n 1)"
[ -n "$link" ] || { echo "FAIL: no link in response" >&2; exit 1; }

status=000
for _ in $(seq 1 60); do
  status="$(request --output "$work/email.mobileconfig" --write-out '%{http_code}' "$link/email.mobileconfig")"
  [ "$status" = 200 ] && break
  sleep 1
done
if [ "$status" != 200 ]; then
  echo "FAIL: profile download answered $status" >&2
  docker compose logs app >&2
  exit 1
fi

curl --silent --show-error --fail --insecure https://127.0.0.1:15000/roots/0 >"$work/root.pem"
openssl cms -verify -inform DER -in "$work/email.mobileconfig" -CAfile "$work/root.pem" -purpose any -out "$work/profile.xml"
grep --quiet "<string>kunde@example.com</string>" "$work/profile.xml"
openssl pkcs7 -inform DER -in "$work/email.mobileconfig" -print_certs -noout | grep --quiet "mobileconfig.test" ||
  openssl pkcs7 -inform DER -in "$work/email.mobileconfig" -print_certs | openssl x509 -noout -ext subjectAltName | grep --quiet "mobileconfig.test"

echo "OK: profile is signed by a certificate for mobileconfig.test and verifies against the ACME root"
