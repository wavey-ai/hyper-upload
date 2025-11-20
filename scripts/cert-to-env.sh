#!/usr/bin/env bash
set -euo pipefail

# Convert a combined PEM (cert chain + private key) into .env entries
# expected by this project: FULLCHAIN_PEM and PRIVKEY_PEM.
#
# Usage:
#   scripts/cert-to-env.sh [INPUT_PEM] [OUTPUT_ENV]
#
# Defaults:
#   INPUT_PEM: cert.pem
#   OUTPUT_ENV: .env

INPUT_PEM=${1:-cert.pem}
OUTPUT_ENV=${2:-.env}

if [[ ! -f "$INPUT_PEM" ]]; then
  echo "error: input PEM not found: $INPUT_PEM" >&2
  exit 1
fi

tmpdir=$(mktemp -d)
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

fullchain_pem="$tmpdir/fullchain.pem"
privkey_pem="$tmpdir/privkey.pem"

# Extract all certificate blocks (full chain)
sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$INPUT_PEM" > "$fullchain_pem"

# Extract private key block (supports EC or PKCS8). RSA PKCS#1 keys are not supported by code.
if grep -q -- '-----BEGIN PRIVATE KEY-----' "$INPUT_PEM"; then
  sed -n '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/p' "$INPUT_PEM" > "$privkey_pem"
elif grep -q -- '-----BEGIN EC PRIVATE KEY-----' "$INPUT_PEM"; then
  sed -n '/-----BEGIN EC PRIVATE KEY-----/,/-----END EC PRIVATE KEY-----/p' "$INPUT_PEM" > "$privkey_pem"
elif grep -q -- '-----BEGIN RSA PRIVATE KEY-----' "$INPUT_PEM"; then
  echo "error: RSA PKCS#1 keys found; convert to PKCS#8 first, e.g.:" >&2
  echo "       openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsa.key -out key.pk8" >&2
  exit 1
else
  echo "error: no supported private key found (need PKCS8 or EC)." >&2
  exit 1
fi

# Create single-line base64 without wrapping. Prefer openssl; fallback to base64 + tr.
if command -v openssl >/dev/null 2>&1; then
  FULLCHAIN_B64=$(openssl base64 -A < "$fullchain_pem")
  PRIVKEY_B64=$(openssl base64 -A < "$privkey_pem")
else
  FULLCHAIN_B64=$(base64 < "$fullchain_pem" | tr -d '\n')
  PRIVKEY_B64=$(base64 < "$privkey_pem" | tr -d '\n')
fi

cat > "$OUTPUT_ENV" <<EOF
FULLCHAIN_PEM=$FULLCHAIN_B64
PRIVKEY_PEM=$PRIVKEY_B64
EOF

echo "Wrote $OUTPUT_ENV with FULLCHAIN_PEM and PRIVKEY_PEM."
