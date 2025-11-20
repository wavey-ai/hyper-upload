# hyper-upload

Quick notes for TLS configuration via `.env`:

- The server expects `FULLCHAIN_PEM` and `PRIVKEY_PEM` environment variables to be base64-encoded PEM payloads (the literal `-----BEGIN ...-----` blocks, base64-encoded as a single line each).
- A helper script is provided to generate `.env` from a combined `cert.pem` that contains your full certificate chain followed by the private key.

Usage:

- Put your combined PEM at the repo root as `cert.pem` (two or more `CERTIFICATE` blocks followed by a `PRIVATE KEY` block).
- Run: `scripts/cert-to-env.sh` to produce `.env` with `FULLCHAIN_PEM` and `PRIVKEY_PEM`.

Manual commands (if you prefer not to use the script):

- Full chain: `sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' cert.pem | openssl base64 -A`
- Private key (PKCS#8 or EC):
  - PKCS#8: `sed -n '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/p' cert.pem | openssl base64 -A`
  - EC: `sed -n '/-----BEGIN EC PRIVATE KEY-----/,/-----END EC PRIVATE KEY-----/p' cert.pem | openssl base64 -A`

Then place the outputs on single lines in `.env` like:

```
FULLCHAIN_PEM=<paste base64 of fullchain.pem>
PRIVKEY_PEM=<paste base64 of privkey.pem>
```

Do not wrap values in quotes. RSA PKCS#1 keys (`BEGIN RSA PRIVATE KEY`) are not supported by this server; convert to PKCS#8 if needed: `openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsa.key -out key.pk8`.

## HTTP/2 Upload Timing Script

- Run the server (listening on `https://localhost:4433` by default).
- Execute: `scripts/h2-upload-test.sh` (or pass a custom base URL like `scripts/h2-upload-test.sh https://127.0.0.1:4433`).
- The script generates `testdata/` files of sizes 10–100MB (10MB steps), then uploads each via curl using HTTP/2 and prints CSV results:
  - Columns: `size_mb,time_ms,speed_MBps,speed_Gbps,http,status,filename,run`
- Env overrides:
  - `DATA_DIR` (default: `testdata`)
  - `SIZES` (default: `"10 20 30 40 50 60 70 80 90 100"`)
  - `RUNS` (default: `1`)
  - `CURL_BIN` (default: `curl` — must be built with HTTP/2)
  - `INSECURE` (default: `1` — uses `-k`; set `0` to enforce TLS verification)
