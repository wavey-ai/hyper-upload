#!/usr/bin/env bash
set -euo pipefail

# Upload test using curl over HTTP/2.
# - Generates test files of 10–100MB (10MB increments) before running.
# - Posts each file to /upload?filename=<name> and records timing.
#
# Usage:
#   scripts/h2-upload-test.sh [BASE_URL]
#
# Env overrides:
#   DATA_DIR   Directory to store generated files (default: testdata)
#   SIZES      Space-separated MB sizes (default: "10 20 ... 100")
#   RUNS       Number of runs per size (default: 1)
#   CURL_BIN   curl binary (default: curl)

BASE_URL=${1:-https://local.aldea.ai:4433}
DATA_DIR=${DATA_DIR:-testdata}
SIZES=${SIZES:-"10 20 30 40 50 60 70 80 90 100"}
RUNS=${RUNS:-1}
CURL_BIN=${CURL_BIN:-curl}

# Ensure curl supports HTTP/2
if ! "$CURL_BIN" -V | grep -q 'HTTP2'; then
  echo "error: $CURL_BIN is not built with HTTP/2 support (missing HTTP2 in -V)." >&2
  exit 1
fi

mkdir -p "$DATA_DIR"

gen_file() {
  local mb=$1
  local path=$2
  local bytes=$((mb * 1024 * 1024))

  # Generate file with /dev/zero to avoid CPU cost of /dev/urandom
  # Use head -c for portability across macOS/Linux
  echo "Generating ${mb}MB at $path" >&2
  head -c "$bytes" </dev/zero >"$path"
}

# Pre-generate test data
for mb in $SIZES; do
  file="$DATA_DIR/${mb}MB.bin"
  if [[ -f "$file" ]]; then
    # Verify size; regenerate if size mismatch
    actual=$(wc -c <"$file")
    expected=$((mb * 1024 * 1024))
    if [[ "$actual" -ne "$expected" ]]; then
      gen_file "$mb" "$file"
    fi
  else
    gen_file "$mb" "$file"
  fi
done

echo "# Upload timings (HTTP/2)"
echo "# Target: $BASE_URL"
echo "size_mb,time_ms,speed_MBps,speed_Gbps,http,status,filename,run"

# Upload loop with timing
for mb in $SIZES; do
  file="$DATA_DIR/${mb}MB.bin"
  name=$(basename "$file")

  for (( run=1; run<=RUNS; run++ )); do
    # Compose curl flags
    flags=(--http2 -sS -o /dev/null -w '%{time_total} %{speed_upload} %{http_code} %{http_version}\n' -X POST --data-binary "@${file}")

    # Execute
    set +e
    output=$("$CURL_BIN" "${flags[@]}" "$BASE_URL/upload?filename=$name" 2>/dev/null)
    rc=$?
    set -e

    if [[ $rc -ne 0 || -z "$output" ]]; then
      echo "${mb},ERROR,ERROR,ERROR,ERROR,$name,$run" >&2
      continue
    fi

    # Parse: time_total speed_upload http_code http_version
    # Convert speed_upload (bytes/sec) to MB/s (MiB) and Gbit/s (decimal)
    time_total=$(awk '{print $1}' <<<"$output")
    # Convert seconds to milliseconds (rounded)
    time_ms=$(awk -v t="$time_total" 'BEGIN { printf("%.0f", t*1000) }')
    speed_bytes=$(awk '{print $2}' <<<"$output")
    http_code=$(awk '{print $3}' <<<"$output")
    http_version=$(awk '{print $4}' <<<"$output")

    # Avoid division by zero
    if [[ "$speed_bytes" == "0" || -z "$speed_bytes" ]]; then
      speed_mbps="0"
      speed_gbps="0"
    else
      # 1048576 = 1024*1024
      speed_mbps=$(awk -v s="$speed_bytes" 'BEGIN { printf("%.3f", s/1048576) }')
      # Gbit/s uses decimal 1e9 bits per second
      speed_gbps=$(awk -v s="$speed_bytes" 'BEGIN { printf("%.3f", (s*8)/1000000000) }')
    fi

    echo "$mb,$time_ms,$speed_mbps,$speed_gbps,$http_version,$http_code,$name,$run"
  done
done
