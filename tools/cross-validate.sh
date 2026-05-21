#!/usr/bin/env bash
# Cross-validates apksig-go vs apksigner over a directory of APKs.
# Usage: ./tools/cross-validate.sh /path/to/apks/
set -u
dir="${1:-.}"
script_dir="$(cd "$(dirname "$0")" && pwd)"
gocmd="${script_dir}/../bin/apksigverify"
if [ ! -x "$gocmd" ]; then
  gocmd="$(command -v apksigverify 2>/dev/null)" || true
fi
if [ -z "$gocmd" ]; then
  echo "error: apksigverify not found. Run 'go build ./cmd/...' first." >&2
  exit 1
fi

pass=0
fail=0
divergent=0
errors=0
log=/tmp/apksig-cross-$(date +%s).log
: > "$log"

shopt -s nullglob
for apk in "$dir"/*.apk; do
  base=$(basename "$apk")
  size=$(stat -f%z "$apk" 2>/dev/null || stat -c%s "$apk")
  # Skip > 100 MB to keep run time reasonable.
  if [ "$size" -gt 104857600 ]; then continue; fi

  ref=$(apksigner verify "$apk" 2>&1)
  refrc=$?
  goout=$($gocmd "$apk" 2>&1)
  gorc=$?

  refOK=$([ $refrc -eq 0 ] && echo 1 || echo 0)
  goOK=$([ $gorc -eq 0 ] && echo 1 || echo 0)

  if [ "$refOK" = "$goOK" ]; then
    if [ "$goOK" = "1" ]; then pass=$((pass+1)); else errors=$((errors+1)); fi
    printf 'OK  %s   ref=%s go=%s\n' "$base" "$refOK" "$goOK" >> "$log"
  else
    divergent=$((divergent+1))
    printf '\n=== DIVERGENT %s (size=%s) ===\n' "$base" "$size" >> "$log"
    printf '  apksigner refrc=%d, ours rc=%d\n' "$refrc" "$gorc" >> "$log"
    printf '  --- apksigner ---\n' >> "$log"
    echo "$ref" | head -8 >> "$log"
    printf '  --- ours ---\n' >> "$log"
    echo "$goout" | head -12 >> "$log"
  fi
done

echo "pass=$pass fail=$errors divergent=$divergent"
echo "Log: $log"
