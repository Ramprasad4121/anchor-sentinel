#!/usr/bin/env sh
# Runs anchor-sentinel on every example in coral-xyz/sealevel-attacks and
# prints the detector IDs and lines found per example.
# Usage: benchmarks/sealevel-attacks.sh [path-to-anchor-sentinel-binary]
set -e
BIN="${1:-anchor-sentinel}"
DIR="${SEALEVEL_DIR:-/tmp/sealevel-attacks}"
if [ ! -d "$DIR" ]; then
  git clone --depth 1 https://github.com/coral-xyz/sealevel-attacks "$DIR"
fi
cd "$DIR"
for f in $(find programs -name lib.rs | sort); do
  name=$(echo "$f" | cut -d/ -f2-3)
  ids=$("$BIN" scan "$f" --format json 2>/dev/null \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(" ".join(sorted(x["detector_id"]+":"+str(x["line"]) for x in d["findings"])) or "-")')
  printf '%-48s %s\n' "$name" "$ids"
done
