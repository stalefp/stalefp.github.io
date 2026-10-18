#!/usr/bin/env bash
# Extra libraries (wreq, got-scraping, hrequests, CycleTLS), kept apart from bench.py / gobench so those can change freely.
#   leaderboard/harness/extra/run_extra.sh <outdir> chrome|firefox
# Writes <outdir>/<lib>_<profile>.json (raw echo JSON from https://tls.peet.ws/api/all), <name>.error.txt for a failed
# case, and <outdir>/_versions.json. Each library is optional: a missing toolchain or a failed build skips only that one.
set -uo pipefail
X="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$1"; WHICH="$2"; mkdir -p "$OUT"
PYBIN="${HARNESS_PYTHON:-$(command -v python || command -v python3)}"
# STALE_LIBS (comma-separated board library names, as in the other harnesses) limits the run; empty = all
wanted() { [ -z "${STALE_LIBS:-}" ] || [[ ",${STALE_LIBS// /}," == *",$1,"* ]]; }
case $WHICH in chrome) WREQ=Chrome149 ;; firefox) WREQ=Firefox151 ;; *) echo "chrome|firefox" >&2; exit 2 ;; esac
# wreq (Rust): pinned in wreq/Cargo.toml + Cargo.lock
if ! wanted wreq; then :
elif command -v cargo >/dev/null; then
  (cd "$X/wreq" && cargo build --release --locked -q) && "$X/wreq/target/release/wreq_bench" "$OUT" "$WREQ" \
    || { echo "wreq failed"; echo "wreq build or request failed" > "$OUT/wreq_$WREQ.error.txt"; }
else echo "cargo not found: wreq skipped"; fi
# got-scraping + CycleTLS (Node): pinned in node/package-lock.json (npm ci checks the lockfile integrity hashes)
if ! wanted got-scraping && ! wanted CycleTLS; then :
elif command -v npm >/dev/null; then
  ( cd "$X/node" && { [ -d node_modules ] || npm ci --silent --no-audit --no-fund; } ) && node "$X/node/bench.mjs" "$OUT" "$WHICH" || echo "node cases failed"
else echo "npm not found: got-scraping/CycleTLS skipped"; fi
# hrequests (Python): pinned in requirements.txt
if wanted hrequests; then "$PYBIN" "$X/hrequests_bench.py" "$OUT" "$WHICH" || echo "hrequests failed"; fi
"$PYBIN" - "$OUT" "$X/wreq/Cargo.lock" <<'PY'
import glob, json, os, re, sys
out, lock = sys.argv[1:]
v = {}
for f in glob.glob(os.path.join(out, "_*versions*.json")):
    if os.path.basename(f) != "_versions.json": v.update(json.load(open(f)))
txt = open(lock).read() if os.path.exists(lock) else ""
for crate in ("wreq", "wreq-util"):
    m = re.search(r'name = "%s"\nversion = "([^"]+)"' % re.escape(crate), txt)
    if m: v["rust:" + crate] = m.group(1)
json.dump(v, open(os.path.join(out, "_versions.json"), "w"), indent=1); print("versions", v)
PY
exit 0
