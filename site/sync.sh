#!/usr/bin/env bash
# Copy the data the static site reads into site/data/.
#   data/platforms.json  capture/data/platforms/index.json (per-OS summary, capture/merge_platforms.py); optional
#   data/latest.json     Chrome reference: capture/data/latest.json (Moe, capture/SCHEMA.md); the assumed-schema stand-in fallback is superseded
#   data/libraries.json  leaderboard output (run leaderboard/run.sh first to refresh it)
#   data/history/        capture/data/history/ if present; otherwise an empty index so the page shows its empty state
set -euo pipefail
SITE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TB="$(dirname "$SITE")"
mkdir -p "$SITE/data"
if [[ -f "$TB/capture/data/latest.json" ]]; then
  cp "$TB/capture/data/latest.json" "$SITE/data/latest.json"; echo "latest.json   <- capture/data/latest.json"
else
  cp "$TB/leaderboard/data/chrome_reference.assumed.json" "$SITE/data/latest.json"; echo "latest.json   <- leaderboard/data/chrome_reference.assumed.json (ASSUMED schema)"
fi
cp "$TB/leaderboard/data/libraries.json" "$SITE/data/libraries.json"; echo "libraries.json <- leaderboard/data/libraries.json"
rm -rf "$SITE/data/history"
if [[ -d "$TB/capture/data/history" ]]; then
  cp -r "$TB/capture/data/history" "$SITE/data/history"; echo "history/      <- capture/data/history/"
fi
if [[ ! -f "$SITE/data/history/index.json" ]]; then
  mkdir -p "$SITE/data/history"; echo '{"captures": []}' > "$SITE/data/history/index.json"; echo "history/      <- empty index (no capture history yet)"
fi
if [[ -f "$TB/capture/data/platforms/index.json" ]]; then
  cp "$TB/capture/data/platforms/index.json" "$SITE/data/platforms.json"; echo "platforms.json <- capture/data/platforms/index.json"
fi
# Older one-off captures (capture/data/chrome-*.json) for the "Compare two Chrome versions" picker
rm -rf "$SITE/data/archive"; mkdir -p "$SITE/data/archive"
python3 - "$TB/capture/data" "$SITE/data/archive" <<'PY'
import glob, json, os, shutil, sys
src, dst = sys.argv[1], sys.argv[2]
caps = []
for p in sorted(glob.glob(os.path.join(src, "chrome-*.json"))):
    d = json.load(open(p))
    shutil.copy(p, dst)
    caps.append(dict(file=os.path.basename(p), chrome_version=d.get("version"), captured_at=d.get("captured_at")))
json.dump({"note": "Older Chrome captures copied from capture/data/ by site/sync.sh (same layout as latest.json).", "captures": caps}, open(os.path.join(dst, "index.json"), "w"), indent=1)
print("archive/      <- %d capture(s) from capture/data/chrome-*.json" % len(caps))
PY
