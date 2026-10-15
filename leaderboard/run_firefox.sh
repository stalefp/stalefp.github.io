#!/usr/bin/env bash
# Firefox leaderboard: run the libraries' Firefox profiles against the TLS echo endpoint and grade them against the real
# Firefox capture (capture/data/firefox/latest.json). Writes leaderboard/data/firefox_libraries.json. Separate from run.sh.
set -euo pipefail
LB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYBIN="${HARNESS_PYTHON:-$(dirname "$LB")/.venv/bin/python}"
[[ -x "$PYBIN" ]] || PYBIN="$(command -v python || command -v python3)"   # CI: the workflow's setup-python interpreter
[[ -f "$(dirname "$LB")/capture/data/firefox/latest.json" ]] || { echo "no Firefox capture yet"; exit 1; }
RUN="$LB/raw/firefox-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$RUN/go" "$RUN/py" "$LB/bin"
echo "{\"started_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"endpoint\": \"https://tls.peet.ws/api/all\"}" > "$RUN/meta.json"
(cd "$LB/harness/gofirefox" && go build -o "$LB/bin/gofirefox" .) && (cd "$RUN/go" && "$LB/bin/gofirefox") || echo "go Firefox cases failed"
"$PYBIN" "$LB/harness/run_firefox.py" "$RUN/py" || echo "python Firefox cases failed"
"${BUILD_PYTHON:-$PYBIN}" "$LB/build_firefox.py" "$RUN"
