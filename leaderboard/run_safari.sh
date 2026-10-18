#!/usr/bin/env bash
# Safari leaderboard: run the libraries' desktop Safari profiles against the TLS echo endpoint, grade them against the real
# Safari capture (capture/data/safari/latest.json, macOS runner), then run the behaviour probe for the Safari board and
# re-annotate. Writes leaderboard/data/safari_libraries.json. Honours STALE_LIBS like the other harnesses.
set -euo pipefail
LB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYBIN="${HARNESS_PYTHON:-$(dirname "$LB")/.venv/bin/python}"
[[ -x "$PYBIN" ]] || PYBIN="$(command -v python || command -v python3)"
CAPPY="${CAPTURE_PYTHON:-$PYBIN}"
[[ -f "$(dirname "$LB")/capture/data/safari/latest.json" ]] || { echo "no Safari capture yet"; exit 1; }
RUN="$LB/raw/safari-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$RUN/go" "$RUN/py" "$LB/bin"
echo "{\"started_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"endpoint\": \"https://tls.peet.ws/api/all\"}" > "$RUN/meta.json"
(cd "$LB/harness/gosafari" && go build -o "$LB/bin/gosafari" .) && (cd "$RUN/go" && "$LB/bin/gosafari") || echo "go Safari cases failed"
"$PYBIN" "$LB/harness/run_safari.py" "$RUN/py" || echo "python Safari cases failed"
"${BUILD_PYTHON:-$PYBIN}" "$LB/build_safari.py" "$RUN"
if [[ -x "$LB/bin/goprobe" ]] || (cd "$LB/harness/goprobe" && go build -o "$LB/bin/goprobe" .); then
  lib_arg=(); [[ -n "${STALE_LIBS:-}" ]] && lib_arg=(--library "$STALE_LIBS")
  "$CAPPY" "$LB/harness/probe.py" --board safari "${lib_arg[@]}" || echo "Safari behaviour probe failed"
  "${BUILD_PYTHON:-$PYBIN}" "$LB/build_safari.py" --annotate-only > /dev/null
fi
