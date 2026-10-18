#!/usr/bin/env bash
# Chrome-for-Android leaderboard: run the libraries' Android Chrome profiles against the TLS echo endpoint and grade them
# against the real Chrome for Android capture (capture/data/platforms/android.json; only when its version was verified).
# Writes leaderboard/data/android_libraries.json. Honours STALE_LIBS like the other harnesses.
set -euo pipefail
LB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYBIN="${HARNESS_PYTHON:-$(dirname "$LB")/.venv/bin/python}"
[[ -x "$PYBIN" ]] || PYBIN="$(command -v python || command -v python3)"
[[ -f "$(dirname "$LB")/capture/data/platforms/android.json" ]] || { echo "no Android capture yet"; exit 0; }
RUN="$LB/raw/android-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$RUN/py"
echo "{\"started_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"endpoint\": \"https://tls.peet.ws/api/all\"}" > "$RUN/meta.json"
"$PYBIN" "$LB/harness/run_android.py" "$RUN/py" || echo "python Android cases failed"
"${BUILD_PYTHON:-$PYBIN}" "$LB/build_android.py" "$RUN"
