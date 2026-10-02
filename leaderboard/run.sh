#!/usr/bin/env bash
# Regenerate leaderboard/data/libraries.json with ONE command.
#
#   leaderboard/run.sh              re-run the existing harness live (bench.py cases, gobench, goresume_raw)
#                                   against https://tls.peet.ws/api/all, plus the HTTP/3 run (harness/run_h3.py:
#                                   each HTTP/3-capable profile against Moe's local aioquic capture endpoint on UDP 28544),
#                                   save raw output to leaderboard/raw/<run>/, then build data/libraries.json
#   leaderboard/run.sh --no-rerun   skip the live run; build from the newest raw captures
#                                   (falls back to tlsbench/results.json + tlsbench/gobench/out from 2026-09-26)
#
# Per case, the newest available capture wins; a failed live case falls back to the previous capture and
# the JSON records which file and date each value came from.
set -euo pipefail
LB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TB="$(dirname "$LB")"
# Interpreter with the harness libraries (curl_cffi, primp, rnet, noble-tls, tls-client; see requirements.txt) and the
# capture deps (aioquic, ...). Defaults to the original box layout; CI sets HARNESS_PYTHON / CAPTURE_PYTHON.
PYBIN="${HARNESS_PYTHON:-$TB/.venv/bin/python}"
CAPPY="${CAPTURE_PYTHON:-$TB/capture/.venv/bin/python}"
export HARNESS_PYTHON="$PYBIN"

# Chrome reference: Moe's pipeline output (capture/data/latest.json, capture/SCHEMA.md). The assumed-schema stand-in
# (build_reference.py / ASSUMED_SCHEMA.md) is superseded and no longer used.
if [[ -f "$TB/capture/data/latest.json" ]]; then
  echo "[ref] using capture/data/latest.json ($(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["browser"], d["version"], d["captured_at"])' "$TB/capture/data/latest.json"))"
else
  echo "[ref] capture/data/latest.json not found: run capture/run_capture.sh first" >&2; exit 1
fi

if [[ "${1:-}" != "--no-rerun" ]]; then
  RUN="$LB/raw/$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$RUN/py" "$RUN/go" "$RUN/resume" "$LB/bin"
  STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[harness] run dir: $RUN"
  (cd "$LB/harness/gobench" && go build -o "$LB/bin/gobench" .)
  (cd "$LB/harness/goresume_raw" && go build -o "$LB/bin/goresume_raw" .)
  (cd "$LB/harness/h3probe" && GOFLAGS=-mod=mod go build -o "$LB/bin/h3probe" .)
  echo "[harness] python cases (bench.py)";   "$PYBIN" "$LB/harness/run_python.py" "$RUN/py" || echo "python harness failed"
  echo "[harness] go cases (gobench)";        (cd "$RUN/go" && "$LB/bin/gobench") || echo "gobench failed"
  echo "[harness] resumption (goresume_raw)"; "$LB/bin/goresume_raw" "$RUN/resume" | tee "$RUN/resume/_stdout.txt" || echo "goresume failed"
  echo "[harness] HTTP/3 (run_h3.py, local QUIC endpoint)"; "$CAPPY" "$LB/harness/run_h3.py" "$RUN/h3" || echo "HTTP/3 harness failed"
  "$PYBIN" - "$RUN" "$STARTED" "$LB/harness/gobench/go.mod" <<'PY'
import json, re, sys, importlib.metadata as md, datetime as dt
run, started, gomod = sys.argv[1:4]
v = {}
for d in ("curl_cffi", "primp", "rnet", "noble-tls", "tls-client"):
    try: v["py:" + d] = md.version(d)
    except Exception: pass
for line in open(gomod):
    m = re.match(r"\s*(github\.com/\S+)\s+(v\S+)", line)
    if m: v["go:" + m.group(1).lower()] = m.group(2)
json.dump(dict(started_at=started, finished_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               endpoint="https://tls.peet.ws/api/all", h3_endpoint="local capture/lib/server.py QUICServer, UDP 28544", versions=v), open(run + "/meta.json", "w"), indent=1)
PY
fi

"${BUILD_PYTHON:-python3}" "$LB/build.py"
