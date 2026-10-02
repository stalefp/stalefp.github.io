#!/usr/bin/env bash
# Rerunnable branded-Chrome fingerprint capture. Usage:
#   ./run_capture.sh [--update] [capture.py options...]
#     --update   fetch the newest google-chrome-stable .deb from Google's official apt repo,
#                verify its SHA256 against the repo's Packages index, and extract it side-by-side
#                into /opt/google-chrome-stable/<version> (needs sudo; does not touch the system package)
#   capture.py options: --chrome PATH --modes headless,headed --seed-wait 180 --no-quic --no-relaunch
#                       --tcp-port 18543 --quic-port 18544 --out DIR --no-latest --label TEXT
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
UPDATE=0; ARGS=()
for a in "$@"; do if [[ "$a" == "--update" ]]; then UPDATE=1; else ARGS+=("$a"); fi; done

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -q aioquic hpack websockets zstandard
fi

if [[ $UPDATE == 1 ]]; then
  mkdir -p pkg
  # dl.google.com is canonical; dl-ssl.google.com is Google's alias for the same repo (used as fallback
  # because dl.google.com timed out from this box's egress on 2026-09-27).
  for base in https://dl.google.com https://dl-ssl.google.com; do
    if curl -sSf --max-time 60 -H 'Cache-Control: no-cache' -o pkg/Packages \
         "$base/linux/chrome-stable/deb/dists/stable/main/binary-amd64/Packages?nocache=$(date +%s)"; then REPO=$base; break; fi
  done
  [[ -n "${REPO:-}" ]] || { echo "could not reach Google's apt repo" >&2; exit 1; }
  read -r VER FN SHA < <(awk '/^Package: google-chrome-stable$/{p=1} p&&/^Version:/{v=$2} p&&/^Filename:/{f=$2} p&&/^SHA256:/{s=$2} p&&/^$/{print v,f,s; exit}' pkg/Packages)
  V="${VER%-*}"; DEST="/opt/google-chrome-stable/$V"
  echo "repo ($REPO) google-chrome-stable = $VER"
  if [[ ! -x "$DEST/opt/google/chrome/chrome" ]]; then
    curl -sSfL --max-time 900 -o "pkg/$(basename "$FN")" "$REPO/linux/chrome-stable/deb/$FN"
    echo "$SHA  pkg/$(basename "$FN")" | sha256sum -c -
    sudo mkdir -p "$DEST" && sudo dpkg-deb -x "pkg/$(basename "$FN")" "$DEST"
    sudo chmod 755 "$DEST" "$DEST/opt" "$DEST/opt/google" "$DEST/opt/google/chrome"
  fi
  sudo ln -sfn "$DEST" /opt/google-chrome-stable/current
fi

exec .venv/bin/python -W ignore lib/capture.py "${ARGS[@]}"
