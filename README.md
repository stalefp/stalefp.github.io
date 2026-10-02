# Stale

**Live site: https://stalefp.github.io**

Stale is a public reference for what real, branded Google Chrome sends on the wire (TLS ClientHello / JA4, HTTP/2
settings, QUIC / HTTP/3), and how far behind the popular Chrome-impersonation libraries are (curl_cffi, tls-client,
azuretls, uTLS, primp, rnet, noble-tls, ...), compared field by field.

## Layout

| path | what |
|---|---|
| `site/` | The static page (plain HTML/CSS/JS, no build). `site/data/` holds the JSON it reads. Deployed by `.github/workflows/pages.yml`. |
| `capture/` | Chrome capture pipeline: launches official stable Chrome against a local TLS/HTTP2/QUIC capture server and records the fingerprints. Schema: `capture/SCHEMA.md`. |
| `leaderboard/` | Library harness (Python + Go, built from source) and `build.py`, which diffs every library profile against the Chrome capture. |
| `.github/workflows/capture.yml` | Daily capture on Linux, Windows and macOS + leaderboard rebuild + data commit + Pages deploy. |

## How the data updates

Every day at 09:37 UTC (and on manual dispatch) `capture.yml`:

1. On `ubuntu-latest`, `windows-latest` and `macos-latest`: installs official stable Google Chrome from Google, generates
   a throwaway self-signed cert, runs `capture/lib/capture.py` against the local capture server, uploads the capture JSON.
2. On Ubuntu: `capture/merge_platforms.py` merges the per-OS captures (Linux stays the leaderboard reference in
   `capture/data/latest.json`; Windows/macOS go to `capture/data/platforms/`), `leaderboard/run.sh` rebuilds the Go
   harness from source and reruns every library profile, `site/sync.sh` copies the data into `site/data/`, and the
   result is committed to `main` by `github-actions[bot]`.
3. `pages.yml` redeploys the site.

If a platform's capture fails, its previous data is kept; a platform that has never been captured is shown as
"not captured yet". Nothing is filled in by guesswork.

Run locally: `capture/run_capture.sh` (Linux, see `capture/README.md`), `leaderboard/run.sh`, `site/sync.sh`, then
`cd site && python3 -m http.server`.
