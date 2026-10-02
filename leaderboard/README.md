# Leaderboard runner

One command regenerates `data/libraries.json`:

```bash
leaderboard/run.sh              # live re-run of the harness (TLS/H2 + HTTP/3), then build
leaderboard/run.sh --no-rerun   # build only, from the newest raw captures already on disk
```

What `run.sh` does:
1. **Chrome reference.** `capture/data/latest.json` from Moe's branded-Chrome capture (`capture/SCHEMA.md`). Required;
   the old assumed-schema stand-in (`ASSUMED_SCHEMA.md`, `build_reference.py`, `data/chrome_reference.assumed.json`) is
   superseded and kept for reference only.
2. **Harness (live).**
   - TLS/HTTP/2 against `https://tls.peet.ws/api/all`: `harness/run_python.py` (runs `harness/bench.py`'s cases via AST),
     `harness/gobench` (built from source), `harness/goresume_raw` (resumption test).
   - HTTP/3: `harness/run_h3.py` (run with `capture/.venv/bin/python`) starts Moe's own capture endpoint code
     (`capture/lib/server.py` `QUICServer` + `capture/lib/fp.py`, the same endpoint that recorded Chrome's QUIC JA4 and h3
     SETTINGS) on UDP **28544** (Moe's `run_capture.sh` uses 18543/18544, so the two never collide), then makes one real
     HTTP/3 request per HTTP/3-capable profile: `harness/h3probe` (Go: tls-client with `WithProtocolRacing`, azuretls
     with `ForceHTTP3`) and `harness/h3_python.py` (curl_cffi `http_version="v3only"`, noble-tls `protocol_racing`).
   - Raw output: `raw/<UTC timestamp>/{py,go/out,resume,h3}/*.json` + `meta.json`.
3. **Build.** `build.py` diffs every capture field by field against **each** real Chrome variant and writes `data/libraries.json`.

Files: `lib/fingerprint.py` (normalization, JA4), `lib/adapter.py` (**the only Python that knows the latest.json layout**),
`build.py` (diff, verdicts, HTTP/3, versions behind).

## Chrome variants (all three are real captures in latest.json)
| id | latest.json config | what |
|---|---|---|
| `default` | `reference_config` (`default-headed`) | branded Chrome, fresh profile, no flags; includes `ca34`. **Verdict basis.** |
| `no_ca34` | `disable-TLSTrustAnchorIDs-<mode>` | `--disable-features=TLSTrustAnchorIDs`. No population figure exists in latest.json. |
| `pq` | `finch-AddTLSServerHandshakePadding-<mode>` | Finch study `PqcBandwidthExperiment`, adds `0x12e0`. Population = sum of `share_of_population` of the enabling groups in `finch_network_studies` (0.06 of Linux stable on 2026-09-27). |

## Verdict rules (in `build.py`)
Counted fields: cipher suites, extension set (incl. ca34 / 0x12e0; ALPS listed separately), signature algorithms,
supported groups, key shares, ALPS codepoint, certificate compression, HTTP/2 Akamai fingerprint.
- `exact`: 0 counted fields differ from the **default** fingerprint.
- `exact_variant` ("Exact, less common variant"): 0 differ from `no_ca34` or `pq`, but not from the default.
- `close`: 1 differs from the default. `behind`: 2+ differ from the default.
Per-variant JA4 / field / resumed-JA4 / QUIC-JA4 matches are in `matches.variants.<id>`. Header order, resumption and HTTP/3 are informational.

**HTTP/3** per library: `http3.status` = `tested` (with `ja4`, `h3_settings`, `ja4_matches` per variant, field `diff`
vs Chrome's default QUIC hello + transport params + SETTINGS; `summary` = match | variant_match | mismatch |
settings_not_observed), `no_support` (reason), `failed`, or `not_tested`.

**Versions behind**: per platform (linux/win/mac) = major of `current_stable.<p>.highest_full_rollout` minus the major in the
profile name. Newer majors that are only partially rolled out (e.g. 155 at 0.5% on Windows/Mac) are listed, not counted.

Python: `HARNESS_PYTHON` (interpreter with `requirements.txt` installed) and `CAPTURE_PYTHON` (with `../capture/requirements.txt`)
can be the same interpreter; the daily GitHub Actions job does exactly that and builds the Go binaries from source.
Library versions are pinned in `requirements.txt` / the Go `go.mod` files; bump them deliberately.

After regenerating, run `../site/sync.sh` to copy the data into the site.
