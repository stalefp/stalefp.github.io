> **SUPERSEDED (2026-10-01).** Moe's real schema landed as `capture/SCHEMA.md` (schema_version 1) and both adapters
> (`leaderboard/lib/adapter.py`, `adaptChromeReference()` in `site/js/app.js`) now read `capture/data/latest.json` in that
> layout. This file and `data/chrome_reference.assumed.json` / `build_reference.py` are kept for reference only and are
> no longer used by `run.sh`, `build.py` or the site. Notable differences from what was assumed: flat `configs[]` instead of
> `tls.fresh`, `0x`-prefixed code points, three real captured variants (default with ca34, `disable-TLSTrustAnchorIDs`,
> `finch-AddTLSServerHandshakePadding`) instead of a derived ca34 variant, QUIC/h3 per config, `current_stable` per platform.

# ASSUMED schema for `capture/data/latest.json` (stand-in until Moe's `SCHEMA.md` lands)

Status: **assumed**. `/workspace/tlsbench/capture/data/latest.json` and `SCHEMA.md` did not exist when this was
written (2026-09-27), so the leaderboard builds against the layout below. It was inferred from
`/workspace/chrome154-capture/ANSWER_KEY.md` and the raw TrackMe captures next to it.
`build_reference.py` writes a real file in this layout (`data/chrome_reference.assumed.json`) from the Chrome 154 capture.

**Switching to Moe's schema:** only two functions know this layout:
- `leaderboard/lib/adapter.py` → `adapt_chrome_reference(raw)` (used by `build.py`)
- `site/js/app.js` → `adaptChromeReference(raw)` (used by the page)

Rewrite those two to read Moe's fields and return the same internal shape; nothing else changes.
`run.sh` and `site/sync.sh` already prefer `capture/data/latest.json` automatically when it exists.

## Conventions
- Codepoints are lowercase 4-digit hex strings (`"0904"`, `"ca34"`, `"11ec"`), GREASE removed.
- `ciphers` and `extensions` are sorted (Chrome shuffles extension order per connection, so order carries no signal).
  `extensions` excludes SNI (`0000`) and ALPN (`0010`), as in JA4.
- `signature_algorithms`, `supported_groups`, `key_shares` keep wire order.
- Timestamps are ISO 8601 UTC. Missing / not captured = `null`.

## Layout
```jsonc
{
  "schema_version": "assumed-0.1",
  "assumed_schema": true,                       // absent or false in Moe's real file
  "browser": {
    "name": "Chrome", "version": "154.0.8037.57", "major": 154,
    "channel": "Stable",                        // Stable | Beta | Dev | Extended
    "build": "Chrome for Testing",              // or "Google Chrome" (branded)
    "branded": false, "platform": "linux64", "user_agent": "..."
  },
  "captured_at": "2026-09-26T22:45:16.000Z",
  "capture": {
    "server": "TrackMe ...", "flags": ["--disable-field-trial-config", "..."],
    "field_trial_config_disabled": true,
    "variations": null,                         // chrome://version variations list, if recorded
    "samples": 6, "cross_checked_with": "tcpdump + tshark ...", "source_files": ["..."]
  },
  "tls": {
    "fresh": {
      "ja4": "t13d1517h2_8daaf6152771_cb7bf5808d99",
      "ja4_r": "t13d1517h2_<ciphers>_<extensions>_<sigalgs>",
      "peetprint_hash": "...",
      "ciphers": ["002f", "..."],
      "extensions": ["0005", "000a", "...", "44cd", "ca34", "fe0d", "ff01"],
      "signature_algorithms": ["0904", "0905", "0906", "0403", "..."],   // ML-DSA first
      "supported_groups": ["11ec", "001d", "0017", "0018"],
      "key_shares": ["11ec", "001d"],             // X25519MLKEM768 + X25519
      "alpn": ["h2", "http/1.1"],
      "alps": { "codepoint": "44cd", "protocols": ["h2"] },
      "ech": "grease",                            // "grease" | "real" | null
      "cert_compression": ["brotli"],
      "trust_anchors": { "present": true, "extension": "ca34" },
      "supported_versions": ["TLS 1.3", "TLS 1.2"]
    },
    "resumed": {                                  // null if no resumed handshake was captured
      "ja4": "t13d1518h2_8daaf6152771_e2d80978ab2e",
      "ja4_r": "...", "extensions": ["...", "0029", "..."], "source": "..."
    }
  },
  "http2": {
    "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "settings": ["HEADER_TABLE_SIZE = 65536", "..."],
    "window_update": 15663105,
    "header_order": [":method", ":authority", ":scheme", ":path", "sec-ch-ua", "..."]
  },
  "http3": null,                                  // when captured: { "settings": {...}, "quic_transport_params": {...}, "ja4_quic": "..." }
  "capture_variants": [                           // optional: other observed variants of the same build
    { "id": "field_trial_config", "label": "...", "ja4_fresh": "...", "ja4_resumed": "...", "note": "...", "samples": 4 }
  ]
}
```

## History (for the site's "What changed" section)
Assumed: `capture/data/history/` holds one file per past capture in the same layout, plus
`capture/data/history/index.json`:
```json
{ "captures": [ { "file": "2026-09-26_154.0.8037.57.json", "chrome_version": "154.0.8037.57", "captured_at": "2026-09-26T22:45:16Z" } ] }
```
`site/sync.sh` copies that directory to `site/data/history/`. The page diffs `latest.json` against the newest
history entry captured before it. With no history the page shows an empty state.

## ca34 (population variant)
`tls.fresh.trust_anchors.present` records whether *this capture* sent `0xca34`. It is on by default since Chrome 141
but is behind the `TLSTrustAnchorIDs` feature flag that Finch can toggle, so both populations exist in the wild.
`build.py` derives the other population's JA4 by adding/removing `ca34` and recomputing JA4 (marked as derived).
