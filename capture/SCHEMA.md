# `data/latest.json` schema (schema_version 1)

Produced by `run_capture.sh` → `lib/capture.py`. `latest.json` is always the newest run; each run is also
saved as `data/chrome-<version>-<YYYY-MM-DD>.json` (same content). Raw per-connection events (including the
raw ClientHello hex for every connection) are in `data/raw/chrome-<version>-<date>/events.json`.

Conventions
- TLS code points are strings `"0x%04x"` (e.g. `"0xca34"`). Human names are in the top-level `code_names` lookup.
- **GREASE values are removed** from every list (ciphers, extensions, sig_algs, groups, key_shares, versions).
- Anything that could not be captured is `null` (scalars/objects) or `[]` (lists), with a message in the config's `notes`.
- Times are ISO 8601 with offset, America/Chicago.

## Top level

| field | type | meaning |
|---|---|---|
| `schema_version` | int | Bumped on breaking changes. |
| `label` | string/null | Optional free text (e.g. archival capture of an old build). |
| `browser` | string | Product name from `chrome --version`, e.g. `"Google Chrome"` (branded). |
| `version` | string | Full version, e.g. `"154.0.8037.57"`. |
| `channel` | string | From `CHROME_VERSION_EXTRA`, e.g. `"stable"`. |
| `os` | string | Capture machine OS, e.g. `"Linux x86_64 (Debian GNU/Linux 13 (trixie), kernel …)"`. |
| `platform` | string | `linux`, `windows` or `macos` (added for the per-OS captures; absent in captures before 2026-10-02 = linux). |
| `captured_at` | string | Start time of the run, ISO 8601 with America/Chicago offset. |
| `chrome_path` | string | Binary used. |
| `chrome_version_string` | string | Raw `chrome --version` output. |
| `capture_server` | string | Description of the local capture endpoint. |
| `current_stable` | object | Per platform (`linux`, `win`, `mac`, `android`, `ios`) from Google's official VersionHistory API (`filter=endtime=none`), fetched at capture time. See below. |
| `is_current_linux_stable` | bool/null | `version == current_stable.linux.newest`. |
| `is_current_platform_stable` | bool/null | `version == current_stable.<own platform>.newest` (win/mac/linux). |
| `ci_run` | string/null | GitHub Actions run URL when captured in CI. |
| `reference_config` | string/null | Name of the config the leaderboard should treat as "real Chrome": first of `default-headed`, `default-headless`, `default-relaunched-headed` that has a JA4. The fresh-profile config is used because the relaunched one gets a *random* Finch group assignment (e.g. ~6% land in a group that adds 0x12e0); population variants are listed in `finch_network_studies` and captured deterministically as `finch-*` configs. |
| `finch_network_studies` | array/null | Studies from the downloaded variations seed whose experiments enable/disable a network/TLS/QUIC/PQC-related feature. See below. `null` if no seed could be parsed. |
| `configs` | array | One entry per (flag config × mode). See below. |
| `baseline_comparisons` | array | Comparison of each config with files in `baselines/` (Chrome for Testing 154 answer key). See below. |
| `code_names` | object | `{extensions, groups, sig_algs, ciphers}`: maps `"0x…"` → name. |
| `notes` | string[] | Run-level caveats (headless vs headed diffs, stale version warning, extension-order randomization, …). |

### `current_stable.<platform>`

| field | type | meaning |
|---|---|---|
| `newest` | string/null | Highest version currently serving on stable for that platform (may be a tiny % rollout). |
| `highest_full_rollout` | string/null | Highest version with `fraction == 1` in its fraction group (null if none). |
| `releases[]` | array | `{version, fraction, fraction_group, serving_since, rollout_tags[]}` as reported by the API. Fractions are per `fraction_group`; several groups can coexist (e.g. Win/Mac staged rollouts). |
| `error` | string | Present only if the API call failed. |

"Versions behind" for the page: compare a library's target version against `current_stable.linux.newest`
(or `win`/`mac` for those populations). Win/Mac/Android are often mid-rollout, so several versions are "current" at once.

### `configs[]`

Names are `<base_config>-<mode>`. Base configs:
- `default` – branded Chrome, fresh temporary profile, no extra flags.
- `default-relaunched` – same profile as `default`, relaunched after Chrome ran for `--seed-wait` seconds (so the downloaded Finch/variations seed is applied). Closest to a real user.
- `disable-field-trial-config` – `--disable-field-trial-config`.
- `disable-TLSTrustAnchorIDs` – `--disable-features=TLSTrustAnchorIDs`.
- `finch-AddTLSServerHandshakePadding` – forces the Finch population variant `PqcBandwidthExperiment`
  (`--enable-features=AddTLSServerHandshakePadding:AddTLSServerHandshakePaddingBytes/9000`), which adds extension 0x12e0.
  Reproduces exactly the JA4 an organically-enrolled client produced (observed 2026-09-27 01:39 CT).

Modes: `headless` (`--headless=new`) and `headed` (real window on Xvfb).

| field | type | meaning |
|---|---|---|
| `name` | string | e.g. `"default-headed"`. |
| `base_config` | string | One of the base configs above. |
| `mode` | string | `"headless"` or `"headed"`. |
| `flags` | string[] | Config-specific flags (the common harness flags are in the raw events' `launch_args`). |
| `relaunch_of` | string/null | For `default-relaunched-*`: the config whose profile was reused. |
| `ja4` | string/null | JA4 of the first fresh (no PSK) TLS-over-TCP ClientHello. |
| `ja4_resumed` | string/null | JA4 of the first resumed ClientHello (has `pre_shared_key` 0x0029). |
| `ja4_r`, `ja4_r_resumed` | string/null | Raw (unhashed) JA4 strings. |
| `ja3` | string/null | JA3 MD5 of the fresh ClientHello. **Not stable across connections** (Chrome shuffles extension order). |
| `ja3_string` | string/null | JA3 pre-hash string. |
| `ja3n` | string/null | JA3 with extensions sorted (stable). |
| `extensions` | string[] | Fresh ClientHello extensions in on-the-wire order, GREASE removed (order is random per connection). |
| `extensions_resumed` | string[] | Same for the resumed ClientHello. |
| `extensions_sorted` | string[] | `extensions` sorted (stable). |
| `has_trust_anchors` | bool/null | Fresh ClientHello contains 0xca34 (trust_anchors / `TLSTrustAnchorIDs`). |
| `has_trust_anchors_resumed` | bool/null | Same for the resumed ClientHello. |
| `trust_anchors_len` | int/null | Byte length of the 0xca34 payload. |
| `ciphers` | string[] | Cipher suites in order. |
| `sig_algs` | string[] | signature_algorithms in order. |
| `groups` | string[] | supported_groups in order. |
| `key_shares` | object[] | `{group, name, key_length}` in order. |
| `tls_versions` | string[] | supported_versions. |
| `alpn` | string[] | ALPN protocols, e.g. `["h2","http/1.1"]`. |
| `alps` | string[] | ALPS (application_settings) protocols. |
| `alps_codepoint` | string/null | `"0x44cd"` (new) or `"0x4469"` (old). |
| `has_ech` | bool/null | encrypted_client_hello (0xfe0d) present (GREASE ECH against our server). |
| `cert_compression` | int[] | compress_certificate algorithms (2 = brotli). |
| `resumption_accepted_by_server` | bool | Our server accepted a PSK on some connection (informational). |
| `h2_akamai` | string/null | Akamai HTTP/2 fingerprint `SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order`. |
| `h2_settings` | object/null | SETTINGS id → value, in the order sent (JSON object key order). |
| `h2_window_update` | int/null | First connection-level WINDOW_UPDATE increment. |
| `h2_priority_frames` | string[]/null | Standalone PRIORITY frames (`stream:excl:dep:weight`); empty for modern Chrome. |
| `h2_headers_priority` | object/null | Priority fields carried in the HEADERS frame `{exclusive, depends_on, weight}`. |
| `http_version` | string/null | Protocol of the navigation request (`h2`). |
| `header_order` | string[] | Header names of the top-level navigation request, in order, pseudo-headers included. |
| `user_agent` | string/null | `user-agent` header value (headless shows `HeadlessChrome`). |
| `sec_ch_ua` | string/null | `sec-ch-ua` header value. |
| `variations_source` | string/null | chrome://version "Variations Source" (e.g. `default seed`, `variations server`, `command line or about flags`). |
| `command_line_variations` | string/null | chrome://version "Command-line Variations" (the effective field-trial state as flags). |
| `active_variations_count` | int/null | Number of active variation IDs. |
| `active_variations` | string[]/null | chrome://version "Active Variations" (hashed `trial-group` IDs). |
| `network_trial_groups` | object/null | For each study in `finch_network_studies`: the group this client was assigned (from Command-line Variations), or `null` = not enrolled. |
| `seed_present_at_exit` | bool | A variations seed existed in the profile when Chrome exited. |
| `seed` | object | From the profile dir after exit: `{seed_file, seed_file_bytes, local_state_seed_bytes, seed_serial_number, variations_country, last_fetch_time, seed_present, seed_decompressed_bytes, seed_mentions_TLSTrustAnchorIDs, seed_scan_error}`. After a relaunch the stored seed file is tiny (not a full seed) and is not scanned (`seed_scan_error` explains). |
| `quic` | object/null | QUIC ClientHello capture (separate launch with `--enable-quic --origin-to-force-quic-on`). `null` if not captured. See below. |
| `notes` | string[] | Per-config caveats / errors. |

### `configs[].quic`

| field | type | meaning |
|---|---|---|
| `flags` | string[] | QUIC-forcing flags added for this launch. |
| `ja4` / `ja4_resumed` | string/null | JA4 with `q` prefix for the fresh / resumed (PSK) QUIC ClientHello. |
| `ja4_r` | string | Raw JA4. |
| `extensions`, `ciphers`, `sig_algs`, `groups`, `key_shares`, `alpn`, `alps` | | As above, for the QUIC ClientHello. |
| `has_trust_anchors` | bool | 0xca34 present in the QUIC ClientHello. |
| `transport_params` | object[] | QUIC transport parameters in order: `{id, name, len, value?|hex?}` (GREASE params named `grease`). |
| `h3_settings` | object/null | HTTP/3 SETTINGS id (decimal string) → value received from Chrome, GREASE ids removed. |
| `h3_grease_settings` | int/null | Number of GREASE SETTINGS ids Chrome sent (value random per connection). |
| `http_version` | string/null | `h3` when the request arrived over HTTP/3. |
| `header_order` | string[] | HTTP/3 request header order. |
| `notes` | string[] | QUIC-specific caveats. |

### `finch_network_studies[]`

Decoded with a minimal protobuf reader (`lib/seedparse.py`) from the seed Chrome downloaded during the run.

| field | type | meaning |
|---|---|---|
| `study` | string | Study (trial) name, e.g. `PqcBandwidthExperiment`. |
| `features` | string[] | Matching feature names, e.g. `AddTLSServerHandshakePadding`. |
| `extension_hint` | string[]/null | TLS extensions the feature is known to add (`0x12e0` for AddTLSServerHandshakePadding, `0xca34` for TLSTrustAnchorIDs). |
| `filter` | object | `{min_version, max_version, channel[], platform[], country[]}` as present. |
| `layer` | object/null | `{layer_id, member_ids[]}` – studies limited to a slice of a seed layer. |
| `population_share` | number/null | Approximate fraction of eligible clients that can enter the study (layer slots / total slots; 1.0 if no layer). |
| `groups[]` | array | `{name, share, share_of_population, enable_features[], disable_features[], params{}}`; `share` = weight within the study, `share_of_population` = `population_share × share`. |

### `baseline_comparisons[]`

`{baseline, baseline_version, baseline_file, same_version, matches: {<config name>: {ja4, ja4_resumed, h2_akamai}}}` –
booleans, meaningful only when `same_version` is true.
