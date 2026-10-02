# Branded Chrome fingerprint capture (leaderboard reference)

Captures the TLS / HTTP2 / QUIC fingerprint of **branded Google Chrome stable** (not Chrome for Testing /
Chromium, which apply `fieldtrial_testing_config.json`) against a **local** capture server, records the
browser's variations (Finch) state, and writes a flat JSON for the leaderboard page.

## Run

```bash
cd capture
./run_capture.sh --update          # fetch+verify newest google-chrome-stable .deb, extract side-by-side, capture
./run_capture.sh                   # capture with whatever is at /opt/google-chrome-stable/current (or $CHROME_BIN)
./run_capture.sh --seed-wait 60 --modes headless --no-quic     # quick run
./run_capture.sh --chrome /opt/google/chrome/chrome --no-latest --label "old build"   # archival capture, keeps latest.json
```

Takes ~9 min by default (two 180 s seed waits). `--only default,finch-AddTLSServerHandshakePadding` limits configs. Needs: python3, openssl, Xvfb (headed mode), sudo only for `--update`.
The first run creates `.venv` (aioquic, hpack, websockets, zstandard).

Outputs
- `data/latest.json` – newest run (the page reads this). Field reference: `SCHEMA.md`.
- `data/chrome-<version>-<YYYY-MM-DD>.json` – versioned copy (same day reruns overwrite).
- `data/raw/chrome-<version>-<date>/events.json` – every ClientHello (raw hex + parse), every h2/h3 request with
  frames, launch args, chrome://version data; `*.chrome.log` – Chrome stderr per launch.
- `data/run-latest.log` – console log of the last run (if you redirect there).

## Automated per-OS captures (GitHub Actions)

`.github/workflows/capture.yml` runs daily (09:37 UTC) and on demand on `ubuntu-latest`, `windows-latest` and
`macos-latest`. Each job installs official stable Google Chrome (Linux: Google's `.deb`; macOS: Google's universal
`.dmg`, code signature checked; Windows: Google's enterprise MSI, Authenticode signature checked), deletes `certs/` so a
fresh throwaway self-signed cert is generated, runs `lib/capture.py` (same configs, same `SCHEMA.md` output plus a
top-level `platform`), and uploads `latest.json` as an artifact. OS adaptations in `lib/capture.py`: Chrome detection
per OS (Windows reads the version from the PE resource because `chrome.exe --version` prints nothing), headed mode uses
Xvfb only on Linux (Windows/macOS runners have a desktop session), `--use-mock-keychain` on macOS, process-tree kill via
`taskkill` on Windows, cert generation via the `cryptography` package instead of the openssl CLI.

`merge_platforms.py` then writes Linux to `data/latest.json` (the leaderboard reference; the previous file is archived to
`data/history/` when the version or a fingerprint field changed), Windows/macOS to `data/platforms/<os>.json`, and a
compact summary + comparison against Linux to `data/platforms/index.json` (the site's `data/platforms.json`).
An OS whose capture fails keeps its previous data; one that never succeeded stays `not_captured`.

## Chrome install (local runs)

`--update` reads `google-chrome-stable` from Google's official apt repo Packages index
(`dl.google.com/linux/chrome-stable/deb`, falling back to its alias `dl-ssl.google.com`), downloads the .deb,
checks its SHA256 against the index, and `dpkg-deb -x`'s it into `/opt/google-chrome-stable/<version>/` with a
`current` symlink. It deliberately does **not** upgrade the system `google-chrome-stable` package: on this box that
package is pinned (`apt-mark hold`, 151.0.7922.169 as of 2026-09-27) and other agents' desktops may rely on it.
The binary is the unmodified official build (`chrome --version` → `Google Chrome <ver> stable`).

## What is captured

For each browser launch a fresh temporary `--user-data-dir` is used, with
`--no-first-run --no-default-browser-check --password-store=basic --host-resolver-rules="MAP capture.test 127.0.0.1"
--ignore-certificate-errors-spki-list=<our cert> --remote-debugging-port=0` (+ `--headless=new` in headless mode).
Driving is done over the DevTools protocol:

1. navigate `https://capture.test:18543/fresh` → fresh TLS 1.3 ClientHello + HTTP/2 request;
   the server answers, sends GOAWAY and closes, so
2. navigate `/resumed` → new connection with a session ticket → resumed ClientHello (`pre_shared_key`).
3. open `chrome://version/?show-variations-cmd` → Variations Source, Command-line Variations, Active Variations.
4. after exit, inspect the profile for a variations seed (`VariationsSeedV2`, zstd; or Local State
   `variations_compressed_seed`) and string-scan it for TLS/QUIC-related study/feature names (e.g. `TLSTrustAnchorIDs`).

Server side (`lib/server.py`): the raw ClientHello bytes are peeked off the socket before the TLS handshake, parsed by
`lib/fp.py` (JA4 per FoxIO spec incl. GREASE removal from sigalgs, JA3, JA3n, full extension list, sig algs, groups,
key shares, ALPN/ALPS, ECH, trust anchors 0xca34, QUIC transport params). HTTP/2 frames are parsed by hand
(SETTINGS order/values, WINDOW_UPDATE, PRIORITY, HEADERS priority, HPACK-decoded header order → Akamai fingerprint).
QUIC: an aioquic HTTP/3 server on UDP 18544; Chrome is forced onto it with `--enable-quic
--origin-to-force-quic-on=capture.test:18544`; the ClientHello is taken from aioquic's TLS layer (hook), H3 SETTINGS
and header order from the H3 connection.

Configs (each headless and headed/Xvfb, each with a TCP launch and a separate QUIC launch):
`default`, `default-relaunched` (same profile relaunched after `--seed-wait` s so the downloaded seed is applied),
`disable-field-trial-config`, `disable-TLSTrustAnchorIDs` (`--disable-features=TLSTrustAnchorIDs`),
`finch-AddTLSServerHandshakePadding` (forces the PqcBandwidthExperiment population variant, adds 0x12e0).

The seed is also decoded (`lib/seedparse.py`): every study touching TLS/QUIC/HTTP/PQC features is listed in
`finch_network_studies` with its group weights and layer-based population share, and each config records which of those
groups it was assigned (`network_trial_groups`). Copies of the seeds are kept in `data/raw/.../seed-*.VariationsSeedV2` (zstd).

`latest.json` also records `current_stable` per platform from Google's VersionHistory API
(`versionhistory.googleapis.com/v1/chrome/platforms/<p>/channels/stable/versions/all/releases?filter=endtime=none`)
so the page can compute "versions behind".

Validation (2026-09-27): JA4 values from `lib/fp.py` were cross-checked against tshark 4.4 on a loopback pcap of a test
run: QUIC JA4 identical; TCP JA4 identical after dropping GREASE sigalgs from tshark's ja4_r (tshark keeps them,
the spec does not – see `/workspace/chrome154-capture/verify_ja4.py`). The hashing reproduces the Chrome for Testing
154 answer key from its JA4_r.

## Findings (2026-09-27, Chrome 154.0.8037.57 Linux stable)

- 0xca34 (trust anchors) is on in branded stable **without any server seed** (fresh profile, "Variations Source: default
  seed"), and the downloaded Linux-stable seed has no study mentioning TrustAnchor → on by default in this build.
  `--disable-field-trial-config` changes nothing on branded Chrome; `--disable-features=TLSTrustAnchorIDs` removes it (TCP and QUIC).
- Branded fresh/seeded JA4 = Chrome for Testing 154 `--disable-field-trial-config` answer key.
- The CfT *with* field-trial-config JA4 (extra 0x12e0) is **also a real branded population**: in one run
  (01:39 CT, `default-relaunched-headed`) the client was organically enrolled in `PqcBandwidthExperiment` /
  `Enabled_09000_20260922_gws_sortednames` and sent 0x12e0 with payload 0x2328 (= 9000, the group's
  `AddTLSServerHandshakePaddingBytes`); JA4 t13d1518h2_8daaf6152771_4980c97edce0 / resumed t13d1519h2_8daaf6152771_3d1b1b7bef36,
  QUIC q13d0313h3_55b375c5d22e_eb028bd37c08. The seed puts that study on ~6% of Linux stable clients (layer slice),
  six 1% groups (padding 0/6000/9000/12000/14000/16000). That run's files were overwritten by later runs; the
  `finch-AddTLSServerHandshakePadding` config reproduces the identical JA4s every run.
- Headless vs headed: identical TLS/H2/QUIC fingerprints; only the UA differs (`HeadlessChrome`).
- Archival: the apt-held system Chrome 151.0.7922.169 (`data/chrome-151.0.7922.169-2026-09-27.json`, label says ARCHIVAL)
  has no 0xca34 in any config (JA4 t13d1516h2_8daaf6152771_806a8c22fdea).

## Caveats

- **Extension order is randomized by Chrome per connection**; `extensions` and `ja3` are one sample. Use `ja4`,
  `ja3n`, `extensions_sorted` for comparisons.
- **Finch is per-client.** The seed is fetched on the first run within seconds, but only applied on the next launch
  (`default-relaunched-*`). Our seed reflects this machine (Linux, country per `seed.variations_country`, random
  client ID); other users can be in other groups. The seed scan is a plain string search of the protobuf, not a parse.
- The first launch of a fresh profile runs with "Variations Source: default seed" (no server seed applied yet).
- Branded Chrome talks to Google on its own (variations seed, component updater, etc.). That traffic is not blocked;
  our capture only connects Chrome to `capture.test` → 127.0.0.1.
- Local server ≠ real site: no HTTPS RR / real ECH configs / Alt-Svc, so Chrome sends GREASE ECH and only uses QUIC
  because it is forced. The self-signed cert is accepted via `--ignore-certificate-errors-spki-list` (no ClientHello impact).
- Resumed captures depend on our server issuing tickets (OpenSSL / aioquic); the resumed QUIC hello also carries early_data.
- Headless UA says `HeadlessChrome`; TLS/H2 are compared per mode in `notes`.
- Local runs capture Linux x86_64 only; Windows/macOS come from the GitHub Actions runners (see above), which can be
  mid-rollout at a different version than Linux. Runner captures reflect GitHub's datacenter network/country for Finch.
