# Extra libraries (wreq, got-scraping, hrequests, CycleTLS)

`run_extra.sh <outdir> chrome|firefox` runs one case per library against https://tls.peet.ws/api/all and saves the raw
echo JSON (`<lib>_<profile>.json`), or `<name>.error.txt` when a case fails. `leaderboard/run.sh` (Chrome) and
`leaderboard/run_firefox.sh` (Firefox) call it; `build.py` / `build_firefox.py` grade the results like every other row.

| Library | Pin | Chrome case | Firefox case |
|---|---|---|---|
| wreq (Rust) | `wreq =0.16.1`, `wreq-util =0.2.0` (`wreq/Cargo.toml`, `Cargo.lock`) | `Chrome149` (newest in wreq-util 0.2.0), platform Linux | `Firefox151` (newest) |
| got-scraping (Node) | `4.2.2` (`node/package-lock.json`) | `browsers: ["chrome"]`, linux desktop | `browsers: ["firefox"]` |
| hrequests (Python) | `0.9.2` (`requirements.txt`) | `chrome` version 131 (newest it ships) | `firefox` version 132 (newest) |
| CycleTLS (Node) | `2.0.5` (`node/package-lock.json`) | README's Chrome example (ja4r + Chrome HTTP/2 + Chrome 138 UA) | README's Firefox example (ja3 + Firefox HTTP/2 + Firefox 141 UA) |

CycleTLS ships no named browser profiles, so its rows use the fingerprints its README documents, copied verbatim into
`node/bench.mjs`. wreq needs Rust >= 1.98, cmake and libclang to build (BoringSSL). hrequests downloads its Go bridge
library from its own GitHub releases on first use and does not verify a checksum; the bridge file name is recorded in
the run's versions.
