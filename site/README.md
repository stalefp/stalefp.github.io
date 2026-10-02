# Stale: static site

Plain HTML/CSS/vanilla JS. No build step, no dependencies. Deployed to GitHub Pages by `.github/workflows/pages.yml`
(index.html, css/, js/, data/ only; `tools/` isn't deployed).

```bash
leaderboard/run.sh     # refresh leaderboard data (optional)
site/sync.sh           # copy data/latest.json, data/libraries.json, data/history/, data/platforms.json into site/data
cd site && python3 -m http.server 8765    # open http://127.0.0.1:8765/
node --experimental-websocket tools/verify.js http://127.0.0.1:8765/   # headless check + screenshots
```

- `js/app.js` → `adaptChromeReference()` is the only function that knows the `latest.json` layout. It implements
  Moe's `capture/SCHEMA.md` (schema_version 1) and is the twin of `leaderboard/lib/adapter.py`; change both together.
- `data/history/` comes from `capture/data/history/` (index.json + past latest.json copies). "What changed" diffs
  latest.json against the newest history entry captured before it.
- Copy lives in `index.html`, marked with `<!-- COPY: Nya -->`. Drafts 1-2 and pass 3 (`../copy/PASS3.md`: legend,
  three-fingerprint caveat, PQ/HTTP/3 labels + tooltips, versions-behind tooltip) are placed; every value is bound
  from data (`data-bind`), `tools/verify.js` fails on unbound nodes or literal `{placeholders}`.
- `data/platforms.json` (from `capture/data/platforms/index.json`) feeds the "Chrome on Linux, Windows and macOS" card;
  a platform without a capture shows a "Not captured yet" note, never Linux values.
- The early-access form posts to FormSubmit via `fetch` (`FORMSUBMIT_ENDPOINT` in `js/app.js`).
