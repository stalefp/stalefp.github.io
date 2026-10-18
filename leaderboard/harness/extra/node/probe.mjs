// Behaviour probe adapter for the Node libraries (leaderboard/harness/probe.py):
//   node probe.mjs <library> <profile> <browser> <url> <n> <headers-json>
// n GETs on ONE client against the local capture server (which closes every connection), with the given headers in the
// given order through each library's own option. Prints {ok, done, error} as the last line.
import { createRequire } from "node:module";
import { CYCLE } from "./cycle_profiles.mjs";
const require = createRequire(import.meta.url);
const [lib, profile, browser, url, n, hjson] = process.argv.slice(2);
const hdrs = JSON.parse(hjson);
const obj = Object.fromEntries(hdrs);   // insertion order = the browser's order
let done = 0, cycle;
try {
  if (lib === "got-scraping") {
    const { gotScraping } = await import("got-scraping");
    // one got instance = one agent; our headers exactly (header generator off), certificate check off for the local cert
    const client = gotScraping.extend({ http2: true, useHeaderGenerator: false, https: { rejectUnauthorized: false }, timeout: { request: 20000 } });
    // the capture server closes each connection after one response: wait for the close so the next request opens a new one
    for (let i = 0; i < +n; i++) { await client({ url: `${url}&i=${i}`, headers: obj, retry: { limit: 2 } }); done++; await new Promise((r) => setTimeout(r, 400)); }
  } else if (lib === "CycleTLS") {
    const initCycleTLS = require("cycletls");
    cycle = await initCycleTLS();
    const cfg = CYCLE[browser];
    if (!cfg) throw new Error(`no CycleTLS ${browser} example`);
    for (let i = 0; i < +n; i++) {
      const r = await cycle(`${url}&i=${i}`, { ...cfg, headers: obj, headerOrder: hdrs.map((h) => h[0]), insecureSkipVerify: true }, "get");
      await r.text(); done++;
    }
  } else throw new Error(`no node adapter for ${lib}`);
  console.log(JSON.stringify({ ok: true, done }));
} catch (e) {
  console.log(JSON.stringify({ ok: done > 0, done, error: String(e && e.message || e).slice(0, 300) }));
} finally {
  if (cycle) await cycle.exit().catch(() => {});
  process.exit(0);
}
