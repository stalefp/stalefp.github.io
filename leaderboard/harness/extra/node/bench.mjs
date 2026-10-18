// node bench.mjs <outdir> chrome|firefox
// got-scraping: its own browser presets (header-generator picks the headers, got-scraping sets that browser's ciphers,
// sigalgs and curves on Node's TLS). CycleTLS has no named browser profiles: the cases use the README's documented
// Chrome example (ja4r + Chrome HTTP/2 fingerprint + UA) and Firefox example (ja3 + Firefox HTTP/2 fingerprint + UA), verbatim.
import fs from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const ECHO = "https://tls.peet.ws/api/all";
const [out, which] = process.argv.slice(2);
fs.mkdirSync(out, { recursive: true });

import { CYCLE } from "./cycle_profiles.mjs";
let failed = 0;
const save = (name, body) => { fs.writeFileSync(`${out}/${name}.json`, body); console.log(name, "ok"); };
// a failed case leaves <name>.error.txt so the leaderboard can say why it is not tested today
const fail = (name, msg) => { failed++; fs.writeFileSync(`${out}/${name}.error.txt`, String(msg).slice(0, 400)); console.error(name, "ERR", String(msg).slice(0, 300)); };

try {
  const { gotScraping } = await import("got-scraping");
  const r = await gotScraping({ url: ECHO, http2: true, timeout: { request: 30000 },
    headerGeneratorOptions: { browsers: [which], devices: ["desktop"], operatingSystems: ["linux"], locales: ["en-US"] } });
  save(`got-scraping_${which}`, r.body);
} catch (e) { fail(`got-scraping_${which}`, e.message); }

let cycle;
try {
  const initCycleTLS = require("cycletls");
  cycle = await initCycleTLS();
  const r = await cycle(ECHO, { ...CYCLE[which] }, "get");
  const body = await r.text();
  if (r.status !== 200) throw new Error(`HTTP ${r.status}: ${body.split("\n")[0]}`);
  save(`cycletls_${which}`, body);
} catch (e) { fail(`cycletls_${which}`, e.message); }
finally { if (cycle) await cycle.exit().catch(() => {}); }

const pkgv = (n) => JSON.parse(fs.readFileSync(new URL(`./node_modules/${n}/package.json`, import.meta.url))).version;
const v = { "npm:got-scraping": pkgv("got-scraping"), "npm:cycletls": pkgv("cycletls"), node: process.version };
fs.writeFileSync(`${out}/_node_versions.json`, JSON.stringify(v));
process.exit(failed ? 1 : 0);
