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

const CYCLE = {
  chrome: { // README "Chrome JA4R fingerprint" + README HTTP/2 table "Chrome" + README Chrome UserAgent
    ja4r: "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0000,0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
    http2Fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
  },
  firefox: { // README "Firefox HTTP/2 fingerprint" example
    http2Fingerprint: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
    ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0",
    userAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
  },
};
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
