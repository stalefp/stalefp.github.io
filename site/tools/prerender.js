// Pre-render the main page at deploy time: loads <site>/index.html in headless Chrome, waits until js/app.js has filled in
// the data (it sets <html data-rendered="1">), and writes the rendered HTML back, so the deployed page shows the real
// numbers (Chrome version, JA4/HTTP/2/HTTP/3 strings, experiment shares, leaderboard rows, summary) without JS and without
// a "Loading…" flash. js/app.js still runs on top of it and rebuilds the same nodes with interactivity.
// Writes nothing unless the rendered page passes the checks below, so a failure leaves the plain page in place.
// Usage: node --experimental-websocket site/tools/prerender.js <site dir> [page path, default index.html]
const { spawn } = require("child_process");
const fs = require("fs"), path = require("path"), os = require("os"), http = require("http");
const DIR = path.resolve(process.argv[2] || "_site");
const PAGE = process.argv[3] || "index.html";
const CHROME = process.env.CHROME || "google-chrome";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png" };

(async () => {
  const server = http.createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    if (p.endsWith("/")) p += "index.html";
    const f = path.join(DIR, p);
    if (!f.startsWith(DIR) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "content-type": TYPES[path.extname(f)] || "application/octet-stream" });
    fs.createReadStream(f).pipe(res);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/${PAGE === "index.html" ? "" : PAGE}`;
  const udd = fs.mkdtempSync(path.join(os.tmpdir(), "stale-prerender-"));
  const chrome = spawn(CHROME, ["--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-gpu",
    `--user-data-dir=${udd}`, "--remote-debugging-port=0", "about:blank"], { stdio: "ignore" });
  const done = (code) => { try { chrome.kill("SIGKILL"); } catch {} server.close(); fs.rmSync(udd, { recursive: true, force: true }); process.exit(code); };
  try {
    let port;
    for (let i = 0; i < 100 && !port; i++) { await sleep(100); try { port = fs.readFileSync(path.join(udd, "DevToolsActivePort"), "utf8").split("\n")[0]; } catch {} }
    if (!port) throw new Error("Chrome didn't start");
    const ver = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
    const ws = new WebSocket(ver.webSocketDebuggerUrl);
    await new Promise((r) => (ws.onopen = r));
    let id = 0; const pending = new Map(); const errors = [];
    ws.onmessage = (m) => { const j = JSON.parse(m.data); if (j.id && pending.has(j.id)) { pending.get(j.id)(j); pending.delete(j.id); }
      else if (j.method === "Runtime.exceptionThrown") errors.push(j.params.exceptionDetails.exception?.description || j.params.exceptionDetails.text); };
    const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const i = ++id; pending.set(i, (j) => (j.error ? rej(new Error(method + ": " + j.error.message)) : res(j.result))); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });
    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    await send("Runtime.enable", {}, sessionId);
    // Dates are written in UTC and en-US; visitors' browsers re-render them in their own zone and locale.
    await send("Emulation.setTimezoneOverride", { timezoneId: "UTC" }, sessionId);
    await send("Emulation.setLocaleOverride", { locale: "en-US" }, sessionId);
    await send("Page.navigate", { url }, sessionId);
    let ready = false;
    for (let i = 0; i < 300 && !ready; i++) {
      await sleep(100);
      try { ready = (await send("Runtime.evaluate", { returnByValue: true, expression: "document.documentElement.getAttribute('data-rendered') === '1'" }, sessionId)).result.value; } catch {}
    }
    if (!ready) throw new Error("page never finished rendering (no data-rendered after 30s)");
    const { result } = await send("Runtime.evaluate", { returnByValue: true, expression: `(() => {
      const d = document, q = (s) => d.querySelector(s);
      const problems = [];
      if (q("#load-error") && !q("#load-error").hidden) problems.push("load error: " + q("#load-error").textContent);
      const unbound = [...d.querySelectorAll("[data-bind]")].filter((n) => n.textContent.trim() === "…").map((n) => n.dataset.bind);
      if (unbound.length) problems.push("unfilled: " + unbound.join(", "));
      if (d.body.dataset.page === "chrome" && !d.querySelectorAll("#lb .row").length) problems.push("no leaderboard rows");
      const loading = [...d.querySelectorAll("main p, main td")].filter((n) => n.textContent.trim() === "Loading…" && !n.closest("[hidden]")).length;
      if (loading) problems.push(loading + " Loading… placeholders left");
      // Snapshot clean-up: default state for every visitor (closed rows, no filter), no relative "N minutes ago" text frozen in.
      d.documentElement.removeAttribute("data-rendered");
      d.querySelectorAll("details[open]").forEach((n) => n.removeAttribute("open"));
      const lu = q("#last-updated"); if (lu) { lu.hidden = true; lu.textContent = ""; }
      const t = q("#toast"); if (t) { t.className = ""; t.textContent = ""; }
      d.documentElement.setAttribute("data-prerendered", new Date().toISOString());
      return { problems, html: "<!doctype html>\\n" + d.documentElement.outerHTML + "\\n" };
    })()` }, sessionId);
    const { problems, html } = result.value;
    if (errors.length) problems.push(...errors.map((e) => "exception: " + e));
    if (problems.length) { console.error("prerender: not writing " + PAGE + ":\n  " + problems.join("\n  ")); ws.close(); return done(1); }
    const out = path.join(DIR, PAGE);
    fs.writeFileSync(out + ".tmp", html); fs.renameSync(out + ".tmp", out);
    console.log(`prerender: wrote ${out} (${html.length} bytes)`);
    ws.close(); done(0);
  } catch (e) { console.error("prerender: " + e.message); done(1); }
})();
