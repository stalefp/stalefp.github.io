// Headless-Chrome check: renders the site at desktop/mobile widths (+ dark mode), saves full-page screenshots,
// and fails on console errors, uncaught exceptions, failed requests, unbound data-bind nodes or literal {placeholders}.
// Usage: node --experimental-websocket site/tools/verify.js [url] [outdir]
const { spawn } = require("child_process");
const fs = require("fs"), path = require("path"), os = require("os");
const URL_ = process.argv[2] || "http://127.0.0.1:8765/";
const OUT = process.argv[3] || path.join(__dirname, "..", "screenshots");
const CHROME = process.env.CHROME || "google-chrome";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const VIEWS = [
  { name: "desktop-1280", width: 1280, height: 900, mobile: false, dsf: 1 },
  { name: "mobile-390", width: 390, height: 844, mobile: true, dsf: 2 },
  { name: "desktop-1280-dark", width: 1280, height: 900, mobile: false, dsf: 1, dark: true },
  { name: "mobile-390-dark", width: 390, height: 844, mobile: true, dsf: 2, dark: true },
];

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const udd = fs.mkdtempSync(path.join(os.tmpdir(), "stale-verify-"));
  const chrome = spawn(CHROME, ["--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-gpu",
    `--user-data-dir=${udd}`, "--remote-debugging-port=0", "about:blank"], { stdio: "ignore" });
  let port;
  for (let i = 0; i < 100 && !port; i++) { await sleep(100); try { port = fs.readFileSync(path.join(udd, "DevToolsActivePort"), "utf8").split("\n")[0]; } catch {} }
  const ver = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const ws = new WebSocket(ver.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let id = 0; const pending = new Map(); const listeners = [];
  ws.onmessage = (m) => { const j = JSON.parse(m.data); if (j.id && pending.has(j.id)) { pending.get(j.id)(j); pending.delete(j.id); } else listeners.forEach((f) => f(j)); };
  const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const i = ++id; pending.set(i, (j) => (j.error ? rej(new Error(method + ": " + j.error.message)) : res(j.result))); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });

  let failed = false; const report = [];
  for (const v of VIEWS) {
    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    const problems = [];
    const onEvt = (j) => {
      if (j.sessionId !== sessionId) return;
      if (j.method === "Runtime.consoleAPICalled" && (j.params.type === "error" || j.params.type === "warning")) problems.push("console." + j.params.type + ": " + j.params.args.map((a) => a.value ?? a.description).join(" "));
      if (j.method === "Runtime.exceptionThrown") problems.push("exception: " + (j.params.exceptionDetails.exception?.description || j.params.exceptionDetails.text));
      if (j.method === "Log.entryAdded" && j.params.entry.level === "error") problems.push("log.error: " + j.params.entry.text + " " + (j.params.entry.url || ""));
      if (j.method === "Network.loadingFailed") problems.push("request failed: " + j.params.errorText);
      if (j.method === "Network.responseReceived" && j.params.response.status >= 400) problems.push("HTTP " + j.params.response.status + " " + j.params.response.url);
    };
    listeners.push(onEvt);
    for (const d of ["Runtime", "Log", "Network", "Page"]) await send(d + ".enable", {}, sessionId);
    await send("Emulation.setDeviceMetricsOverride", { width: v.width, height: v.height, deviceScaleFactor: v.dsf, mobile: v.mobile }, sessionId);
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: v.dark ? "dark" : "light" }] }, sessionId);
    await send("Page.navigate", { url: URL_ }, sessionId);
    await sleep(2500);
    const { result } = await send("Runtime.evaluate", { returnByValue: true, expression: `(() => ({
      rows: document.querySelectorAll('#lb tbody tr.row').length,
      verdicts: [...document.querySelectorAll('#lb tbody tr.row')].map(r => r.querySelector('.lib').textContent + ' ' + r.querySelector('code').textContent + ': ' + r.querySelector('.badge').textContent),
      version: document.querySelector('[data-bind=chrome_version]').textContent,
      ja4: document.querySelector('[data-bind=ja4]').textContent,
      ja4r: document.querySelector('[data-bind=ja4_resumed]').textContent,
      h2: document.querySelector('[data-bind=h2_fingerprint]').textContent,
      captured: document.querySelector('[data-bind=captured_at]').textContent,
      changes: document.querySelector('#changes-body').innerText.slice(0, 600),
      loadError: document.querySelector("#load-error").hidden ? false : document.querySelector("#load-error").textContent,
      signupDisabled: document.querySelector('#early-access-form button').disabled && document.querySelector('#early-access-form button').textContent,
      formAction: document.querySelector('#early-access-form').getAttribute('action'),
      unbound: [...document.querySelectorAll('[data-bind]')].filter(n => n.textContent.trim() === '…').map(n => n.dataset.bind),
      placeholders: (document.body.innerText.match(/\{[a-z0-9_]+\}/gi) || []).concat([...document.querySelectorAll('[data-tip]')].map(n => n.dataset.tip).join(' ').match(/\{[a-z0-9_]+\}/gi) || []),
      notCaptured: [...document.querySelectorAll('[data-bind]')].filter(n => n.textContent.trim() === 'not captured').map(n => n.dataset.bind),
      variantBadges: [...document.querySelectorAll('#lb .badge.v-variant')].length,
      overflowX: document.documentElement.scrollWidth > window.innerWidth,
    }))()` }, sessionId);
    const info = result.value;
    const m = await send("Page.getLayoutMetrics", {}, sessionId);
    const h = Math.ceil(m.cssContentSize.height);
    const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: v.width, height: h, scale: 1 } }, sessionId);
    const file = path.join(OUT, v.name + ".png");
    fs.writeFileSync(file, Buffer.from(shot.data, "base64"));
    const bad = problems.length || info.loadError || info.rows === 0 || info.unbound.length || info.placeholders.length || info.overflowX;
    if (bad) failed = true;
    report.push({ view: v.name, screenshot: file, pageHeight: h, ok: !bad, problems, ...info });
    listeners.splice(listeners.indexOf(onEvt), 1);
    await send("Target.closeTarget", { targetId });
  }
  console.log(JSON.stringify(report, null, 1));
  ws.close(); chrome.kill("SIGTERM"); await sleep(500); try { chrome.kill("SIGKILL"); } catch {}
  fs.rmSync(udd, { recursive: true, force: true });
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
