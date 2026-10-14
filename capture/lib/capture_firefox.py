#!/usr/bin/env python3
"""Official Mozilla Firefox (release) TLS + HTTP/2 fingerprint capture. Separate from the Chrome pipeline on purpose:
it only reuses the capture server and parsers, writes capture/data/firefox/latest.json, and never touches Chrome data.

  python capture/lib/capture_firefox.py --firefox /path/to/firefox [--out capture/data/firefox]

Firefox is driven over WebDriver BiDi (built in, no extra driver). The throwaway self-signed cert is trusted with an
enterprise policy (Certificates.Install) written to <firefox dir>/distribution/policies.json for the run and removed
afterwards; capture.test is mapped to localhost with network.dns.localDomains.
Fresh visit = first connection; resumed = second navigation after the server closes the connection.
"""
import argparse, asyncio, json, os, shutil, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server
from capture import ensure_cert, analyse, h2_fields, fetch_current_stable, now_iso, log, HOST, HERE, PSEUDO  # noqa: F401

PREFS = {
    "network.dns.localDomains": HOST,
    "browser.shell.checkDefaultBrowser": False, "browser.startup.page": 0, "datareporting.policy.dataSubmissionEnabled": False,
    "toolkit.telemetry.reportingpolicy.firstRun": False, "app.update.disabledForTesting": True,
}


def ff_version(path):
    out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
    return out.split()[-1], out


async def drive(port, origin, rec, mark):
    import websockets
    errors = []
    for _ in range(150):
        try:
            ws = await websockets.connect("ws://127.0.0.1:%d/session" % port, max_size=None); break
        except Exception:
            await asyncio.sleep(0.2)
    else:
        return ["WebDriver BiDi did not come up"]
    n = [0]
    async def call(method, params):
        n[0] += 1; i = n[0]
        await ws.send(json.dumps({"id": i, "method": method, "params": params}))
        while True:
            m = json.loads(await asyncio.wait_for(ws.recv(), 60))
            if m.get("id") == i:
                if m.get("type") == "error": raise RuntimeError("%s: %s" % (method, m.get("message") or m.get("error")))
                return m.get("result")
    await call("session.new", {"capabilities": {}})
    ctx = (await call("browsingContext.getTree", {}))["contexts"][0]["context"]
    for phase in ("fresh", "resumed"):
        path = "/%s?cfg=firefox" % phase
        try:
            await call("browsingContext.navigate", {"context": ctx, "url": origin + path, "wait": "complete"})
        except Exception as e:
            errors.append("navigate %s: %s" % (phase, e))
        for _ in range(50):
            if any(e["kind"] == "request" and e.get("path") == path for e in rec.snapshot(mark)): break
            await asyncio.sleep(0.2)
        else:
            errors.append("no request seen for %s" % path)
        await asyncio.sleep(2.5)   # server closes the connection; the next navigation opens a new one (resumption)
    try: await call("session.end", {})
    except Exception: pass
    await ws.close()
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--firefox", required=True); ap.add_argument("--out", default=os.path.join(HERE, "data", "firefox"))
    ap.add_argument("--tcp-port", type=int, default=18553); ap.add_argument("--bidi-port", type=int, default=19222)
    a = ap.parse_args()
    version, version_line = ff_version(a.firefox)
    log("Firefox:", version_line)
    crt, key, _ = ensure_cert(os.path.join(HERE, "certs"))
    dist = os.path.join(os.path.dirname(os.path.realpath(a.firefox)), "distribution")
    os.makedirs(dist, exist_ok=True)
    pol = os.path.join(dist, "policies.json")
    json.dump({"policies": {"Certificates": {"Install": [os.path.abspath(crt)]}, "DisableAppUpdate": True}}, open(pol, "w"))
    rec = server.Recorder()
    server.TCPServer(rec, a.tcp_port, crt, key).start()
    prof = tempfile.mkdtemp(prefix="ffcap-")
    with open(os.path.join(prof, "user.js"), "w") as f:
        for k, v in PREFS.items(): f.write("user_pref(%s, %s);\n" % (json.dumps(k), json.dumps(v)))
    env = dict(os.environ, MOZ_HEADLESS="1")
    mark = rec.mark()
    p = subprocess.Popen([a.firefox, "--headless", "--no-remote", "--profile", prof, "--remote-debugging-port", str(a.bidi_port), "about:blank"],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        errors = asyncio.run(drive(a.bidi_port, "https://%s:%d" % (HOST, a.tcp_port), rec, mark))
    finally:
        p.terminate()
        try: p.wait(15)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
        shutil.rmtree(prof, ignore_errors=True)
        try: os.remove(pol)
        except OSError: pass
    t = analyse({"events": rec.snapshot(mark)}, "tcp")
    f, r, req = t["fresh"], t["resumed"], t["request"]
    if not f:
        log("no Firefox ClientHello captured:", errors); sys.exit(1)
    ak, settings, wu = h2_fields(req)
    hdrs = req["headers"] if req else []
    out = {
        "schema": "firefox-capture-1", "browser": "Mozilla Firefox", "channel": "release", "version": version,
        "os": "Linux x86_64", "captured_at": now_iso(), "mode": "headless", "source": "official Mozilla release build (archive.mozilla.org, SHA512 verified by the workflow)",
        "ja4": f["ja4"], "ja4_r": f["ja4_r"], "ja3": f["ja3"], "ja4_resumed": r["ja4"] if r else None,
        "ciphers": f["ciphers"], "extensions": f["extensions"], "sig_algs": f["sig_algs"], "groups": f["groups"],
        "key_shares": f["key_shares"], "alpn": f["alpn"], "has_ech": f["has_ech"], "cert_compression": f["cert_compression"],
        "tls_versions": f["tls_versions"],
        "http2": {"akamai": ak, "settings": settings, "window_update": wu, "header_order": [k for k, _ in hdrs]} if ak else None,
        "user_agent": next((v for k, v in hdrs if k.lower() == "user-agent"), None),
        "protocol": req.get("proto") if req else None,
        "errors": errors + ([] if r else ["no resumed (PSK) ClientHello captured"]),
    }
    os.makedirs(a.out, exist_ok=True)
    json.dump(out, open(os.path.join(a.out, "latest.json"), "w"), indent=1)
    log("Firefox %s ja4=%s resumed=%s h2=%s errors=%s" % (version, out["ja4"], out["ja4_resumed"], ak, out["errors"]))


if __name__ == "__main__":
    main()
