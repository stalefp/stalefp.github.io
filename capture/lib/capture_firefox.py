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
from capture import ensure_cert, analyse, h2_fields, now_iso, log, os_string, HOST, HERE, PLATFORM, IS_WIN, IS_MAC  # noqa: F401

PREFS = {
    "network.dns.localDomains": HOST,
    "browser.shell.checkDefaultBrowser": False, "browser.startup.page": 0, "datareporting.policy.dataSubmissionEnabled": False,
    "toolkit.telemetry.reportingpolicy.firstRun": False, "app.update.disabledForTesting": True,
    "network.dns.disableIPv6": True,   # capture server listens on 127.0.0.1 only (resolver setting; not part of the handshake)
}


def quic_prefs(port):
    """Force HTTP/3 to the local QUIC endpoint (Firefox's own testing prefs for Alt-Svc mapping)."""
    return {"network.http.http3.enable": True,
            "network.http.http3.alt-svc-mapping-for-testing": "%s;h3=:%d" % (HOST, port),
            "network.http.http3.force-use-alt-svc-mapping-for-testing": True}


def ff_version(path):
    if IS_WIN:   # firefox.exe --version prints nothing to a console; the version is in application.ini
        ini = open(os.path.join(os.path.dirname(path), "application.ini"), encoding="utf-8").read()
        v = next(l.split("=", 1)[1].strip() for l in ini.splitlines() if l.startswith("Version="))
        return v, "Mozilla Firefox " + v
    out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
    return out.split()[-1], out


def distribution_dir(path):
    d = os.path.dirname(os.path.realpath(path))
    if IS_MAC and d.endswith("Contents/MacOS"):   # Firefox.app/Contents/Resources/distribution
        return os.path.join(os.path.dirname(d), "Resources", "distribution")
    return os.path.join(d, "distribution")


def run_once(a, rec, prefs, port, tag):
    """One Firefox launch on a fresh profile: navigate /fresh then /resumed against https://capture.test:<port>."""
    prof = tempfile.mkdtemp(prefix="ffcap-")
    with open(os.path.join(prof, "user.js"), "w") as f:
        for k, v in prefs.items(): f.write("user_pref(%s, %s);\n" % (json.dumps(k), json.dumps(v)))
    env = dict(os.environ, MOZ_HEADLESS="1")
    mark = rec.mark()
    pk = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WIN else {"start_new_session": True}
    p = subprocess.Popen([a.firefox, "--headless", "--no-remote", "--profile", prof, "--remote-debugging-port", str(a.bidi_port), "about:blank"],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **pk)
    try:
        errors = asyncio.run(drive(a.bidi_port, "https://%s:%d" % (HOST, port), rec, mark, tag))
    finally:
        p.terminate()
        try: p.wait(15)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
        time.sleep(1.5 if IS_WIN else 0.3)
        shutil.rmtree(prof, ignore_errors=True)
    ev = rec.snapshot(mark)
    if os.environ.get("FFCAP_DEBUG"):
        log(tag, [(e["kind"], e.get("transport") or e.get("proto"), e.get("path") or e.get("alpn") or e.get("error", "")[-200:]) for e in ev])
    return {"events": ev}, errors


async def drive(port, origin, rec, mark, tag="firefox"):
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
        path = "/%s?cfg=%s" % (phase, tag)
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
    ap.add_argument("--tcp-port", type=int, default=18553); ap.add_argument("--quic-port", type=int, default=18554)
    ap.add_argument("--bidi-port", type=int, default=19222); ap.add_argument("--no-quic", action="store_true")
    a = ap.parse_args()
    version, version_line = ff_version(a.firefox)
    log("Firefox:", version_line, "platform:", PLATFORM)
    crt, key, _ = ensure_cert(os.path.join(HERE, "certs"))
    dist = distribution_dir(a.firefox)
    os.makedirs(dist, exist_ok=True)
    pol = os.path.join(dist, "policies.json")
    json.dump({"policies": {"Certificates": {"Install": [os.path.abspath(crt)]}, "DisableAppUpdate": True}}, open(pol, "w"))
    rec = server.Recorder()
    server.TCPServer(rec, a.tcp_port, crt, key).start()
    qs = None
    if not a.no_quic:
        qs = server.QUICServer(rec, a.quic_port, crt, key); qs.start()
        if qs.error: log("QUIC server failed:", qs.error.splitlines()[-1]); qs = None
    if qs:   # TCP listener on the QUIC port number too, so Firefox can reach the origin while it switches to HTTP/3
        server.TCPServer(rec, a.quic_port, crt, key).start()
    try:
        tcp, errors = run_once(a, rec, PREFS, a.tcp_port, "firefox")
        quic, qerrors = (run_once(a, rec, dict(PREFS, **quic_prefs(a.quic_port)), a.quic_port, "quic-firefox") if qs else (None, []))
    finally:
        try: os.remove(pol)
        except OSError: pass
    t = analyse(tcp, "tcp")
    f, r, req = t["fresh"], t["resumed"], t["request"]
    if not f:
        log("no Firefox ClientHello captured:", errors); sys.exit(1)
    ak, settings, wu = h2_fields(req)
    hdrs = req["headers"] if req else []
    exts = f["extensions"]
    alps = next((x for x in exts if x.lower() in ("0x4469", "0x44cd")), None)
    h3 = None
    if quic is not None:
        q = analyse(quic, "quic"); qf, qr, qreq = q["fresh"], q["resumed"], q["request"]
        h3set = next((e["h3_settings"] for e in quic["events"] if e["kind"] == "h3_settings"), None) or (qreq or {}).get("h3_settings")
        h3 = {"ja4": qf["ja4"] if qf else None, "ja4_r": qf["ja4_r"] if qf else None, "ja4_resumed": qr["ja4"] if qr else None,
              "transport_params": qf.get("quic_transport_params") if qf else None, "h3_settings": h3set,
              "header_order": [k for k, _ in (qreq or {}).get("headers") or []] if qreq and qreq.get("proto") == "h3" else None,
              "request_over_h3": bool(qreq and qreq.get("proto") == "h3"),
              "errors": qerrors + ([] if qf else ["no QUIC ClientHello captured (Firefox did not use HTTP/3)"])}
    out = {
        "schema": "firefox-capture-2", "browser": "Mozilla Firefox", "channel": "release", "version": version,
        "platform": PLATFORM, "os": os_string(), "captured_at": now_iso(), "mode": "headless",
        "source": "official Mozilla release build (archive.mozilla.org, SHA512 verified by the workflow)",
        "ja4": f["ja4"], "ja4_r": f["ja4_r"], "ja3": f["ja3"], "ja4_resumed": r["ja4"] if r else None,
        "ciphers": f["ciphers"], "extensions": exts, "sig_algs": f["sig_algs"], "groups": f["groups"],
        "key_shares": f["key_shares"], "alpn": f["alpn"], "has_ech": f["has_ech"], "cert_compression": f["cert_compression"],
        "tls_versions": f["tls_versions"], "alps_codepoint": alps, "has_trust_anchors": f["has_trust_anchors"],
        "h2_akamai": ak, "header_order": [k for k, _ in hdrs] or None,
        "http2": {"akamai": ak, "settings": settings, "window_update": wu, "header_order": [k for k, _ in hdrs]} if ak else None,
        "http3": h3,
        "user_agent": next((v for k, v in hdrs if k.lower() == "user-agent"), None),
        "protocol": req.get("proto") if req else None,
        "errors": errors + ([] if r else ["no resumed (PSK) ClientHello captured"]),
    }
    os.makedirs(a.out, exist_ok=True)
    json.dump(out, open(os.path.join(a.out, "latest.json"), "w"), indent=1)
    log("Firefox %s %s ja4=%s resumed=%s h2=%s quic=%s errors=%s" % (version, PLATFORM, out["ja4"], out["ja4_resumed"], ak,
        (h3 or {}).get("ja4"), out["errors"] + ((h3 or {}).get("errors") or [])))


if __name__ == "__main__":
    main()
