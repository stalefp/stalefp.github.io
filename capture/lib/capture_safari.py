#!/usr/bin/env python3
"""Real Safari (macOS) TLS + HTTP/2 fingerprint capture, driven by Apple's safaridriver (WebDriver, built into macOS).
Same capture server and parsers as Chrome/Firefox; writes <out>/latest.json and never touches Chrome or Firefox data.

  python capture/lib/capture_safari.py [--out out/safari-macos]

Needs (done here with sudo on the GitHub macOS runner, which has passwordless sudo):
  * safaridriver --enable          (allow remote automation)
  * the throwaway capture cert trusted in the System keychain (security add-trusted-cert), removed afterwards
  * capture.test -> 127.0.0.1 in /etc/hosts (Safari has no host-mapping pref), removed afterwards
Navigation: /fresh, /resumed, then /again?i=1..N. The server closes every connection after one response, so each
navigation is a new TLS connection: the first is the fresh handshake, later ones show resumption and whether the
extension order changes between connections (the shuffle reference for the Safari board).
"""
import argparse, json, os, plistlib, subprocess, sys, time, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server
from capture import ensure_cert, analyse, h2_fields, now_iso, log, os_string, HOST, HERE, PLATFORM  # noqa: F401

SAFARI = "/Applications/Safari.app"
HOSTS_LINE = "127.0.0.1 %s # stale-capture" % HOST


def sh(*cmd, check=True):
    log("$", " ".join(cmd))
    return subprocess.run(list(cmd), check=check, capture_output=True, text=True)


def wd(port, method, path, body=None):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), method=method,
                                 data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read() or b"{}").get("value")


def setup(crt):
    sh("sudo", "safaridriver", "--enable")
    sh("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", os.path.abspath(crt))
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], input=HOSTS_LINE + "\n", text=True, check=True, capture_output=True)
    sh("sudo", "dscacheutil", "-flushcache", check=False)


def teardown(crt):
    sh("sudo", "security", "remove-trusted-cert", "-d", os.path.abspath(crt), check=False)
    sh("sudo", "sed", "-i", "", "/# stale-capture$/d", "/etc/hosts", check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "data", "safari"))
    ap.add_argument("--tcp-port", type=int, default=18563); ap.add_argument("--driver-port", type=int, default=19333)
    ap.add_argument("--again", type=int, default=6)
    a = ap.parse_args()
    info = plistlib.load(open(os.path.join(SAFARI, "Contents", "Info.plist"), "rb"))
    version = info["CFBundleShortVersionString"]
    log("Safari", version, "build", info.get("CFBundleVersion"), "platform", PLATFORM)
    crt, key, _ = ensure_cert(os.path.join(HERE, "certs"))
    rec = server.Recorder()
    server.TCPServer(rec, a.tcp_port, crt, key).start()
    errors, mark = [], rec.mark()
    setup(crt)
    drv = subprocess.Popen(["safaridriver", "-p", str(a.driver_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sid = None
    try:
        for _ in range(100):
            try:
                wd(a.driver_port, "GET", "/status"); break
            except Exception:
                time.sleep(0.2)
        sid = wd(a.driver_port, "POST", "/session", {"capabilities": {"alwaysMatch": {"browserName": "safari"}}})["sessionId"]
        origin = "https://%s:%d" % (HOST, a.tcp_port)
        paths = ["/fresh?cfg=safari", "/resumed?cfg=safari"] + ["/again?cfg=safari&i=%d" % i for i in range(1, a.again + 1)]
        for path in paths:
            try:
                wd(a.driver_port, "POST", "/session/%s/url" % sid, {"url": origin + path})
            except Exception as e:
                errors.append("navigate %s: %s" % (path, str(e)[:200]))
            for _ in range(50):
                if any(e["kind"] == "request" and e.get("path") == path for e in rec.snapshot(mark)): break
                time.sleep(0.2)
            else:
                errors.append("no request seen for %s" % path)
            time.sleep(2.0)   # server closes the connection; the next navigation opens a new one
    finally:
        if sid:
            try: wd(a.driver_port, "DELETE", "/session/%s" % sid)
            except Exception: pass
        drv.terminate()
        teardown(crt)
    ev = rec.snapshot(mark)
    t = analyse({"events": ev}, "tcp")
    f, r, req = t["fresh"], t["resumed"], t["request"]
    if not f:
        log("no Safari ClientHello captured:", errors, [(e["kind"], e.get("error", "")[-200:]) for e in ev][:20]); sys.exit(1)
    chs = [e["summary"] for e in ev if e["kind"] == "clienthello" and e["transport"] == "tcp" and e["summary"]["sni"] == HOST]
    ak, settings, wu = h2_fields(req)
    hdrs = req["headers"] if req else []
    exts = f["extensions"]
    out = {
        "schema": "safari-capture-1", "browser": "Apple Safari", "channel": "release", "version": version,
        "build": info.get("CFBundleVersion"), "platform": PLATFORM, "os": os_string(), "captured_at": now_iso(), "mode": "headed (safaridriver)",
        "source": "Safari preinstalled on the GitHub macOS runner, driven by Apple's safaridriver",
        "ja4": f["ja4"], "ja4_r": f["ja4_r"], "ja3": f["ja3"], "ja4_resumed": r["ja4"] if r else None,
        "ciphers": f["ciphers"], "extensions": exts, "extensions_resumed": r["extensions"] if r else None,
        "extension_orders": [c["extensions"] for c in chs],   # every connection, for the shuffle reference
        "sig_algs": f["sig_algs"], "groups": f["groups"], "key_shares": f["key_shares"], "alpn": f["alpn"], "has_ech": f["has_ech"],
        "cert_compression": f["cert_compression"], "tls_versions": f["tls_versions"],
        "alps_codepoint": next((x for x in exts if x.lower() in ("0x4469", "0x44cd")), None), "has_trust_anchors": f["has_trust_anchors"],
        "h2_akamai": ak, "header_order": [k for k, _ in hdrs] or None,
        "http2": {"akamai": ak, "settings": settings, "window_update": wu, "header_order": [k for k, _ in hdrs]} if ak else None,
        "http3": None,
        "user_agent": next((v for k, v in hdrs if k.lower() == "user-agent"), None),
        "protocol": req.get("proto") if req else None, "connections": len(chs), "resumption_accepted": t["resumption_accepted"],
        "errors": errors + ([] if r else ["no resumed (PSK) ClientHello captured"]),
    }
    os.makedirs(a.out, exist_ok=True)
    json.dump(out, open(os.path.join(a.out, "latest.json"), "w"), indent=1)
    log("Safari %s ja4=%s resumed=%s h2=%s connections=%d distinct_orders=%d errors=%s" % (
        version, out["ja4"], out["ja4_resumed"], ak, len(chs), len({tuple(o) for o in out["extension_orders"]}), out["errors"]))


if __name__ == "__main__":
    main()
