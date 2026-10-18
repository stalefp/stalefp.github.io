#!/usr/bin/env python3
"""Real Chrome for Android TLS + HTTP/2 (+ HTTP/3 where reachable) capture, on an Android emulator (x86_64, Google system
image), driven over adb + Chrome's DevTools socket. Same capture server, parsers and config set as lib/capture.py; writes a
SCHEMA.md-layout latest.json with platform "android" plus an "android" block saying where the Chrome came from and whether
its version was verified.

  python capture/lib/capture_android.py --out out/capture-android [--expect-version X] [--source apk|preinstalled]
         [--apk-sha256 ..] [--apk-cert ..] [--apk-url ..] [--system-cert ..]

Needs a booted emulator on adb. How Chrome is pointed at our server (no root, no Google sign-in):
  * `am set-debug-app --persistent com.android.chrome` makes Chrome read /data/local/tmp/chrome-command-line (the documented
    way to pass flags to Chrome on a non-rooted device). The flags are the desktop capture's: --host-resolver-rules (MAP
    capture.test to the host), --ignore-certificate-errors-spki-list (our throwaway cert), plus --disable-fre (skip the first-run
    screens) and the per-config feature flags. Each config starts from a cleared profile (`pm clear`).
  * TLS/HTTP/2: `adb reverse tcp:PORT tcp:PORT`, capture.test -> 127.0.0.1 inside the emulator, i.e. our server on the host.
  * QUIC/HTTP/3: adb reverse is TCP-only, so the QUIC launch maps capture.test to 10.0.2.2 (the emulator's alias for the
    host loopback) and forces QUIC with --origin-to-force-quic-on, like desktop.
  * Navigation over CDP (`adb forward tcp:N localabstract:chrome_devtools_remote`): /fresh, /resumed, then /again?i=1..N
    (default config) so the extension order of several connections is recorded, as for Safari.
"""
import argparse, json, os, re, shlex, subprocess, sys, tempfile, time, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fp, server
from capture import (BASE_CONFIGS, CDP, HERE, HOST, SCHEMA_VERSION, VERSION_JS, analyse, build_config, ensure_cert,
                     fetch_current_stable, http_json, log, now_iso, vkey)

PKG = "com.android.chrome"
MAIN = PKG + "/com.google.android.apps.chrome.Main"
CMDLINE = "/data/local/tmp/chrome-command-line"


def adb(*args, check=True, timeout=180):
    r = subprocess.run(["adb"] + list(args), capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError("adb %s failed: %s" % (" ".join(args), (r.stdout + r.stderr).strip()[-300:]))
    return r.stdout.strip()


def sh(cmd, check=False): return adb("shell", cmd, check=check)


def prop(k): return sh("getprop " + k)


def installed_version():
    out = sh("dumpsys package " + PKG)
    # first versionName is the active package (an installed update comes before the hidden system package)
    m = re.search(r"versionName=(\S+)", out); c = re.search(r"versionCode=(\d+)", out)
    path = re.search(r"codePath=(\S+)", out)
    return (m.group(1) if m else None), (c.group(1) if c else None), (path.group(1) if path else None)


def write_cmdline(flags):
    line = "_ " + " ".join('"%s"' % f if " " in f else f for f in flags) + "\n"
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as t:
        t.write(line); p = t.name
    adb("push", p, CMDLINE); sh("chmod 644 " + CMDLINE); os.remove(p)
    return line.strip()


def launch(rec, name, flags, port, spki, quic=False, again=0, dport=9333):
    host_ip = "10.0.2.2" if quic else "127.0.0.1"
    qflags = ["--enable-quic", "--origin-to-force-quic-on=%s:%d" % (HOST, port)] if quic else []
    args = ["--host-resolver-rules=MAP %s %s" % (HOST, host_ip), "--ignore-certificate-errors-spki-list=" + spki,
            "--disable-fre", "--no-default-browser-check", "--no-first-run"] + qflags + flags
    res = {"flags": flags + qflags, "launch_args": args, "errors": [], "seed": {"seed_present": None}}
    sh("am force-stop " + PKG)
    sh("pm clear " + PKG)                                        # fresh profile for every launch, like desktop's new user-data-dir
    sh("pm grant %s android.permission.POST_NOTIFICATIONS" % PKG)  # no permission dialog on Android 13+
    res["command_line_file"] = write_cmdline(args)
    mark = rec.mark()
    adb("forward", "tcp:%d" % dport, "localabstract:chrome_devtools_remote")
    sh("am start -W -n %s -a android.intent.action.VIEW -d about:blank" % MAIN)
    cdp = None
    try:
        ver = None
        for _ in range(120):
            try: ver = http_json("http://127.0.0.1:%d/json/version" % dport); break
            except Exception: time.sleep(0.5)
        if not ver: raise RuntimeError("Chrome DevTools socket not reachable after 60 s")
        res["devtools_version"] = ver
        page = None
        for _ in range(40):
            try: page = next((t for t in http_json("http://127.0.0.1:%d/json/list" % dport) if t.get("type") == "page"), None)
            except Exception: page = None
            if page: break
            time.sleep(0.5)
        if not page:
            req = urllib.request.Request("http://127.0.0.1:%d/json/new?about:blank" % dport, method="PUT")
            page = json.load(urllib.request.urlopen(req, timeout=10))
        cdp = CDP(page["webSocketDebuggerUrl"])
        cdp.call("Page.enable")
        origin = "https://%s:%d" % (HOST, port)
        tag = ("quic-" if quic else "") + name
        paths = ["/fresh?cfg=" + tag, "/resumed?cfg=" + tag] + ["/again?cfg=%s&i=%d" % (tag, i) for i in range(1, again + 1)]
        for path in paths:
            cdp.call("Page.navigate", {"url": origin + path})
            for _ in range(100):
                if any(e["kind"] == "request" and e.get("path") == path for e in rec.snapshot(mark)): break
                time.sleep(0.2)
            else:
                res["errors"].append("no request seen for %s" % path)
            time.sleep(2.5)
        cdp.call("Page.navigate", {"url": "chrome://version/?show-variations-cmd"}); time.sleep(2)
        v = cdp.call("Runtime.evaluate", {"expression": VERSION_JS, "returnByValue": True})
        res["chrome_version_page"] = json.loads(v["result"]["result"]["value"])
    except Exception as e:
        res["errors"].append("launch/cdp error: %s" % e)
    finally:
        if cdp: cdp.close()
        sh("am force-stop " + PKG)
        adb("forward", "--remove", "tcp:%d" % dport, check=False)
    time.sleep(0.5)
    res["events"] = rec.snapshot(mark)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tcp-port", type=int, default=18543); ap.add_argument("--quic-port", type=int, default=18544)
    ap.add_argument("--again", type=int, default=6); ap.add_argument("--no-quic", action="store_true")
    ap.add_argument("--expect-version"); ap.add_argument("--source", default="preinstalled", choices=["apk", "preinstalled"])
    ap.add_argument("--apk-sha256"); ap.add_argument("--apk-cert"); ap.add_argument("--apk-url"); ap.add_argument("--apk-version-code")
    ap.add_argument("--system-cert"); ap.add_argument("--preinstalled-version")
    ap.add_argument("--image", default=os.environ.get("ANDROID_IMAGE"))
    a = ap.parse_args()
    version, vcode, codepath = installed_version()
    if not version: raise SystemExit("Chrome (%s) is not installed on the emulator" % PKG)
    emu = {k: prop(p) for k, p in dict(release="ro.build.version.release", sdk="ro.build.version.sdk", abi="ro.product.cpu.abi",
                                         fingerprint="ro.build.fingerprint", build_type="ro.build.type", model="ro.product.model").items()}
    log("Chrome for Android", version, vcode, codepath, "| emulator", emu)
    current_stable = fetch_current_stable()
    and_rel = current_stable.get("android", {})
    serving = {r["version"]: r["fraction"] for r in and_rel.get("releases", []) if (r.get("fraction") or 0) > 0}
    log("Android stable serving now:", serving)
    crt, key, spki = ensure_cert(os.path.join(HERE, "certs"))
    rec = server.Recorder()
    server.TCPServer(rec, a.tcp_port, crt, key).start()
    qs = None
    if not a.no_quic:
        qs = server.QUICServer(rec, a.quic_port, crt, key); qs.start()
        if qs.error: log("QUIC server failed:", qs.error); qs = None
    adb("reverse", "tcp:%d" % a.tcp_port, "tcp:%d" % a.tcp_port)
    sh("am set-debug-app --persistent " + PKG, check=True)
    captured_at = now_iso(); date = captured_at[:10]
    raw_dir = os.path.join(a.out, "raw", "chrome-android-%s-%s" % (version, date)); os.makedirs(raw_dir, exist_ok=True)
    configs, raw, notes = [], {}, []
    for name, flags in BASE_CONFIGS:
        log("== %s / android" % name)
        tr = launch(rec, name + "-headed", flags, a.tcp_port, spki, again=a.again if name == "default" else 0)
        qr = launch(rec, name + "-headed", flags, a.quic_port, spki, quic=True) if qs else None
        c = build_config(name, "headed", tr, qr)
        if name == "default":
            chs = [e["summary"] for e in tr["events"] if e["kind"] == "clienthello" and e["transport"] == "tcp" and e["summary"]["sni"] == HOST]
            c["extension_orders"] = [x["extensions"] for x in chs]
            c["connections"] = len(chs)
        c["command_line_file"] = tr.get("command_line_file")
        configs.append(c); raw[c["name"]] = {"tcp": tr, "quic": qr}
        log("   ja4=%s resumed=%s ca34=%s quic=%s h2=%s errors=%s" % (c["ja4"], c["ja4_resumed"], c["has_trust_anchors"],
            (c["quic"] or {}).get("ja4"), c["h2_akamai"], c["notes"][:3]))
    by = {c["name"]: c for c in configs}
    ref = "default-headed" if by.get("default-headed", {}).get("ja4") else None
    d0 = by.get("default-headed") or {}
    orders = d0.get("extension_orders") or []
    if orders:
        notes.append("extension order across %d TLS connections of one Chrome session: %d distinct orders" % (len(orders), len({tuple(o) for o in orders})))
    # ---- version verification: the package manager, DevTools and chrome://version must agree, and the APK signer must be Google's ----
    cv = (raw.get("default-headed", {}).get("tcp") or {}).get("chrome_version_page") or {}
    dv = ((raw.get("default-headed", {}).get("tcp") or {}).get("devtools_version") or {}).get("Browser", "")
    page_ver = (re.match(r"[\d.]+", cv.get("version") or "") or [None])[0] if cv.get("version") else None
    checks = dict(package_manager=version, devtools=dv.split("/")[-1] if dv else None, chrome_version_page=page_ver,
                  expected=a.expect_version)
    from fetch_pin import PIN
    signer_ok = (a.apk_cert == PIN) if a.source == "apk" else (a.system_cert == PIN)
    agree = len({x for x in (checks["package_manager"], checks["devtools"], checks["chrome_version_page"]) if x}) == 1 and all(
        checks[k] for k in ("package_manager", "devtools", "chrome_version_page"))
    verified = bool(agree and signer_ok and (not a.expect_version or a.expect_version == version))
    flags_applied = "--host-resolver-rules" in (cv.get("command_line") or "")
    android = dict(package=PKG, version_code=vcode, code_path=codepath, source=a.source,
                   source_detail=("Google-signed x86_64 APK from APKMirror, installed over the image's preinstalled Chrome: " + (a.apk_url or ""))
                   if a.source == "apk" else "Chrome preinstalled in the Google system image (not updated: no Play sign-in)",
                   apk_sha256=a.apk_sha256, signer_cert_sha256=a.apk_cert if a.source == "apk" else a.system_cert, google_cert_pin=PIN,
                   system_image_signer_sha256=a.system_cert, preinstalled_version=a.preinstalled_version,
                   version_checks=checks, version_verified=verified, flags_applied=flags_applied,
                   is_serving_on_android_stable=version in serving, android_stable_serving=serving,
                   emulator=dict(emu, image=a.image), user_agent=d0.get("user_agent"))
    if not verified: notes.insert(0, "version NOT verified: %s, signer ok %s" % (checks, signer_ok))
    if version not in serving:
        notes.insert(0, "captured Chrome %s is NOT currently serving on Android stable (serving: %s)" % (version, sorted(serving, key=vkey)))
    elif and_rel.get("newest") != version:
        notes.insert(0, "captured Chrome %s is serving on Android stable (%.1f%% of users); newest serving is %s (%.2f%%)" % (
            version, 100 * serving[version], and_rel.get("newest"), 100 * (serving.get(and_rel.get("newest")) or 0)))
    notes.append("Captured on an Android emulator (%s, Android %s / API %s, %s), not a physical phone. Cipher order and other TLS "
                 "choices come from Chrome's own BoringSSL; the x86_64 CPU has AES instructions, like current arm64 phones." % (
                     a.image or "google system image", emu["release"], emu["sdk"], emu["abi"]))
    out = {
        "schema_version": SCHEMA_VERSION, "label": None, "browser": "Google Chrome", "version": version, "channel": "stable",
        "os": "Android %s (API %s, %s emulator, %s)" % (emu["release"], emu["sdk"], emu["abi"], a.image or "google system image"),
        "platform": "android", "captured_at": captured_at, "chrome_path": codepath, "chrome_version_string": "Google Chrome %s (%s)" % (version, PKG),
        "capture_server": "local (lib/server.py): TLS/h2 on 127.0.0.1:%d via adb reverse, QUIC/h3 on 127.0.0.1:%d via the emulator's 10.0.2.2 host alias, SNI %s" % (a.tcp_port, a.quic_port, HOST),
        "current_stable": current_stable,
        "is_current_linux_stable": None,
        "is_current_platform_stable": version in serving,
        "ci_run": os.environ.get("CAPTURE_RUN_URL") or None,
        "reference_config": ref, "finch_network_studies": None, "configs": configs, "baseline_comparisons": [],
        "code_names": fp.code_names(), "notes": notes, "android": android,
    }
    os.makedirs(a.out, exist_ok=True)
    js = json.dumps(out, indent=2)
    for p in (os.path.join(a.out, "chrome-android-%s-%s.json" % (version, date)), os.path.join(a.out, "latest.json")):
        open(p, "w").write(js)
    json.dump(raw, open(os.path.join(raw_dir, "events.json"), "w"), indent=1, default=str)
    log("wrote", a.out, "| verified", verified, checks, "| flags applied", flags_applied)


if __name__ == "__main__":
    main()
