#!/usr/bin/env python3
"""Branded Google Chrome TLS/H2/QUIC fingerprint capture pipeline. See ../README.md and ../SCHEMA.md."""
import argparse, base64, datetime, glob, hashlib, json, os, platform, re, shutil, signal, subprocess, sys, tempfile, time, traceback, urllib.request
from zoneinfo import ZoneInfo
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fp, server, seedparse

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = "capture.test"
TZ = ZoneInfo("America/Chicago")  # needs the tzdata package on Windows
IS_WIN, IS_MAC = sys.platform.startswith("win"), sys.platform == "darwin"
PLATFORM = "windows" if IS_WIN else "macos" if IS_MAC else "linux"
VH_PLATFORM = {"windows": "win", "macos": "mac", "linux": "linux"}[PLATFORM]   # VersionHistory API platform id
SCHEMA_VERSION = 1
PSEUDO = {":method": "m", ":authority": "a", ":scheme": "s", ":path": "p", ":protocol": "r"}
BASE_CONFIGS = [
    ("default", []),
    ("disable-field-trial-config", ["--disable-field-trial-config"]),
    ("disable-TLSTrustAnchorIDs", ["--disable-features=TLSTrustAnchorIDs"]),
    # Finch population variant seen in the wild: PqcBandwidthExperiment (~6% of Linux stable clients per the 2026-09-26 seed)
    # enables AddTLSServerHandshakePadding, which adds extension 0x12e0. Forced here so the variant is captured every run.
    ("finch-AddTLSServerHandshakePadding", ["--enable-features=AddTLSServerHandshakePadding:AddTLSServerHandshakePaddingBytes/9000"]),
]

def log(*a): print(time.strftime("[%H:%M:%S]"), *a, flush=True)
def now_iso(): return datetime.datetime.now(TZ).isoformat(timespec="seconds")

# ---------- chrome detection ----------
WIN_CANDS = [os.path.join(os.environ.get(v, ""), "Google", "Chrome", "Application", "chrome.exe")
             for v in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA") if os.environ.get(v)]
MAC_CANDS = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]

def _win_version(c):
    """chrome.exe --version prints nothing on Windows; read the PE version resource instead."""
    ps = ("$v=(Get-Item -LiteralPath '%s').VersionInfo; "
          "Write-Output ($v.ProductName + '|' + $v.ProductVersion)") % c.replace("'", "''")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=60).stdout.strip()
    name, _, ver = out.partition("|")
    return ("%s %s" % (name.strip(), ver.strip())).strip()

def detect_chrome(explicit=None):
    cands = [explicit, os.environ.get("CHROME_BIN")]
    if IS_WIN: cands += WIN_CANDS
    elif IS_MAC: cands += MAC_CANDS
    else: cands += ["/opt/google-chrome-stable/current/opt/google/chrome/chrome", "/opt/google/chrome/chrome", shutil.which("google-chrome-stable")]
    for c in cands:
        if c and os.path.exists(c):
            if IS_WIN or IS_MAC:
                out = _win_version(c) if IS_WIN else subprocess.run([c, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
                m = re.match(r"(Google Chrome|Chromium|Google Chrome for Testing)\s+([\d.]+)\s*(\S*)", out)
                if not m: continue
                # Windows/macOS builds don't ship CHROME_VERSION_EXTRA; the CI installs the stable channel and says so via CHROME_CHANNEL.
                channel = m.group(3) or os.environ.get("CHROME_CHANNEL") or None
                return {"path": c, "browser": m.group(1), "version": m.group(2), "channel": channel, "version_string": out}
            c = os.path.realpath(c)
            # the /usr/bin wrapper points at a shell script; prefer the real binary next to it
            if c.endswith("google-chrome") and os.path.exists(os.path.join(os.path.dirname(c), "chrome")):
                c = os.path.join(os.path.dirname(c), "chrome")
            out = subprocess.run([c, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
            m = re.match(r"(Google Chrome|Chromium|Google Chrome for Testing)\s+([\d.]+)\s*(\S*)", out)
            if not m: continue
            extra = os.path.join(os.path.dirname(c), "CHROME_VERSION_EXTRA")
            channel = open(extra).read().strip() if os.path.exists(extra) else (m.group(3) or None)
            return {"path": c, "browser": m.group(1), "version": m.group(2), "channel": channel, "version_string": out}
    raise SystemExit("No Chrome binary found (set CHROME_BIN)")

def os_string():
    if IS_WIN:
        return "Windows %s (%s, build %s)" % (platform.release(), platform.machine(), platform.version())
    if IS_MAC:
        return "macOS %s (%s, Darwin %s)" % (platform.mac_ver()[0] or "unknown", platform.machine(), platform.release())
    pretty = None
    try:
        for l in open("/etc/os-release"):
            if l.startswith("PRETTY_NAME="): pretty = l.split("=", 1)[1].strip().strip('"')
    except Exception: pass
    return "Linux %s (%s, kernel %s)" % (platform.machine(), pretty or "unknown distro", platform.release())

# ---------- current stable per platform (official VersionHistory API) ----------
VH = "https://versionhistory.googleapis.com/v1/chrome/platforms/%s/channels/stable/versions/all/releases?filter=endtime=none"
def vkey(v): return tuple(int(x) for x in v.split("."))
def to_chicago(ts):
    try: return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(TZ).isoformat(timespec="seconds")
    except Exception: return ts
def fetch_current_stable(platforms=("linux", "win", "mac", "android", "ios")):
    out = {}
    for pf in platforms:
        try:
            with urllib.request.urlopen(VH % pf, timeout=20) as r: rel = json.load(r).get("releases", [])
            items = [{"version": x["version"], "fraction": x.get("fraction"), "fraction_group": x.get("fractionGroup"),
                      "serving_since": to_chicago(x.get("serving", {}).get("startTime", "")),
                      "rollout_tags": sorted({t for rd in x.get("rolloutData", []) for t in rd.get("tag", [])})} for x in rel]
            items.sort(key=lambda x: vkey(x["version"]), reverse=True)
            full = [x["version"] for x in items if x["fraction"] == 1]
            out[pf] = {"newest": items[0]["version"] if items else None,
                       "highest_full_rollout": full[0] if full else None, "releases": items}
        except Exception as e:
            out[pf] = {"newest": None, "highest_full_rollout": None, "releases": [], "error": str(e)}
    return out

# ---------- certs ----------
def ensure_cert(d):
    """Throwaway self-signed P-256 cert for capture.test (+ localhost), generated locally on first use and never committed
    (certs/ is gitignored). Uses the `cryptography` package (an aioquic dependency) so it works without openssl on Windows."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    os.makedirs(d, exist_ok=True)
    crt, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    if not (os.path.exists(crt) and os.path.exists(key)):
        k = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST), x509.DNSName("localhost")]), critical=False)
                .sign(k, hashes.SHA256()))
        with open(key, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with open(crt, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    cert = x509.load_pem_x509_certificate(open(crt, "rb").read())
    der = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return crt, key, base64.b64encode(hashlib.sha256(der).digest()).decode()

# ---------- Xvfb ----------
def start_xvfb():
    r, w = os.pipe()
    p = subprocess.Popen(["Xvfb", "-displayfd", str(w), "-screen", "0", "1366x768x24", "-nolisten", "tcp"],
                         pass_fds=(w,), stderr=subprocess.DEVNULL)
    os.close(w)
    disp = b""
    while not disp.endswith(b"\n"):
        c = os.read(r, 16)
        if not c: break
        disp += c
    os.close(r)
    return p, ":" + disp.decode().strip()

# ---------- CDP ----------
class CDP:
    def __init__(self, url):
        from websockets.sync.client import connect
        self.ws = connect(url, max_size=None, open_timeout=15, compression=None); self.i = 0
    def call(self, method, params=None, timeout=20):
        self.i += 1; mid = self.i
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        end = time.time() + timeout
        while time.time() < end:
            try: msg = json.loads(self.ws.recv(timeout=max(0.1, end - time.time())))
            except TimeoutError: break
            if msg.get("id") == mid: return msg
        raise TimeoutError(method)
    def close(self):
        try: self.ws.close()
        except Exception: pass

def http_json(url):
    with urllib.request.urlopen(url, timeout=5) as r: return json.load(r)

VERSION_JS = r"""(() => { const g = id => { const e = document.getElementById(id); return e ? e.innerText.trim() : null; };
  const inner = g('inner') || '';
  const m = inner.match(/Active Variations\t([\s\S]*)$/);
  return JSON.stringify({version: g('version'), command_line: g('command_line'), executable_path: g('executable_path'),
    useragent: g('useragent'), variations_source: g('variations-source'), variations_seed_type: g('variations-seed-type'),
    command_line_variations: g('variations-cmd'),
    active_variations: (g('variations-list') || (m ? m[1] : '')).split('\n').map(s => s.trim()).filter(Boolean)}); })()"""

def seed_info(udd, save_dir=None, tag=""):
    info = {"seed_file": None, "seed_file_bytes": None, "local_state_seed_bytes": None, "seed_serial_number": None,
            "variations_country": None, "last_fetch_time": None}
    for n in ("VariationsSeedV2", "VariationsSeedV1", "VariationsSeed"):
        p = os.path.join(udd, n)
        if os.path.exists(p): info["seed_file"], info["seed_file_bytes"] = n, os.path.getsize(p); break
    try:
        ls = json.load(open(os.path.join(udd, "Local State")))
        s = ls.get("variations_compressed_seed")
        info["local_state_seed_bytes"] = len(s) if s else None
        info["seed_serial_number"] = ls.get("variations_seed_serial_number")
        info["variations_country"] = ls.get("variations_country")
        info["last_fetch_time"] = ls.get("variations_last_fetch_time")
    except Exception: pass
    info["seed_present"] = bool(info["seed_file_bytes"] and info["seed_file_bytes"] > 64) or bool(info["local_state_seed_bytes"])
    info.update(seed_scan(udd, info, save_dir, tag))
    return info

SEED_KW = rb"TrustAnchor|TLS|Tls|SSL|Ssl|Quic|QUIC|MLKEM|Kyber|EncryptedClientHello|ECH|Http2|HTTP2|Http3|MerkleTree|Pqc|PostQuantum"
NET_FEATURE_SUBSTRINGS = ["TLS", "SSL", "Quic", "TrustAnchor", "Http2", "Spdy", "MLKEM", "Kyber", "EncryptedClientHello",
                          "Alps", "Http3", "Pqc", "PostQuantum", "ClientHello"]
FEATURE_EXT = {"AddTLSServerHandshakePadding": "0x12e0", "TLSTrustAnchorIDs": "0xca34"}
def seed_scan(udd, info, save_dir=None, tag=""):
    """Decompress the stored variations seed (zstd, VariationsSeedV2) or Local State seed (base64+gzip) and list
    study/feature/group names that look TLS/QUIC/HTTP related. Plain string scan of the protobuf, not a full parse."""
    import re as _re
    res = {"seed_mentions_TLSTrustAnchorIDs": None, "seed_network_related_names": None, "seed_scan_error": None}
    if not info.get("seed_present"): return res
    try:
        data = None
        if info.get("seed_file"):
            b = open(os.path.join(udd, info["seed_file"]), "rb").read()
            if b[:4] == b"\x28\xb5\x2f\xfd":
                import zstandard
                data = zstandard.ZstdDecompressor().decompressobj().decompress(b)
            elif b[:2] == b"\x1f\x8b":
                import gzip; data = gzip.decompress(b)
            else: data = b
        else:
            import gzip
            ls = json.load(open(os.path.join(udd, "Local State")))
            data = gzip.decompress(base64.b64decode(ls["variations_compressed_seed"]))
        res["seed_decompressed_bytes"] = len(data)
        if len(data) < 4096:
            res["seed_scan_error"] = "stored seed is only %d bytes decompressed at exit; not a full seed, not scanned" % len(data)
            return res
        names = sorted({m.group(0).decode("latin1") for m in _re.finditer(rb"[A-Za-z0-9_]*(?:" + SEED_KW + rb")[A-Za-z0-9_]*", data)})
        res["seed_mentions_TLSTrustAnchorIDs"] = b"TLSTrustAnchorIDs" in data or b"TrustAnchor" in data
        try:
            res["network_studies"] = seedparse.network_studies(data, NET_FEATURE_SUBSTRINGS)
            for st in res["network_studies"]:
                st["extension_hint"] = sorted({FEATURE_EXT[f] for f in st["features"] if f in FEATURE_EXT}) or None
        except Exception as e:
            res["seed_parse_error"] = str(e)
        if save_dir and info.get("seed_file"):
            shutil.copy(os.path.join(udd, info["seed_file"]), os.path.join(save_dir, "seed-%s.%s" % (tag, info["seed_file"])))
        res["seed_network_related_names"] = names
        res["seed_decompressed_bytes"] = len(data)
    except Exception as e:
        res["seed_scan_error"] = str(e)
    return res

# ---------- one browser launch ----------
def launch(chrome, rec, name, mode, flags, udd, port, spki, display, quic=False, linger=0, logdir=None):
    base = ["--user-data-dir=" + udd, "--no-first-run", "--no-default-browser-check", "--password-store=basic",
            "--host-resolver-rules=MAP %s 127.0.0.1" % HOST, "--ignore-certificate-errors-spki-list=" + spki,
            "--remote-debugging-port=0"]
    if IS_MAC: base.append("--use-mock-keychain")  # avoid the macOS keychain prompt on a fresh profile (no network effect)
    if mode == "headless": base.append("--headless=new")
    qflags = ["--enable-quic", "--origin-to-force-quic-on=%s:%d" % (HOST, port)] if quic else []
    args = base + qflags + flags + ["about:blank"]
    env = dict(os.environ)
    if not (IS_WIN or IS_MAC):  # Linux: headed runs on Xvfb; Windows/macOS use the runner's own desktop session
        if mode == "headed": env["DISPLAY"] = display
        else: env.pop("DISPLAY", None)
    try: os.remove(os.path.join(udd, "DevToolsActivePort"))
    except FileNotFoundError: pass
    mark = rec.mark()
    logf = open(os.path.join(logdir, "%s%s.chrome.log" % (name, "-quic" if quic else "")), "w") if logdir else subprocess.DEVNULL
    pk = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WIN else {"start_new_session": True}
    p = subprocess.Popen([chrome["path"]] + args, env=env, stdout=logf, stderr=logf, **pk)
    res = {"flags": flags + qflags, "launch_args": args, "errors": []}
    cdp = None
    try:
        dtp = os.path.join(udd, "DevToolsActivePort")
        for _ in range(300):   # up to 60 s (first launch on a cold Windows/macOS runner is slow)
            if os.path.exists(dtp) and open(dtp).read().count("\n") >= 1: break
            time.sleep(0.2)
        lines = open(dtp).read().split("\n"); dport = lines[0]
        res["devtools_version"] = http_json("http://127.0.0.1:%s/json/version" % dport)
        page = next(t for t in http_json("http://127.0.0.1:%s/json/list" % dport) if t["type"] == "page")
        cdp = CDP(page["webSocketDebuggerUrl"])
        cdp.call("Page.enable")
        origin = "https://%s:%d" % (HOST, port)
        tag = ("quic-" if quic else "") + name
        for phase in ("fresh", "resumed"):
            path = "/%s?cfg=%s" % (phase, tag)
            cdp.call("Page.navigate", {"url": origin + path})
            ok = False
            for _ in range(100):
                if any(e["kind"] == "request" and e.get("path") == path for e in rec.snapshot(mark)): ok = True; break
                time.sleep(0.2)
            if not ok: res["errors"].append("no request seen for %s" % path)
            time.sleep(2.5)  # server GOAWAYs/closes; next navigation must open a new connection
        cdp.call("Page.navigate", {"url": "chrome://version/?show-variations-cmd"}); time.sleep(1.5)
        v = cdp.call("Runtime.evaluate", {"expression": VERSION_JS, "returnByValue": True})
        res["chrome_version_page"] = json.loads(v["result"]["result"]["value"])
        if linger:
            log("  lingering %ds so Chrome can fetch a variations seed..." % linger); time.sleep(linger)
        try:
            b = CDP("ws://127.0.0.1:%s%s" % (dport, lines[1].strip())); b.call("Browser.close", timeout=5); b.close()
        except Exception: pass
    except Exception as e:
        res["errors"].append("launch/cdp error: %s" % e)
    finally:
        if cdp: cdp.close()
        try: p.wait(10)
        except subprocess.TimeoutExpired:
            if IS_WIN: subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
            else: os.killpg(p.pid, signal.SIGKILL)
            p.wait()
        if IS_WIN: time.sleep(1.5)  # let child processes release the profile directory
        if logdir: logf.close()
    time.sleep(0.5)
    res["events"] = rec.snapshot(mark)
    res["seed"] = seed_info(udd, logdir, name + ("-quic" if quic else ""))
    return res

def analyse(res, transport):
    ev = res["events"]
    chs = [e for e in ev if e["kind"] == "clienthello" and e["transport"] == transport and e["summary"]["sni"] == HOST]
    fresh = [e for e in chs if not e["summary"]["has_psk"]]
    resumed = [e for e in chs if e["summary"]["has_psk"]]
    proto = "h3" if transport == "quic" else "h2"
    reqs = [e for e in ev if e["kind"] == "request" and e["proto"] in (proto, "http/1.1")]
    freq = next((e for e in reqs if (e.get("path") or "").startswith("/fresh")), reqs[0] if reqs else None)
    out = {"fresh": fresh[0]["summary"] if fresh else None, "resumed": resumed[0]["summary"] if resumed else None,
           "fresh_ja4_all": sorted({e["summary"]["ja4"] for e in fresh}),
           "resumed_ja4_all": sorted({e["summary"]["ja4"] for e in resumed}),
           "clienthello_count": len(chs), "request": freq,
           "resumption_accepted": any(e.get("resumed") for e in ev if e["kind"] in ("tls_done", "quic_alpn"))}
    return out

def h2_fields(req):
    if not req or req.get("proto") != "h2": return None, None, None
    s = req.get("settings") or []
    pseudo = ",".join(PSEUDO.get(k, k) for k, _ in req["headers"] if k.startswith(":"))
    ak = "%s|%s|%s|%s" % (";".join("%d:%d" % (k, v) for k, v in s), req.get("window_update") or 0,
                          ",".join(req.get("priority_frames") or []) or "0", pseudo)
    return ak, {str(k): v for k, v in s}, req.get("window_update")

def build_config(name, mode, tcp_res, quic_res, relaunch_of=None):
    notes = []
    t = analyse(tcp_res, "tcp")
    f, r = t["fresh"], t["resumed"]
    req = t["request"]
    ak, settings, wu = h2_fields(req)
    hdrs = req["headers"] if req else []
    hv = lambda n: next((v for k, v in hdrs if k.lower() == n), None)
    if f is None: notes.append("no fresh TCP ClientHello captured")
    if r is None: notes.append("no resumed (PSK) TCP ClientHello captured")
    if len(t["fresh_ja4_all"]) > 1: notes.append("multiple fresh JA4 values seen in one launch: %s" % t["fresh_ja4_all"])
    notes += tcp_res["errors"]
    cv = tcp_res.get("chrome_version_page") or {}
    trials = {}
    m = re.search(r'--force-fieldtrials="([^"]*)"', cv.get("command_line_variations") or "")
    if m:
        parts = m.group(1).split("/")
        trials = {parts[i].lstrip("*"): parts[i + 1] for i in range(0, len(parts) - 1, 2)}
    cfg = {
        "name": "%s-%s" % (name, mode), "base_config": name, "mode": mode,
        "flags": tcp_res["flags"], "relaunch_of": relaunch_of,
        "ja4": f["ja4"] if f else None, "ja4_resumed": r["ja4"] if r else None,
        "ja4_r": f["ja4_r"] if f else None, "ja4_r_resumed": r["ja4_r"] if r else None,
        "ja3": f["ja3"] if f else None, "ja3_string": f["ja3_string"] if f else None,
        "ja3n": f["ja3n"] if f else None,
        "extensions": f["extensions"] if f else [], "extensions_resumed": r["extensions"] if r else [],
        "extensions_sorted": sorted(f["extensions"]) if f else [],
        "has_trust_anchors": f["has_trust_anchors"] if f else None,
        "has_trust_anchors_resumed": r["has_trust_anchors"] if r else None,
        "trust_anchors_len": f["trust_anchors_len"] if f else None,
        "ciphers": f["ciphers"] if f else [], "sig_algs": f["sig_algs"] if f else [],
        "groups": f["groups"] if f else [], "key_shares": f["key_shares"] if f else [],
        "tls_versions": f["tls_versions"] if f else [], "alpn": f["alpn"] if f else [], "alps": f["alps"] if f else [],
        "alps_codepoint": f["alps_codepoint"] if f else None,
        "has_ech": f["has_ech"] if f else None, "cert_compression": f["cert_compression"] if f else [],
        "resumption_accepted_by_server": t["resumption_accepted"],
        "h2_akamai": ak, "h2_settings": settings, "h2_window_update": wu,
        "h2_priority_frames": (req or {}).get("priority_frames"), "h2_headers_priority": (req or {}).get("headers_priority"),
        "http_version": req["proto"] if req else None,
        "header_order": [k for k, _ in hdrs], "user_agent": hv("user-agent"), "sec_ch_ua": hv("sec-ch-ua"),
        "variations_source": cv.get("variations_source"), "command_line_variations": cv.get("command_line_variations"),
        "active_variations_count": len(cv.get("active_variations") or []) if cv else None,
        "active_variations": cv.get("active_variations"),
        "field_trials": trials,
        "seed_present_at_exit": tcp_res["seed"]["seed_present"],
        "seed": {k: v for k, v in tcp_res["seed"].items() if k not in ("network_studies", "seed_network_related_names")},
        "_network_studies": tcp_res["seed"].get("network_studies"),
        "quic": None, "notes": notes,
    }
    if quic_res is not None:
        q = analyse(quic_res, "quic"); qf, qr = q["fresh"], q["resumed"]
        qreq = q["request"]
        if qf is None:
            notes.append("QUIC: no QUIC ClientHello captured" + ("; " + "; ".join(quic_res["errors"]) if quic_res["errors"] else ""))
        else:
            qn = []
            if qr is None: qn.append("no resumed (PSK) QUIC ClientHello captured")
            qn += quic_res["errors"]
            h3raw = qreq.get("h3_settings") if qreq and qreq.get("proto") == "h3" else None
            if not h3raw:
                late = [e for e in quic_res["events"] if e["kind"] == "h3_settings"]
                h3raw = late[0]["h3_settings"] if late else None
            h3s, h3g = None, None
            if h3raw:
                h3s = {k: v for k, v in h3raw.items() if (int(k) - 0x21) % 0x1F != 0}
                h3g = len(h3raw) - len(h3s)
            cfg["quic"] = {
                "flags": quic_res["flags"], "ja4": qf["ja4"], "ja4_resumed": qr["ja4"] if qr else None,
                "ja4_r": qf["ja4_r"], "extensions": qf["extensions"], "has_trust_anchors": qf["has_trust_anchors"],
                "ciphers": qf["ciphers"], "sig_algs": qf["sig_algs"], "groups": qf["groups"], "key_shares": qf["key_shares"],
                "alpn": qf["alpn"], "alps": qf["alps"], "transport_params": qf.get("quic_transport_params"),
                "h3_settings": h3s, "h3_grease_settings": h3g, "http_version": qreq["proto"] if qreq else None,
                "header_order": [k for k, _ in qreq["headers"]] if qreq and qreq.get("proto") == "h3" else [],
                "notes": qn,
            }
    return cfg

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome"); ap.add_argument("--out", default=os.path.join(HERE, "data"))
    ap.add_argument("--tcp-port", type=int, default=18543); ap.add_argument("--quic-port", type=int, default=18544)
    ap.add_argument("--modes", default="headless,headed"); ap.add_argument("--seed-wait", type=int, default=180)
    ap.add_argument("--only", default=None, help="comma list of base configs to run (default: all)")
    ap.add_argument("--no-quic", action="store_true"); ap.add_argument("--no-relaunch", action="store_true")
    ap.add_argument("--no-latest", action="store_true", help="only write the versioned file (archival/older builds)")
    ap.add_argument("--label", default=None, help="optional label stored in the JSON (e.g. 'stale system install')")
    a = ap.parse_args()
    chrome = detect_chrome(a.chrome)
    log("Chrome:", chrome)
    current_stable = fetch_current_stable()
    log("VersionHistory stable:", {k: (v["newest"], v["highest_full_rollout"]) for k, v in current_stable.items()})
    captured_at = now_iso(); date = captured_at[:10]
    raw_dir = os.path.join(a.out, "raw", "chrome-%s-%s" % (chrome["version"], date)); os.makedirs(raw_dir, exist_ok=True)
    crt, key, spki = ensure_cert(os.path.join(HERE, "certs"))
    rec = server.Recorder()
    server.TCPServer(rec, a.tcp_port, crt, key).start()
    qs = None
    if not a.no_quic:
        qs = server.QUICServer(rec, a.quic_port, crt, key); qs.start()
        if qs.error: log("QUIC server failed:", qs.error); qs = None
    modes = [m.strip() for m in a.modes.split(",") if m.strip()]
    xv, display = (start_xvfb() if ("headed" in modes and PLATFORM == "linux") else (None, None))
    if display: log("Xvfb on", display)
    work = tempfile.mkdtemp(prefix="chromecap-")
    configs, raw = [], {}
    notes = []
    try:
        for mode in modes:
            for name, flags in BASE_CONFIGS:
                if a.only and name not in a.only.split(","): continue
                log("== %s / %s" % (name, mode))
                udd = os.path.join(work, "%s-%s" % (name, mode))
                linger = a.seed_wait if (name == "default" and not a.no_relaunch) else 0
                tr = launch(chrome, rec, name + "-" + mode, mode, flags, udd, a.tcp_port, spki, display, linger=linger, logdir=raw_dir)
                qr = None
                if qs:
                    qr = launch(chrome, rec, name + "-" + mode, mode, flags, udd + "-quic", a.quic_port, spki, display, quic=True, logdir=raw_dir)
                c = build_config(name, mode, tr, qr); configs.append(c)
                raw[c["name"]] = {"tcp": tr, "quic": qr}
                log("   ja4=%s resumed=%s ca34=%s quic=%s seed=%s" % (c["ja4"], c["ja4_resumed"], c["has_trust_anchors"],
                    (c["quic"] or {}).get("ja4"), c["seed_present_at_exit"]))
                if name == "default" and not a.no_relaunch:
                    log("== default-relaunched / %s (same profile, after %ds)" % (mode, a.seed_wait))
                    tr2 = launch(chrome, rec, "default-relaunched-" + mode, mode, [], udd, a.tcp_port, spki, display, logdir=raw_dir)
                    qr2 = launch(chrome, rec, "default-relaunched-" + mode, mode, [], udd, a.quic_port, spki, display, quic=True, logdir=raw_dir) if qs else None
                    c2 = build_config("default-relaunched", mode, tr2, qr2, relaunch_of=c["name"])
                    c2["notes"].append("same user-data-dir as %s, relaunched after lingering %ds; variations seed present before relaunch: %s"
                                       % (c["name"], a.seed_wait, c["seed_present_at_exit"]))
                    configs.append(c2); raw[c2["name"]] = {"tcp": tr2, "quic": qr2}
                    log("   ja4=%s resumed=%s ca34=%s quic=%s src=%s" % (c2["ja4"], c2["ja4_resumed"], c2["has_trust_anchors"],
                        (c2["quic"] or {}).get("ja4"), c2["variations_source"]))
    finally:
        if xv: xv.terminate()
        shutil.rmtree(work, ignore_errors=True)
    if not qs and not a.no_quic: notes.append("QUIC server failed to start; quic fields are null")
    # ---- cross-config notes ----
    by = {c["name"]: c for c in configs}
    for base, _ in BASE_CONFIGS + [("default-relaunched", [])]:
        hl, hd = by.get(base + "-headless"), by.get(base + "-headed")
        if hl and hd:
            diffs = [k for k in ("ja4", "ja4_resumed", "has_trust_anchors", "h2_akamai", "header_order") if hl[k] != hd[k]]
            ua = hl["user_agent"] != hd["user_agent"]
            notes.append("%s: headless vs headed differ in %s%s" % (base, diffs or "no TLS/H2 fingerprint fields",
                         "; user-agent differs (%r vs %r)" % (hl["user_agent"], hd["user_agent"]) if ua else ""))
    notes.append("Chrome randomizes TLS extension order per connection: 'extensions' and 'ja3' reflect one observed connection; "
                 "use 'ja4' / 'ja3n' / 'extensions_sorted' for stable comparison.")
    # Finch / trust-anchors interpretation
    for mode in modes:
        d0, dr = by.get("default-" + mode), by.get("default-relaunched-" + mode)
        if d0 and d0["ja4"]:
            scanned = d0["seed"].get("seed_mentions_TLSTrustAnchorIDs") is not None
            notes.append("%s: fresh profile (Variations Source %r, %s active variations) has 0xca34=%s; seed downloaded during the run: %s%s"
                         % (d0["name"], d0["variations_source"], d0["active_variations_count"], d0["has_trust_anchors"],
                            d0["seed_present_at_exit"],
                            ("; that seed %s TrustAnchor" % ("mentions" if d0["seed"]["seed_mentions_TLSTrustAnchorIDs"] else "does NOT mention")) if scanned else ""))
        if d0 and dr and dr["ja4"]:
            notes.append("%s vs %s (seed applied, Variations Source %r, %s active variations): JA4 %s, resumed JA4 %s, 0xca34 %s"
                         % (d0["name"], dr["name"], dr["variations_source"], dr["active_variations_count"],
                            "same" if d0["ja4"] == dr["ja4"] else "DIFFERENT", "same" if d0["ja4_resumed"] == dr["ja4_resumed"] else "DIFFERENT",
                            "same" if d0["has_trust_anchors"] == dr["has_trust_anchors"] else "DIFFERENT"))
    ref = next((n for n in ("default-headed", "default-headless", "default-relaunched-headed") if by.get(n) and by[n]["ja4"]), None)
    net_studies = next((c["_network_studies"] for c in configs if c.get("_network_studies")), None)
    for c in configs:
        c.pop("_network_studies", None)
        c["network_trial_groups"] = ({st["study"]: c["field_trials"].get(st["study"]) for st in net_studies}
                                     if net_studies is not None and c.get("field_trials") else None)
        c.pop("field_trials", None)
    if ref:
        r = by[ref]
        for c in configs:
            if c["base_config"] in ("default", "default-relaunched") and c["ja4"] and c["ja4"] != r["ja4"]:
                extra = sorted(set(c["extensions_sorted"]) ^ set(r["extensions_sorted"]))
                grp = {k: v for k, v in (c.get("network_trial_groups") or {}).items() if v}
                notes.append("%s JA4 %s differs from reference %s (%s): extension diff %s; network field-trial groups of this client: %s"
                             % (c["name"], c["ja4"], ref, r["ja4"], extra, grp))
    if net_studies:
        for st in net_studies:
            if st.get("extension_hint"):
                notes.append("Finch study %s (features %s, ~%s of eligible clients per seed layer, groups %s) can change the ClientHello: %s"
                             % (st["study"], st["features"], st["population_share"],
                                [(g["name"], g["share_of_population"]) for g in st["groups"] if g["share"] > 0], st["extension_hint"]))
    # baseline comparison (e.g. Chrome for Testing answer key)
    comparisons = []
    for bf in sorted(glob.glob(os.path.join(HERE, "baselines", "*.json"))):
        b = json.load(open(bf))
        comparisons.append({"baseline": b["label"], "baseline_version": b["version"], "baseline_file": os.path.relpath(bf, HERE),
                            "same_version": b["version"] == chrome["version"],
                            "matches": {c["name"]: {"ja4": c["ja4"] == b.get("ja4"), "ja4_resumed": c["ja4_resumed"] == b.get("ja4_resumed"),
                                                     "h2_akamai": c["h2_akamai"] == b.get("h2_akamai")} for c in configs}})
    lin = current_stable.get("linux", {})
    own = current_stable.get(VH_PLATFORM, {})
    if own.get("newest") and own["newest"] != chrome["version"]:
        pname = {"linux": "Linux", "windows": "Windows", "macos": "macOS"}[PLATFORM]
        notes.insert(0, "captured version %s is NOT the newest %s stable (%s per VersionHistory API; highest full rollout %s)"
                     % (chrome["version"], pname, own["newest"], own.get("highest_full_rollout")))
    out = {
        "schema_version": SCHEMA_VERSION, "label": a.label, "browser": chrome["browser"], "version": chrome["version"], "channel": chrome["channel"],
        "os": os_string(), "platform": PLATFORM, "captured_at": captured_at, "chrome_path": chrome["path"], "chrome_version_string": chrome["version_string"],
        "capture_server": "local (lib/server.py): TLS/h2 on 127.0.0.1:%d, QUIC/h3 (aioquic) on 127.0.0.1:%d, SNI %s" % (a.tcp_port, a.quic_port, HOST),
        "current_stable": current_stable,
        "is_current_linux_stable": (lin.get("newest") == chrome["version"]) if lin.get("newest") else None,
        "is_current_platform_stable": (own.get("newest") == chrome["version"]) if own.get("newest") else None,
        "ci_run": os.environ.get("CAPTURE_RUN_URL") or None,
        "reference_config": ref, "finch_network_studies": net_studies, "configs": configs, "baseline_comparisons": comparisons,
        "code_names": fp.code_names(), "notes": notes,
    }
    os.makedirs(a.out, exist_ok=True)
    js = json.dumps(out, indent=2)
    vpath = os.path.join(a.out, "chrome-%s-%s.json" % (chrome["version"], date))
    for p in ([vpath] if a.no_latest else [vpath, os.path.join(a.out, "latest.json")]):
        open(p, "w").write(js)
    json.dump(raw, open(os.path.join(raw_dir, "events.json"), "w"), indent=1, default=str)
    log("wrote", vpath, "" if a.no_latest else "and latest.json", "; raw events in", raw_dir)

if __name__ == "__main__":
    main()
