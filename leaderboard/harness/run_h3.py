"""HTTP/3 (QUIC) fingerprint run for the leaderboard.

Reuses Moe's capture endpoint code unchanged: capture/lib/server.py QUICServer (aioquic h3 server that hooks the TLS
layer to record the raw QUIC ClientHello) and capture/lib/fp.py (JA4 'q' / transport params), i.e. the same endpoint
that produced Chrome's QUIC JA4 + h3 SETTINGS in capture/data/latest.json. Runs on its own UDP port (default 28544) so
it never collides with run_capture.sh (18543/18544).

Run with capture/.venv/bin/python (has aioquic):  run_h3.py <out_dir> [--port 28544]
Writes <out_dir>/<case>.json per case and <out_dir>/_summary.json. Nothing is guessed: a case whose client errors or
whose ClientHello isn't seen is saved with ok=false / clienthello=null.
"""
import json, os, subprocess, sys, time, datetime
HERE = os.path.dirname(os.path.abspath(__file__))
LB = os.path.dirname(HERE); TB = os.path.dirname(LB)
sys.path.insert(0, os.path.join(TB, "capture", "lib"))
import server, fp  # Moe's capture endpoint

GO = os.path.join(LB, "bin", "h3probe")
# Python that has the HTTP/3-capable libraries (curl_cffi, noble-tls). $HARNESS_PYTHON overrides (CI uses one interpreter).
PY = [os.environ.get("HARNESS_PYTHON") or os.path.join(TB, ".venv", "bin", "python"), os.path.join(HERE, "h3_python.py")]
# (case file name, command prefix, client case id). Only library/profiles whose installed version exposes HTTP/3.
CASES = [
    ("tls-client(go)_Chrome_152", [GO], "tls-client:Chrome_152"),
    ("tls-client(go)_Chrome_152_PSK", [GO], "tls-client:Chrome_152_PSK"),
    ("tls-client(go)_Chrome_150", [GO], "tls-client:Chrome_150"),
    ("azuretls_Chrome", [GO], "azuretls:Chrome"),
    ("curl_cffi_chrome150", PY, "curl_cffi:chrome150"),
    ("curl_cffi_chrome146", PY, "curl_cffi:chrome146"),
    ("curl_cffi_chrome136", PY, "curl_cffi:chrome136"),
    ("noble-tls_chrome_146", PY, "noble-tls:chrome_146"),
]
HOST = "localhost"

def h3_split(raw):
    if not raw: return None, None
    s = {k: v for k, v in raw.items() if (int(k) - 0x21) % 0x1F != 0}   # same GREASE rule as capture.py
    return s, len(raw) - len(s)

def main():
    out = sys.argv[1]; port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 28544
    os.makedirs(out, exist_ok=True)
    rec = server.Recorder()
    certs = os.path.join(TB, "capture", "certs")
    import capture as _cap  # generates the throwaway self-signed cert if it doesn't exist yet (never committed)
    _cap.ensure_cert(certs)
    qs = server.QUICServer(rec, port, os.path.join(certs, "cert.pem"), os.path.join(certs, "key.pem"), host="::")
    qs.start()
    if qs.error: sys.exit("QUIC server failed: " + qs.error)
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = []
    for name, cmd, cid in CASES:
        url = "https://%s:%d/fresh?case=%s" % (HOST, port, name)
        m = rec.mark(); t0 = time.time()
        try:
            p = subprocess.run(cmd + [cid, url], capture_output=True, text=True, timeout=60)
            line = (p.stdout.strip().splitlines() or ["{}"])[-1]
            try: client = json.loads(line)
            except Exception: client = dict(ok=False, error="unparsable output: " + p.stdout[-300:] + p.stderr[-300:])
        except subprocess.TimeoutExpired:
            client = dict(ok=False, error="timeout after 60s")
        time.sleep(1.5)
        ev = rec.snapshot(m)
        chs = [e["summary"] for e in ev if e["kind"] == "clienthello" and e["transport"] == "quic"]
        fresh = next((c for c in chs if not c["has_psk"]), None)
        reqs = [e for e in ev if e["kind"] == "request" and e.get("proto") == "h3"]
        late = [e for e in ev if e["kind"] == "h3_settings"]
        raw_set = (reqs[0].get("h3_settings") if reqs else None) or (late[0]["h3_settings"] if late else None)
        h3s, h3g = h3_split(raw_set)
        rec_ = dict(case=name, client_case=cid, url=url, tested_at=datetime.datetime.fromtimestamp(t0, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    endpoint="local capture/lib/server.py QUICServer (aioquic) on UDP %d, SNI %s" % (port, HOST),
                    client=client, clienthello_count=len(chs), clienthello=fresh,
                    ja4=fresh["ja4"] if fresh else None, ja4_r=fresh["ja4_r"] if fresh else None,
                    h3_request_seen=bool(reqs), h3_settings=h3s, h3_grease_settings=h3g,
                    header_order=[k for k, _ in reqs[0]["headers"]] if reqs else [],
                    server_errors=[e.get("error") for e in ev if e["kind"] == "server_error"][:3])
        json.dump(rec_, open(os.path.join(out, name + ".json"), "w"), indent=1)
        summary.append(dict(case=name, ok=client.get("ok"), error=client.get("error"), ja4=rec_["ja4"], h3_settings=h3s, h3_request_seen=bool(reqs)))
        print("%-32s ok=%s ja4=%s h3=%s err=%s" % (name, client.get("ok"), rec_["ja4"], h3s, (client.get("error") or "")[:120]), flush=True)
    json.dump(dict(started_at=started, port=port, cases=summary), open(os.path.join(out, "_summary.json"), "w"), indent=1)

if __name__ == "__main__":
    main()
