"""Behaviour probe: session resumption, extension-order shuffling and header order, for every row on every board.

  probe.py [--library NAME] [--board chrome|firefox|safari] [--n 8] [--port 28643]

Runs each library/profile against our own local capture server (capture/lib/server.py TCPServer, the same code that
captures real Chrome), N requests on ONE client. The server closes each connection after one response, so every
request is a new TLS connection. Per row it records each ClientHello (extension order, pre_shared_key), whether the
server accepted resumption, and the request headers in the order they arrived.

Every library gets the same request headers: the browser's captured header names in the captured order
(capture/data/latest.json, capture/data/<browser>/latest.json) with the usual navigation values, passed through the
library's own ordered-header option. Whether that worked is measured, not assumed (probe_grade.py: 'fair' = the same
header set arrived, in the same order on every request).

Rows come from the board files (leaderboard/data/*libraries.json), so a new library row is probed as soon as an
adapter exists for it: Python adapters in probe_py.py, Go adapters in goprobe/main.go (+ GO_LIBS below). Rows without
an adapter are recorded as status 'no_adapter'.

Writes leaderboard/data/probe.json. With --library only that library's rows are replaced (others kept).
"""
import datetime as dt, json, os, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
LB = os.path.dirname(HERE); TB = os.path.dirname(LB)
sys.path.insert(0, os.path.join(TB, "capture", "lib"))
sys.path.insert(0, HERE)
import server, fp  # noqa: E402
from probe_py import ADAPTERS as PY_ADAPTERS  # noqa: E402

OUT = os.path.join(LB, "data", "probe.json")
GO_BIN = os.path.join(LB, "bin", "goprobe")
GO_LIBS = {"tls-client", "azuretls-client", "uTLS"}
PY = os.environ.get("HARNESS_PYTHON") or sys.executable
BOARDS = {"chrome": "libraries.json", "firefox": "firefox_libraries.json", "safari": "safari_libraries.json"}
# Extra, ungraded cases that check whether a library CAN resume when the board's profile doesn't: its own session-
# resumption ("_PSK") profiles. Add a line here when a new library has such a profile.
CAPABILITY = {
    "chrome": [("tls-client", "Chrome_152_PSK"), ("noble-tls", "chrome_146_PSK"), ("tls-client (Python)", "chrome_152_PSK")],
    "firefox": [("tls-client", "Firefox_147_PSK"), ("noble-tls", "firefox_147_PSK"), ("tls-client (Python)", "firefox_147_PSK")],
}
IGNORE_FOR_ORDER = {0x0029, 0x0015}   # pre_shared_key (always last, only on resumption) and padding (size-dependent)

# Usual navigation values; names and order always come from the capture.
VALUES = {
    "chrome": {"sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Linux"', "upgrade-insecure-requests": "1",
               "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
               "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1", "sec-fetch-dest": "document",
               "accept-encoding": "gzip, deflate, br, zstd", "accept-language": "en-US,en;q=0.9", "priority": "u=0, i"},
    "firefox": {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "accept-language": "en-US,en;q=0.5",
                "accept-encoding": "gzip, deflate, br, zstd", "upgrade-insecure-requests": "1", "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate", "sec-fetch-site": "none", "sec-fetch-user": "?1", "priority": "u=0, i", "te": "trailers"},
    "safari": {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "accept-language": "en-US,en;q=0.9",
               "accept-encoding": "gzip, deflate, br", "sec-fetch-dest": "document", "sec-fetch-mode": "navigate", "sec-fetch-site": "none",
               "priority": "u=0, i", "upgrade-insecure-requests": "1"},
}


def browser_reference(board):
    """(header order, user agent, sec-ch-ua) from our capture of the real browser."""
    if board == "chrome":
        d = json.load(open(os.path.join(TB, "capture", "data", "latest.json")))
        c = next(x for x in d["configs"] if x["name"] == d["reference_config"])
        return c["header_order"], c.get("user_agent"), c.get("sec_ch_ua")
    p = os.path.join(TB, "capture", "data", board, "latest.json")
    if not os.path.exists(p):
        return None, None, None
    d = json.load(open(p))
    return d.get("header_order"), d.get("user_agent"), None


def header_set(board):
    order, ua, chua = browser_reference(board)
    if not order:
        return None
    vals = dict(VALUES[board], **{"user-agent": ua or "Mozilla/5.0"})
    if chua:
        vals["sec-ch-ua"] = chua
    return [[k, vals[k]] for k in order if not k.startswith(":") and k in vals]


# Adapters in other languages (harness/extra): library -> command prefix, or None when its toolchain/build is missing
# (the row then says no_adapter). Every adapter takes: <library> <profile> <browser> <url> <n> <headers-json> and prints
# {ok, done, error} as its last line. To plug in a new library, add a line here (or to probe_py.py / goprobe).
EXTRA = os.path.join(HERE, "extra")
_have = lambda *p: os.path.exists(os.path.join(EXTRA, *p))
NODE_CMD = lambda: ["node", os.path.join(EXTRA, "node", "probe.mjs")] if _have("node", "node_modules") else None
EXTRA_CMDS = {
    "got-scraping": NODE_CMD, "CycleTLS": NODE_CMD,
    "wreq": lambda: [os.path.join(EXTRA, "wreq", "target", "release", "wreq_bench"), "--probe"] if _have("wreq", "target", "release", "wreq_bench") else None,
}


def run_case(rec, port, board, row, hdrs, n):
    lib, prof = row["library"], row["profile"]
    url = "https://localhost:%d/probe?case=%s" % (port, row["id"].replace(" ", "_"))
    if lib in PY_ADAPTERS:
        cmd = [PY, os.path.join(HERE, "probe_py.py")]
    elif lib in GO_LIBS:
        cmd = [GO_BIN]
    elif lib in EXTRA_CMDS and EXTRA_CMDS[lib]():
        cmd = EXTRA_CMDS[lib]()
    else:
        return dict(status="no_adapter")
    m = rec.mark()
    try:
        p = subprocess.run(cmd + [lib, prof, board, url, str(n), json.dumps(hdrs)], capture_output=True, text=True, timeout=180)
        try:
            client = json.loads((p.stdout.strip().splitlines() or ["{}"])[-1])
        except Exception:
            client = dict(ok=False, error="unparsable output: " + (p.stdout[-200:] + p.stderr[-200:]))
    except subprocess.TimeoutExpired:
        client = dict(ok=False, error="timeout")
    time.sleep(1.0)
    ev = rec.snapshot(m)
    done = {e["conn"]: e for e in ev if e["kind"] == "tls_done"}
    conns = []
    for e in ev:
        if e["kind"] == "clienthello" and e["transport"] == "tcp":
            s = e["summary"]
            ch = fp.parse_client_hello(bytes.fromhex(e["raw_hex"]))
            conns.append(dict(ja4=s["ja4"], has_psk=s["has_psk"], server_resumed=(done.get(e["conn"]) or {}).get("resumed"),
                              ext_order=["0x%04x" % x for x in ch["extensions"] if not fp.is_grease(x) and x not in IGNORE_FOR_ORDER]))
    reqs = [[k for k, _ in e["headers"] if not k.startswith(":")] for e in ev if e["kind"] == "request"]
    pseudo = [[k for k, _ in e["headers"] if k.startswith(":")] for e in ev if e["kind"] == "request"]
    return dict(status="tested" if conns else "failed", client=client, connections=conns, request_headers=reqs,
                pseudo_order=pseudo[0] if pseudo else None, tested_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


def main():
    a = sys.argv
    only = a[a.index("--library") + 1] if "--library" in a else (os.environ.get("STALE_LIBS") or None)
    boards = [a[a.index("--board") + 1]] if "--board" in a else list(BOARDS)
    n = int(a[a.index("--n") + 1]) if "--n" in a else 8
    port = int(a[a.index("--port") + 1]) if "--port" in a else 28643
    import capture as _cap  # throwaway self-signed cert (never committed)
    certs = os.path.join(TB, "capture", "certs"); _cap.ensure_cert(certs)
    rec = server.Recorder()
    server.TCPServer(rec, port, os.path.join(certs, "cert.pem"), os.path.join(certs, "key.pem")).start()
    data = json.load(open(OUT)) if os.path.exists(OUT) else {}
    data.setdefault("boards", {})
    for board in boards:
        path = os.path.join(LB, "data", BOARDS[board])
        hdrs = header_set(board)
        if not os.path.exists(path) or not hdrs:
            continue
        rows = json.load(open(path))["libraries"]
        res = data["boards"].setdefault(board, {"rows": {}})
        res["requested_headers"] = hdrs
        if not only:
            res["rows"] = {k: v for k, v in res["rows"].items() if any(r["id"] == k for r in rows)}
        for row in rows:
            if only and row["library"] not in only.split(","):
                continue
            r = run_case(rec, port, board, row, hdrs, n)
            r.update(library=row["library"], profile=row["profile"])
            res["rows"][row["id"]] = r
            c = r.get("connections") or []
            print("%-8s %-36s %-10s conns=%d psk=%d orders=%d err=%s" % (
                board, row["id"], r["status"], len(c), sum(x["has_psk"] for x in c), len({tuple(x["ext_order"]) for x in c}),
                ((r.get("client") or {}).get("error") or "")[:80]), flush=True)
        cap = res.setdefault("capability", {})
        for lib, prof in CAPABILITY.get(board, []):
            if only and lib not in only.split(","):
                continue
            r = run_case(rec, port, board, dict(id="cap|%s|%s" % (lib, prof), library=lib, profile=prof), hdrs, n)
            c = r.get("connections") or []
            cap["%s|%s" % (lib, prof)] = dict(library=lib, profile=prof, status=r["status"], connections=len(c),
                                              resumed=sum(1 for x in c if x["has_psk"] and x.get("server_resumed")),
                                              error=(r.get("client") or {}).get("error"))
            print("capability %-8s %-22s %-18s resumed=%s/%d" % (board, lib, prof, cap["%s|%s" % (lib, prof)]["resumed"], len(c)), flush=True)
    data.update(generated_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), connections_per_row=n,
                endpoint="local capture/lib/server.py TCPServer (closes each connection after one response; TLS 1.3 session tickets on)")
    json.dump(data, open(OUT, "w"), indent=1)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
