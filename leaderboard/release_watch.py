#!/usr/bin/env python3
"""Re-test a library on the day it ships an update (.github/workflows/release-watch.yml).

  release_watch.py check            compare each tested library's newest release (PyPI / Go module proxy) with the pinned
                                    version; writes $RUNNER_TEMP-free JSON to stdout-file leaderboard/raw/release_updates.json
  release_watch.py bump             pin the new versions (leaderboard/requirements.txt, every harness go.mod)
  release_watch.py validate         after the re-run: every updated library must still have tested rows on both boards,
                                    at the new version; exit 1 otherwise
  release_watch.py record           append one event per updated library to leaderboard/data/release_log.json

A library is re-tested at most once a day (an event already logged today for it is skipped). Pre-releases only count
when the pinned version is itself a pre-release (rnet is pinned to a 3.0 release candidate).
"""
import datetime as dt, glob, json, os, re, subprocess, sys, urllib.request
from packaging.version import Version, InvalidVersion

HERE = os.path.dirname(os.path.abspath(__file__))
REQ = os.path.join(HERE, "requirements.txt")
GOMODS = sorted(glob.glob(os.path.join(HERE, "harness", "*", "go.mod")))
UPD = os.path.join(HERE, "raw", "release_updates.json")
LOG = os.path.join(HERE, "data", "release_log.json")
BOARDS = {"chrome": os.path.join(HERE, "data", "libraries.json"), "firefox": os.path.join(HERE, "data", "firefox_libraries.json")}
# leaderboard library name -> (ecosystem, package / module)
SOURCES = {
    "curl_cffi": ("pypi", "curl_cffi"), "primp": ("pypi", "primp"), "rnet": ("pypi", "rnet"),
    "noble-tls": ("pypi", "noble-tls"), "tls-client (Python)": ("pypi", "tls-client"),
    "tls-client": ("go", "github.com/bogdanfinn/tls-client"), "azuretls-client": ("go", "github.com/Noooste/azuretls-client"),
    "uTLS": ("go", "github.com/refraction-networking/utls"),
}
TODAY = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "stalefp-release-watch"}), timeout=30) as r:
        return json.load(r)


def V(s):
    try:
        return Version(s.lstrip("v"))
    except InvalidVersion:
        return None


def pinned():
    out = {}
    for line in open(REQ):
        m = re.match(r"\s*([A-Za-z0-9_.-]+)==(\S+)", line)
        if m:
            out[("pypi", m.group(1).lower().replace("_", "-"))] = m.group(2)
    for line in open(GOMODS[0]):
        m = re.match(r"\s*(github\.com/\S+)\s+(v\S+)", line)
        if m:
            out[("go", m.group(1).lower())] = m.group(2)
    return out


def latest(eco, pkg, cur):
    pre_ok = bool(V(cur) and V(cur).is_prerelease)
    if eco == "pypi":
        d = get("https://pypi.org/pypi/%s/json" % pkg)
        rel = {v: f for v, f in d["releases"].items() if f and not all(x.get("yanked") for x in f) and V(v) and (pre_ok or not V(v).is_prerelease)}
        best = max(rel, key=V)
        return best, min(x["upload_time_iso_8601"] for x in rel[best]), "https://pypi.org/project/%s/%s/" % (pkg, best)
    esc = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), pkg)
    d = get("https://proxy.golang.org/%s/@latest" % esc)
    if V(d["Version"]) and V(d["Version"]).is_prerelease and not pre_ok:
        vs = [v for v in urllib.request.urlopen("https://proxy.golang.org/%s/@v/list" % esc, timeout=30).read().decode().split() if V(v) and not V(v).is_prerelease]
        best = max(vs, key=V); d = get("https://proxy.golang.org/%s/@v/%s.info" % (esc, best))
    return d["Version"], d["Time"], "https://%s/releases/tag/%s" % (pkg.replace("github.com", "github.com", 1), d["Version"])


def load_log():
    return json.load(open(LOG)) if os.path.exists(LOG) else {"_format": "One event per library release we re-tested (leaderboard/release_watch.py).", "events": []}


def check():
    pins, log = pinned(), load_log()
    done_today = {e["library"] for e in log["events"] if e.get("retested_at", "")[:10] == TODAY}
    ups, report = [], []
    for lib, (eco, pkg) in SOURCES.items():
        key = (eco, pkg.lower().replace("_", "-") if eco == "pypi" else pkg.lower())
        cur = pins.get(key)
        try:
            new, when, url = latest(eco, pkg, cur or "")
        except Exception as e:
            print("::warning::%s: could not read the latest release (%s)" % (lib, e)); continue
        newer = bool(cur and V(new) and V(cur) and V(new) > V(cur))
        state = "NEW" if newer else "up to date"
        if newer and lib in done_today:
            state = "new, but already re-tested today"; newer = False
        report.append("%-22s pinned %-12s latest %-12s (%s) %s" % (lib, cur, new, when[:10], state))
        if newer:
            ups.append(dict(library=lib, ecosystem=eco, package=pkg, from_version=cur, to_version=new, released_at=when, url=url))
    print("\n".join(report))
    os.makedirs(os.path.dirname(UPD), exist_ok=True)
    json.dump(ups, open(UPD, "w"), indent=1)
    gh = os.environ.get("GITHUB_OUTPUT")
    if gh:
        open(gh, "a").write("updates=%d\n" % len(ups))
    return 0


def bump():
    ups = json.load(open(UPD))
    for u in ups:
        if u["ecosystem"] == "pypi":
            s = open(REQ).read()
            s2 = re.sub(r"(?im)^(%s)==\S+" % re.sub(r"[-_]", "[-_]", u["package"]), r"\g<1>==" + u["to_version"], s)
            assert s2 != s, "pin for %s not found" % u["package"]
            open(REQ, "w").write(s2)
        else:
            for gm in GOMODS:
                if u["package"].lower() in open(gm).read().lower():
                    subprocess.run(["go", "get", "%s@%s" % (u["package"], u["to_version"])], cwd=os.path.dirname(gm), check=True)
                    subprocess.run(["go", "mod", "tidy"], cwd=os.path.dirname(gm), check=True)
        print("pinned %s %s -> %s" % (u["library"], u["from_version"], u["to_version"]))
    return 0


def rows(board, lib):
    if not os.path.exists(BOARDS[board]):
        return []
    return [e for e in json.load(open(BOARDS[board]))["libraries"] if e["library"] == lib]


def validate():
    ups, bad = json.load(open(UPD)), []
    for u in ups:
        for board in BOARDS:
            rs = rows(board, u["library"])
            if not rs:
                continue
            for e in rs:
                if e["verdict"] == "not tested":
                    bad.append("%s board: %s %s was not tested" % (board, u["library"], e["profile"]))
                elif (e.get("version") or "").lstrip("v") != u["to_version"].lstrip("v"):
                    bad.append("%s board: %s %s still reports version %s, expected %s" % (board, u["library"], e["profile"], e.get("version"), u["to_version"]))
    for b in bad:
        print("::error title=Re-test check failed::" + b)
    return 1 if bad else 0


def summary(rs):
    VR = {"exact": 0, "exact_variant": 1, "close": 2, "behind": 3}
    t = [e for e in rs if e["verdict"] in VR]
    if not t:
        return None
    b = min(t, key=lambda e: (VR[e["verdict"]], len(e.get("counted_mismatches") or [])))
    return dict(best_profile=b["profile"], verdict=b["verdict"], counted_diffs=len(b.get("counted_mismatches") or []),
                versions_behind=b.get("versions_behind"), matches=b["verdict"] == "exact")


def record(before_dir):
    ups, log = json.load(open(UPD)), load_log()
    for u in ups:
        ev = dict(library=u["library"], from_version=u["from_version"], version=u["to_version"], released_at=u["released_at"],
                  release_url=u["url"], retested_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  run=os.environ.get("RUN_URL"), boards={})
        for board, path in BOARDS.items():
            prev = os.path.join(before_dir, os.path.basename(path))
            old = [e for e in json.load(open(prev))["libraries"] if e["library"] == u["library"]] if os.path.exists(prev) else []
            a, b = summary(old), summary(rows(board, u["library"]))
            if b is None:
                continue
            ev["boards"][board] = dict(before=a, after=b, gap_closed=bool(b["matches"] and not (a or {}).get("matches")),
                                       improved=bool(a and b["counted_diffs"] < a["counted_diffs"]))
        ev["gap_closed"] = any(x["gap_closed"] for x in ev["boards"].values())
        log["events"].append(ev)
        print("recorded %s %s: %s" % (u["library"], u["to_version"], {k: (v["after"]["verdict"], v["after"]["counted_diffs"]) for k, v in ev["boards"].items()}))
    json.dump(log, open(LOG, "w"), indent=1)
    return 0


def libs():
    """Board library names that have a new release (for STALE_LIBS, which limits every harness to those libraries)."""
    print(",".join(u["library"] for u in json.load(open(UPD))))
    return 0


def merge(before_dir):
    """After a re-test limited to the updated libraries (STALE_LIBS): keep their new rows, and put every other library's
    rows back from before the run, so a partial run never drops or 'not tested's the libraries it skipped."""
    upd = {u["library"] for u in json.load(open(UPD))}
    for board, path in BOARDS.items():
        prev = os.path.join(before_dir, os.path.basename(path))
        if not (os.path.exists(prev) and os.path.exists(path)):
            continue
        old, new = json.load(open(prev)), json.load(open(path))
        fresh = {e["id"]: e for e in new["libraries"] if e["library"] in upd}
        rows = [fresh.pop(e["id"], e) if e["library"] in upd else e for e in old["libraries"]] + list(fresh.values())
        new["libraries"] = rows
        json.dump(new, open(path, "w"), indent=1)
        print("%s board: %d rows re-tested (%s), %d kept from before" % (board, sum(e["library"] in upd for e in rows), ", ".join(sorted(upd)),
                                                                       sum(e["library"] not in upd for e in rows)))
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    fn = {"check": check, "bump": bump, "validate": validate, "libs": libs}.get(cmd)
    sys.exit(fn() if fn else merge(sys.argv[2]) if cmd == "merge" else record(sys.argv[2]))
