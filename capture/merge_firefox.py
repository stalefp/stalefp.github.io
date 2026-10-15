"""Merge per-OS Firefox captures (CI artifacts firefox-<id>/latest.json) into capture/data/firefox/.

  python capture/merge_firefox.py --artifacts ff-artifacts

Writes (only from captures that exist; an OS that failed keeps its previous file and is marked stale in the index):
  capture/data/firefox/latest.json             Linux capture (the reference the Firefox leaderboard is graded against)
  capture/data/firefox/platforms/<os>.json      linux / windows / macos
  capture/data/firefox/platforms/index.json     per-OS summary
  capture/data/firefox/history/<file> + index.json   dated Linux captures (one per day, newest of the day wins)
"""
import argparse, glob, json, os, shutil
HERE = os.path.dirname(os.path.abspath(__file__))
FF = os.path.join(HERE, "data", "firefox")
OSES = [("linux", "Linux"), ("windows", "Windows"), ("macos", "macOS")]


def summary(d, status):
    h3 = d.get("http3") or {}
    return dict(status=status, version=d.get("version"), captured_at=d.get("captured_at"), os=d.get("os"), ja4=d.get("ja4"),
                ja4_resumed=d.get("ja4_resumed"), h2_akamai=d.get("h2_akamai") or (d.get("http2") or {}).get("akamai"),
                quic_ja4=h3.get("ja4"), user_agent=d.get("user_agent"))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--artifacts", default="ff-artifacts"); a = ap.parse_args()
    os.makedirs(os.path.join(FF, "platforms"), exist_ok=True); os.makedirs(os.path.join(FF, "history"), exist_ok=True)
    idx = {"platforms": {}}
    for pid, label in OSES:
        src = os.path.join(a.artifacts, "firefox-" + pid, "latest.json")
        dst = os.path.join(FF, "platforms", pid + ".json")
        status = None
        if os.path.exists(src):
            try:
                d = json.load(open(src))
                assert d.get("browser") == "Mozilla Firefox" and d.get("ja4"), "not a Firefox capture"
                shutil.copy(src, dst); status = "captured"
            except Exception as e:
                print("firefox %s: bad capture (%s); keeping previous" % (pid, e))
        if status is None and pid == "linux" and not os.path.exists(dst) and os.path.exists(os.path.join(FF, "latest.json")):
            shutil.copy(os.path.join(FF, "latest.json"), dst)   # first run after the move from the publish job
        if os.path.exists(dst):
            idx["platforms"][pid] = dict(summary(json.load(open(dst)), status or "previous (today's capture failed)"), label=label)
        else:
            idx["platforms"][pid] = dict(status="not captured yet", label=label)
        print("firefox %s: %s" % (pid, idx["platforms"][pid]["status"]))
    json.dump(idx, open(os.path.join(FF, "platforms", "index.json"), "w"), indent=1)
    lin = os.path.join(FF, "platforms", "linux.json")
    if os.path.exists(lin) and idx["platforms"]["linux"]["status"] == "captured":
        shutil.copy(lin, os.path.join(FF, "latest.json"))
    if os.path.exists(os.path.join(FF, "latest.json")):
        record_history(json.load(open(os.path.join(FF, "latest.json"))))


def record_history(d):
    os.makedirs(os.path.join(FF, "history"), exist_ok=True)
    hi = os.path.join(FF, "history", "index.json")
    h = json.load(open(hi)) if os.path.exists(hi) else {"note": "Dated Firefox captures (Linux), one per day; same layout as ../latest.json.", "captures": []}
    day = d["captured_at"][:10]
    fn = "firefox-%s-%s.json" % (d["version"], day)
    for old in [c for c in h["captures"] if c["captured_at"][:10] == day and c["file"] != fn]:
        try: os.remove(os.path.join(FF, "history", old["file"]))
        except OSError: pass
    h["captures"] = [c for c in h["captures"] if c["captured_at"][:10] != day]
    json.dump(d, open(os.path.join(FF, "history", fn), "w"), indent=1)
    h["captures"].append(dict(file=fn, firefox_version=d["version"], captured_at=d["captured_at"], ja4=d["ja4"]))
    h["captures"].sort(key=lambda c: c["captured_at"])
    json.dump(h, open(hi, "w"), indent=1)




def seed_from_git():
    """Backfill history from the git history of capture/data/firefox/latest.json (CI captures only)."""
    import subprocess
    root = os.path.dirname(HERE); rel = "capture/data/firefox/latest.json"
    for c in subprocess.check_output(["git", "log", "--reverse", "--format=%h", "--", rel], cwd=root, text=True).split():
        try:
            record_history(json.loads(subprocess.check_output(["git", "show", "%s:%s" % (c, rel)], cwd=root, text=True)))
        except Exception as e:
            print("skip", c, e)


if __name__ == "__main__":
    import sys
    if "--seed-history" in sys.argv:
        seed_from_git()
    else:
        main()
