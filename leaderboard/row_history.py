"""Per-row status history: leaderboard/data/row_history.json.

One entry per (UTC) day: Chrome version compared against and, per row id, verdict / versions_behind / counted
mismatches, copied from that day's libraries.json. Nothing is interpolated: days without a libraries.json are absent.

  python leaderboard/row_history.py --seed   rebuild from the git history of leaderboard/data/libraries.json
  record(data)                               called by build.py after each build (replaces today's entry)
"""
import json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "row_history.json")
FMT = ("One entry per UTC day, newest build of that day. rows[id] = {verdict, versions_behind, mismatches} from that day's "
       "leaderboard/data/libraries.json. Seeded from git history of that file; appended by leaderboard/build.py.")


def snapshot(data, source):
    rows = {l["id"]: dict(verdict=l.get("verdict"), versions_behind=l.get("versions_behind"),
                          mismatches=len(l.get("counted_mismatches") or []) if l.get("verdict") != "not tested" else None)
            for l in data.get("libraries") or []}
    ref = data.get("reference") or {}
    return dict(date=(data.get("generated_at") or "")[:10], chrome_version=ref.get("chrome_version"), rows=rows, source=source)


def load():
    return json.load(open(OUT)) if os.path.exists(OUT) else {"_format": FMT, "entries": []}


def save(h):
    h["entries"].sort(key=lambda e: e["date"])
    json.dump(h, open(OUT, "w"), indent=1)


def record(data, source="build"):
    s = snapshot(data, source)
    if not s["date"]:
        return
    h = load()
    h["entries"] = [e for e in h["entries"] if e["date"] != s["date"]] + [s]
    save(h)


def seed():
    rel = "leaderboard/data/libraries.json"
    commits = subprocess.check_output(["git", "log", "--reverse", "--format=%h", "--", rel], cwd=os.path.dirname(HERE), text=True).split()
    by_day = {}
    for c in commits:
        try:
            d = json.loads(subprocess.check_output(["git", "show", f"{c}:{rel}"], cwd=os.path.dirname(HERE), text=True))
        except Exception:
            continue
        s = snapshot(d, "git " + c)
        if s["date"]:
            by_day[s["date"]] = s      # later commit of the same day wins
    h = load()
    keep = {e["date"]: e for e in h["entries"]}
    keep.update(by_day)
    h["entries"] = list(keep.values())
    save(h)
    print("row_history: %d days" % len(h["entries"]))


if __name__ == "__main__":
    if "--seed" in sys.argv:
        seed()
