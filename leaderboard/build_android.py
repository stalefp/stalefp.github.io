"""Grade libraries' Chrome-for-Android profiles against our real Chrome for Android capture
(capture/data/platforms/android.json, Android emulator, written by capture/merge_platforms.py).

  python leaderboard/build_android.py <run dir from run_android.sh>

Same row shape and rules as build_safari.py / build.py (diff, verdict incl. the less common Chrome variants, why lines,
HTTP/2 grade, versions behind = current Android Chrome major minus the profile's major). Only runs when the Android capture's
version was verified. A case that fails today keeps its previous result. Writes leaderboard/data/android_libraries.json.
"""
import datetime as dt, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "lib"))
import build as B   # noqa: E402
from fingerprint import normalize_echo  # noqa: E402
from adapter import adapt_chrome_reference  # noqa: E402

TB = os.path.dirname(HERE)
SRC = os.path.join(TB, "capture", "data", "platforms", "android.json")
OUT = os.path.join(HERE, "data", "android_libraries.json")
PY = "Python"
CASES = [
    dict(library="curl_cffi", maintainer="lexiforest", language=PY, profile="chrome131_android", raw="py/curl_cffi_chrome131_android", pkg="py:curl-cffi"),
    dict(library="curl_cffi", maintainer="lexiforest", language=PY, profile="chrome99_android", raw="py/curl_cffi_chrome99_android", pkg="py:curl-cffi"),
    dict(library="primp", maintainer="deedy5", language=PY, profile="chrome_146 (os android)", raw="py/primp_chrome_146_android", pkg="py:primp",
         note="desktop Chrome 146 profile with impersonate_os=\"android\""),
    dict(library="rnet", maintainer="0x676e67", language=PY, profile="Chrome145 (EmulationOS.Android)", raw="py/rnet_Chrome145_Android", pkg="py:rnet",
         note="desktop Chrome 145 emulation with emulation_os=Android"),
]


def to_and(text):
    return text.replace("Chrome's", "Chrome for Android's").replace("current Chrome", "current Chrome for Android") if text else text


def build(run):
    raw = json.load(open(SRC))
    if not (raw.get("android") or {}).get("version_verified"):
        print("Android capture version not verified; not grading"); return
    ref = adapt_chrome_reference(raw)
    rf = ref["fresh"]; cur = ref["major"]
    meta = json.load(open(os.path.join(run, "meta.json"))) if run and os.path.exists(os.path.join(run, "meta.json")) else {}
    prev = {l["id"]: l for l in json.load(open(OUT))["libraries"]} if os.path.exists(OUT) else {}
    vers = {}
    for line in open(os.path.join(HERE, "requirements.txt")):
        m = re.match(r"([A-Za-z0-9_.-]+)==(\S+)", line.strip())
        if m: vers["py:" + m.group(1).lower().replace("_", "-")] = m.group(2)
    libs = []
    for c in CASES:
        rid = ("android|%s|%s" % (c["library"], c["profile"].split(" ")[0])).lower().replace(" ", "-")
        p = os.path.join(run, c["raw"] + ".json") if run else None
        if not p or not os.path.exists(p):
            if rid in prev and prev[rid].get("verdict") != "not tested":
                libs.append(prev[rid]); continue
            err = os.path.join(run, c["raw"] + ".error.txt") if run else None
            libs.append(dict(id=rid, library=c["library"], maintainer=c["maintainer"], language=c["language"], profile=c["profile"], note=c.get("note"),
                             verdict="not tested", diff=[], missing=[], why=[], counted_mismatches=[], tested_at=None, fingerprint=None,
                             behind_text="Not tested yet.", not_tested=["everything: " + (open(err).read().strip()[:300] if err and os.path.exists(err) else "no capture found")]))
            continue
        fp = normalize_echo(json.load(open(p)))
        dfs = B.diff(rf, fp)
        per = {}
        for v in ref["variants"]:
            dv = B.diff(v["fingerprint"], fp)
            per[v["id"]] = dict(fields_exact=not B.counted_bad(dv), ja4_fresh=fp["ja4"] == v["ja4"], counted_mismatches=B.counted_bad(dv))
        vd, bad, why, mv = B.verdict(per, dfs)
        e = dict(id=rid, library=c["library"], maintainer=c["maintainer"], language=c["language"], profile=c["profile"], note=c.get("note"),
                 version=vers.get(c["pkg"]), tested_at=meta.get("started_at"), endpoint=meta.get("endpoint"),
                 sources={"fresh": os.path.relpath(p, TB)}, verdict=vd, verdict_reason=to_and(why), matched_variant=mv, counted_mismatches=bad, diff=dfs,
                 fingerprint=dict(ja4_fresh=fp["ja4"], ja4_r_fresh=fp["ja4_r"], http2_akamai=(fp.get("http2") or {}).get("akamai"), user_agent=fp.get("user_agent")),
                 matches=dict(http2=next(d for d in dfs if d["field"] == "http2_akamai")["status"] == "match",
                              variants={k: dict(ja4_fresh=v["ja4_fresh"], counted_mismatches=v["counted_mismatches"]) for k, v in per.items()}),
                 missing=[dict(i, label=to_and(i["label"])) for i in B.missing_items(rf, fp, dfs, None)],
                 not_tested=["TLS resumption (resumed JA4)", "extension-order shuffling", "HTTP/3 (QUIC) fingerprint"])
        m = re.search(r"(\d{2,3})", c["profile"])
        e["profile_chrome_major"] = int(m.group(1)) if m else None
        e["versions_behind"] = (cur - e["profile_chrome_major"]) if m else None
        e["versions_behind_uniform"] = True
        e["why"] = [to_and(x) for x in B.why_lines(e, rf, [])]
        e["http2_grade"] = B.http2_grade(e)
        e["behind_text"] = to_and(B.behind_text(e, cur))
        if e["versions_behind"] is not None and e["versions_behind"] < 0:   # profile newer than the Chrome we could capture (old image Chrome)
            e["behind_text"] = "Copies Chrome %d, newer than the Chrome for Android %d we captured; %s" % (
                e["profile_chrome_major"], cur, e["behind_text"].split("; ", 1)[-1])
        libs.append(e)
    for e in libs:
        peers = [x.get("profile_chrome_major") for x in libs if x["library"] == e["library"] and x.get("profile_chrome_major") is not None]
        e["is_newest_profile"] = e.get("profile_chrome_major") is None or e["profile_chrome_major"] == max(peers)
    order = {"exact": 0, "exact_variant": 1, "close": 2, "behind": 3, "not tested": 4}
    libs.sort(key=lambda e: (order.get(e["verdict"], 5), len(e.get("counted_mismatches") or []), e["library"], e["profile"]))
    an = raw["android"]
    data = dict(schema_version="android-leaderboard-1", generated_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                reference=dict(browser="Google Chrome (Android)", android_version=raw["version"], android_major=cur, captured_at=raw["captured_at"],
                               os=raw.get("os"), ja4_fresh=rf["ja4"], http2_akamai=(ref["http2"] or {}).get("akamai"), source="capture/data/platforms/android.json",
                               apk_source=an.get("source"), version_verified=an.get("version_verified")),
                verdict_rules="Same counted fields and thresholds as the Chrome leaderboard, against Chrome for Android's default fingerprint "
                              "(the less common no-ca34 and post-quantum variants count as 'Exact, less common variant').",
                caveats=["Libraries are tested against the public TLS echo endpoint (tls.peet.ws); real Chrome for Android is captured on an Android emulator "
                         "(Google Play system image, x86_64) against our local capture server. Both record the raw ClientHello and HTTP/2 frames.",
                         "Resumption, extension-order shuffling and HTTP/3 are not tested for the Android profiles yet."],
                libraries=libs)
    json.dump(data, open(OUT, "w"), indent=1)
    print("wrote %s (Chrome for Android %s)" % (OUT, raw["version"]))
    for l in libs:
        print("  %-14s %-44s %s" % (l["verdict"], l["library"] + " " + l["profile"], l.get("behind_text")))


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else None)
