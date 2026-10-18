"""Grade libraries' desktop Safari profiles against the real Safari capture (capture/data/safari/latest.json, macOS runner).

  python leaderboard/build_safari.py <run dir from run_safari.sh>

A copy of build_firefox.py with Safari's cases and reference. Writes leaderboard/data/safari_libraries.json, same row shape as libraries.json (verdict, diff, missing, why,
behind_text, versions_behind, http2_grade, fingerprint) so the site and badges reuse the Chrome code. Uses build.py's
diff/verdict rules unchanged. A case that fails today keeps its previous result (with its old tested_at), never a guess.
"""
import datetime as dt, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build as B   # noqa: E402  (diff, counted_bad, verdict, missing_items, why_lines, http2_grade, behind_text)
from fingerprint import normalize_echo, split_ja4_r  # noqa: E402
from adapter import _fingerprint  # noqa: E402

TB = os.path.dirname(HERE)
FF = os.path.join(TB, "capture", "data", "safari")
OUT = os.path.join(HERE, "data", "safari_libraries.json")
PY = "Python"
CASES = [
    dict(library="tls-client", maintainer="bogdanfinn", language="Go", profile="Safari_16_0", raw="go/out/tls-client(go)_Safari_16_0", pkg="go:github.com/bogdanfinn/tls-client"),
    dict(library="tls-client", maintainer="bogdanfinn", language="Go", profile="Safari_15_6_1", raw="go/out/tls-client(go)_Safari_15_6_1", pkg="go:github.com/bogdanfinn/tls-client"),
    dict(library="azuretls-client", maintainer="Noooste", language="Go", profile="Safari", raw="go/out/azuretls_Safari", pkg="go:github.com/noooste/azuretls-client"),
    dict(library="uTLS", maintainer="refraction-networking", language="Go", profile="HelloSafari_Auto", raw="go/out/utls_HelloSafari_Auto", pkg="go:github.com/refraction-networking/utls",
         note="HTTP/2 via golang.org/x/net/http2 (uTLS is TLS-only)"),
    dict(library="curl_cffi", maintainer="lexiforest", language=PY, profile="safari2601", raw="py/curl_cffi_safari2601", pkg="py:curl-cffi"),
    dict(library="curl_cffi", maintainer="lexiforest", language=PY, profile="safari184", raw="py/curl_cffi_safari184", pkg="py:curl-cffi"),
    dict(library="rnet", maintainer="0x676e67", language=PY, profile="Safari26_2", raw="py/rnet_Safari26_2", pkg="py:rnet"),
    dict(library="rnet", maintainer="0x676e67", language=PY, profile="Safari18_5", raw="py/rnet_Safari18_5", pkg="py:rnet"),
    dict(library="primp", maintainer="deedy5", language=PY, profile="safari_26", raw="py/primp_safari_26", pkg="py:primp"),
    dict(library="noble-tls", maintainer="Nitrams", language=PY, profile="safari_16_0", raw="py/noble-tls_safari_16_0", pkg="py:noble-tls", note="wraps Go tls-client"),
    dict(library="tls-client (Python)", maintainer="FlorianREGAZ", language=PY, profile="safari_16_0", raw="py/tls-client(py)_safari_16_0", pkg="py:tls-client", note="wraps Go tls-client"),
]


def ff_reference(d):
    """Map a Safari capture onto the adapter's fingerprint shape (same fields the Chrome reference uses)."""
    cfg = dict(ja4=d["ja4"], ja4_r=d["ja4_r"], sig_algs=d.get("sig_algs"), groups=d.get("groups"), key_shares=d.get("key_shares"),
               alps_codepoint=d.get("alps_codepoint") or next((x for x in d.get("extensions") or [] if x.lower() in ("0x4469", "0x44cd")), None),
               cert_compression=d.get("cert_compression"),
               has_trust_anchors=d.get("has_trust_anchors", "0xca34" in [x.lower() for x in d.get("extensions") or []]),
               h2_akamai=d.get("h2_akamai") or (d.get("http2") or {}).get("akamai"),
               header_order=d.get("header_order") or (d.get("http2") or {}).get("header_order"), user_agent=d.get("user_agent"))
    return _fingerprint(cfg)


def timeline():
    idx = os.path.join(FF, "history", "index.json")
    out = {}
    for c in (json.load(open(idx))["captures"] if os.path.exists(idx) else []):
        try:
            d = json.load(open(os.path.join(FF, "history", c["file"])))
            out[int(d["version"].split(".")[0])] = (d["version"], ff_reference(d))
        except Exception:
            pass
    return [(m, v, f) for m, (v, f) in sorted(out.items())]


def to_ff(text):
    return text.replace("Chrome's", "Safari's").replace("Chrome", "Safari") if text else text


def detail(line, dfs):
    """Name the actual items behind the generic cipher / group lines (from the same diff)."""
    d = {x["field"]: x for x in dfs}
    j = lambda xs: ", ".join(str(x) for x in xs)
    if line.startswith("Cipher suites differ") and d.get("ciphers"):
        c = d["ciphers"]; parts = []
        if c.get("extra"): parts.append("sends %s, which Safari doesn't" % j("0x" + x for x in c["extra"]))
        if c.get("missing"): parts.append("doesn't send %s" % j("0x" + x for x in c["missing"]))
        return "Cipher suites differ: " + "; ".join(parts) + "." if parts else line
    if line.startswith("Supported groups differ") and d.get("supported_groups"):
        g = d["supported_groups"]; parts = []
        if g.get("extra"): parts.append("offers %s, which Safari doesn't" % j("%s (0x%s)" % (B.GROUP_NAMES.get(x, "?"), x) for x in g["extra"]))
        if g.get("missing"): parts.append("doesn't offer %s" % j("%s (0x%s)" % (B.GROUP_NAMES.get(x, "?"), x) for x in g["missing"]))
        if not parts and g.get("note"): parts.append(g["note"])
        return "Supported groups differ: " + "; ".join(parts) + "." if parts else line
    return line


def go_versions():
    v = {}
    for line in open(os.path.join(HERE, "harness", "gosafari", "go.mod")):
        m = re.match(r"\s*(github\.com/\S+)\s+(v\S+)", line)
        if m: v["go:" + m.group(1).lower()] = m.group(2)
    for line in open(os.path.join(HERE, "requirements.txt")):
        m = re.match(r"([A-Za-z0-9_.-]+)==(\S+)", line.strip())
        if m: v["py:" + m.group(1).lower().replace("_", "-")] = m.group(2)
    return v


def build(run):
    raw = json.load(open(os.path.join(FF, "latest.json")))
    rf = ff_reference(raw)
    cur = int(raw["version"].split(".")[0])
    meta = json.load(open(os.path.join(run, "meta.json"))) if run and os.path.exists(os.path.join(run, "meta.json")) else {}
    prev = {l["id"]: l for l in json.load(open(OUT))["libraries"]} if os.path.exists(OUT) else {}
    vers, tl = go_versions(), timeline()
    if run and os.path.exists(os.path.join(run, "ext", "_versions.json")):
        vers.update(json.load(open(os.path.join(run, "ext", "_versions.json"))))
    libs = []
    for c in CASES:
        rid = ("%s|%s" % (c["library"], c["profile"])).lower().replace(" ", "-")
        p = os.path.join(run, c["raw"] + ".json") if run else None
        if not p or not os.path.exists(p):
            err = os.path.join(run, c["raw"] + ".error.txt") if run else None
            if rid in prev and prev[rid].get("verdict") != "not tested":
                old = prev[rid]; old.setdefault("not_tested", []); libs.append(old); continue
            libs.append(dict(id=rid, library=c["library"], maintainer=c["maintainer"], language=c["language"], profile=c["profile"], note=c.get("note"),
                             verdict="not tested", diff=[], missing=[], why=[], counted_mismatches=[], tested_at=None, fingerprint=None,
                             behind_text="Not tested yet.", not_tested=["everything: " + ("the newest harness run failed: " + open(err).read().strip()[:300]
                                                                           if err and os.path.exists(err) else "no capture found")]))
            continue
        fp = normalize_echo(json.load(open(p)))
        dfs = B.diff(rf, fp)
        vd, bad, why, _ = B.verdict({}, dfs)
        e = dict(id=rid, library=c["library"], maintainer=c["maintainer"], language=c["language"], profile=c["profile"], note=c.get("note"),
                 version=vers.get(c["pkg"]), tested_at=meta.get("started_at"), endpoint=meta.get("endpoint"),
                 sources={"fresh": os.path.relpath(p, TB)}, verdict=vd, verdict_reason=to_ff(why), counted_mismatches=bad, diff=dfs,
                 fingerprint=dict(ja4_fresh=fp["ja4"], ja4_r_fresh=fp["ja4_r"], http2_akamai=(fp.get("http2") or {}).get("akamai"),
                                  user_agent=fp.get("user_agent")),
                 matches=dict(http2=next(d for d in dfs if d["field"] == "http2_akamai")["status"] == "match", variants={"default": dict(ja4_fresh=fp["ja4"] == rf["ja4"])}),
                 missing=[dict(i, label=to_ff(i["label"])) for i in B.missing_items(rf, fp, dfs, None)],
                 not_tested=["TLS resumption (resumed JA4)", "HTTP/3 (QUIC) fingerprint"])
        m = re.search(r"(\d\d)", c["profile"])   # safari2601 -> 26, Safari18_5 -> 18, Safari_15_6_1 -> 15
        e["profile_chrome_major"] = int(m.group(1)) if m else None   # field name shared with the Chrome rows (= profile's browser major)
        e["versions_behind"] = (cur - e["profile_chrome_major"]) if m else None
        e["versions_behind_uniform"] = True
        e["why"] = [detail(w, dfs) for w in (to_ff(x) for x in B.why_lines(e, rf, tl))]
        e["http2_grade"] = B.http2_grade(e)
        e["behind_text"] = to_ff(B.behind_text(e, cur))
        libs.append(e)
    for e in libs:
        peers = [x.get("profile_chrome_major") for x in libs if x["library"] == e["library"] and x.get("profile_chrome_major") is not None]
        e["is_newest_profile"] = e.get("profile_chrome_major") is None or e["profile_chrome_major"] == max(peers)
    order = {"exact": 0, "close": 2, "behind": 3, "not tested": 4}
    libs.sort(key=lambda e: (order.get(e["verdict"], 5), len(e.get("counted_mismatches") or []), e["language"], e["library"], e["profile"]))
    data = dict(schema_version="safari-leaderboard-1", generated_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                reference=dict(browser="Apple Safari", safari_version=raw["version"], safari_major=cur, captured_at=raw["captured_at"],
                               os=raw.get("os"), ja4_fresh=rf["ja4"], http2_akamai=rf["http2"]["akamai"], source="capture/data/safari/latest.json"),
                verdict_rules="Same counted fields and thresholds as the Chrome leaderboard, against Safari's default fingerprint. "
                              "Versions behind = current Safari major minus the major in the profile name.",
                caveats=["Libraries are tested against the public TLS echo endpoint (tls.peet.ws); real Safari (preinstalled on the GitHub macOS runner, driven by safaridriver) is captured against our local capture server. Both record the raw ClientHello and HTTP/2 frames.",
                         "Resumption, extension-order shuffling and header order come from the behaviour probe (leaderboard/harness/probe.py): 8 requests per row on one client against our local capture server, which closes each connection, with the browser's captured header set passed in the browser's order. Header order counts toward the verdict only where the exact header set arrived in the same order on every request.",
                         "Only desktop (macOS) Safari profiles are graded; iOS/iPadOS profiles have no real-device capture to compare against. HTTP/3 is not tested for Safari."],
                libraries=libs)
    annotate(data)
    json.dump(data, open(OUT, "w"), indent=1)
    print("wrote %s (Safari %s)" % (OUT, raw["version"]))
    for l in libs:
        print("  %-12s %-34s %s" % (l["verdict"], l["library"] + " " + l["profile"], l.get("behind_text")))


NOTES = os.path.join(HERE, "safari_notes.json")
VR = {"exact": 0, "close": 2, "behind": 3}


def annotate(data):
    """Hand-written notes (safari_notes.json) + one-line fix: only when another tested profile of the same library has
    strictly fewer counted differences from Safari (same rule and call templates as the Chrome board, build.FIX_TEMPLATES)."""
    import probe_grade
    probe_grade.apply("safari", data, "Safari")
    notes = json.load(open(NOTES)) if os.path.exists(NOTES) else {}
    notes = {k: v for k, v in notes.items() if not k.startswith("_")}
    rank = lambda x: (len(x.get("counted_mismatches") or []), VR.get(x["verdict"], 9))
    for e in data["libraries"]:
        n = notes.get(e["id"]) or notes.get(e["library"])
        e["notes"] = ([n] if isinstance(n, str) else list(n)) if n else []
        e["fix"] = None
        peers = [x for x in data["libraries"] if x["library"] == e["library"] and x["verdict"] in VR]
        best = min(peers, key=rank) if peers else None
        if best and best is not e and e["verdict"] in VR and rank(best) < rank(e) and e["library"] in B.FIX_TEMPLATES:
            t = B.FIX_TEMPLATES[e["library"]]
            e["fix"] = dict(to_id=best["id"], to_profile=best["profile"], to_verdict=best["verdict"],
                            from_diffs=len(e["counted_mismatches"]), to_diffs=len(best["counted_mismatches"]),
                            old=t % e["profile"], new=t % best["profile"])
    B.release_updates(data, "Safari")
    return data


if __name__ == "__main__":
    if "--annotate-only" in sys.argv:
        d = annotate(json.load(open(OUT)))
        json.dump(d, open(OUT, "w"), indent=1)
        for l in d["libraries"]:
            print(" ", l["id"], "| fix:", (l["fix"] or {}).get("new"), "|", l["notes"])
    else:
        build(sys.argv[1] if len(sys.argv) > 1 else None)
