"""Build leaderboard/data/libraries.json from real harness captures + the Chrome reference.

Reference: capture/data/latest.json (Moe's branded-Chrome capture, capture/SCHEMA.md) via lib/adapter.py. Three real
Chrome variants are compared: default (with ca34), without ca34, post-quantum experiment (0x12e0).

Sources (newest wins, per case):
  1. leaderboard/raw/<run>/   written by run.sh (live re-run of the existing harness; h3/ = HTTP/3 run, harness/run_h3.py)
  2. legacy result files      gobench/out/*.json and results.json from the 2026-09-26 run (only on the original box;
                              not in the public repo, so absent cases there are simply "not tested")
Nothing is invented: a value that was not measured is null and marked "not tested".
"""
import datetime as dt, glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
TLSBENCH = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "lib"))
from fingerprint import (normalize_echo, normalize_legacy_summary, ja4_from_parts, split_ja4_r,
                         EXT_NAMES, SIGALG_NAMES, GROUP_NAMES, ML_DSA, MLKEM, CA34, ALPS_CODES)
from adapter import adapt_chrome_reference

MOE_LATEST = os.path.join(TLSBENCH, "capture", "data", "latest.json")
OUT = os.path.join(HERE, "data", "libraries.json")

PY = "Python"
# kind: where the fresh capture comes from. py = bench.py cases, go = gobench, resume = goresume_raw
CASES = [
    dict(library="tls-client", maintainer="bogdanfinn", language="Go", profile="Chrome_152_PSK", pkg=("go", "github.com/bogdanfinn/tls-client"),
         h3=("h3", "tls-client(go)_Chrome_152_PSK"), fresh=("resume", "tls-client(go)_Chrome_152_PSK_req1"), resumed=("resume", ["tls-client(go)_Chrome_152_PSK_req2", "tls-client(go)_Chrome_152_PSK_req3"])),
    dict(library="tls-client", maintainer="bogdanfinn", language="Go", profile="Chrome_152", pkg=("go", "github.com/bogdanfinn/tls-client"),
         h3=("h3", "tls-client(go)_Chrome_152"), fresh=("go", "tls-client(go)_Chrome_152"), resumed=("resume", ["tls-client(go)_Chrome_152_req2", "tls-client(go)_Chrome_152_req3"])),
    dict(library="tls-client", maintainer="bogdanfinn", language="Go", profile="Chrome_150", pkg=("go", "github.com/bogdanfinn/tls-client"),
         fresh=("go", "tls-client(go)_Chrome_150"), h3=("h3", "tls-client(go)_Chrome_150")),
    dict(library="azuretls-client", maintainer="Noooste", language="Go", profile="Chrome", pkg=("go", "github.com/Noooste/azuretls-client"),
         fresh=("go", "azuretls_Chrome"), h3=("h3", "azuretls_Chrome")),
    dict(library="uTLS", maintainer="refraction-networking", language="Go", profile="HelloChrome_Auto", pkg=("go", "github.com/refraction-networking/utls"),
         no_h3="uTLS is a TLS-only library (no QUIC/HTTP/3 client); the harness pairs it with golang.org/x/net/http2", fresh=("go", "utls_HelloChrome_Auto"), note="HTTP/2 via golang.org/x/net/http2 (uTLS is TLS-only)"),
    dict(library="curl_cffi", maintainer="lexiforest", language=PY, profile="chrome150", pkg=("py", "curl_cffi"), fresh=("py", "curl_cffi_chrome150"), h3=("h3", "curl_cffi_chrome150"), note="binds curl-impersonate (C/BoringSSL)"),
    dict(library="curl_cffi", maintainer="lexiforest", language=PY, profile="chrome146", pkg=("py", "curl_cffi"), fresh=("py", "curl_cffi_chrome146"), h3=("h3", "curl_cffi_chrome146"), note="binds curl-impersonate (C/BoringSSL)"),
    dict(library="curl_cffi", maintainer="lexiforest", language=PY, profile="chrome136", pkg=("py", "curl_cffi"), fresh=("py", "curl_cffi_chrome136"), h3=("h3", "curl_cffi_chrome136"), note="binds curl-impersonate (C/BoringSSL)"),
    dict(library="primp", maintainer="deedy5", language=PY, profile="chrome_146", pkg=("py", "primp"), no_h3="primp 2.0.1 has no HTTP/3 option and its binary contains no HTTP/3 stack", fresh=("py", "primp_chrome_146"), note="Rust core"),
    dict(library="rnet", maintainer="0x676e67", language=PY, profile="Chrome145", pkg=("py", "rnet"), no_h3="rnet 3.0.0rc22 has no HTTP/3 option and its binary contains no HTTP/3 stack", fresh=("py", "rnet_Chrome145"), note="Rust core (wreq)"),
    dict(library="rnet", maintainer="0x676e67", language=PY, profile="Chrome137", pkg=("py", "rnet"), no_h3="rnet 3.0.0rc22 has no HTTP/3 option and its binary contains no HTTP/3 stack", fresh=("py", "rnet_Chrome137"), note="Rust core (wreq)"),
    dict(library="noble-tls", maintainer="Nitrams", language=PY, profile="chrome_146", pkg=("py", "noble-tls"), fresh=("py", "noble-tls_chrome_146"), h3=("h3", "noble-tls_chrome_146"), note="wraps Go tls-client"),
    dict(library="tls-client (Python)", maintainer="FlorianREGAZ", language=PY, profile="chrome_120", pkg=("py", "tls-client"), no_h3="tls-client (Python) 1.0.1 bundles Go tls-client v1.7.2, which has no HTTP/3 support", fresh=("py", "tls-client(py)_chrome_120"), note="wraps Go tls-client"),
]

def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pct(share):
    if share is None:
        return None
    p = share * 100
    return ("%d%%" % round(p)) if abs(p - round(p)) < 0.05 else ("%.1f%%" % p)


# ---------------------------------------------------------------- reference
def load_reference():
    """Chrome reference from Moe's capture/data/latest.json (SCHEMA.md). The assumed-schema stand-in is superseded and
    only used if latest.json is missing (it has no variants, so the build stops rather than guess)."""
    if not os.path.exists(MOE_LATEST):
        sys.exit("capture/data/latest.json not found. The assumed-schema stand-in (ASSUMED_SCHEMA.md) is superseded; "
                 "run capture/run_capture.sh first.")
    raw = json.load(open(MOE_LATEST))
    ref = adapt_chrome_reference(raw)
    ref["source"] = os.path.relpath(MOE_LATEST, TLSBENCH)
    for v in ref["variants"]:
        f = v["fingerprint"]
        a, c, e, s = split_ja4_r(f["ja4_r"])
        assert ja4_from_parts(a, c, e, s) == f["ja4"], "Chrome %s JA4 does not recompute from its ja4_r" % v["id"]
    ids = [v["id"] for v in ref["variants"]]
    assert ids[0] == "default", "latest.json has no reference_config (default) fingerprint"
    return ref


def stable_info(ref):
    """Per-platform Chrome stable from latest.json current_stable (Google VersionHistory API at capture time)."""
    out = {}
    for p in ("linux", "win", "mac"):
        cs = (ref.get("current_stable") or {}).get(p) or {}
        full, newest = cs.get("highest_full_rollout"), cs.get("newest")
        partial = []
        for r in cs.get("releases") or []:
            if full and int(r["version"].split(".")[0]) > int(full.split(".")[0]):
                partial.append(dict(version=r["version"], fraction=r.get("fraction"), fraction_group=r.get("fraction_group"),
                                    rollout_tags=r.get("rollout_tags"), serving_since=r.get("serving_since")))
        out[p] = dict(highest_full_rollout=full, full_major=int(full.split(".")[0]) if full else None, newest=newest,
                      newest_major=int(newest.split(".")[0]) if newest else None, partial_newer_majors=partial, error=cs.get("error"))
    return out

def platform_caveat():
    """Which OSes have a Chrome capture (capture/data/platforms/index.json, written by capture/merge_platforms.py)."""
    try:
        idx = json.load(open(os.path.join(TLSBENCH, "capture", "data", "platforms", "index.json")))
        have = [s["label"] for p, s in idx["platforms"].items() if s.get("status") == "captured" and p != "linux"]
        missing = [s["label"] for p, s in idx["platforms"].items() if s.get("status") != "captured" and p != "linux"]
    except Exception:
        have, missing = [], ["Windows", "macOS"]
    txt = "Verdicts compare against the Linux Chrome capture."
    if have:
        txt += " %s Chrome %s captured separately and shown next to Linux; libraries are not scored against %s." % (
            " and ".join(have), "is" if len(have) == 1 else "are", "it" if len(have) == 1 else "them")
    if missing:
        txt += " %s Chrome %s not been captured yet and may differ (often mid-rollout at another version)." % (
            " and ".join(missing), "has" if len(missing) == 1 else "have")
    return txt


# ---------------------------------------------------------------- captures
def runs():
    """Harness runs, newest first."""
    out = []
    for m in sorted(glob.glob(os.path.join(HERE, "raw", "*", "meta.json")), reverse=True):
        meta = json.load(open(m))
        meta["dir"] = os.path.dirname(m)
        out.append(meta)
    return out


def legacy_versions():
    v = {}
    for line in open(os.path.join(HERE, "harness", "gobench", "go.mod")):
        m = re.match(r"\s*(github\.com/\S+)\s+(v\S+)", line)
        if m:
            v["go:" + m.group(1).lower()] = m.group(2)
    for di in glob.glob(os.path.join(TLSBENCH, ".venv", "lib", "python*", "site-packages", "*.dist-info")):
        name, ver = os.path.basename(di)[:-10].rsplit("-", 1)
        v["py:" + name.lower().replace("_", "-")] = ver
    return v


LEGACY_RESULTS = None


def find_capture(kind, name, all_runs):
    """Return (raw_or_None, fp, meta) for the newest capture of this case."""
    global LEGACY_RESULTS
    sub = {"py": "py", "go": "go/out", "resume": "resume", "h3": "h3"}[kind]
    for r in all_runs:
        p = os.path.join(r["dir"], sub, name + ".json")
        if os.path.exists(p):
            if kind == "h3":  # raw run_h3.py record (QUIC ClientHello summary + h3 SETTINGS), not an echo response
                d = json.load(open(p))
                return d, dict(path=os.path.relpath(p, TLSBENCH), tested_at=d.get("tested_at") or r["started_at"],
                               endpoint=d.get("endpoint"), versions=r.get("versions", {}), run=os.path.basename(r["dir"]))
            return normalize_echo(json.load(open(p))), dict(path=os.path.relpath(p, TLSBENCH), tested_at=r["started_at"],
                                                            endpoint=r.get("endpoint"), versions=r.get("versions", {}), run=os.path.basename(r["dir"]))
    if kind == "h3":
        return None, None
    lv = legacy_versions()
    if kind == "go":
        p = os.path.join(TLSBENCH, "gobench", "out", name + ".json")
        if os.path.exists(p):
            return normalize_echo(json.load(open(p))), dict(path=os.path.relpath(p, TLSBENCH), tested_at=iso(os.path.getmtime(p)),
                                                            endpoint="https://tls.peet.ws/api/all", versions=lv, run="legacy")
    if kind == "py":
        if LEGACY_RESULTS is None:
            lp = os.path.join(TLSBENCH, "results.json")
            LEGACY_RESULTS = json.load(open(lp)) if os.path.exists(lp) else {"results": []}
        for res in LEGACY_RESULTS["results"]:
            if f"{res['lib']}_{res['profile']}" == name and res.get("ok"):
                p = os.path.join(TLSBENCH, "results.json")
                return normalize_legacy_summary(res["fp"]), dict(path="results.json", tested_at=iso(os.path.getmtime(p)),
                                                                 endpoint="https://tls.peet.ws/api/all", versions=lv, run="legacy")
    return None, None


# ---------------------------------------------------------------- diff
def names(codes, table):
    return [f"{c} {table.get(c, '')}".strip() for c in codes] if codes is not None else None


def field(fid, label, chrome, lib, counts=True, table=None, ordered=True, note=None):
    if lib is None or chrome is None:
        status = "not_tested"
    else:
        same = chrome == lib if ordered else sorted(chrome) == sorted(lib)
        status = "match" if same else "mismatch"
    d = dict(field=fid, label=label, status=status, counts_toward_verdict=counts,
             chrome=names(chrome, table) if table else chrome, library=names(lib, table) if table else lib)
    if status == "mismatch" and isinstance(chrome, list) and isinstance(lib, list):
        d["missing"] = [x for x in chrome if x not in lib]
        d["extra"] = [x for x in lib if x not in chrome]
        if not d["missing"] and not d["extra"]:
            d["note"] = "same items, different order"
    if note:
        d["note"] = (d.get("note", "") + " " + note).strip()
    return d


def rel_order(a, b):
    """Order of the headers both sides send (like bench.py's header-order check)."""
    common = [h for h in a if h in b]
    return common, [h for h in b if h in a]


COUNTED = ["ciphers", "extensions", "signature_algorithms", "supported_groups", "key_shares", "alps", "cert_compression", "http2_akamai"]


def diff(rf, fp):
    """Field-by-field diff of a library fingerprint against ONE Chrome variant's fingerprint (rf)."""
    strip = lambda e: [x for x in e if x not in ALPS_CODES] if e is not None else None
    out = [
        field("ciphers", "Cipher suites (JA4 b)", rf["ciphers"], fp["ciphers"], ordered=False),
        field("extensions", "Extension set (incl. ca34 / 0x12e0; ALPS listed separately)", strip(rf["extensions"]), strip(fp["extensions"]), table=EXT_NAMES, ordered=False),
        field("signature_algorithms", "Signature algorithms", rf["signature_algorithms"], fp["signature_algorithms"], table=SIGALG_NAMES),
        field("supported_groups", "Supported groups", rf["supported_groups"], fp["supported_groups"], table=GROUP_NAMES),
        field("key_shares", "Key shares", rf["key_shares"], fp["key_shares"], table=GROUP_NAMES),
        field("alps", "ALPS codepoint", rf["alps"], fp["alps"]),
        field("cert_compression", "Certificate compression", rf["cert_compression"], fp["cert_compression"]),
        field("http2_akamai", "HTTP/2 fingerprint (Akamai)", rf["http2"]["akamai"], (fp.get("http2") or {}).get("akamai")),
    ]
    ch, lh = rf["http2"].get("header_order"), (fp.get("http2") or {}).get("header_order")
    if ch and lh:
        c1, l1 = rel_order(ch, lh)
        out.append(field("header_order", "HTTP/2 header order (headers both send)", c1, l1, counts=False,
                         note="Informational: depends on which headers the caller sets."))
    else:
        out.append(field("header_order", "HTTP/2 header order", ch, lh, counts=False))
    return out


def missing_items(rf, fp, dfs, resumption):
    """Human-readable gaps vs the DEFAULT Chrome fingerprint."""
    items = []
    sig = fp["signature_algorithms"] or []
    if fp["signature_algorithms"] is not None and any(x in rf["signature_algorithms"] for x in ML_DSA) and not any(x in sig for x in ML_DSA):
        items.append(dict(id="ml-dsa", label="ML-DSA signature algorithms (0x0904-0906)", kind="missing"))
    ks, gr = fp["key_shares"], fp["supported_groups"]
    if MLKEM in (rf["key_shares"] or []) and ((ks is not None and MLKEM not in ks) or (gr is not None and MLKEM not in gr)):
        items.append(dict(id="mlkem", label="X25519MLKEM768 (MLKEM) key share", kind="missing"))
    if rf["alps"] and fp["alps"] != rf["alps"] and fp["alps"] is not None:
        items.append(dict(id="alps", label=f"New ALPS codepoint (sends {EXT_NAMES.get(fp['alps'], fp['alps'])})", kind="different"))
    for d in dfs:
        if d["field"] == "extensions" and d["status"] == "mismatch":
            for x in d["missing"]:
                items.append(dict(id="ext-" + x, label=("ca34 trust anchors (Chrome's default sends it)" if x == CA34 else f"Extension {x} {EXT_NAMES.get(x, '')}".strip()),
                                  kind="missing"))
            for x in d["extra"]:
                items.append(dict(id="extra-" + x, label=f"Extra extension {x} {EXT_NAMES.get(x, '')}".strip(), kind="extra"))
        if d["field"] == "ciphers" and d["status"] == "mismatch":
            items.append(dict(id="ciphers", label="Cipher suite list differs", kind="different"))
        if d["field"] == "cert_compression" and d["status"] == "mismatch":
            items.append(dict(id="certc", label="Certificate compression differs", kind="different"))
        if d["field"] == "http2_akamai" and d["status"] == "mismatch":
            items.append(dict(id="h2", label="Chrome HTTP/2 SETTINGS / WINDOW_UPDATE", kind="different"))
        if d["field"] == "signature_algorithms" and d["status"] == "mismatch" and not any(i["id"] == "ml-dsa" for i in items):
            items.append(dict(id="sigalgs", label="Signature algorithm list differs", kind="different"))
    if resumption and resumption["tested"] and not resumption["resumed"]:
        items.append(dict(id="resumption", label="TLS session resumption (never sent pre_shared_key)", kind="missing"))
    return items


def counted_bad(dfs):
    return [d["field"] for d in dfs if d["counts_toward_verdict"] and d["status"] == "mismatch"]


def verdict(per_variant, default_dfs):
    """Verdict is based on the DEFAULT Chrome fingerprint. A library that matches a minority variant on every counted
    field (and not the default) is 'exact_variant'."""
    if any(d["status"] == "not_tested" for d in default_dfs if d["field"] in ("ciphers", "extensions", "signature_algorithms")):
        return "not tested", [], "Core TLS fields were not measured.", None
    bad = counted_bad(default_dfs)
    if not bad:
        return "exact", bad, "Every counted TLS and HTTP/2 field matches Chrome's default fingerprint (with ca34).", "default"
    exact_minor = [vid for vid, pv in per_variant.items() if vid != "default" and pv["fields_exact"]]
    if exact_minor:
        return ("exact_variant", bad, "Every counted field matches the less common Chrome variant '%s'; vs the default fingerprint: %s."
                % (exact_minor[0], ", ".join(bad)), exact_minor[0])
    if len(bad) == 1:
        return "close", bad, f"One counted field differs from Chrome's default fingerprint: {bad[0]}.", None
    return "behind", bad, f"{len(bad)} counted fields differ from Chrome's default fingerprint: {', '.join(bad)}.", None


# ---------------------------------------------------------------- HTTP/3
TP_IGNORE = {"grease", "initial_source_connection_id", "version_information"}  # random / per-connection values


def _tp_map(tps):
    return {t["name"]: (t.get("value") if "value" in t else t.get("ascii", t.get("hex"))) for t in tps or [] if t["name"] not in TP_IGNORE}


def h3_result(case, ref, all_runs):
    """HTTP/3 result for one library case. status: tested | failed | no_support | not_tested. Never guessed."""
    if case.get("no_h3"):
        return dict(status="no_support", reason=case["no_h3"])
    if not case.get("h3"):
        return dict(status="not_tested", reason="no HTTP/3 case in the harness")
    d, meta = find_capture(*case["h3"], all_runs)
    if d is None:
        return dict(status="not_tested", reason="HTTP/3 harness (harness/run_h3.py) has not been run for this profile")
    base = dict(source=meta["path"], tested_at=meta["tested_at"], endpoint=meta["endpoint"], client=d.get("client"))
    ch = d.get("clienthello")
    if not ch or not d.get("ja4"):
        return dict(base, status="failed", reason="no QUIC ClientHello reached the endpoint: " + str((d.get("client") or {}).get("error")))
    a, c, e, s = split_ja4_r(d["ja4_r"])
    chrome = ref["http3"]
    ca, cc, ce, cs_ = split_ja4_r(chrome["ja4_r"])
    hx = lambda xs: [x[2:] for x in xs]
    tp_l, tp_c = _tp_map(ch.get("quic_transport_params")), _tp_map(chrome["transport_params"])
    h3s = d.get("h3_settings")
    fields = [
        field("q_ciphers", "QUIC cipher suites", sorted(cc), sorted(c), ordered=False, counts=False),
        field("q_extensions", "QUIC extension set", sorted(ce), sorted(e), table=EXT_NAMES, ordered=False, counts=False),
        field("q_sigalgs", "QUIC signature algorithms", cs_, s, table=SIGALG_NAMES, counts=False),
        field("q_groups", "QUIC supported groups", chrome.get("groups"), hx(ch.get("groups") or []), table=GROUP_NAMES, counts=False),
        field("q_key_shares", "QUIC key shares", chrome.get("key_shares"), [k["group"][2:] for k in ch.get("key_shares") or []], table=GROUP_NAMES, counts=False),
        field("q_alps", "QUIC ALPS", chrome.get("alps"), ch.get("alps") or [], counts=False),
        field("q_tp_names", "QUIC transport parameters (set; GREASE, CIDs, version_information ignored)", sorted(tp_c), sorted(tp_l), ordered=False, counts=False),
        field("q_tp_values", "QUIC transport parameter values", {k: tp_c[k] for k in sorted(tp_c)}, {k: tp_l[k] for k in sorted(tp_l)}, counts=False),
        field("h3_settings", "HTTP/3 SETTINGS (GREASE removed)", chrome.get("h3_settings"), h3s, counts=False,
              note=None if h3s is not None else "no SETTINGS frame observed from the client"),
        field("h3_grease", "HTTP/3 GREASE SETTINGS count", chrome.get("h3_grease_settings"), d.get("h3_grease_settings"), counts=False),
    ]
    ja4m = {v["id"]: (v["http3"] or {}).get("ja4") == d["ja4"] for v in ref["variants"] if v.get("http3")}
    settings_match = h3s is not None and h3s == chrome.get("h3_settings")
    if h3s is None:
        summary = "settings_not_observed"   # QUIC JA4 recorded, but no HTTP/3 SETTINGS frame reached the endpoint
    elif ja4m.get("default") and settings_match:
        summary = "match"
    elif any(ja4m.get(k) for k in ja4m if k != "default") and settings_match:
        summary = "variant_match"
    else:
        summary = "mismatch"
    return dict(base, status="tested", ja4=d["ja4"], ja4_r=d["ja4_r"], h3_settings=h3s, h3_grease_settings=d.get("h3_grease_settings"),
                header_order=d.get("header_order"), transport_params=[t["name"] for t in ch.get("quic_transport_params") or []],
                ja4_matches=ja4m, h3_settings_match=settings_match if h3s is not None else None, summary=summary, diff=fields,
                chrome_ja4=chrome["ja4"], chrome_h3_settings=chrome.get("h3_settings"))



# ---------------------------------------------------------------- plain-words summary + "why" lines
NOTES = os.path.join(HERE, "notes.json")


def chrome_timeline():
    """Every real Chrome capture in the repo (capture/data/*.json, history/, latest.json), oldest major first, one per
    major (newest build of that major). Used only to say in which captured Chrome version a field first appeared."""
    seen = {}
    for p in glob.glob(os.path.join(TLSBENCH, "capture", "data", "*.json")) + glob.glob(os.path.join(TLSBENCH, "capture", "data", "history", "chrome-*.json")):
        try:
            r = adapt_chrome_reference(json.load(open(p)))
        except Exception:
            continue
        key = tuple(int(x) for x in r["version"].split("."))
        if r["major"] not in seen or key > seen[r["major"]][0]:
            seen[r["major"]] = (key, r["version"], r["variants"][0]["fingerprint"])
    return [(m, v[1], v[2]) for m, v in sorted(seen.items())]


def first_seen(timeline, has, it="it"):
    """'added in N' only when an older capture lacks it; otherwise 'already in N' (N = oldest capture we have)."""
    hits = [i for i, (_, _, f) in enumerate(timeline) if has(f)]
    if not hits:
        return None
    i = hits[0]
    if i > 0:
        return "Chrome added %s in %d" % (it, timeline[i][0])
    return "Chrome already sent %s in %d, the oldest version we've captured" % (it, timeline[0][0])


def _ext_name(x):
    n = EXT_NAMES.get(x, "")
    return ("%s (%s)" % (n.replace("_", " "), x)) if n else x


def why_lines(e, rf, timeline):
    """Plain-language reasons from the real field diff vs Chrome's default fingerprint. Nothing invented: every line
    comes from a diff entry or a missing_items() entry computed from captures."""
    out = []
    dfs = {d["field"]: d for d in e.get("diff") or []}
    for it in e.get("missing") or []:
        i = it["id"]
        if i.startswith("ext-"):
            x = i[4:]
            when = first_seen(timeline, lambda f, x=x: x in (f.get("extensions") or []))
            out.append("Missing 1 extension: %s%s." % ("trust anchors (ca34)" if x == CA34 else _ext_name(x), "; " + when if when else ""))
        elif i.startswith("extra-"):
            out.append("Sends extension %s, which Chrome doesn't send." % _ext_name(i[6:]))
        elif i == "ml-dsa":
            when = first_seen(timeline, lambda f: any(a in (f.get("signature_algorithms") or []) for a in ML_DSA), "them")
            out.append("Doesn't offer the ML-DSA post-quantum signature algorithms (0x0904-0906)%s." % ("; " + when if when else ""))
        elif i == "mlkem":
            when = first_seen(timeline, lambda f: MLKEM in (f.get("key_shares") or []))
            out.append("Doesn't send the X25519MLKEM768 post-quantum key share%s." % ("; " + when if when else ""))
        elif i == "alps":
            out.append("Uses the old ALPS codepoint 0x%s; Chrome sends the new one, 0x%s." % ((dfs.get("alps") or {}).get("library"), rf["alps"]))
        elif i == "h2":
            d = dfs.get("http2_akamai") or {}
            out.append("HTTP/2 settings differ: Chrome sends %s, this library sends %s." % (d.get("chrome"), d.get("library")))
        elif i == "ciphers":
            d = dfs.get("ciphers") or {}
            out.append("Cipher suites differ (%s missing, %s extra)." % (len(d.get("missing") or []), len(d.get("extra") or [])))
        elif i == "sigalgs":
            d = dfs.get("signature_algorithms") or {}
            out.append("Signature algorithm list differs" + (": " + d["note"] if d.get("note") else "") + ".")
        elif i == "certc":
            d = dfs.get("cert_compression") or {}
            out.append("Certificate compression differs: Chrome %s, library %s." % (d.get("chrome"), d.get("library")))
        elif i == "resumption":
            out.append("Never resumes a TLS session (no pre_shared_key on new connections), unlike Chrome.")
        else:
            out.append(it["label"] + ".")
    covered = {"extensions", "signature_algorithms", "key_shares", "supported_groups", "alps", "http2_akamai", "ciphers", "cert_compression"}
    for f in e.get("counted_mismatches") or []:
        if f in ("supported_groups", "key_shares") and not any("MLKEM" in l for l in out):
            out.append("%s differ from Chrome's." % dfs[f]["label"])
        elif f not in covered:
            out.append("%s differs from Chrome's." % dfs[f]["label"])
    ho = dfs.get("header_order") or {}
    if ho.get("status") == "mismatch" and ho.get("chrome") and ho.get("library"):
        c1, l1 = ho["chrome"], ho["library"]
        i = next((k for k in range(min(len(c1), len(l1))) if c1[k] != l1[k]), None)
        if i is not None:
            out.append("HTTP/2 header order differs (not counted in the verdict; it depends partly on which headers the caller sets): "
                       "this library sends %s before %s; Chrome sends %s first." % (l1[i], c1[i], c1[i]))
    return out


def http2_grade(e):
    """HTTP/2 sub-grade from real captures: SETTINGS/WINDOW_UPDATE/PRIORITY/pseudo-header order (Akamai string,
    counted in the verdict) and regular header order (shown, not counted)."""
    dfs = {d["field"]: d for d in e.get("diff") or []}
    ak, ho = (dfs.get("http2_akamai") or {}).get("status"), (dfs.get("header_order") or {}).get("status")
    if ak in (None, "not_tested"):
        return dict(grade="not_tested", settings=None, header_order=None)
    g = "settings_differ" if ak == "mismatch" else ("header_order_differs" if ho == "mismatch" else ("match" if ho == "match" else "settings_match"))
    return dict(grade=g, settings=ak == "match", header_order=None if ho in (None, "not_tested") else ho == "match")


def behind_text(e, cur_major):
    if e["verdict"] == "not tested":
        return "Not tested yet."
    p, vb = e.get("profile_chrome_major"), e.get("versions_behind")
    if p is None or vb is None:
        head = "The profile name doesn't say which Chrome version it copies"
    elif vb <= 0:
        head = "Copies current Chrome %d" % p
    elif not e.get("versions_behind_uniform", True):
        head = "Copies Chrome %d, up to %d versions behind current Chrome (varies by platform)" % (p, vb)
    else:
        head = "Copies Chrome %d, %d version%s behind current %s" % (p, vb, "" if vb == 1 else "s", cur_major)
    tail = {"exact": "its fingerprint still matches current Chrome on every counted field",
            "exact_variant": "it matches a less common current-Chrome variant, not the default",
            "close": "1 counted field differs from current Chrome",
            "behind": "%d counted fields differ from current Chrome" % len(e.get("counted_mismatches") or [])}[e["verdict"]]
    return head + "; " + tail + "."


def annotate(data):
    """Add behind_text / why / notes to every library entry. Notes come from leaderboard/notes.json (hand-written)."""
    timeline = chrome_timeline()
    ref = load_reference()
    rf = {v["id"]: v for v in ref["variants"]}["default"]["fingerprint"]
    stable = (data.get("reference") or {}).get("current_stable") or {}
    cur = (stable.get("linux") or {}).get("full_major") or data["reference"].get("chrome_major")
    notes = json.load(open(NOTES)) if os.path.exists(NOTES) else {}
    notes = {k: v for k, v in notes.items() if not k.startswith("_")}
    for e in data["libraries"]:
        e["behind_text"] = behind_text(e, cur)
        e["why"] = why_lines(e, rf, timeline)
        e["http2_grade"] = http2_grade(e)
        n = notes.get(e["id"]) or notes.get(e["library"])
        e["notes"] = ([n] if isinstance(n, str) else list(n)) if n else []
    VR = {"exact": 0, "exact_variant": 1, "close": 2, "behind": 3}
    for e in data["libraries"]:
        e["resumed_status"] = resumed_status(e)
    rank = lambda x: (VR.get(x["verdict"], 9), len(x.get("counted_mismatches") or []), x["resumed_status"] != "match",
                      -(x.get("profile_chrome_major") or 0))
    for e in data["libraries"]:
        peers = [x for x in data["libraries"] if x["library"] == e["library"] and x["verdict"] in VR]
        best = min(peers, key=rank) if peers else None
        e["fix"] = None
        if best and best is not e and rank(best)[:3] < rank(e)[:3] and e["library"] in FIX_TEMPLATES:
            t = FIX_TEMPLATES[e["library"]]
            e["fix"] = dict(to_id=best["id"], to_profile=best["profile"], to_verdict=best["verdict"],
                            old=t % e["profile"], new=t % best["profile"])
    data["chrome_timeline"] = [dict(major=m, version=v) for m, v, _ in timeline]
    data["upcoming"] = upcoming(data)
    data["catchup"] = catchup(data)
    return data


CATCHUP_LOG = os.path.join(HERE, "data", "catchup_log.json")


def catchup(data):
    """Catch-up ranking. Logs one entry per harness day (date of data["generated_at"]) to data/catchup_log.json, then for every
    change of Chrome's default JA4 seen in the log counts the days until each library had a profile that matched it again."""
    log = json.load(open(CATCHUP_LOG)) if os.path.exists(CATCHUP_LOG) else {"entries": []}
    r = data.get("reference") or {}
    if r.get("ja4_fresh") and data.get("libraries"):
        exact = {}
        for e in data["libraries"]:
            if e["verdict"] != "not tested":
                exact[e["library"]] = exact.get(e["library"], False) or e["verdict"] == "exact"
        day = data["generated_at"][:10]
        log["entries"] = [x for x in log["entries"] if x["date"] != day] + [
            dict(date=day, chrome_version=r.get("chrome_version"), chrome_ja4=r["ja4_fresh"], exact=exact)]
        log["entries"].sort(key=lambda x: x["date"])
        json.dump(log, open(CATCHUP_LOG, "w"), indent=1)
    ent = log["entries"]
    D = lambda s: dt.date.fromisoformat(s)
    events = [dict(date=b["date"], chrome_version=b["chrome_version"], from_ja4=a["chrome_ja4"], to_ja4=b["chrome_ja4"])
              for a, b in zip(ent, ent[1:]) if a["chrome_ja4"] != b["chrome_ja4"]]
    libs = sorted({l for x in ent for l in x["exact"]})
    rows = []
    for lib in libs:
        done, pending = [], []
        for i, ev in enumerate(events):
            end = events[i + 1]["date"] if i + 1 < len(events) else "9999"
            hit = next((x for x in ent if ev["date"] <= x["date"] < end and x["exact"].get(lib)), None)
            if hit:
                done.append(dict(chrome_version=ev["chrome_version"], changed=ev["date"], matched=hit["date"], days=(D(hit["date"]) - D(ev["date"])).days))
            elif i + 1 == len(events):
                pending.append(dict(chrome_version=ev["chrome_version"], changed=ev["date"], days_so_far=(D(ent[-1]["date"]) - D(ev["date"])).days))
        avg = round(sum(x["days"] for x in done) / len(done), 1) if done else None
        rows.append(dict(library=lib, avg_days=avg, caught_up=done, still_behind=pending, enough_data=bool(done)))
    rows.sort(key=lambda x: (x["avg_days"] is None, x["avg_days"] if x["avg_days"] is not None else 0, -max([p["days_so_far"] for p in x["still_behind"]] or [0]), x["library"]))
    return dict(tracking_since=ent[0]["date"] if ent else None, days_logged=len(ent), fingerprint_changes=events,
                enough_data=any(x["enough_data"] for x in rows), libraries=rows,
                method="Counts only changes of Chrome's default TLS JA4 seen after tracking began; a library catches up on the first logged day one of its tested profiles is an exact match again.")


def upcoming(data):
    """'Coming in Chrome N': compare each pre-release channel capture (capture/data/channels/<c>.json, written by
    merge_platforms.py) with the current stable reference, and list the library rows that match stable today but
    would stop matching on that field."""
    sys.path.insert(0, os.path.join(TLSBENCH, "capture"))
    import merge_platforms as mp
    stable = mp.load(os.path.join(TLSBENCH, "capture", "data", "latest.json"))
    if not mp.usable(stable):
        return []
    sv = {vid: mp.fp(mp.cfg(stable, base)) for vid, base in (("default", "default"), ("no_ca34", "disable-TLSTrustAnchorIDs"))}
    out = []
    for c in mp.CHANNELS:
        d = mp.load(os.path.join(mp.CHAN_DIR, c + ".json"))
        if not mp.usable(d):
            out.append(dict(channel=c, status="not_captured"))
            continue
        cv = {vid: mp.fp(mp.cfg(d, base)) for vid, base in (("default", "default"), ("no_ca34", "disable-TLSTrustAnchorIDs"))}
        a, b = sv["default"] or {}, cv["default"] or {}
        diffs = []
        for f, lbl in mp.COMPARE:
            if a.get(f) is not None and b.get(f) is not None and a.get(f) != b.get(f):
                x, y = a.get(f), b.get(f)
                if isinstance(x, list) and isinstance(y, list):
                    diffs.append(dict(field=f, label=lbl, added=[i for i in y if i not in x], removed=[i for i in x if i not in y],
                                      reordered=sorted(x) == sorted(y)))
                else:
                    diffs.append(dict(field=f, label=lbl, stable=x, channel=y))
        breaks = []
        for e in data["libraries"]:
            fpl, mv = e.get("fingerprint") or {}, ((e.get("matches") or {}).get("variants") or {})
            why = []
            for vid in ("default", "no_ca34"):
                if (mv.get(vid) or {}).get("ja4_fresh") and cv.get(vid) and fpl.get("ja4_fresh") != cv[vid]["ja4"]:
                    why.append("TLS JA4" + ("" if vid == "default" else " (without ca34)"))
            if (e.get("matches") or {}).get("http2") and fpl.get("http2_akamai") and fpl["http2_akamai"] != b.get("h2_akamai"):
                why.append("HTTP/2 fingerprint")
            if why:
                breaks.append(dict(id=e["id"], library=e["library"], profile=e["profile"], fields=why))
        m = re.match(r"(\d+)", d.get("version") or "")
        out.append(dict(channel=c, status="captured", version=d.get("version"), major=int(m.group(1)) if m else None,
                        captured_at=d.get("captured_at"), stable_version=stable.get("version"),
                        same_as_stable=not diffs, differences=diffs, breaks=breaks))
    return out


# One-line fix snippets: the real call each harness case uses (leaderboard/harness/bench.py, gobench/main.go)
FIX_TEMPLATES = {
    "curl_cffi": 'requests.get(url, impersonate="%s")',
    "primp": 'primp.Client(impersonate="%s")',
    "rnet": "rnet.Client(emulation=rnet.Emulation.%s)",
    "tls-client": "tls_client.WithClientProfile(profiles.%s)",
    "tls-client (Python)": 'tls_client.Session(client_identifier="%s")',
}


def resumed_status(e):
    """Resumed-connection result from data already in the entry: match / match_variant / mismatch / never / not_tested."""
    r = e.get("resumption") or {}
    if not r.get("tested"):
        return "not_tested"
    if not r.get("resumed"):
        return "never"
    v = (e.get("matches") or {}).get("variants") or {}
    if (v.get("default") or {}).get("ja4_resumed"):
        return "match"
    if any(x.get("ja4_resumed") for k, x in v.items() if k != "default"):
        return "match_variant"
    return "mismatch"


# ---------------------------------------------------------------- build
def build():
    ref = load_reference()
    stable = stable_info(ref)
    all_runs = runs()
    variants = {v["id"]: v for v in ref["variants"]}
    rf = variants["default"]["fingerprint"]
    libs = []
    for c in CASES:
        fp, meta = find_capture(*c["fresh"], all_runs)
        entry = dict(id=f"{c['library']}|{c['profile']}".lower().replace(" ", "-"), library=c["library"], maintainer=c["maintainer"],
                     language=c["language"], profile=c["profile"], note=c.get("note"))
        entry["http3"] = h3_result(c, ref, all_runs)
        if fp is None:
            entry.update(verdict="not tested", tested_at=None, version=None, fingerprint=None, diff=[], missing=[],
                         not_tested=["everything: no capture found"])
            libs.append(entry)
            continue
        kind, pkg = c["pkg"]
        vers = {k.lower().replace("_", "-"): val for k, val in meta["versions"].items()}
        entry["version"] = vers.get(f"{kind}:{pkg.lower().replace('_', '-')}")
        entry["tested_at"] = meta["tested_at"]
        entry["endpoint"] = meta["endpoint"]
        entry["sources"] = {"fresh": meta["path"]}
        if entry["http3"].get("source"):
            entry["sources"]["http3"] = entry["http3"]["source"]
        resumption = dict(tested=False, resumed=None, ja4=None, ja4s=None)
        if c.get("resumed"):
            k, names_ = c["resumed"]
            caps = [find_capture(k, n, all_runs) for n in names_]
            caps = [x for x in caps if x[0] is not None]
            if caps:
                ja4s = [x[0]["ja4"] for x in caps]
                res = [x[0] for x in caps if x[0]["resumed"]]
                resumption = dict(tested=True, resumed=bool(res), ja4=res[0]["ja4"] if res else None, ja4s=ja4s,
                                  attempts=len(caps), note="new connection per request on the same client")
                entry["sources"]["resumed"] = [x[1]["path"] for x in caps]
        per_variant = {}
        for v in ref["variants"]:
            dfs_v = diff(v["fingerprint"], fp)
            bad_v = counted_bad(dfs_v)
            per_variant[v["id"]] = dict(
                ja4_fresh=fp["ja4"] == v["ja4"],
                ja4_resumed=(resumption["ja4"] == v["ja4_resumed"]) if resumption["resumed"] else None,
                fields_exact=not bad_v and not any(d["status"] == "not_tested" for d in dfs_v if d["field"] in ("ciphers", "extensions", "signature_algorithms")),
                counted_mismatches=bad_v,
                quic_ja4=(entry["http3"].get("ja4") == (v["http3"] or {}).get("ja4")) if entry["http3"]["status"] == "tested" else None)
        dfs = diff(rf, fp)
        vd, bad, why, matched = verdict(per_variant, dfs)
        h3 = entry["http3"]
        entry.update(
            fingerprint=dict(ja4_fresh=fp["ja4"], ja4_r_fresh=fp["ja4_r"], ja4_resumed=resumption["ja4"],
                             http2_akamai=(fp.get("http2") or {}).get("akamai"), http3_ja4=h3.get("ja4"), user_agent=fp.get("user_agent"),
                             sends_ca34=fp["trust_anchors"], sends_12e0="12e0" in (fp["extensions"] or [])),
            resumption=resumption,
            matches=dict(variants=per_variant,
                         http2=next(d for d in dfs if d["field"] == "http2_akamai")["status"] == "match",
                         http3=h3.get("summary") if h3["status"] == "tested" else h3["status"]),
            matched_variant=matched,
            verdict=vd, verdict_reason=why, counted_mismatches=bad,
            missing=missing_items(rf, fp, dfs, resumption),
            diff=dfs,
            not_tested=([] if h3["status"] in ("tested", "no_support") else ["HTTP/3 (QUIC) fingerprint"])
                       + ([] if resumption["tested"] else ["TLS resumption (resumed JA4)"])
                       + ([] if fp["key_shares"] is not None else ["key shares (not recorded in legacy results.json)"]),
        )
        libs.append(entry)

    # Versions behind: Chrome major the profile targets (from the profile name only) vs the newest FULLY rolled-out stable
    # major on each platform (latest.json current_stable.highest_full_rollout). Partial rollouts are listed, not counted.
    for e in libs:
        m = re.search(r"(\d{2,3})", e["profile"])
        e["profile_chrome_major"] = int(m.group(1)) if m else None
        vb = {p: (s["full_major"] - e["profile_chrome_major"]) if (m and s["full_major"]) else None for p, s in stable.items()}
        e["versions_behind_by_platform"] = vb
        vals = {x for x in vb.values() if x is not None}
        e["versions_behind"] = vals.pop() if len(vals) == 1 else (max(vals) if vals else None)
        e["versions_behind_uniform"] = len({x for x in vb.values() if x is not None}) <= 1
    for e in libs:
        peers = [x["profile_chrome_major"] for x in libs if x["library"] == e["library"] and x["profile_chrome_major"] is not None]
        e["is_newest_profile"] = e["profile_chrome_major"] is None or e["profile_chrome_major"] == max(peers)
    order = {"exact": 0, "exact_variant": 1, "close": 2, "behind": 3, "not tested": 4}
    libs.sort(key=lambda e: (order[e["verdict"]], len(e.get("counted_mismatches") or []), e["language"], e["library"], e["profile"]))

    pq = variants.get("pq", {}).get("population") or {}
    ref_out_variants = []
    for v in ref["variants"]:
        ref_out_variants.append(dict(id=v["id"], label=v["label"], config=v["config"], is_default=v["is_default"], flags=v["flags"],
                                     ja4_fresh=v["ja4"], ja4_resumed=v["ja4_resumed"], ja4_r=v["fingerprint"]["ja4_r"],
                                     has_trust_anchors=v["has_trust_anchors"], sends_12e0=v["fingerprint"]["pq_padding_ext"],
                                     http3_ja4=(v["http3"] or {}).get("ja4"), http3_ja4_resumed=(v["http3"] or {}).get("ja4_resumed"),
                                     h3_settings=(v["http3"] or {}).get("h3_settings"),
                                     population=v["population"], population_pct=pct(v["population"].get("share"))))
    h3_tested = [l for l in libs if l["http3"]["status"] == "tested"]
    data = dict(
        schema_version="leaderboard-0.2",
        generated_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        reference=dict(
            source=ref["source"], schema="capture/SCHEMA.md v%s" % ref["schema_version"], assumed_schema=False,
            chrome_version=ref["version"], chrome_major=ref["major"], browser=ref["browser"], branded=ref["branded"],
            channel=ref["channel"], os=ref["os"], captured_at=ref["captured_at"], reference_config=ref["reference_config"],
            is_current_linux_stable=ref["is_current_linux_stable"], variations_source=ref["variations_source"],
            capture_server=ref["capture_server"],
            variants=ref_out_variants,
            ja4_fresh=variants["default"]["ja4"], ja4_resumed=variants["default"]["ja4_resumed"],
            http2_akamai=rf["http2"]["akamai"], http3=ref["http3"],
            current_stable=stable,
        ),
        verdict_rules=dict(
            reference="Chrome's default fingerprint (branded Chrome, fresh profile, no flags; includes ca34)",
            counted_fields=COUNTED,
            exact="0 counted fields differ from Chrome's default fingerprint",
            exact_variant="0 counted fields differ from one of Chrome's less common variants (without ca34, or the post-quantum experiment), but not the default",
            close="exactly 1 counted field differs from the default fingerprint",
            behind="2 or more counted fields differ from the default fingerprint",
            informational=["header_order", "resumption", "http3"],
            versions_behind="Chrome major of the newest fully rolled-out stable (per platform, latest.json current_stable.highest_full_rollout) minus the major in the profile name",
        ),
        caveats=[
            ("Chrome sends more than one real fingerprint. The default (branded Chrome %s, fresh profile, no flags) includes the trust-anchors "
             "extension ca34; --disable-features=TLSTrustAnchorIDs removes it; and %s of %s stable clients are in Google's "
             "PqcBandwidthExperiment, which adds extension 0x12e0. Every library is compared against all three; the verdict uses the default."
             % (ref["version"], pct(pq.get("share")) or "an unmeasured share", "/".join(pq.get("platform") or []) or "?")),
            "Reference: branded Google Chrome %s (%s), captured %s on Linux x86_64 against a local capture server (capture/lib/server.py)." % (
                ref["version"], ref["channel"], dt.datetime.fromisoformat(ref["captured_at"]).strftime("%b %-d, %Y")),
            "No population figure exists in the capture for Chrome without ca34 (no Finch study in the seed toggles it), so none is shown.",
            ("HTTP/3: %d library profiles were tested over QUIC against the same local aioquic endpoint that captured Chrome's QUIC fingerprint; "
             "libraries without an HTTP/3 client are marked 'no HTTP/3 support'." % len(h3_tested)),
            "Resumption was only tested for bogdanfinn tls-client (Chrome_152 and Chrome_152_PSK).",
            "Header order is informational: the harness sets Chrome headers for the Go libraries, while Python cases use each library's defaults.",
            platform_caveat(),
        ],
        harness=dict(runs_used=sorted({l["sources"]["fresh"].split("/")[2] if l.get("sources", {}).get("fresh", "").startswith("leaderboard/raw/") else "legacy" for l in libs if l.get("sources")}),
                     endpoints=sorted({l.get("endpoint") for l in libs if l.get("endpoint")}),
                     http3_endpoints=sorted({l["http3"].get("endpoint") for l in libs if l["http3"].get("endpoint")})),
        libraries=libs,
    )
    annotate(data)
    json.dump(data, open(OUT, "w"), indent=1)
    print(f"wrote {OUT} (reference: {ref['source']}, Chrome {ref['version']})")
    for l in libs:
        pv = (l.get("matches") or {}).get("variants") or {}
        h3 = l["http3"]
        print(f"  {l['verdict']:13} {l['library'] + ' ' + l['profile']:34} {str(l.get('version')):12} "
              f"ja4={l['fingerprint']['ja4_fresh'] if l.get('fingerprint') else None} "
              + " ".join(f"{k}={'Y' if x['ja4_fresh'] else 'n'}/{len(x['counted_mismatches'])}" for k, x in pv.items())
              + f" vb={l.get('versions_behind_by_platform')} h3={h3['status']}:{h3.get('summary')}:{h3.get('ja4')}")


if __name__ == "__main__":
    if "--annotate-only" in sys.argv:   # refresh behind_text / why / notes in the existing libraries.json (no harness data needed)
        d = annotate(json.load(open(OUT)))
        json.dump(d, open(OUT, "w"), indent=1)
        for l in d["libraries"]:
            print(" ", l["id"], "|", l["behind_text"], "|", l["why"], l["notes"])
    else:
        build()
