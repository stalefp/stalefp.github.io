#!/usr/bin/env python3
"""Build the Stale Feed sample payload (stale-feed/v1) from the site's current data.

  build_feed.py [--site DIR] [--out FILE]

Reads the files the public site serves (site/data/latest.json, platforms.json, libraries.json, history/) and writes
site/feed/sample-v1.json in the documented stale-feed/v1 format (site/feed/index.html, site/feed/schema-v1.json).
site/sync.sh runs this after copying the data, so the sample always reflects the latest published capture.

The payload is deterministic for a given set of inputs: generated_at is the newest source timestamp, not the wall clock,
so an unchanged capture doesn't produce a diff. If the `jsonschema` package is installed, the output is validated
against schema-v1.json and the script exits non-zero on a mismatch.
"""
import argparse, datetime as dt, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "capture"))
from merge_platforms import summary, cfg as find_cfg  # same per-variant summary the site's platforms.json uses

SCHEMA_ID = "stale-feed/v1"
SITE_URL = "https://stalefp.github.io/"
PLATFORMS = ["linux", "windows", "macos"]
VARIANTS = ["default", "no_ca34", "pq"]
VERDICTS = {"exact": "exact", "exact_variant": "exact_variant", "close": "close", "behind": "behind", "not tested": "not_tested"}
# (feed field name, platforms.json/merge_platforms.fp key, label) compared per variant between consecutive captures
VARIANT_FIELDS = [
    ("ja4", "ja4", "TLS JA4 (fresh connection)"),
    ("ja4_resumed", "ja4_resumed", "TLS JA4 (resumed connection)"),
    ("quic_ja4", "quic_ja4", "QUIC JA4"),
    ("quic_ja4_resumed", "quic_ja4_resumed", "QUIC JA4 (resumed)"),
    ("h2_akamai", "h2_akamai", "HTTP/2 Akamai fingerprint"),
    ("h3_settings", "h3_settings", "HTTP/3 SETTINGS"),
    ("has_trust_anchors", "has_trust_anchors", "Trust anchors extension (ca34) sent"),
    ("extensions", "extensions_sorted", "TLS extension set"),
    ("sig_algs", "sig_algs", "Signature algorithms"),
    ("groups", "groups", "Supported groups"),
    ("ciphers", "ciphers", "Cipher suites"),
    ("quic_transport_params", "quic_transport_params", "QUIC transport parameters (sorted id=value)"),
]


def load(p):
    with open(p) as f:
        return json.load(f)


def utc(ts):
    """ISO 8601 (any offset) -> UTC 'YYYY-MM-DDTHH:MM:SSZ'. None stays None."""
    if not ts:
        return None
    d = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def variant_out(v):
    if not v:
        return None
    return dict(config=v.get("config"), ja4=v.get("ja4"), ja4_resumed=v.get("ja4_resumed"), ja4_r=v.get("ja4_r"),
                quic_ja4=v.get("quic_ja4"), quic_ja4_resumed=v.get("quic_ja4_resumed"), h2_akamai=v.get("h2_akamai"),
                h3_settings=v.get("h3_settings"), has_trust_anchors=v.get("has_trust_anchors"))


def platform_out(p, s):
    if not s or s.get("status") != "captured":
        return dict(status="not_captured", platform=p)
    at = utc(s.get("captured_at"))
    return dict(status="captured", platform=p, browser=s.get("browser"), channel=s.get("channel"), version=s.get("version"),
                os=s.get("os"), captured_at=at, captured_date=at[:10] if at else None, capture_run=s.get("ci_run"),
                stable_newest=s.get("platform_stable_newest"), stable_full_rollout=s.get("platform_stable_full_rollout"),
                variants={vid: variant_out((s.get("variants") or {}).get(vid)) for vid in VARIANTS})


def pq_share(raw):
    for st in raw.get("finch_network_studies") or []:
        if "0x12e0" in (st.get("extension_hint") or []):
            feats = set(st.get("features") or [])
            g = [x["share_of_population"] for x in st.get("groups") or [] if feats & set(x.get("enable_features") or []) and x.get("share_of_population")]
            return round(sum(g), 6) if g else None
    return None


def capture_facts(raw):
    """Per-capture values the change log compares: summary variants + default-only fields not in the summary."""
    s = summary(raw, raw.get("platform") or "linux", "")
    d = find_cfg(raw, "default") or {}
    return dict(version=raw.get("version"), captured_at=utc(raw.get("captured_at")), variants=s["variants"],
                key_shares=[k.get("group") for k in d.get("key_shares") or []] or None, alps=d.get("alps_codepoint"),
                pq_population_share=pq_share(raw))


def diff(prev, cur):
    out = []
    add = lambda field, variant, label, a, b: out.append(dict(field=field, variant=variant, label=label, before=a, after=b)) if a != b else None
    add("chrome_version", None, "Chrome version", prev["version"], cur["version"])
    for vid in VARIANTS:
        a, b = prev["variants"].get(vid) or {}, cur["variants"].get(vid) or {}
        for field, key, label in VARIANT_FIELDS:
            add(field, vid, label, a.get(key), b.get(key))
    add("key_shares", "default", "Key shares", prev["key_shares"], cur["key_shares"])
    add("alps", "default", "ALPS codepoint", prev["alps"], cur["alps"])
    add("pq_population_share", "pq", "Share of the platform's stable users in the post-quantum experiment",
        prev["pq_population_share"], cur["pq_population_share"])
    return out


def library_out(l):
    vs = (l.get("matches") or {}).get("variants") or {}
    h = l.get("http3") or {}
    f = l.get("fingerprint") or {}
    r = l.get("resumption") or {}
    return dict(
        id=l["id"], library=l.get("library"), maintainer=l.get("maintainer"), language=l.get("language"),
        library_version=l.get("version"), profile=l.get("profile"), profile_chrome_major=l.get("profile_chrome_major"),
        is_newest_profile=l.get("is_newest_profile") is not False, tested_at=utc(l.get("tested_at")),
        verdict=VERDICTS.get(l.get("verdict"), "not_tested"), matched_variant=l.get("matched_variant"),
        counted_mismatches=l.get("counted_mismatches") or [],
        versions_behind=l.get("versions_behind"), versions_behind_by_platform=l.get("versions_behind_by_platform") or {},
        variants={vid: dict(ja4_match=x.get("ja4_fresh"), ja4_resumed_match=x.get("ja4_resumed"), fields_exact=x.get("fields_exact"),
                            counted_mismatches=x.get("counted_mismatches"), quic_ja4_match=x.get("quic_ja4"))
                  for vid, x in vs.items() if vid in VARIANTS},
        http2_match=(l.get("matches") or {}).get("http2"),
        http3=dict(status=h.get("status") or "not_tested", summary=h.get("summary"), quic_ja4=h.get("ja4"),
                   ja4_matches=h.get("ja4_matches"), h3_settings_match=h.get("h3_settings_match"), reason=h.get("reason")),
        resumption=dict(tested=bool(r.get("tested")), resumed=r.get("resumed") if r.get("tested") else None),
        fingerprint=dict(ja4=f.get("ja4_fresh"), ja4_resumed=f.get("ja4_resumed"), h2_akamai=f.get("http2_akamai"), quic_ja4=f.get("http3_ja4")),
        missing=[dict(id=m.get("id"), label=m.get("label")) for m in l.get("missing") or []],
    )


def build(site):
    data = os.path.join(site, "data")
    latest = load(os.path.join(data, "latest.json"))
    libs = load(os.path.join(data, "libraries.json"))
    plat_path = os.path.join(data, "platforms.json")
    plats = load(plat_path) if os.path.exists(plat_path) else {"platforms": {"linux": summary(latest, "linux", "latest.json")}}
    hist_dir = os.path.join(data, "history")
    idx = load(os.path.join(hist_dir, "index.json")) if os.path.exists(os.path.join(hist_dir, "index.json")) else {"captures": []}

    # Linux capture chain: archived captures (oldest first) + the current one. Windows/macOS aren't archived yet.
    chain = []
    for c in sorted(idx.get("captures") or [], key=lambda c: utc(c["captured_at"])):
        p = os.path.join(hist_dir, c["file"])
        if os.path.exists(p):
            chain.append(capture_facts(load(p)))
    cur = capture_facts(latest)
    chain = [c for c in chain if c["captured_at"] < cur["captured_at"]] + [cur]
    changes = []
    for prev, nxt in zip(chain, chain[1:]):
        changes.append(dict(platform="linux", date=nxt["captured_at"][:10],
                            previous=dict(version=prev["version"], captured_at=prev["captured_at"]),
                            current=dict(version=nxt["version"], captured_at=nxt["captured_at"]),
                            fields=diff(prev, nxt)))
    changes.reverse()  # newest first
    history = [dict(platform="linux", version=c["version"], captured_at=c["captured_at"], captured_date=c["captured_at"][:10],
                    variants={vid: dict(ja4=(c["variants"].get(vid) or {}).get("ja4"), ja4_resumed=(c["variants"].get(vid) or {}).get("ja4_resumed"),
                                        quic_ja4=(c["variants"].get(vid) or {}).get("quic_ja4"), h2_akamai=(c["variants"].get(vid) or {}).get("h2_akamai"))
                              for vid in VARIANTS})
               for c in reversed(chain)]

    ref = libs.get("reference") or {}
    defs = {}
    for v in ref.get("variants") or []:
        if v.get("id") in VARIANTS:
            pop = v.get("population") or {}
            defs[v["id"]] = dict(label=v.get("label"), flags=v.get("flags") or [],
                                 population_share=pop.get("share"), population_platforms=pop.get("platform"), population_study=pop.get("study"))
    stamps = [utc(x) for x in (plats.get("generated_at"), libs.get("generated_at"), latest.get("captured_at")) if x]
    return {
        "schema": SCHEMA_ID,
        "schema_url": SITE_URL + "feed/schema-v1.json",
        "docs_url": SITE_URL + "feed/",
        "sample": True,
        "generated_at": max(stamps),
        "reference_platform": "linux",
        "variant_definitions": defs,
        "platforms": {p: platform_out(p, (plats.get("platforms") or {}).get(p)) for p in PLATFORMS},
        "changes": changes,
        "history": history,
        "libraries_compared_against": dict(platform="linux", chrome_version=ref.get("chrome_version"), captured_at=utc(ref.get("captured_at")),
                                           endpoints=(libs.get("harness") or {}).get("endpoints") or []),
        "libraries": [library_out(l) for l in libs.get("libraries") or []],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", default=os.path.join(ROOT, "site"))
    ap.add_argument("--out")
    a = ap.parse_args()
    out = a.out or os.path.join(a.site, "feed", "sample-v1.json")
    feed = build(a.site)
    try:
        import jsonschema
    except ImportError:
        jsonschema = None
        print("build_feed: jsonschema not installed; schema check skipped")
    if jsonschema:
        jsonschema.Draft202012Validator(load(os.path.join(a.site, "feed", "schema-v1.json")), format_checker=jsonschema.FormatChecker()).validate(feed)
        print("build_feed: sample valid against schema-v1.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(feed, f, indent=1)
        f.write("\n")
    n = sum(len(c["fields"]) for c in feed["changes"])
    print("feed/sample-v1.json <- %s: %d platforms captured, %d capture pairs (%d field changes), %d library profiles" % (
        SCHEMA_ID, sum(p["status"] == "captured" for p in feed["platforms"].values()), len(feed["changes"]), n, len(feed["libraries"])))


if __name__ == "__main__":
    main()
