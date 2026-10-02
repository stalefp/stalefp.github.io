#!/usr/bin/env python3
"""Merge per-OS Chrome captures (CI artifacts) into capture/data and write the per-platform summary the site reads.

  merge_platforms.py [--artifacts DIR] [--attempt-url URL]

DIR contains one sub-folder per OS (capture-linux/, capture-windows/, capture-macos/), each with the latest.json written by
lib/capture.py on that OS (SCHEMA.md layout + top-level "platform"). Missing or unusable captures leave the previous data
for that OS untouched; an OS that never had a usable capture stays "not_captured".

Writes
  data/latest.json                 Linux capture = the leaderboard reference (unchanged layout). The previous one is
                                   archived to data/history/ when the version or any fingerprint field changed.
  data/platforms/windows.json      newest usable Windows capture (full SCHEMA.md layout)
  data/platforms/macos.json        newest usable macOS capture
  data/platforms/index.json        compact per-platform summary + comparison against Linux (read by the site)
Without --artifacts it only (re)builds index.json from what is on disk.
"""
import argparse, datetime as dt, glob, json, os, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
PLAT_DIR = os.path.join(DATA, "platforms")
HIST = os.path.join(DATA, "history")
PLATFORMS = ["linux", "windows", "macos"]
LABEL = {"linux": "Linux", "windows": "Windows", "macos": "macOS"}
VH = {"linux": "linux", "windows": "win", "macos": "mac"}
COMPARE = [("ja4", "TLS JA4 (fresh)"), ("ja4_resumed", "TLS JA4 (resumed)"), ("quic_ja4", "QUIC JA4"),
           ("h2_akamai", "HTTP/2 fingerprint"), ("h3_settings", "HTTP/3 SETTINGS"), ("has_trust_anchors", "trust anchors (ca34)"),
           ("extensions_sorted", "TLS extension set"), ("sig_algs", "signature algorithms"), ("groups", "supported groups"),
           ("ciphers", "cipher suites"), ("quic_transport_param_ids", "QUIC transport parameter ids")]


def load(p):
    try:
        return json.load(open(p))
    except Exception:
        return None


def usable(d):
    if not d or not d.get("configs"):
        return False
    ref = next((c for c in d["configs"] if c["name"] == d.get("reference_config")), None)
    return bool(ref and ref.get("ja4") and ref.get("h2_akamai"))


def cfg(d, base):
    cs = {c["name"]: c for c in d.get("configs", [])}
    ref = cs.get(d.get("reference_config")) or {}
    return cs.get("%s-%s" % (base, ref.get("mode"))) or next((c for c in d["configs"] if c["base_config"] == base and c.get("ja4")), None)


def fp(c):
    if not c:
        return None
    q = c.get("quic") or {}
    return dict(config=c["name"], ja4=c.get("ja4"), ja4_resumed=c.get("ja4_resumed"), ja4_r=c.get("ja4_r"),
                quic_ja4=q.get("ja4"), quic_ja4_resumed=q.get("ja4_resumed"), h2_akamai=c.get("h2_akamai"),
                h3_settings=q.get("h3_settings"), has_trust_anchors=c.get("has_trust_anchors"),
                extensions_sorted=c.get("extensions_sorted"), sig_algs=c.get("sig_algs"), groups=c.get("groups"),
                ciphers=c.get("ciphers"),
                quic_transport_param_ids=[t.get("id") for t in (q.get("transport_params") or []) if t.get("name") != "grease"] or None,
                user_agent=c.get("user_agent"), sec_ch_ua=c.get("sec_ch_ua"))


def summary(d, platform, file):
    cs = (d.get("current_stable") or {}).get(VH[platform]) or {}
    return dict(status="captured", file=file, platform=platform, label=LABEL[platform],
                browser=d.get("browser"), version=d.get("version"), channel=d.get("channel"), os=d.get("os"),
                captured_at=d.get("captured_at"), ci_run=d.get("ci_run"),
                platform_stable_newest=cs.get("newest"), platform_stable_full_rollout=cs.get("highest_full_rollout"),
                reference_config=d.get("reference_config"),
                variants=dict(default=fp(cfg(d, "default")), no_ca34=fp(cfg(d, "disable-TLSTrustAnchorIDs")),
                              pq=fp(cfg(d, "finch-AddTLSServerHandshakePadding"))))


def fingerprint_key(d):
    s = summary(d, d.get("platform") or "linux", "")
    return json.dumps(dict(v=d.get("version"), f={k: {f: (x or {}).get(f) for f, _ in COMPARE} for k, x in s["variants"].items()}), sort_keys=True)


def archive_linux(old):
    """Copy the outgoing data/latest.json into history/ and list it in history/index.json."""
    os.makedirs(HIST, exist_ok=True)
    name = "chrome-%s-%s.json" % (old["version"], old["captured_at"][:10])
    shutil.copy(os.path.join(DATA, "latest.json"), os.path.join(HIST, name))
    idx = load(os.path.join(HIST, "index.json")) or {"captures": []}
    idx["captures"] = [c for c in idx.get("captures", []) if c.get("file") != name]
    idx["captures"].append(dict(file=name, chrome_version=old["version"], captured_at=old["captured_at"]))
    idx["captures"].sort(key=lambda c: c["captured_at"])
    json.dump(idx, open(os.path.join(HIST, "index.json"), "w"), indent=1)
    print("archived previous latest.json ->", name)


def merge(artifacts, attempt_url):
    os.makedirs(PLAT_DIR, exist_ok=True)
    prev_idx = load(os.path.join(PLAT_DIR, "index.json")) or {}
    attempts = (prev_idx.get("last_attempt") or {}) if isinstance(prev_idx.get("last_attempt"), dict) else {}
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for p in PLATFORMS:
        new = None
        for f in glob.glob(os.path.join(artifacts, "*%s*" % p, "**", "latest.json"), recursive=True):
            new = load(f)
            break
        ok = usable(new) and (new.get("platform") or "linux") == p and new.get("browser") == "Google Chrome"
        attempts[p] = dict(at=now, ok=bool(ok), run=attempt_url,
                           detail=None if ok else ("no capture artifact" if new is None else "capture had no usable default fingerprint or was not branded Google Chrome"))
        if not ok:
            print("%s: no usable capture in this run; keeping previous data" % p)
            continue
        if p == "linux":
            old = load(os.path.join(DATA, "latest.json"))
            if old and old.get("captured_at") != new.get("captured_at") and fingerprint_key(old) != fingerprint_key(new):
                archive_linux(old)
            json.dump(new, open(os.path.join(DATA, "latest.json"), "w"), indent=2)
        else:
            json.dump(new, open(os.path.join(PLAT_DIR, p + ".json"), "w"), indent=2)
        print("%s: Chrome %s captured %s" % (p, new.get("version"), new.get("captured_at")))
    return attempts


def build_index(attempts):
    out = dict(note="Per-platform branded Google Chrome captures (capture/merge_platforms.py). Full data: linux = latest.json, "
                    "others = platforms/<os>.json (capture/SCHEMA.md layout).",
               generated_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), platforms={}, comparison={},
               last_attempt=attempts or {})
    for p in PLATFORMS:
        path = os.path.join(DATA, "latest.json") if p == "linux" else os.path.join(PLAT_DIR, p + ".json")
        d = load(path)
        if usable(d) and (d.get("platform") or "linux") == p:
            out["platforms"][p] = summary(d, p, "latest.json" if p == "linux" else "platforms/%s.json" % p)
        else:
            out["platforms"][p] = dict(status="not_captured", platform=p, label=LABEL[p])
    lin = out["platforms"]["linux"]
    for p in ("windows", "macos"):
        s = out["platforms"][p]
        if s["status"] != "captured" or lin["status"] != "captured":
            continue
        cmp = dict(vs="linux", same_version=s["version"] == lin["version"], variants={})
        for vid in ("default", "no_ca34", "pq"):
            a, b = (lin["variants"].get(vid) or {}), (s["variants"].get(vid) or {})
            if not a or not b:
                continue
            fields = {f: (a.get(f) == b.get(f)) if (a.get(f) is not None and b.get(f) is not None) else None for f, _ in COMPARE}
            cmp["variants"][vid] = dict(fields=fields, differs=[lbl for f, lbl in COMPARE if fields[f] is False])
        out["comparison"][p] = cmp
    json.dump(out, open(os.path.join(PLAT_DIR, "index.json"), "w"), indent=1)
    for p, s in out["platforms"].items():
        c = out["comparison"].get(p, {}).get("variants", {}).get("default")
        print("%-8s %-13s %s %s" % (p, s["status"], s.get("version") or "", ("differs from Linux in: %s" % (c["differs"] or "nothing")) if c else ""))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts")
    ap.add_argument("--attempt-url")
    a = ap.parse_args()
    attempts = merge(a.artifacts, a.attempt_url) if a.artifacts else (load(os.path.join(PLAT_DIR, "index.json")) or {}).get("last_attempt")
    build_index(attempts)
