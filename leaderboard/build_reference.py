"""SUPERSEDED (2026-10-01): no longer called by run.sh; the reference is capture/data/latest.json (capture/SCHEMA.md).
Kept for reference only.

Build a stand-in Chrome reference (leaderboard/data/chrome_reference.assumed.json) in the ASSUMED schema
(see ASSUMED_SCHEMA.md) from the real Chrome 154 capture in /workspace/chrome154-capture.

Only used while Moe's pipeline output (/workspace/tlsbench/capture/data/latest.json) does not exist.
Every value is copied from the capture files or recomputed from them; nothing is typed in by hand.
"""
import csv, glob, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from fingerprint import normalize_echo, split_ja4_r, ja4_from_parts, GREASE

CAP = "/workspace/chrome154-capture"
OUT = os.path.join(os.path.dirname(__file__), "data", "chrome_reference.assumed.json")


def load(p):
    return json.load(open(p))


def pcap_hellos():
    """ClientHellos from the tcpdump/tshark cross-check, JA4 recomputed per spec (as in verify_ja4.py)."""
    rows = []
    with open(os.path.join(CAP, "pcap", "tshark_clienthellos.csv")) as f:
        for r in csv.DictReader(f, escapechar="\\"):
            ja4_r = r["tls.handshake.ja4_r"]
            a, c, e, s = split_ja4_r(ja4_r)
            rows.append(dict(ja4=ja4_from_parts(a, c, e, s), ja4_a=a, ciphers=c, extensions=e, sigalgs=s,
                             ja4_r="_".join([a, ",".join(c), ",".join(e), ",".join(s)])))
    return rows


def main():
    noft = sorted(glob.glob(f"{CAP}/captures/*_noft_*.json"))
    ft = sorted(glob.glob(f"{CAP}/captures/*_ft_*.json"))
    base = load(noft[0])  # all noft captures share one JA4 (checked below)
    fp = normalize_echo(base)
    meta = base["_capture_meta"]
    ja4s = {load(p)["tls"]["ja4"] for p in noft}
    assert ja4s == {fp["ja4"]}, ja4s
    tls = base["tls"]
    exts = {e["name"]: e for e in tls["extensions"]}
    ext = lambda prefix: next((v for k, v in exts.items() if k.startswith(prefix)), None)
    alps = ext("application_settings")
    frames = base["http2"]["sent_frames"]
    settings = next(f for f in frames if f["frame_type"] == "SETTINGS")["settings"]
    wu = next((f for f in frames if f["frame_type"] == "WINDOW_UPDATE"), {})

    hellos = pcap_hellos()
    resumed = [h for h in hellos if "0029" in h["extensions"] and "12e0" not in h["extensions"]]
    fresh_pcap = [h for h in hellos if "0029" not in h["extensions"] and "12e0" not in h["extensions"]]
    assert resumed and len({h["ja4"] for h in resumed}) == 1
    assert {h["ja4"] for h in fresh_pcap} == {fp["ja4"]}
    ft_fresh = [h for h in hellos if "12e0" in h["extensions"] and "0029" not in h["extensions"]]
    ft_res = [h for h in hellos if "12e0" in h["extensions"] and "0029" in h["extensions"]]
    ver = meta["browser"].split("/")[1]

    ref = {
        "schema_version": "assumed-0.1",
        "assumed_schema": True,
        "generated_by": "leaderboard/build_reference.py (stand-in until capture/data/latest.json exists)",
        "browser": {"name": "Chrome", "version": ver, "major": int(ver.split(".")[0]), "channel": "Stable",
                    "build": "Chrome for Testing", "branded": False, "platform": "linux64",
                    "user_agent": base["user_agent"]},
        "captured_at": min(load(p)["_capture_meta"]["captured_at"] for p in noft),
        "capture": {
            "server": "TrackMe (pagpeter/TrackMe @ 9d2e865), local",
            "flags": meta["args"],
            "field_trial_config_disabled": True,
            "variations": None,
            "samples": len(noft),
            "cross_checked_with": "tcpdump + tshark 4.4.18, JA4 recomputed per FoxIO spec",
            "source_files": [os.path.relpath(p, CAP) for p in noft] + ["pcap/tshark_clienthellos.csv"],
        },
        "tls": {
            "fresh": {
                "ja4": fp["ja4"], "ja4_r": fp["ja4_r"],
                "peetprint_hash": tls.get("peetprint_hash"),  # JA3 omitted: Chrome shuffles extensions, so it changes per connection
                "ciphers": fp["ciphers"], "extensions": fp["extensions"],
                "signature_algorithms": fp["signature_algorithms"],
                "supported_groups": fp["supported_groups"], "key_shares": fp["key_shares"],
                "alpn": ext("application_layer_protocol_negotiation")["protocols"],
                "alps": {"codepoint": fp["alps"], "protocols": alps["protocols"] if alps else None},
                "ech": "grease" if ext("extensionEncryptedClientHello") else None,
                "cert_compression": fp["cert_compression"],
                "trust_anchors": {"present": fp["trust_anchors"], "extension": "ca34"},
                "supported_versions": [v for v in ext("supported_versions")["versions"] if "GREASE" not in v],
            },
            "resumed": {
                "ja4": resumed[0]["ja4"], "ja4_r": resumed[0]["ja4_r"], "extensions": sorted(resumed[0]["extensions"]),
                "source": "pcap/tshark_clienthellos.csv (%d resumed ClientHellos)" % len(resumed),
            },
        },
        "http2": {
            "akamai": base["http2"]["akamai_fingerprint"],
            "settings": settings,
            "window_update": wu.get("increment"),
            "header_order": fp["http2"]["header_order"],
        },
        "http3": None,
        "capture_variants": [{
            "id": "field_trial_config",
            "label": "Chrome for Testing without --disable-field-trial-config",
            "ja4_fresh": ft_fresh[0]["ja4"] if ft_fresh else None,
            "ja4_resumed": ft_res[0]["ja4"] if ft_res else None,
            "note": "Chrome for Testing auto-applies fieldtrial_testing_config.json and then adds extension 0x12e0. "
                    "Branded stable does not auto-apply it, so this is treated as a capture artifact.",
            "samples": len(ft),
        }],
    }
    json.dump(ref, open(OUT, "w"), indent=1)
    print("wrote", OUT, ref["tls"]["fresh"]["ja4"], ref["tls"]["resumed"]["ja4"])


if __name__ == "__main__":
    main()
