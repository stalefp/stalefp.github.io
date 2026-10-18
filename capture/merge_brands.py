"""Merge the Linux Edge / Brave captures (CI artifact brands-linux/<brand>-linux/latest.json, lib/capture_brand.py).

  python capture/merge_brands.py --artifacts brand-artifacts

Writes capture/data/brands/<brand>/latest.json (only from a good capture; a failed day keeps the previous file) and
capture/data/brands/index.json: one summary per brand, compared with the Chrome reference (capture/data/latest.json).
"""
import argparse, glob, json, os, shutil
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "brands")
BRANDS = [("edge", "Microsoft Edge"), ("brave", "Brave Browser")]


def ref_config(d):
    return next((c for c in d.get("configs", []) if c["name"] == d.get("reference_config")), {})


def summary(d, status, chrome):
    r = ref_config(d); q = r.get("quic") or {}
    cr = ref_config(chrome) if chrome else {}; cq = cr.get("quic") or {}
    same = lambda a, b: None if a is None or b is None else a == b
    return dict(status=status, browser=d.get("browser"), version=d.get("version"), brand_version=d.get("brand_version"),
                chromium_major=d.get("chromium_major"), captured_at=d.get("captured_at"), os=d.get("os"), package=d.get("package"),
                ja4=r.get("ja4"), ja4_resumed=r.get("ja4_resumed"), h2_akamai=r.get("h2_akamai"), header_order=r.get("header_order"),
                user_agent=r.get("user_agent"), sec_ch_ua=r.get("sec_ch_ua"), quic_ja4=q.get("ja4"), h3_settings=q.get("h3_settings"),
                vs_chrome=dict(chrome_version=chrome.get("version") if chrome else None,
                               ja4=same(r.get("ja4"), cr.get("ja4")), ja4_resumed=same(r.get("ja4_resumed"), cr.get("ja4_resumed")),
                               h2_akamai=same(r.get("h2_akamai"), cr.get("h2_akamai")), header_order=same(r.get("header_order"), cr.get("header_order")),
                               quic_ja4=same(q.get("ja4"), cq.get("ja4")), h3_settings=same(q.get("h3_settings"), cq.get("h3_settings"))))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--artifacts", default="brand-artifacts"); a = ap.parse_args()
    chrome_p = os.path.join(HERE, "data", "latest.json")
    chrome = json.load(open(chrome_p)) if os.path.exists(chrome_p) else None
    idx = {"note": "Linux captures of other Chromium-based browsers (capture/lib/capture_brand.py); vs_chrome compares the default "
                   "profile with the Chrome reference capture (true = identical).", "brands": {}}
    for bid, name in BRANDS:
        os.makedirs(os.path.join(OUT, bid), exist_ok=True)
        dst = os.path.join(OUT, bid, "latest.json"); status = None
        for src in glob.glob(os.path.join(a.artifacts, "**", bid + "-linux", "latest.json"), recursive=True):
            try:
                d = json.load(open(src))
                assert d.get("browser") == name and ref_config(d).get("ja4"), "not a %s capture" % name
                shutil.copy(src, dst); status = "captured"
            except Exception as e:
                print("%s: bad capture (%s); keeping previous" % (bid, e))
        if os.path.exists(dst):
            idx["brands"][bid] = dict(summary(json.load(open(dst)), status or "previous (today's capture failed)", chrome), id=bid)
        else:
            idx["brands"][bid] = dict(status="not captured yet", browser=name, id=bid)
        print("%s: %s" % (bid, idx["brands"][bid]["status"]))
    json.dump(idx, open(os.path.join(OUT, "index.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
