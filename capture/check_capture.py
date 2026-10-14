#!/usr/bin/env python3
"""Daily-run gate: refuse a capture that is empty, malformed, or not the Chrome the runner installed.

  check_capture.py LATEST_JSON [--expect-version X.Y.Z.W] [--expect-channel stable|beta|dev|canary] [--quarantine]

Exits 1 (and prints a GitHub ::error) when the check fails. With --quarantine a failing file is renamed to
latest.invalid.json, so the uploaded artifact has no latest.json and merge_platforms.py keeps the previous data.
"""
import argparse, json, os, re, sys

JA4 = re.compile(r"^t13d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$")
AKAMAI = re.compile(r"^[\d:;]+\|\d+\|[\d:,]+\|[masp,]+$")


def problems(d, expect_version=None, expect_channel=None):
    out = []
    if not isinstance(d, dict):
        return ["capture is not a JSON object"]
    if d.get("browser") != "Google Chrome":
        out.append("browser is %r, expected 'Google Chrome'" % d.get("browser"))
    v = d.get("version") or ""
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
        out.append("version %r is not a full Chrome version" % v)
    if expect_version and v != expect_version:
        out.append("captured Chrome %s but the runner installed %s" % (v, expect_version))
    alias = {"unstable": "dev"}
    if expect_channel and alias.get(d.get("channel"), d.get("channel") or "") != alias.get(expect_channel, expect_channel):
        out.append("channel is %r, expected %r" % (d.get("channel"), expect_channel))
    cfgs = d.get("configs") or []
    if not cfgs:
        out.append("no configs captured")
    ref = next((c for c in cfgs if c.get("name") == d.get("reference_config")), None)
    if not ref:
        out.append("reference config %r missing" % d.get("reference_config"))
    else:
        if not JA4.match(ref.get("ja4") or ""):
            out.append("default JA4 %r is missing or malformed" % ref.get("ja4"))
        if not AKAMAI.match(ref.get("h2_akamai") or ""):
            out.append("default HTTP/2 fingerprint %r is missing or malformed" % ref.get("h2_akamai"))
        if not ref.get("extensions_sorted"):
            out.append("default config has no TLS extensions")
    if not d.get("captured_at"):
        out.append("captured_at missing")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path"); ap.add_argument("--expect-version"); ap.add_argument("--expect-channel")
    ap.add_argument("--quarantine", action="store_true")
    a = ap.parse_args()
    try:
        d = json.load(open(a.path, encoding="utf-8"))
        bad = problems(d, a.expect_version, a.expect_channel)
    except Exception as e:
        bad = ["cannot read %s: %s" % (a.path, e)]
    if not bad:
        print("capture check passed: %s %s (%s), %d configs" % (d["browser"], d["version"], d.get("channel"), len(d["configs"])))
        return 0
    for b in bad:
        print("::error title=Capture check failed::%s: %s" % (a.path, b))
    if a.quarantine and os.path.exists(a.path):
        os.replace(a.path, os.path.join(os.path.dirname(a.path), "latest.invalid.json"))
        print("moved %s aside (latest.invalid.json); the previous data will be kept" % a.path)
    return 1


if __name__ == "__main__":
    sys.exit(main())
