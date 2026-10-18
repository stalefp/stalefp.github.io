#!/usr/bin/env python3
"""Capture another Chromium-based browser (Microsoft Edge, Brave) with the same pipeline as Chrome (lib/capture.py).

Kept separate from the Chrome capture: own output dir, own JSON, never touches capture/data. The binary must come from the
vendor's official signed apt repo (see capture/install_brand_deb.sh, which checks the repo signature and the .deb SHA256).

  python capture/lib/capture_brand.py --brand edge  --bin /opt/microsoft/msedge/msedge --out out/edge-linux
  python capture/lib/capture_brand.py --brand brave --bin /opt/brave.com/brave/brave   --out out/brave-linux

Only the 'default' config is captured (headed under Xvfb on Linux, no relaunch) to keep CI minutes low. Chrome's Finch/
VersionHistory data does not apply to these browsers, so current_stable / is_current_* are dropped; "current" here means
the newest version in the vendor's repo at capture time (passed in via --package-version / --repo).
"""
import argparse, json, os, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture

BRANDS = {"edge": "Microsoft Edge", "brave": "Brave Browser"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--brand", required=True, choices=sorted(BRANDS)); ap.add_argument("--bin", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--modes", default="headed")
    ap.add_argument("--package-version"); ap.add_argument("--repo"); ap.add_argument("--deb-sha256"); ap.add_argument("--signing-key")
    a = ap.parse_args()
    name = BRANDS[a.brand]
    if capture.IS_WIN:   # msedge.exe / brave.exe --version print nothing on Windows; read the PE version resource
        out = capture._win_version(a.bin)
        m = re.match(r"(?:%s|%s)\s+([\d.]+)" % (re.escape(name), re.escape(name.split()[0])), out)
    else:
        out = subprocess.run([a.bin, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
        m = re.match(re.escape(name) + r"\s+([\d.]+)", out)
    if not m: raise SystemExit("unexpected version output for %s: %r" % (name, out))
    ver = m.group(1)
    if a.brand == "brave" and int(ver.split(".")[0]) < 100 and a.package_version and int(a.package_version.split(".")[0]) >= 100:
        ver = a.package_version
    info = {"path": os.path.realpath(a.bin), "browser": name, "version": ver, "channel": "stable", "version_string": out}
    capture.detect_chrome = lambda explicit=None: info
    capture.fetch_current_stable = lambda *x, **k: {}       # Chrome's VersionHistory is not this browser's release feed
    sys.argv = [sys.argv[0], "--out", a.out, "--modes", a.modes, "--only", "default", "--no-relaunch", "--seed-wait", "0"]
    capture.main()
    p = os.path.join(a.out, "latest.json"); d = json.load(open(p))
    for k in ("current_stable", "is_current_linux_stable", "is_current_platform_stable", "baseline_comparisons"): d.pop(k, None)
    d["schema_version"] = "brand-capture-1"; d["brand"] = a.brand
    # Brave's version is <chromium major>.<brave version>; Edge's major is the Chromium major
    d["chromium_major"] = int(ver.split(".")[0])
    d["brand_version"] = ".".join(ver.split(".")[1:]) if a.brand == "brave" else ver
    d["package"] = {"version": a.package_version, "repo": a.repo, "sha256": a.deb_sha256, "signing_key": a.signing_key,
                    "kind": "windows installer (SHA256 + Authenticode checked)" if capture.IS_WIN else "signed apt repo .deb"}
    d["notes"] = [n for n in d.get("notes", []) if "VersionHistory" not in n and "Finch" not in n]
    d["notes"].append("Only the default profile was captured (%s, no relaunch). 'Current' = newest %s %s at capture time." % (a.modes, name, "from the vendor's Windows release feed" if capture.IS_WIN else "in the vendor's official apt repo"))
    js = json.dumps(d, indent=2)
    open(p, "w").write(js)
    for f in os.listdir(a.out):   # rewrite the versioned copy too (capture.py names it chrome-<ver>-<date>.json)
        if f.startswith("chrome-") and f.endswith(".json"):
            os.replace(os.path.join(a.out, f), os.path.join(a.out, "%s-%s" % (a.brand, f[len("chrome-"):])))
    for f in os.listdir(a.out):
        if f.startswith(a.brand + "-") and f.endswith(".json"): open(os.path.join(a.out, f), "w").write(js)
    r = next((c for c in d["configs"] if c["name"] == d.get("reference_config")), {})
    print("%s %s (Chromium %s) ja4=%s resumed=%s h2=%s quic=%s" % (name, ver, d["chromium_major"], r.get("ja4"), r.get("ja4_resumed"), r.get("h2_akamai"), (r.get("quic") or {}).get("ja4")))

if __name__ == "__main__":
    main()
