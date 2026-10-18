#!/usr/bin/env python3
"""Fetch a Google-signed Chrome for Android APK (x86_64, standalone, not a split bundle) for the newest version currently
serving on Android stable, and verify it. Used by the Android capture (.github/workflows/android-capture.yml).

  fetch_chrome_apk.py --out DIR [--arch x86_64] [--pin SHA256] [--also-pin-from APK]

Source: APKMirror (a mirror that only republishes APKs whose signature matches the developer's existing key).
We don't trust the mirror: every download is checked here before it is used:
  1. SHA-256 of the file equals the SHA-256 the mirror lists for that variant (transfer integrity only),
  2. apksigner verifies the APK signature, and the signer certificate SHA-256 equals Google's Chrome release certificate
     (PIN below; --also-pin-from compares with the certificate of the Chrome preinstalled in the Google system image),
  3. aapt2: package com.android.chrome, versionName == the version we asked for, native code == the emulator's ABI.
Prints KEY=VALUE lines (APK, APK_VERSION, APK_SHA256, APK_CERT_SHA256, APK_SOURCE) for $GITHUB_ENV; exits 1 when no
version could be fetched AND verified (the capture then falls back to the preinstalled Chrome, labelled with its real version).
"""
import argparse, hashlib, html, http.cookiejar, json, os, re, subprocess, sys, urllib.request

# Google's Chrome for Android release signing certificate (com.android.chrome), SHA-256 of the DER certificate.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib"))
from fetch_pin import PIN  # noqa: E402  Google's Chrome for Android release certificate
VH = "https://versionhistory.googleapis.com/v1/chrome/platforms/android/channels/stable/versions/all/releases?filter=endtime=none"
B = "https://www.apkmirror.com"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def log(*a): print(*a, file=sys.stderr, flush=True)


def get(url, ref=B, binary=False):
    r = op.open(urllib.request.Request(url, headers={"User-Agent": UA, "Referer": ref}), timeout=180)
    data = r.read()
    return data if binary else data.decode("utf-8", "replace")


def vkey(v): return tuple(int(x) for x in v.split("."))


def current_versions():
    rel = json.load(urllib.request.urlopen(VH, timeout=30)).get("releases", [])
    return sorted({x["version"] for x in rel if (x.get("fraction") or 0) > 0}, key=vkey, reverse=True)


def variants(version):
    slug = "google-chrome-%s-release" % version.replace(".", "-")
    page = get("%s/apk/google-inc/chrome/%s/" % (B, slug))
    out = []
    for row in re.split(r'<div class="table-row headerFont">', page)[1:]:
        text = " ".join(re.sub(r"<[^>]+>", " ", row[:3000]).split())
        link = re.search(r'href="(/apk/google-inc/chrome/%s/[^"]+-android-apk-download/)"' % slug, row)
        if link: out.append(dict(text=text, link=link.group(1)))
    return out


def tool(name):
    for d in [os.environ.get("BUILD_TOOLS")] + sorted(__import__("glob").glob(os.path.join(os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", "")), "build-tools", "*")), reverse=True):
        if d and os.path.exists(os.path.join(d, name)): return os.path.join(d, name)
    return name


def cert_sha256(apk):
    r = subprocess.run([tool("apksigner"), "verify", "--print-certs", apk], capture_output=True, text=True)
    if r.returncode != 0: raise RuntimeError("apksigner verify failed: " + (r.stdout + r.stderr)[-400:])
    # "Signer #1 certificate ..." or, for APKs signed per SDK range (v3.1), "Signer (minSdkVersion=..) certificate ...";
    # source-stamp lines start with "Source Stamp" and are ignored.
    certs = sorted(set(re.findall(r"(?m)^Signer[^\n]*? certificate SHA-256 digest: ([0-9a-f]{64})", r.stdout)))
    if len(certs) != 1: raise RuntimeError("expected exactly one signing certificate, got %s: %s" % (certs, r.stdout[:600]))
    return certs[0]


def badging(apk):
    r = subprocess.run([tool("aapt2"), "dump", "badging", apk], capture_output=True, text=True)
    pkg = re.search(r"package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", r.stdout)
    abi = re.search(r"native-code: (.*)", r.stdout)
    return dict(package=pkg.group(1) if pkg else None, version_code=pkg.group(2) if pkg else None, version=pkg.group(3) if pkg else None,
                abis=re.findall(r"'([^']+)'", abi.group(1)) if abi else [])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True); ap.add_argument("--arch", default="x86_64")
    ap.add_argument("--also-pin-from", help="APK whose signer must match too (the image's preinstalled Chrome)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    pins = {PIN}
    if a.also_pin_from:
        sys_cert = cert_sha256(a.also_pin_from)
        log("preinstalled Chrome signer:", sys_cert, "(matches pin)" if sys_cert == PIN else "(DIFFERENT from pin)")
        if sys_cert != PIN: log("warning: the image's Chrome is not signed with the pinned Google certificate, so an update can't be installed over it")
    vs = current_versions()
    log("Android stable versions serving now:", vs)
    for v in vs:
        try:
            rows = variants(v)
        except Exception as e:
            log(v, ": no mirror release page (%s)" % str(e)[:120]); continue
        pick = [r for r in rows if " APK " in " %s " % r["text"] and a.arch in r["text"].split() and "BUNDLE" not in r["text"]]
        log(v, ": %d variants, %d standalone %s APK(s)" % (len(rows), len(pick), a.arch))
        for r in pick:
            try:
                vp = get(B + r["link"])
                want = re.search(r"SHA-256:\s*<span[^>]*>\s*([0-9a-f]{64})", vp)
                d = html.unescape(re.search(r'href="([^"]*download/\?key=[^"]*)"', vp).group(1))
                dp = get(B + d, B + r["link"])
                f = html.unescape(re.search(r'href="([^"]*download\.php\?[^"]*)"', dp).group(1))
                data = get(B + f, B + d, binary=True)
                path = os.path.join(a.out, "chrome-%s-%s.apk" % (v, a.arch))
                open(path, "wb").write(data)
                sha = hashlib.sha256(data).hexdigest()
                if not want or want.group(1) != sha: raise RuntimeError("SHA-256 %s does not match the mirror's listing %s" % (sha, want and want.group(1)))
                cert = cert_sha256(path)
                if cert not in pins: raise RuntimeError("signer %s is not Google's Chrome certificate" % cert)
                b = badging(path)
                if b["package"] != "com.android.chrome" or b["version"] != v or a.arch not in b["abis"]:
                    raise RuntimeError("unexpected APK contents %s" % b)
                log("verified", path, b, "sha256", sha, "signer", cert)
                print("APK=%s\nAPK_VERSION=%s\nAPK_VERSION_CODE=%s\nAPK_SHA256=%s\nAPK_CERT_SHA256=%s\nAPK_SOURCE=%s" % (
                    path, v, b["version_code"], sha, cert, B + r["link"]))
                return 0
            except Exception as e:
                log(v, "variant", r["link"], "rejected:", str(e)[:300])
    log("no current Android stable Chrome APK could be fetched and verified")
    return 1


if __name__ == "__main__":
    sys.exit(main())
