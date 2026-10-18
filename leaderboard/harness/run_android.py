"""Python cases for libraries' Chrome-for-Android profiles (same shape as run_safari.py). Saves the raw echo JSON per case.
Usage: run_android.py <outdir>"""
import asyncio, json, os, sys
URL = "https://tls.peet.ws/api/all"


def run_curl(t):
    from curl_cffi import requests as r
    return r.get(URL, impersonate=t, timeout=30).json()


def run_primp(t):
    import primp
    browser, _, os_ = t.partition("@")
    return json.loads(primp.Client(impersonate=browser, impersonate_os=os_, timeout=30).get(URL).text)


def run_rnet(t):
    import rnet
    browser, _, os_ = t.partition("@")
    async def f():
        c = rnet.Client(emulation=rnet.EmulationOption(emulation=getattr(rnet.Emulation, browser), emulation_os=getattr(rnet.EmulationOS, os_)))
        resp = await c.get(URL); return json.loads(await resp.text())
    return asyncio.run(f())


# Chrome-on-Android profiles that exist in the pinned versions (leaderboard/requirements.txt). curl_cffi has dedicated
# Android targets; primp and rnet take a desktop Chrome profile plus an "android" OS option.
CASES = [("curl_cffi", "chrome131_android", run_curl), ("curl_cffi", "chrome99_android", run_curl),
         ("primp", "chrome_146@android", run_primp), ("rnet", "Chrome145@Android", run_rnet)]


def wanted(lib):
    v = os.environ.get("STALE_LIBS", "")
    return not v or lib in [x.strip() for x in v.split(",")]


if __name__ == "__main__":
    out = sys.argv[1]; os.makedirs(out, exist_ok=True)
    for lib, profile, fn in CASES:
        if not wanted(lib):
            continue
        name = f"{lib}_{profile}".replace("@", "_")
        try:
            d = fn(profile)
            json.dump(d, open(os.path.join(out, name + ".json"), "w"), indent=1)
            print(f"{name:32} ok  ja4={d.get('tls', {}).get('ja4')} ua={d.get('user_agent', '')[:80]}", flush=True)
        except Exception as e:
            open(os.path.join(out, name + ".error.txt"), "w").write(repr(e)[:500])
            print(f"{name:32} ERR {repr(e)[:200]}", flush=True)
