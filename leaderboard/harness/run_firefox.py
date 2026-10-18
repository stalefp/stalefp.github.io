"""Python Firefox-profile cases (separate from bench.py's Chrome cases). Saves the raw echo JSON per case.
Usage: run_firefox.py <outdir>"""
import asyncio, json, os, sys, time
URL = "https://tls.peet.ws/api/all"


def run_curl(t):
    from curl_cffi import requests as r
    return r.get(URL, impersonate=t, timeout=30).json()


def run_rnet(t):
    import rnet
    async def f():
        c = rnet.Client(emulation=getattr(rnet.Emulation, t))
        resp = await c.get(URL); return json.loads(await resp.text())
    return asyncio.run(f())


def run_tlsclient(t):
    import tls_client
    return tls_client.Session(client_identifier=t).get(URL).json()


def run_noble(t):
    import noble_tls
    from noble_tls import Client
    async def f():
        s = noble_tls.Session(client=getattr(Client, t.upper()))
        return (await s.get(URL)).json()
    return asyncio.run(f())


# Only profiles that exist in the pinned versions (leaderboard/requirements.txt).
CASES = [("curl_cffi", "firefox147", run_curl), ("curl_cffi", "firefox144", run_curl),
         ("rnet", "Firefox147", run_rnet), ("rnet", "Firefox139", run_rnet),
         ("noble-tls", "firefox_147", run_noble), ("tls-client(py)", "firefox_120", run_tlsclient)]

def wanted(lib):
    """STALE_LIBS (comma-separated board library names) limits the run to those libraries; empty = all cases."""
    import os
    v = os.environ.get("STALE_LIBS", "")
    return not v or {"tls-client(py)": "tls-client (Python)", "tls-client(go)": "tls-client", "azuretls": "azuretls-client", "utls": "uTLS"}.get(lib, lib) in [x.strip() for x in v.split(",")]


if __name__ == "__main__":
    out = sys.argv[1]; os.makedirs(out, exist_ok=True)
    for lib, profile, fn in CASES:
        if not wanted(lib):
            continue
        name = f"{lib}_{profile}"
        try:
            d = fn(profile)
            json.dump(d, open(os.path.join(out, name + ".json"), "w"), indent=1)
            print(f"{name:32} ok  ja4={d.get('tls', {}).get('ja4')}", flush=True)
        except Exception as e:
            print(f"{name:32} ERR {repr(e)[:200]}", flush=True)
