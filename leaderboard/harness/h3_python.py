"""One HTTP/3 request with a Python library's Chrome profile (run with tlsbench/.venv/bin/python).
Usage: h3_python.py <case> <url>   cases: curl_cffi:<target> | noble-tls:<client>
Prints one JSON line {case, ok, proto, status, error}. Certificate verification is off (local self-signed endpoint).
Called by run_h3.py, which records the QUIC ClientHello + HTTP/3 SETTINGS with capture/lib/server.py."""
import asyncio, json, sys

def curl(t, url):
    from curl_cffi import requests as r
    resp = r.get(url, impersonate=t, http_version="v3only", verify=False, timeout=15)
    return dict(ok=True, proto=str(getattr(resp, "http_version", "")), status=resp.status_code)

def noble(t, url):
    import noble_tls
    from noble_tls import Client
    async def f():
        s = noble_tls.Session(client=getattr(Client, t.upper()), protocol_racing=True)
        resp = await s.get(url, insecure_skip_verify=True, timeout_seconds=15)
        return dict(ok=True, proto=None, status=resp.status_code)
    return asyncio.run(f())

case, url = sys.argv[1], sys.argv[2]
lib, _, prof = case.partition(":")
try:
    res = {"curl_cffi": curl, "noble-tls": noble}[lib](prof, url)
except Exception as e:
    res = dict(ok=False, error=repr(e)[:400])
res["case"] = case
print(json.dumps(res))
