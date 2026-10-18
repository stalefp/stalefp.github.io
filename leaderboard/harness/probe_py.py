"""Python side of the behaviour probe (probe.py). One library client, N requests on that SAME client.

  probe_py.py <library> <profile> <browser> <url> <n> <headers-json>

The probe server closes every connection after one response, so each request opens a new TLS connection: that is
what lets probe.py see session resumption (pre_shared_key) and per-connection extension order. Headers are passed
in the browser's captured order through each library's own ordered-header option, with the library's default
headers switched off where it allows. Prints one JSON line {ok, error, done}.

To add a library: write a factory below (profile, browser, headers) -> get(url) and add it to ADAPTERS.
"""
import asyncio, json, sys


def curl_cffi(profile, browser, hdrs):
    from curl_cffi import requests as r
    s = r.Session(impersonate=profile, verify=False, default_headers=False)
    return lambda url: s.get(url, headers=dict(hdrs), timeout=20)


def primp(profile, browser, hdrs):
    import primp as p
    c = p.Client(impersonate=profile, verify=False)
    return lambda url: c.get(url, headers=dict(hdrs), timeout=20)


def rnet(profile, browser, hdrs):
    import rnet as rn
    from rnet.blocking import Client
    c = Client(emulation=getattr(rn.Emulation, profile), verify=False)
    names = [k for k, _ in hdrs]
    return lambda url: c.get(url, headers=dict(hdrs), orig_headers=names, default_headers=False)


def tls_client_py(profile, browser, hdrs):
    import tls_client
    # same random_tls_extension_order setting as the main harness (bench.py: on for Chrome cases, off for Firefox)
    s = tls_client.Session(client_identifier=profile, random_tls_extension_order=(browser == "chrome"), header_order=[k for k, _ in hdrs])
    s.headers.clear()
    return lambda url: s.get(url, headers=dict(hdrs), insecure_skip_verify=True, timeout_seconds=20)


def noble_tls(profile, browser, hdrs):
    import noble_tls as nt
    from noble_tls import Client
    loop = asyncio.new_event_loop()
    s = nt.Session(client=getattr(Client, profile.upper()), random_tls_extension_order=(browser == "chrome"), header_order=[k for k, _ in hdrs])
    try:
        s.headers.clear()
    except Exception:
        pass
    return lambda url: loop.run_until_complete(s.get(url, headers=dict(hdrs), insecure_skip_verify=True, timeout_seconds=20))


def hrequests(profile, browser, hdrs):
    """Board profile "chrome 131" = hrequests' built-in browser + version (harness/extra/hrequests_bench.py)."""
    import hrequests as hr
    b, v = profile.split()
    s = hr.Session(browser=b, version=int(v), os="lin", verify=False, header_order=[k for k, _ in hdrs])
    s.headers.clear()
    return lambda url: s.get(url, headers=dict(hdrs), verify=False, timeout=20)


ADAPTERS = {"hrequests": hrequests, "curl_cffi": curl_cffi, "primp": primp, "rnet": rnet, "tls-client (Python)": tls_client_py, "noble-tls": noble_tls}

if __name__ == "__main__":
    lib, profile, browser, url, n, hdrs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), json.loads(sys.argv[6])
    done = 0
    try:
        get = ADAPTERS[lib](profile, browser, hdrs)
        for i in range(n):
            get("%s&i=%d" % (url, i)); done += 1
        print(json.dumps(dict(ok=True, done=done)))
    except Exception as e:
        print(json.dumps(dict(ok=done > 0, done=done, error=repr(e)[:300])))
