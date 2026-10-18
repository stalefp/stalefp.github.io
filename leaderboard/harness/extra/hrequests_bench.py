"""hrequests cases: python hrequests_bench.py <outdir> chrome|firefox
Uses hrequests' newest built-in TLS version per browser (session.chrome/firefox.versions in the pinned release), os=linux.
Note: hrequests downloads its Go bridge (hrequests-cgo-<ver>-linux-amd64.so) from the daijro/hrequests GitHub releases on
first use; hrequests itself does not check a checksum. The bridge file name is recorded with the versions."""
import json, os, sys, traceback
out, which = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
import hrequests
from hrequests.session import BROWSER_MAP
ver = BROWSER_MAP[which].versions[-1]
name = "hrequests_%s%d" % (which, ver)
try:
    s = hrequests.Session(browser=which, version=ver, os="lin")
    r = s.get("https://tls.peet.ws/api/all")
    if r.status_code != 200: raise RuntimeError("HTTP %s" % r.status_code)
    json.loads(r.text)
    open(os.path.join(out, name + ".json"), "w").write(r.text); print(name, "ok")
    ok = True
except Exception as e:
    open(os.path.join(out, name + ".error.txt"), "w").write(repr(e)[:400]); print(name, "ERR", repr(e)[:300]); ok = False
import importlib.metadata as md, hrequests.cffi as hc
bins = [f for f in os.listdir(os.path.join(os.path.dirname(hc.__file__), "bin")) if f.startswith("hrequests-cgo")]
json.dump({"py:hrequests": md.version("hrequests"), "hrequests_bridge": bins[0] if bins else None, "hrequests_%s_profile" % which: name},
          open(os.path.join(out, "_hrequests_versions_%s.json" % which), "w"))
sys.exit(0 if ok else 1)
