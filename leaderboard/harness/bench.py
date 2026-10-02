import json,time,asyncio,re,sys,statistics
from fp import summarize, load
URL="https://tls.peet.ws/api/all"
def g(x): return [v for v in (x or []) if 'GREASE' not in v]
def run_curl(t):
    from curl_cffi import requests as r
    return r.get(URL,impersonate=t,timeout=30).json()
def run_primp(t):
    import primp
    return json.loads(primp.Client(impersonate=t,timeout=30).get(URL).text)
def run_rnet(t):
    import rnet
    async def f():
        c=rnet.Client(emulation=getattr(rnet.Emulation,t))
        resp=await c.get(URL); return json.loads(await resp.text())
    return asyncio.run(f())
def run_tlsclient(t):
    import tls_client
    return tls_client.Session(client_identifier=t,random_tls_extension_order=True).get(URL).json()
def run_noble(t):
    import noble_tls
    from noble_tls import Client
    async def f():
        s=noble_tls.Session(client=getattr(Client,t.upper()),random_tls_extension_order=True)
        return (await s.get(URL)).json()
    return asyncio.run(f())
CASES=[("curl_cffi","chrome150",run_curl),("curl_cffi","chrome146",run_curl),("curl_cffi","chrome136",run_curl),
 ("primp","chrome_146",run_primp),("rnet","Chrome145",run_rnet),("rnet","Chrome137" ,run_rnet),
 ("noble-tls","chrome_146",run_noble),("tls-client(py)","chrome_120",run_tlsclient)]
ref=summarize(load("chrome_raw.html"))
def score(s):
    chk={
     "JA4 exact":s['ja4']==ref['ja4'],
     "HTTP/2 (Akamai)":s['akamai']==ref['akamai'],
     "Groups+PQ":g(s['groups'])==g(ref['groups']),
     "ALPS new id":s['alps']==ref['alps'],
     "ECH GREASE":s['ech']==ref['ech'],
     "Cert compress":s['certc']==ref['certc'],
     "Ext set":s['exts']==ref['exts'],
     "Header order":[h for h in s['header_names'] if h in ref['header_names']]==[h for h in ref['header_names'] if h in s['header_names']],
    }
    return chk
out=[]
for lib,t,fn in CASES:
    try:
        t0=time.time(); d=fn(t); dt=time.time()-t0
        s=summarize(d); c=score(s)
        out.append(dict(lib=lib,profile=t,ok=True,secs=round(dt,2),checks=c,passed=sum(c.values()),fp=s))
        print(f"{lib:15} {t:12} {sum(c.values())}/{len(c)} ja4={s['ja4']} akamai={s['akamai']} alps={s['alps']} groups={g(s['groups'])}",flush=True)
    except Exception as e:
        out.append(dict(lib=lib,profile=t,ok=False,err=repr(e)[:300])); print(lib,t,"ERR",repr(e)[:200],flush=True)
json.dump(dict(ref=ref,results=out),open("results.json","w"),indent=1)
