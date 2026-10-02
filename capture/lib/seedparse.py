"""Minimal protobuf reader for Chrome's VariationsSeed (components/variations/proto/{variations_seed,study}.proto).
Only the fields needed to answer "which studies touch network/TLS features, with which group weights" are decoded."""

def _varint(b, i):
    v = s = 0
    while True:
        x = b[i]; i += 1; v |= (x & 0x7F) << s; s += 7
        if not x & 0x80: return v, i

def fields(b):
    i = 0; out = []
    while i < len(b):
        key, i = _varint(b, i); fn, wt = key >> 3, key & 7
        if wt == 0: v, i = _varint(b, i)
        elif wt == 1: v = b[i:i+8]; i += 8
        elif wt == 2:
            ln, i = _varint(b, i); v = b[i:i+ln]; i += ln
        elif wt == 5: v = b[i:i+4]; i += 4
        else: raise ValueError("wire type %d" % wt)
        out.append((fn, wt, v))
    return out

PLATFORMS = {0: "windows", 1: "mac", 2: "linux", 3: "chromeos", 4: "android", 5: "ios", 6: "chromeos_lacros", 7: "android_webview", 8: "fuchsia", 9: "android_weblayer"}
CHANNELS = {-1: "unknown", 0: "canary", 1: "dev", 2: "beta", 3: "stable"}

def parse_layers(seed_bytes):
    """VariationsSeed.layers (field 6): Layer{id=1, num_slots=2, members=3{id=1, slots=2{start=1,end=2}}}."""
    layers = {}
    for fn, wt, v in fields(seed_bytes):
        if fn != 6 or wt != 2: continue
        lid, nslots, members = None, None, {}
        for f2, w2, v2 in fields(v):
            if f2 == 1 and w2 == 0: lid = v2
            elif f2 == 2 and w2 == 0: nslots = v2
            elif f2 == 3 and w2 == 2:
                mid, cnt = None, 0
                for f3, w3, v3 in fields(v2):
                    if f3 == 1 and w3 == 0: mid = v3
                    elif f3 == 2 and w3 == 2:
                        r = dict((a, c) for a, _, c in fields(v3)); cnt += r.get(2, 0) - r.get(1, 0) + 1
                members[mid] = cnt
        layers[lid] = {"num_slots": nslots, "members": members}
    return layers

def parse_study(b):
    st = {"name": None, "experiments": [], "filter": {}, "layer": None}
    for fn, wt, v in fields(b):
        if fn == 1 and wt == 2: st["name"] = v.decode("utf-8", "replace")
        elif fn == 16 and wt == 2:
            ref = {"layer_id": None, "member_ids": []}
            for f2, w2, v2 in fields(v):
                if f2 == 1 and w2 == 0: ref["layer_id"] = v2
                elif f2 == 2 and w2 == 0: ref["member_ids"].append(v2)
                elif f2 == 3: ref["member_ids"].extend([v2] if w2 == 0 else _packed(v2))
            st["layer"] = ref
        elif fn == 9 and wt == 2:
            ex = {"name": None, "weight": 0, "enable_features": [], "disable_features": [], "params": {}}
            for f2, w2, v2 in fields(v):
                if f2 == 1 and w2 == 2: ex["name"] = v2.decode("utf-8", "replace")
                elif f2 == 2 and w2 == 0: ex["weight"] = v2
                elif f2 == 6 and w2 == 2:
                    kv = {a: c.decode("utf-8", "replace") for a, _, c in fields(v2) if isinstance(c, (bytes, bytearray))}
                    if 1 in kv: ex["params"][kv[1]] = kv.get(2)
                elif f2 == 12 and w2 == 2:
                    for f3, w3, v3 in fields(v2):
                        if w3 == 2 and f3 in (1, 3): ex["enable_features"].append(v3.decode())
                        elif w3 == 2 and f3 in (2, 4): ex["disable_features"].append(v3.decode())
            st["experiments"].append(ex)
        elif fn == 10 and wt == 2:
            flt = st["filter"]
            for f2, w2, v2 in fields(v):
                if f2 == 2 and w2 == 2: flt["min_version"] = v2.decode()
                elif f2 == 3 and w2 == 2: flt["max_version"] = v2.decode()
                elif f2 == 4:
                    vals = [v2] if w2 == 0 else _packed(v2)
                    flt.setdefault("channel", []).extend(CHANNELS.get(x if x < 2**31 else x - 2**64, x) for x in vals)
                elif f2 == 5:
                    vals = [v2] if w2 == 0 else _packed(v2)
                    flt.setdefault("platform", []).extend(PLATFORMS.get(x, x) for x in vals)
                elif f2 == 9 and w2 == 2: flt.setdefault("country", []).append(v2.decode())
    return st

def _packed(b):
    i = 0; out = []
    while i < len(b):
        v, i = _varint(b, i); out.append(v)
    return out

def unwrap(b):
    """VariationsSeedV2 (seed-file trial) stores a wrapper whose field 1 is the serialized VariationsSeed."""
    try:
        f = fields(b)
        if f and f[0][0] == 1 and f[0][1] == 2 and len(f[0][2]) > len(b) // 2:
            inner = fields(f[0][2])
            if any(fn == 2 for fn, _, _ in inner): return f[0][2]
    except Exception:
        pass
    return b

def studies(seed_bytes):
    seed_bytes = unwrap(seed_bytes)
    return [parse_study(v) for fn, wt, v in fields(seed_bytes) if fn == 2 and wt == 2]

def network_studies(seed_bytes, feature_substrings):
    """Studies where any experiment enables/disables a feature whose name contains one of feature_substrings.
    Returns studies with per-group share (weight / total weight)."""
    res = []
    layers = parse_layers(unwrap(seed_bytes))
    for st in studies(seed_bytes):
        feats = {f for ex in st["experiments"] for f in ex["enable_features"] + ex["disable_features"]}
        hit = sorted(f for f in feats if any(s.lower() in f.lower() for s in feature_substrings))
        if not hit: continue
        tot = sum(ex["weight"] for ex in st["experiments"]) or 1
        pop = 1.0
        if st["layer"]:
            L = layers.get(st["layer"]["layer_id"])
            if L and L["num_slots"]:
                pop = sum(L["members"].get(m, 0) for m in st["layer"]["member_ids"]) / L["num_slots"]
            else:
                pop = None
        res.append({"study": st["name"], "features": hit, "filter": st["filter"], "layer": st["layer"],
                    "population_share": round(pop, 4) if pop is not None else None,
                    "groups": [{"name": ex["name"], "share": round(ex["weight"] / tot, 4),
                                "share_of_population": round(pop * ex["weight"] / tot, 4) if pop is not None else None,
                                "enable_features": ex["enable_features"],
                                "disable_features": ex["disable_features"], "params": ex["params"]} for ex in st["experiments"]]})
    return res
