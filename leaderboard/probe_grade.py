"""Grade the behaviour probe (harness/probe.py -> data/probe.json) for every board: reconnection (session resumption),
extension-order shuffling and header order. Used by build.py (Chrome) and build_firefox.py (and any future board), so a
new library or board gets the same grading once probe.json has rows for it.

Header order counts toward the verdict only for rows where the comparison was fair: the library sent exactly the header
set we gave it, in the same order on every request. Otherwise it stays a note with the reason.
"""
import glob, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
TB = os.path.dirname(HERE)
PROBE = os.path.join(HERE, "data", "probe.json")
ESCALATE = {"exact": "close", "exact_variant": "close", "close": "behind", "behind": "behind"}


def _load(p):
    try:
        return json.load(open(p))
    except Exception:
        return None


def browser_behaviour(board):
    """What the real browser does, from our own captures: does extension order vary between connections, its resumed JA4s,
    and its header order."""
    caps = []
    if board == "chrome":
        for f in [os.path.join(TB, "capture", "data", "latest.json")] + sorted(glob.glob(os.path.join(TB, "capture", "data", "platforms", "*.json"))):
            for c in (_load(f) or {}).get("configs", []):
                caps += [c.get("extensions"), c.get("extensions_resumed")]
        d = _load(os.path.join(TB, "capture", "data", "latest.json")) or {}
        ref = next((c for c in d.get("configs", []) if c["name"] == d.get("reference_config")), {})
        resumed = sorted({c.get("ja4_resumed") for c in d.get("configs", []) if c.get("ja4_resumed")})
        default_resumed, hdr = ref.get("ja4_resumed"), ref.get("header_order")
    else:
        base = os.path.join(TB, "capture", "data", board)
        files = sorted(glob.glob(os.path.join(base, "history", "*.json"))) + [os.path.join(base, "latest.json")] + sorted(glob.glob(os.path.join(base, "platforms", "*.json")))
        for f in files:
            d = _load(f)
            if d and d.get("extensions"):
                caps += [d.get("extensions"), d.get("extensions_resumed")] + list(d.get("extension_orders") or [])
        d = _load(os.path.join(base, "latest.json")) or {}
        default_resumed, hdr = d.get("ja4_resumed"), d.get("header_order")
        resumed = [default_resumed] if default_resumed else []
    orders = {tuple(x for x in c if x not in ("0x0029", "0x0015")) for c in caps if c}
    return dict(captures=len([c for c in caps if c]), distinct_orders=len(orders), varies=order_varies(orders) if orders else None,
                resumed_ja4s=resumed, default_resumed_ja4=default_resumed, header_order=[h for h in (hdr or []) if not h.startswith(":")])


def order_varies(orders):
    """True when the same set of extensions arrived in more than one order. A resumed hello has a different set
    (early_data etc.), so a fresh/resumed difference alone is not shuffling."""
    by_set = {}
    for o in orders:
        by_set.setdefault(frozenset(o), set()).add(tuple(o))
    return any(len(v) > 1 for v in by_set.values())


def apply(board, data, browser_name):
    probe = _load(PROBE) or {}
    bp = (probe.get("boards") or {}).get(board) or {}
    rows = bp.get("rows") or {}
    beh = browser_behaviour(board)
    data["probe_reference"] = dict(beh, connections_per_row=probe.get("connections_per_row"), generated_at=probe.get("generated_at"),
                                   endpoint=probe.get("endpoint"), requested_headers=[k for k, _ in bp.get("requested_headers") or []])
    requested = data["probe_reference"]["requested_headers"]
    # a profile of the library that resumed (board row or capability case, any board): "this profile doesn't" vs "never seen"
    resumers = {}
    boards = probe.get("boards") or {}
    for b in ([boards[board]] if board in boards else []) + [v for k, v in boards.items() if k != board]:   # same board first
        for r in b.get("rows", {}).values():
            if any(c.get("has_psk") and c.get("server_resumed") for c in r.get("connections") or []):
                resumers.setdefault(r["library"], r["profile"])
        for r in (b.get("capability") or {}).values():
            if r.get("resumed"):
                resumers.setdefault(r["library"], r["profile"])
    for e in data["libraries"]:
        if "base_verdict" not in e:   # the TLS/HTTP2 verdict; re-annotating never stacks the header-order penalty
            e["base_verdict"], e["base_counted"] = e["verdict"], list(e.get("counted_mismatches") or [])
        e["verdict"], e["counted_mismatches"] = e["base_verdict"], list(e["base_counted"])
        p = rows.get(e["id"])
        e["behaviour"] = []
        if not p or p.get("status") != "tested":
            e["resumption_probe"] = dict(status="no_adapter" if (p or {}).get("status") == "no_adapter" else "not_tested")
            e["shuffle"] = e["header_order_probe"] = None
            continue
        conns = p["connections"]
        psk = [c for c in conns if c["has_psk"]]
        ok = [c for c in psk if c.get("server_resumed")]
        if ok:
            st, rj = "resumes", ok[0]["ja4"]
            match, match_any = rj == beh["default_resumed_ja4"], rj in beh["resumed_ja4s"]
        else:
            st = "profile_no_resume" if e["library"] in resumers else "no_resume"
            rj = match = match_any = None
        e["resumption_probe"] = dict(status=st, resuming_profile=resumers.get(e["library"]) if st == "profile_no_resume" else None,
                                     connections=len(conns), resumed_connections=len(ok), offered_psk=len(psk), resumed_ja4=rj,
                                     browser_resumed_ja4=beh["default_resumed_ja4"], matches_browser=match, matches_browser_variant=match_any)
        orders = {tuple(c["ext_order"]) for c in conns}
        varies = order_varies(orders)
        e["shuffle"] = dict(connections=len(conns), distinct_orders=len(orders), varies=varies, browser_varies=beh["varies"],
                            match=(varies == beh["varies"]) if beh["varies"] is not None else None)
        rh = p.get("request_headers") or []
        first = rh[0] if rh else []
        reason = None
        if not rh:
            reason = "no request reached the server"
        elif not all(set(x) == set(requested) for x in rh):
            extra = sorted({h for x in rh for h in x} - set(requested)); missing = sorted(set(requested) - {h for x in rh for h in x})
            reason = "the library changed the header set (%s)" % "; ".join(filter(None, ["added " + ", ".join(extra) if extra else "",
                                                                                          "dropped " + ", ".join(missing) if missing else ""]))
        elif not all(x == first for x in rh):
            reason = ("the header order changed from request to request (%d different orders in %d requests), so the caller can't "
                      "control it" % (len({tuple(x) for x in rh}), len(rh)))
        fair = reason is None
        hmatch = (first == requested) if fair else None
        e["header_order_probe"] = dict(fair=fair, unfair_reason=reason, sent=first, browser=requested, match=hmatch, counted=fair,
                                       pseudo_order=p.get("pseudo_order"))
        if fair and not hmatch:
            e["counted_mismatches"].append("header_order")
            e["verdict"] = ESCALATE.get(e["verdict"], e["verdict"])
        e["behaviour"] = lines(e, browser_name)
    return data


def lines(e, b):
    out = []
    r = e.get("resumption_probe") or {}
    n = r.get("connections")
    if r.get("status") == "resumes":
        m = ("and its resumed JA4 matches %s's" % b if r["matches_browser"] else "and its resumed JA4 matches one of %s's variants" % b
             if r["matches_browser_variant"] else "but its resumed JA4 differs from %s's" % b)
        out.append("Reconnecting: resumed the TLS session on %d of %d new connections, %s." % (r["resumed_connections"], n - 1, m))
    elif r.get("status") == "profile_no_resume":
        out.append("Reconnecting: this profile never resumed the TLS session in %d connections; the library's %s profile did in our test, and %s resumes."
                   % (n, r["resuming_profile"], b))
    elif r.get("status") == "no_resume":
        out.append("Reconnecting: never resumed the TLS session in %d connections, and no profile of this library resumed in our test; %s resumes." % (n, b))
    s = e.get("shuffle") or {}
    if s:
        bv = "varies on every connection" if s["browser_varies"] else "stays the same on every connection"
        lv = ("varied (%d different orders in %d connections)" % (s["distinct_orders"], s["connections"])) if s["varies"] else "stayed the same in all %d connections" % s["connections"]
        out.append("Extension order: %s %s; this library's %s%s." % (b, bv, lv, "" if s["match"] is None else (", which matches" if s["match"] else ", which doesn't match")))
    h = e.get("header_order_probe") or {}
    if h:
        if h["fair"]:
            out.append("Header order (counted): " + ("sent our %s header set in %s's order." % (b, b) if h["match"] else "sent the same headers in a different order than %s." % b))
        else:
            out.append("Header order (not graded for this row): " + h["unfair_reason"] + ".")
    return out
