"""THE ONLY PLACE that knows the layout of the Chrome reference file (capture/data/latest.json).

adapt_chrome_reference(raw) maps Moe's capture output (capture/SCHEMA.md, schema_version 1) into the internal reference
the leaderboard diffs against. Its JS twin is `adaptChromeReference` in site/js/app.js; keep the two in step.
(The pre-SCHEMA.md stand-in layout is leaderboard/ASSUMED_SCHEMA.md, now superseded.)

Internal reference shape (fingerprint dicts use the fingerprint.py shape: hex4 codes without "0x", GREASE removed):
  version, major, browser, branded, channel, os, captured_at, schema_version, assumed_schema(False), reference_config
  variations_source, active_variations_count
  fresh      fingerprint of the DEFAULT config (reference_config) incl. http2 {akamai, header_order}
  resumed    {ja4, ja4_r} | None
  http3      {ja4, ja4_resumed, ja4_r, h3_settings, h3_grease_settings, transport_params, header_order, alpn, has_trust_anchors} | None
  variants   [ {id, config, label, is_default, fingerprint, ja4, ja4_resumed, http3, population, flags} ]
             id: "default" (with ca34) | "no_ca34" (--disable-features=TLSTrustAnchorIDs) | "pq" (PqcBandwidthExperiment, 0x12e0)
             population: {share, platform, study, groups, source, note}; share is None unless latest.json states it
  current_stable  {platform: {newest, highest_full_rollout, releases[]}} as in latest.json
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from fingerprint import split_ja4_r

CERT_COMPRESSION = {1: "zlib", 2: "brotli", 3: "zstd"}  # RFC 8879 code points -> names used by the echo normalizer
VARIANT_CONFIGS = [  # (id, base_config, label)
    ("default", None, "Default (with ca34)"),
    ("no_ca34", "disable-TLSTrustAnchorIDs", "Without ca34"),
    ("pq", "finch-AddTLSServerHandshakePadding", "Post-quantum experiment (0x12e0)"),
]


def _hex(x):
    return x[2:].lower() if isinstance(x, str) and x.lower().startswith("0x") else x


def _hexes(xs):
    return [_hex(x) for x in xs] if xs is not None else None


def _fingerprint(cfg):
    ja4_r = cfg.get("ja4_r")
    if not ja4_r:
        return None
    a, c, e, s = split_ja4_r(ja4_r)
    return dict(
        ja4=cfg.get("ja4"), ja4_r=ja4_r, ja4_a=a,
        ciphers=sorted(c), extensions=sorted(e),           # from ja4_r: GREASE-free, SNI/ALPN excluded (JA4 rule)
        signature_algorithms=_hexes(cfg.get("sig_algs")),
        supported_groups=_hexes(cfg.get("groups")),
        key_shares=[_hex(k["group"]) for k in cfg["key_shares"]] if cfg.get("key_shares") is not None else None,
        alps=_hex(cfg.get("alps_codepoint")),
        cert_compression=[CERT_COMPRESSION.get(x, str(x)) for x in cfg["cert_compression"]] if cfg.get("cert_compression") is not None else None,
        trust_anchors=cfg.get("has_trust_anchors"),
        pq_padding_ext="12e0" in e,
        http2=dict(akamai=cfg.get("h2_akamai"), header_order=cfg.get("header_order") or None,
                   settings=cfg.get("h2_settings"), window_update=cfg.get("h2_window_update")),
        user_agent=cfg.get("user_agent"),
    )


def _http3(cfg):
    q = cfg.get("quic")
    if not q or not q.get("ja4"):
        return None
    return dict(ja4=q.get("ja4"), ja4_resumed=q.get("ja4_resumed"), ja4_r=q.get("ja4_r"),
                h3_settings=q.get("h3_settings"), h3_grease_settings=q.get("h3_grease_settings"),
                transport_params=q.get("transport_params") or [], header_order=q.get("header_order") or [],
                alpn=q.get("alpn"), alps=q.get("alps"), has_trust_anchors=q.get("has_trust_anchors"),
                groups=_hexes(q.get("groups")), key_shares=[_hex(k["group"]) for k in q.get("key_shares") or []],
                sig_algs=_hexes(q.get("sig_algs")))


def _population(raw, vid):
    """Population figure for a variant, only as stated in latest.json (finch_network_studies). Never estimated."""
    studies = raw.get("finch_network_studies") or []
    hint = {"pq": "0x12e0", "no_ca34": "0xca34"}.get(vid)
    if vid == "default":
        return dict(share=None, platform=None, study=None, groups=None, source=None,
                    note="Branded Chrome's built-in default (fresh profile, no flags). latest.json gives no share for it.")
    for s in studies:
        if hint in (s.get("extension_hint") or []):
            feats = set(s.get("features") or [])
            enabling = [g for g in s.get("groups") or [] if feats & set(g.get("enable_features") or []) and g.get("share_of_population")]
            share = round(sum(g["share_of_population"] for g in enabling), 6) if enabling else None
            return dict(share=share, platform=(s.get("filter") or {}).get("platform"), channel=(s.get("filter") or {}).get("channel"),
                        study=s.get("study"), groups=[g["name"] for g in enabling], source="latest.json finch_network_studies",
                        note="Sum of share_of_population over the study groups that enable %s." % ", ".join(sorted(feats)))
    if vid == "no_ca34":
        return dict(share=None, platform=None, study=None, groups=None, source=None,
                    note="No study in the captured variations seed toggles TLSTrustAnchorIDs, so latest.json has no population figure; "
                         "branded Chrome drops ca34 only with --disable-features=TLSTrustAnchorIDs (or a future Finch study).")
    return dict(share=None, platform=None, study=None, groups=None, source=None, note="No population figure in latest.json.")


def adapt_chrome_reference(raw):
    """raw: parsed capture/data/latest.json (SCHEMA.md v1). Returns the internal reference dict (see module doc)."""
    configs = {c["name"]: c for c in raw.get("configs") or []}
    ref_name = raw.get("reference_config")
    ref_cfg = configs.get(ref_name) or {}
    mode = ref_cfg.get("mode")
    version = raw.get("version")
    variants = []
    for vid, base, label in VARIANT_CONFIGS:
        cfg = ref_cfg if vid == "default" else configs.get("%s-%s" % (base, mode)) or next(
            (c for c in configs.values() if c.get("base_config") == base and c.get("ja4")), None)
        if not cfg:
            continue
        variants.append(dict(id=vid, label=label, config=cfg.get("name"), is_default=vid == "default", flags=cfg.get("flags") or [],
                             fingerprint=_fingerprint(cfg), ja4=cfg.get("ja4"), ja4_resumed=cfg.get("ja4_resumed"),
                             ja4_r_resumed=cfg.get("ja4_r_resumed"), has_trust_anchors=cfg.get("has_trust_anchors"),
                             http3=_http3(cfg), population=_population(raw, vid)))
    return dict(
        version=version,
        major=int(version.split(".")[0]) if version else None,
        browser=raw.get("browser"),
        branded=raw.get("browser") == "Google Chrome",
        channel=raw.get("channel"),
        os=raw.get("os"),
        platform=raw.get("os"),
        build=raw.get("browser"),
        captured_at=raw.get("captured_at"),
        schema_version=raw.get("schema_version"),
        assumed_schema=False,
        label=raw.get("label"),
        reference_config=ref_name,
        is_current_linux_stable=raw.get("is_current_linux_stable"),
        variations_source=ref_cfg.get("variations_source"),
        active_variations_count=ref_cfg.get("active_variations_count"),
        fresh=_fingerprint(ref_cfg),
        resumed=dict(ja4=ref_cfg.get("ja4_resumed"), ja4_r=ref_cfg.get("ja4_r_resumed")) if ref_cfg.get("ja4_resumed") else None,
        http2=dict(akamai=ref_cfg.get("h2_akamai"), settings=ref_cfg.get("h2_settings"), window_update=ref_cfg.get("h2_window_update"),
                   header_order=ref_cfg.get("header_order")),
        http3=_http3(ref_cfg),
        variants=variants,
        current_stable=raw.get("current_stable") or {},
        capture_server=raw.get("capture_server"),
        notes=raw.get("notes") or [],
    )
