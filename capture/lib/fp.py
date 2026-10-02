"""ClientHello parsing + JA3 / JA4 computation (no third-party deps).

JA4 follows the FoxIO spec (github.com/FoxIO-LLC/ja4, JA4 TLS client):
  a = proto(t|q) + tls version + sni(d|i) + #ciphers(2) + #extensions(2) + alpn(first+last char)
  b = sha256(sorted ciphers, comma-joined 4-hex)[:12]
  c = sha256(sorted extensions minus SNI/ALPN + "_" + sigalgs in original order)[:12]
  GREASE values are ignored everywhere (ciphers, extensions, sigalgs, groups).
"""
import hashlib, struct

def is_grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)

EXT_NAMES = {
    0x0000: "server_name", 0x0005: "status_request", 0x000A: "supported_groups",
    0x000B: "ec_point_formats", 0x000D: "signature_algorithms", 0x0010: "application_layer_protocol_negotiation",
    0x0012: "signed_certificate_timestamp", 0x0015: "padding", 0x0017: "extended_master_secret",
    0x001B: "compress_certificate", 0x0023: "session_ticket", 0x0029: "pre_shared_key",
    0x002A: "early_data", 0x002B: "supported_versions", 0x002D: "psk_key_exchange_modes",
    0x0031: "post_handshake_auth", 0x0033: "key_share", 0x0039: "quic_transport_parameters",
    0x4469: "application_settings_old (ALPS)", 0x44CD: "application_settings (ALPS)",
    0xCA34: "trust_anchors (TLSTrustAnchorIDs)",
    0x12E0: "unassigned 0x12e0: server handshake padding request (Chrome AddTLSServerHandshakePadding / Finch PqcBandwidthExperiment; payload = requested bytes)", 0xFE0D: "encrypted_client_hello",
    0xFF01: "renegotiation_info",
}
GROUP_NAMES = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519", 0x001E: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024", 0x6399: "X25519Kyber768Draft00", 0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
}
SIG_NAMES = {
    0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384", 0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519", 0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256", 0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512", 0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1",
    0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
}
CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256", 0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES_256_GCM_SHA384", 0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",
    0xCCA9: "ECDHE_ECDSA_CHACHA20_POLY1305", 0xCCA8: "ECDHE_RSA_CHACHA20_POLY1305",
    0xC013: "ECDHE_RSA_AES_128_CBC_SHA", 0xC014: "ECDHE_RSA_AES_256_CBC_SHA",
    0x009C: "RSA_AES_128_GCM_SHA256", 0x009D: "RSA_AES_256_GCM_SHA384",
    0x002F: "RSA_AES_128_CBC_SHA", 0x0035: "RSA_AES_256_CBC_SHA",
}
QUIC_TP_NAMES = {
    0x00: "original_destination_connection_id", 0x01: "max_idle_timeout", 0x02: "stateless_reset_token",
    0x03: "max_udp_payload_size", 0x04: "initial_max_data", 0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote", 0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi", 0x09: "initial_max_streams_uni", 0x0A: "ack_delay_exponent",
    0x0B: "max_ack_delay", 0x0C: "disable_active_migration", 0x0D: "preferred_address",
    0x0E: "active_connection_id_limit", 0x0F: "initial_source_connection_id", 0x10: "retry_source_connection_id",
    0x11: "version_information", 0x20: "max_datagram_frame_size", 0x2AB2: "grease_quic_bit",
    0x3127: "google_initial_rtt", 0x3128: "google_connection_options", 0x4752: "google_user_agent_id",
    0x4751: "google_quic_version", 0xFF73DB: "version_information_draft", 0xFF04DE1B: "min_ack_delay",
}

def h4(v):
    return "0x%04x" % v

class R:
    def __init__(self, b): self.b, self.i = b, 0
    def u8(self): v = self.b[self.i]; self.i += 1; return v
    def u16(self): v = struct.unpack_from(">H", self.b, self.i)[0]; self.i += 2; return v
    def u24(self): v = int.from_bytes(self.b[self.i:self.i+3], "big"); self.i += 3; return v
    def take(self, n): v = self.b[self.i:self.i+n]; self.i += n; return v
    def left(self): return len(self.b) - self.i

def varint(r):
    first = r.u8(); ln = 1 << (first >> 6); v = first & 0x3F
    for _ in range(ln - 1): v = (v << 8) | r.u8()
    return v

def parse_client_hello(msg):
    """msg = handshake message starting with type byte 0x01 (no record header)."""
    r = R(msg)
    if r.u8() != 1: raise ValueError("not a ClientHello")
    r.u24()
    ch = {"legacy_version": r.u16()}
    r.take(32)
    ch["session_id_len"] = r.u8(); r.take(ch["session_id_len"])
    n = r.u16(); ch["ciphers"] = [r.u16() for _ in range(n // 2)]
    n = r.u8(); ch["compression"] = list(r.take(n))
    exts = []
    if r.left() >= 2:
        end = r.u16() + r.i
        while r.i < end:
            t = r.u16(); d = r.take(r.u16()); exts.append((t, bytes(d)))
    ch["ext_raw"] = exts
    ch["extensions"] = [t for t, _ in exts]
    ch.update(sni=None, groups=[], point_formats=[], sig_algs=[], alpn=[], alps=[], versions=[],
              key_shares=[], psk_modes=[], cert_compression=[], quic_tp=None, trust_anchors_len=None,
              ech_len=None, psk_identities=None, padding_len=None, alps_codepoint=None)
    for t, d in exts:
        x = R(d)
        try:
            if t == 0x0000 and len(d) > 5:
                x.u16(); x.u8(); ch["sni"] = x.take(x.u16()).decode("ascii", "replace")
            elif t == 0x000A:
                ch["groups"] = [x.u16() for _ in range(x.u16() // 2)]
            elif t == 0x000B:
                ch["point_formats"] = list(x.take(x.u8()))
            elif t == 0x000D:
                ch["sig_algs"] = [x.u16() for _ in range(x.u16() // 2)]
            elif t in (0x0010, 0x4469, 0x44CD):
                end = x.u16() + 2; lst = []
                while x.i < end: lst.append(x.take(x.u8()).decode("ascii", "replace"))
                if t == 0x0010: ch["alpn"] = lst
                else: ch["alps"] = lst; ch["alps_codepoint"] = t
            elif t == 0x002B:
                ch["versions"] = [x.u16() for _ in range(x.u8() // 2)]
            elif t == 0x0033:
                end = x.u16() + 2
                while x.i < end:
                    g = x.u16(); ln = x.u16(); x.take(ln); ch["key_shares"].append((g, ln))
            elif t == 0x002D:
                ch["psk_modes"] = list(x.take(x.u8()))
            elif t == 0x001B:
                ch["cert_compression"] = [x.u16() for _ in range(x.u8() // 2)]
            elif t == 0x0039:
                tps = []
                while x.left():
                    k = varint(x); v = x.take(varint(x)); tps.append((k, bytes(v)))
                ch["quic_tp"] = tps
            elif t == 0xCA34:
                ch["trust_anchors_len"] = len(d); ch["trust_anchors_hex"] = d.hex()
            elif t == 0xFE0D:
                ch["ech_len"] = len(d)
            elif t == 0x0029:
                end = x.u16() + 2; cnt = 0
                while x.i < end: x.take(x.u16()); x.take(4); cnt += 1
                ch["psk_identities"] = cnt
            elif t == 0x0015:
                ch["padding_len"] = len(d)
        except Exception as e:  # keep going; record parse issue
            ch.setdefault("parse_errors", []).append("%s: %s" % (h4(t), e))
    return ch

def extract_from_tls_records(buf):
    """Given raw TCP bytes beginning with TLS records, return the complete ClientHello handshake
    message bytes, or None if incomplete."""
    hs = b""; i = 0
    while i + 5 <= len(buf):
        if buf[i] != 0x16: raise ValueError("not a handshake record")
        ln = struct.unpack_from(">H", buf, i + 3)[0]
        if i + 5 + ln > len(buf): return None
        hs += buf[i+5:i+5+ln]; i += 5 + ln
        if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
            return hs[:4 + int.from_bytes(hs[1:4], "big")]
    return None

def _alpn_code(alpn):
    if not alpn: return "00"
    a = alpn[0]
    if not a: return "00"
    if a[0].isalnum() and a[-1].isalnum(): return a[0] + a[-1]
    hx = a.encode().hex(); return hx[0] + hx[-1]

def _sha12(s): return hashlib.sha256(s.encode()).hexdigest()[:12]

def ja4(ch, proto="t"):
    vers = [v for v in ch["versions"] if not is_grease(v)]
    v = max(vers) if vers else ch["legacy_version"]
    vmap = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}
    ciphers = [c for c in ch["ciphers"] if not is_grease(c)]
    exts = [e for e in ch["extensions"] if not is_grease(e)]
    sni = "d" if ch["sni"] else "i"
    a = "%s%s%s%02d%02d%s" % (proto, vmap.get(v, "00"), sni, min(len(ciphers), 99), min(len(exts), 99), _alpn_code(ch["alpn"]))
    cs = ",".join("%04x" % c for c in sorted(ciphers))
    es = ",".join("%04x" % e for e in sorted(exts) if e not in (0x0000, 0x0010))
    sa = ",".join("%04x" % s for s in ch["sig_algs"] if not is_grease(s))
    c_raw = es + ("_" + sa if sa else "")
    b = _sha12(cs) if ciphers else "000000000000"
    c = _sha12(c_raw) if exts else "000000000000"
    return a + "_" + b + "_" + c, a + "_" + cs + "_" + c_raw

def ja3(ch):
    ng = lambda xs: [x for x in xs if not is_grease(x)]
    exts = ng(ch["extensions"])
    parts = [str(ch["legacy_version"]), "-".join(map(str, ng(ch["ciphers"]))), "-".join(map(str, exts)),
             "-".join(map(str, ng(ch["groups"]))), "-".join(map(str, ch["point_formats"]))]
    s = ",".join(parts)
    parts_n = list(parts); parts_n[2] = "-".join(map(str, sorted(exts)))
    sn = ",".join(parts_n)
    return hashlib.md5(s.encode()).hexdigest(), s, hashlib.md5(sn.encode()).hexdigest(), sn

def summarize(ch, proto="t"):
    """Friendly, GREASE-free summary used by the output JSON."""
    ng = lambda xs: [x for x in xs if not is_grease(x)]
    j4, j4r = ja4(ch, proto)
    j3, j3s, j3n, j3ns = ja3(ch)
    out = {
        "ja4": j4, "ja4_r": j4r, "ja3": j3, "ja3_string": j3s, "ja3n": j3n, "ja3n_string": j3ns,
        "tls_versions": [h4(v) for v in ng(ch["versions"])],
        "ciphers": [h4(c) for c in ng(ch["ciphers"])],
        "extensions": [h4(e) for e in ng(ch["extensions"])],
        "grease_extension_positions": [i for i, e in enumerate(ch["extensions"]) if is_grease(e)],
        "sig_algs": [h4(s) for s in ng(ch["sig_algs"])],
        "groups": [h4(g) for g in ng(ch["groups"])],
        "key_shares": [{"group": h4(g), "name": GROUP_NAMES.get(g, "unknown"), "key_length": ln}
                       for g, ln in ch["key_shares"] if not is_grease(g)],
        "alpn": ch["alpn"], "alps": ch["alps"],
        "alps_codepoint": h4(ch["alps_codepoint"]) if ch["alps_codepoint"] is not None else None,
        "has_trust_anchors": 0xCA34 in ch["extensions"],
        "trust_anchors_len": ch["trust_anchors_len"],
        "has_psk": 0x0029 in ch["extensions"],
        "has_ech": 0xFE0D in ch["extensions"], "ech_len": ch["ech_len"],
        "cert_compression": ch["cert_compression"], "psk_modes": ch["psk_modes"],
        "sni": ch["sni"], "session_id_len": ch["session_id_len"],
    }
    if ch.get("quic_tp") is not None:
        tps = []
        for k, v in ch["quic_tp"]:
            item = {"id": "0x%x" % k, "name": QUIC_TP_NAMES.get(k, "grease" if (k - 27) % 31 == 0 else "unknown"), "len": len(v)}
            if k == 0x3128:
                item["hex"] = v.hex(); item["ascii"] = v.decode("ascii", "replace")
            elif len(v) <= 8 and k not in (0x00, 0x02, 0x0F, 0x10, 0x11, 0x3128, 0x4752):
                try: item["value"] = varint(R(v)) if v else None
                except Exception: item["hex"] = v.hex()
            else:
                item["hex"] = v.hex()[:64]
            tps.append(item)
        out["quic_transport_params"] = tps
    if ch.get("parse_errors"): out["parse_errors"] = ch["parse_errors"]
    return out

def code_names():
    f = lambda d: {h4(k): v for k, v in sorted(d.items())}
    return {"extensions": f(EXT_NAMES), "groups": f(GROUP_NAMES), "sig_algs": f(SIG_NAMES), "ciphers": f(CIPHER_NAMES)}
