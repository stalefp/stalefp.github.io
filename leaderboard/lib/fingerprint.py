"""Shared fingerprint helpers: normalize an echo-server response (TrackMe / tls.peet.ws /api/all)
into the internal fingerprint shape, compute JA4 from parts, and human-readable code names.

Internal fingerprint shape (used for both Chrome and the libraries):
  ja4, ja4_r, ja4_a                      str
  ciphers, extensions                    [hex4] sorted, GREASE removed; extensions exclude SNI/ALPN (JA4 rule)
  signature_algorithms                   [hex4] in wire order, GREASE removed
  supported_groups, key_shares           [hex4] in wire order, GREASE removed
  alps                                   hex4 codepoint or None
  cert_compression                       [str]
  trust_anchors                          bool (extension 0xca34 present)
  http2: {akamai, header_order}          header_order = request header names incl. pseudo headers
  user_agent                             str
Any value that was not measured is None.
"""
import hashlib, re

GREASE = {f"{x:02x}{x:02x}" for x in range(0x0a, 0x100, 0x10)}  # 0a0a,1a1a,...,fafa

EXT_NAMES = {
    "0000": "server_name", "0005": "status_request", "000a": "supported_groups", "000b": "ec_point_formats",
    "000d": "signature_algorithms", "0010": "alpn", "0012": "signed_certificate_timestamp", "0015": "padding",
    "0017": "extended_master_secret", "001b": "compress_certificate", "0023": "session_ticket",
    "0029": "pre_shared_key", "002b": "supported_versions", "002d": "psk_key_exchange_modes", "0033": "key_share",
    "4469": "application_settings (old ALPS, 17513)", "44cd": "application_settings (ALPS, 17613)",
    "ca34": "trust_anchors (ca34)", "fe0d": "encrypted_client_hello", "ff01": "renegotiation_info",
    "12e0": "0x12e0 (handshake padding, PqcBandwidthExperiment)", "0039": "quic_transport_parameters",
}
SIGALG_NAMES = {
    "0904": "ML-DSA-44", "0905": "ML-DSA-65", "0906": "ML-DSA-87",
    "0403": "ecdsa_secp256r1_sha256", "0804": "rsa_pss_rsae_sha256", "0401": "rsa_pkcs1_sha256",
    "0503": "ecdsa_secp384r1_sha384", "0805": "rsa_pss_rsae_sha384", "0501": "rsa_pkcs1_sha384",
    "0806": "rsa_pss_rsae_sha512", "0601": "rsa_pkcs1_sha512", "0201": "rsa_pkcs1_sha1", "0603": "ecdsa_secp521r1_sha512", "0807": "ed25519", "0203": "ecdsa_sha1",
}
GROUP_NAMES = {"11ec": "X25519MLKEM768", "6399": "X25519Kyber768Draft00", "001d": "X25519", "0017": "P-256",
               "0018": "P-384", "0019": "P-521", "0100": "ffdhe2048", "0101": "ffdhe3072"}
ML_DSA = ["0904", "0905", "0906"]
MLKEM = "11ec"
CA34 = "ca34"
ALPS_CODES = {"44cd", "4469"}


def h4(n):
    return f"{int(n):04x}"


def paren_int(s):
    """'X25519MLKEM768 (4588)' -> 4588 ; 'TLS_GREASE (0xfafa)' -> 0xfafa"""
    m = re.search(r"\((0x[0-9a-fA-F]+|\d+)\)\s*$", s.strip())
    if not m:
        return None
    v = m.group(1)
    return int(v, 16) if v.lower().startswith("0x") else int(v)


def split_ja4_r(ja4_r):
    a, c, e, s = ja4_r.split("_")
    strip = lambda xs: [x for x in xs.split(",") if x and x not in GREASE]
    return a, strip(c), strip(e), strip(s)


def ja4_from_parts(ja4_a, ciphers, extensions, sigalgs):
    """JA4 per FoxIO spec: a + sha256(sorted ciphers)[:12] + sha256(sorted exts (no SNI/ALPN) + '_' + sigalgs)[:12]."""
    b = hashlib.sha256(",".join(sorted(ciphers)).encode()).hexdigest()[:12]
    cstr = ",".join(sorted(extensions)) + ("_" + ",".join(sigalgs) if sigalgs else "")
    c = hashlib.sha256(cstr.encode()).hexdigest()[:12]
    return f"{ja4_a}_{b}_{c}"


def ja4_a_with_ext_delta(ja4_a, delta):
    """Adjust the extension count in JA4_a (e.g. t13d1517h2 -> t13d1516h2 when removing one extension)."""
    n = int(ja4_a[6:8]) + delta
    return ja4_a[:6] + f"{min(n, 99):02d}" + ja4_a[8:]


def header_names(headers):
    out = []
    for h in headers or []:
        if h.startswith(":"):
            out.append(":" + h[1:].split(": ")[0])
        else:
            out.append(h.split(": ")[0].lower())
    return out


def normalize_echo(d):
    """Normalize a raw TrackMe / tls.peet.ws /api/all JSON response into the internal fingerprint."""
    tls = d.get("tls") or {}
    h2 = d.get("http2") or {}
    ja4_r = tls.get("ja4_r")
    fp = dict(ja4=tls.get("ja4"), ja4_r=ja4_r, ja4_a=None, ciphers=None, extensions=None, signature_algorithms=None,
              supported_groups=None, key_shares=None, alps=None, cert_compression=None, trust_anchors=None,
              resumed=None, http2=None, user_agent=d.get("user_agent"), http_version=d.get("http_version"))
    if ja4_r:
        a, c, e, s = split_ja4_r(ja4_r)
        fp.update(ja4_a=a, ciphers=sorted(c), extensions=sorted(e), signature_algorithms=s,
                  trust_anchors=CA34 in e, resumed="0029" in e)
        fp["alps"] = next((x for x in e if x in ALPS_CODES), None)
    for ext in tls.get("extensions", []):
        n = ext.get("name", "")
        if n.startswith("supported_groups"):
            fp["supported_groups"] = [h4(v) for v in map(paren_int, ext.get("supported_groups") or []) if v is not None and h4(v) not in GREASE]
        elif n.startswith("key_share"):
            ks = []
            for k in ext.get("shared_keys") or []:
                for name in k:
                    v = paren_int(name)
                    if v is not None and h4(v) not in GREASE:
                        ks.append(h4(v))
            fp["key_shares"] = ks
        elif n.startswith("compress_certificate"):
            fp["cert_compression"] = [re.sub(r"\s*\(\d+\)$", "", x) for x in ext.get("algorithms") or []]
    if h2:
        hdrs = []
        for f in h2.get("sent_frames", []):
            if f.get("frame_type") == "HEADERS":
                hdrs = f.get("headers", [])
                break
        fp["http2"] = dict(akamai=h2.get("akamai_fingerprint"), header_order=header_names(hdrs))
    return fp


def normalize_legacy_summary(s):
    """Normalize an entry of tlsbench/results.json (output of fp.summarize). It lacks key shares
    (fp.summarize computes but does not return them), so key_shares stays None (= not recorded)."""
    d = {"tls": {"ja4": s.get("ja4"), "ja4_r": s.get("ja4_r"), "extensions": [
        {"name": "supported_groups (10)", "supported_groups": s.get("groups") or []},
        {"name": "compress_certificate (27)", "algorithms": s.get("certc") or []}]},
        "http2": {"akamai_fingerprint": s.get("akamai"), "sent_frames": [{"frame_type": "HEADERS", "headers": s.get("headers") or []}]},
        "user_agent": s.get("ua"), "http_version": s.get("http")}
    return normalize_echo(d)
