/* Stale: static leaderboard page. No build step, no dependencies, no network calls except ./data/*.json. */
(function () {
  "use strict";

  /* ------------------------------------------------------------------------------------------
   * adaptChromeReference: THE ONLY PLACE in the site that knows the layout of data/latest.json.
   * It implements Moe's capture/SCHEMA.md (schema_version 1). Its Python twin is leaderboard/lib/adapter.py;
   * keep the two in step. (The older leaderboard/ASSUMED_SCHEMA.md layout is superseded.)
   * ---------------------------------------------------------------------------------------- */
  function adaptChromeReference(raw) {
    var hx = function (x) { return typeof x === "string" && /^0x/i.test(x) ? x.slice(2).toLowerCase() : x; };
    var hxs = function (xs) { return xs ? xs.map(hx) : null; };
    var CERTC = { 1: "zlib", 2: "brotli", 3: "zstd" };
    var configs = {};
    (raw.configs || []).forEach(function (c) { configs[c.name] = c; });
    var ref = configs[raw.reference_config] || {};
    var mode = ref.mode;
    var findCfg = function (base) {
      return configs[base + "-" + mode] || (raw.configs || []).filter(function (c) { return c.base_config === base && c.ja4; })[0] || null;
    };
    var quic = function (c) {
      var q = c && c.quic;
      if (!q || !q.ja4) return null;
      return { ja4: q.ja4, ja4Resumed: q.ja4_resumed || null, ja4R: q.ja4_r || null, settings: q.h3_settings || null,
        greaseSettings: q.h3_grease_settings, transportParams: q.transport_params || [], headerOrder: q.header_order || [] };
    };
    var studies = raw.finch_network_studies || [];
    var population = function (hint) {
      for (var i = 0; i < studies.length; i++) {
        var st = studies[i];
        if ((st.extension_hint || []).indexOf(hint) < 0) continue;
        var feats = st.features || [];
        var share = 0, n = 0;
        (st.groups || []).forEach(function (g) {
          if ((g.enable_features || []).some(function (f) { return feats.indexOf(f) >= 0; }) && g.share_of_population) { share += g.share_of_population; n++; }
        });
        return { share: n ? share : null, platform: (st.filter || {}).platform || null, channel: (st.filter || {}).channel || null, study: st.study };
      }
      return { share: null, platform: null, channel: null, study: null };
    };
    var variant = function (id, label, c, hint) {
      if (!c) return null;
      return { id: id, label: label, config: c.name, isDefault: id === "default", ja4: c.ja4 || null, ja4Resumed: c.ja4_resumed || null,
        ja4R: c.ja4_r || null, hasTrustAnchors: c.has_trust_anchors, quic: quic(c), population: hint ? population(hint) : null };
    };
    var variants = [variant("default", "Default (with ca34)", ref, null),
      variant("no_ca34", "Without ca34", findCfg("disable-TLSTrustAnchorIDs"), "0xca34"),
      variant("pq", "Post-quantum experiment", findCfg("finch-AddTLSServerHandshakePadding"), "0x12e0")].filter(Boolean);
    var version = raw.version || null;
    return {
      version: version,
      major: version ? parseInt(version.split(".")[0], 10) : null,
      browser: raw.browser || null,
      branded: raw.browser === "Google Chrome",
      channel: raw.channel || null,
      os: raw.os || null,
      capturedAt: raw.captured_at || null,
      assumed: false,
      label: raw.label || null,
      referenceConfig: raw.reference_config || null,
      isCurrentLinuxStable: raw.is_current_linux_stable,
      variationsSource: ref.variations_source || null,
      activeVariations: ref.active_variations_count,
      ja4Fresh: ref.ja4 || null,
      ja4R: ref.ja4_r || null,
      ja4Resumed: ref.ja4_resumed || null,
      ciphers: hxs(ref.ciphers),
      extensions: hxs(ref.extensions_sorted),
      sigalgs: hxs(ref.sig_algs),
      groups: hxs(ref.groups),
      keyShares: ref.key_shares ? ref.key_shares.map(function (k) { return hx(k.group); }) : null,
      alps: hx(ref.alps_codepoint) || null,
      certCompression: ref.cert_compression ? ref.cert_compression.map(function (x) { return CERTC[x] || String(x); }) : null,
      ech: ref.has_ech == null ? null : ref.has_ech ? "GREASE ECH sent (local server has no ECH config)" : "not sent",
      trustAnchors: ref.has_trust_anchors,
      h2Akamai: ref.h2_akamai || null,
      h2HeaderOrder: ref.header_order || null,
      h3: quic(ref),
      variants: variants,
      currentStable: raw.current_stable || {}
    };
  }

  var NAMES = {
    ext: { "0005": "status_request", "000a": "supported_groups", "000b": "ec_point_formats", "000d": "signature_algorithms", "0012": "signed_certificate_timestamp",
      "0017": "extended_master_secret", "001b": "compress_certificate", "0023": "session_ticket", "0029": "pre_shared_key", "002b": "supported_versions",
      "002d": "psk_key_exchange_modes", "0033": "key_share", "4469": "ALPS (old, 17513)", "44cd": "ALPS (17613)", "ca34": "trust_anchors", "fe0d": "encrypted_client_hello", "ff01": "renegotiation_info", "12e0": "0x12e0 (handshake padding)", "0000": "server_name", "0010": "alpn", "0039": "quic_transport_parameters" },
    sig: { "0904": "ML-DSA-44", "0905": "ML-DSA-65", "0906": "ML-DSA-87", "0403": "ecdsa_secp256r1_sha256", "0804": "rsa_pss_rsae_sha256", "0401": "rsa_pkcs1_sha256",
      "0503": "ecdsa_secp384r1_sha384", "0805": "rsa_pss_rsae_sha384", "0501": "rsa_pkcs1_sha384", "0806": "rsa_pss_rsae_sha512", "0601": "rsa_pkcs1_sha512", "0201": "rsa_pkcs1_sha1", "0807": "ed25519", "0603": "ecdsa_secp521r1_sha512", "0203": "ecdsa_sha1" },
    grp: { "11ec": "X25519MLKEM768", "001d": "X25519", "0017": "P-256", "0018": "P-384", "0019": "P-521" }
  };

  // Swap this endpoint for FormSubmit's random alias string after activation.
  var FORMSUBMIT_ENDPOINT = "https://formsubmit.co/ajax/emailforcatgirls@proton.me";

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") e.textContent = attrs[k];
      else if (k === "cls") e.className = attrs[k];
      else e.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return e;
  }
  var bound = {};
  function bind(name, value) {
    bound[name] = value;
    $$('[data-bind="' + name + '"]').forEach(function (n) { n.textContent = value == null || value === "" ? "not captured" : value; });
  }
  function localTime(iso) {
    if (!iso) return null;
    var d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  function localDate(iso) {
    if (!iso) return null;
    var d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  function named(codes, table) {
    return (codes || []).map(function (c) { return table[c] ? c + " " + table[c] : c; }).join(", ");
  }
  function getJSON(path) {
    return fetch(path, { cache: "no-cache" }).then(function (r) {
      if (!r.ok) throw new Error(path + ": HTTP " + r.status);
      return r.json();
    });
  }
  function toast(msg) {
    var t = $("#toast"); t.textContent = msg; t.classList.add("show");
    clearTimeout(toast._t); toast._t = setTimeout(function () { t.classList.remove("show"); }, 1400);
  }

  var PLAT = { linux: "Linux", win: "Windows", mac: "macOS", android: "Android", ios: "iOS" };
  function pct(share) {
    if (share == null) return null;
    var p = share * 100;
    return Math.abs(p - Math.round(p)) < 0.05 ? Math.round(p) + "%" : p.toFixed(1) + "%";
  }
  function platList(p) { return (p || []).map(function (x) { return PLAT[x] || x; }).join("/"); }
  function variantById(ref, id) { return (ref.variants || []).filter(function (v) { return v.id === id; })[0] || null; }
  function h3SettingsText(set, grease) {
    if (!set) return null;
    return Object.keys(set).map(function (k) { return k + ":" + set[k]; }).join("; ") + (grease ? " (+" + grease + " GREASE)" : "");
  }

  /* ---------------- 1. Current Chrome ---------------- */
  function renderChrome(ref, lb) {
    var r = lb.reference || {};
    bind("chrome_version", ref.version);
    bind("chrome_version_footer", ref.version);
    bind("chrome_build", "(" + [ref.browser, ref.channel, ref.os ? ref.os.split(" (")[0] : null].filter(Boolean).join(", ") + ")");
    bind("captured_at", localTime(ref.capturedAt));
    $('[data-bind="captured_at"]').setAttribute("datetime", ref.capturedAt || "");
    bind("ja4", ref.ja4Fresh);
    bind("ja4_resumed", ref.ja4Resumed);
    bind("h2_fingerprint", ref.h2Akamai);
    var noCa = variantById(ref, "no_ca34"), pq = variantById(ref, "pq");
    bind("ja4_no_ca34", noCa && noCa.ja4);
    bind("ja4_pq", pq && pq.ja4);
    var pop = (pq && pq.population) || {};
    var pp = pct(pop.share) || "an unmeasured share", pl = platList(pop.platform) || "the captured platform";
    ["pq_pct", "pq_pct2", "pq_pct3"].forEach(function (k) { bind(k, pp); });
    ["pq_platform", "pq_platform2", "pq_platform3"].forEach(function (k) { bind(k, pl); });
    bind("ja4_quic", ref.h3 && ref.h3.ja4);
    bind("h3_settings", ref.h3 ? h3SettingsText(ref.h3.settings, ref.h3.greaseSettings) : null);
    bind("h3_endpoint", ((lb.harness || {}).http3_endpoints || []).join(", "));
    $("#assumed-flag").hidden = !ref.assumed;
    var lin = (ref.currentStable || {}).linux || {};
    var stale = $("#stale-flag");
    if (lin.newest && ref.version && lin.newest !== ref.version) {
      stale.hidden = false;
      stale.textContent = "This capture is Chrome " + ref.version + "; when it was taken, Linux stable was " + lin.newest + ".";
    }
    var dl = $("#chrome-details");
    var rows = [
      ["Signature algorithms", named(ref.sigalgs, NAMES.sig)],
      ["Supported groups", named(ref.groups, NAMES.grp)],
      ["Key shares", named(ref.keyShares, NAMES.grp)],
      ["Extensions (sorted, GREASE removed)", named(ref.extensions, NAMES.ext)],
      ["ALPS codepoint", ref.alps], ["ECH", ref.ech], ["Certificate compression", (ref.certCompression || []).join(", ")],
      ["Trust anchors (ca34) in the default capture", ref.trustAnchors == null ? null : ref.trustAnchors ? "present" : "absent"],
      ["JA4_r (fresh)", ref.ja4R],
      ["JA4, resumed: without ca34 / post-quantum", [noCa && noCa.ja4Resumed, pq && pq.ja4Resumed].map(function (x) { return x || "not captured"; }).join(" / ")],
      ["QUIC JA4: without ca34 / post-quantum", [noCa && noCa.quic && noCa.quic.ja4, pq && pq.quic && pq.quic.ja4].map(function (x) { return x || "not captured"; }).join(" / ")],
      ["QUIC transport parameters", ref.h3 ? ref.h3.transportParams.filter(function (t) { return t.name !== "grease"; }).map(function (t) { return t.name + (t.value != null ? "=" + t.value : t.ascii ? "=" + t.ascii : ""); }).join(", ") : null],
      ["Capture notes", [ref.branded ? "branded Google Chrome" : "not branded Chrome", "reference config " + ref.referenceConfig,
        "variations source: " + (ref.variationsSource || "not recorded"), (pop.study ? "post-quantum variant = Finch study " + pop.study : null)].filter(Boolean).join("; ")]
    ];
    rows.forEach(function (x) { dl.appendChild(el("div", {}, [el("dt", { text: x[0] }), el("dd", {}, [el("code", { text: x[1] || "not captured" })])])); });
  }

  /* ---------------- 1b. Chrome per platform ---------------- */
  // data/platforms.json is written by capture/merge_platforms.py (summary of data/latest.json = Linux and the
  // Windows/macOS captures). The Linux panel always uses REF (data/latest.json) so it can't disagree with the card above.
  var OSES = [["linux", "Linux"], ["windows", "Windows"], ["macos", "macOS"]];
  var VH_PLAT = { linux: "linux", windows: "win", macos: "mac" };
  function linuxFromRef(ref) {
    var v = function (id) {
      var x = variantById(ref, id); if (!x) return null;
      return { ja4: x.ja4, ja4_resumed: x.ja4Resumed, quic_ja4: x.quic && x.quic.ja4, h3_settings: x.quic && x.quic.settings, has_trust_anchors: x.hasTrustAnchors };
    };
    var d = v("default") || {};
    d.h2_akamai = ref.h2Akamai;
    var cs = (ref.currentStable || {}).linux || {};
    return { status: "captured", label: "Linux", browser: ref.browser, channel: ref.channel, version: ref.version, os: ref.os, captured_at: ref.capturedAt,
      platform_stable_newest: cs.newest, variants: { "default": d, no_ca34: v("no_ca34"), pq: v("pq") } };
  }
  function renderPlatforms(ref, idx) {
    var grid = $("#platform-grid"); grid.innerHTML = "";
    var plats = (idx && idx.platforms) || {}, cmp = (idx && idx.comparison) || {}, att = (idx && idx.last_attempt) || {};
    var captured = 0;
    OSES.forEach(function (o) {
      var id = o[0], name = o[1];
      var p = id === "linux" ? linuxFromRef(ref) : plats[id];
      if (!p || p.status !== "captured") {
        var a = att[id];
        grid.appendChild(el("div", { cls: "plat pending" }, [
          el("div", { cls: "plat-head" }, [el("h3", { text: name }), el("span", { cls: "badge v-na", text: "Not captured yet" })]),
          el("p", { text: "We haven't captured Chrome on " + name + " yet, so there is no " + name + " fingerprint to show. It will appear here after the first automated " + name + " capture lands." }),
          a && a.ok === false ? el("p", { cls: "small", text: "The latest attempt (" + localDate(a.at) + ") didn't produce a usable capture." }) : null
        ]));
        return;
      }
      captured++;
      var d = (p.variants || {})["default"] || {};
      var verTxt = (p.version || "unknown") + (p.platform_stable_newest && p.platform_stable_newest !== p.version ? " (newest " + name + " stable then: " + p.platform_stable_newest + ")" : "");
      var row = function (label, val) { return el("div", {}, [el("dt", { text: label }), el("dd", {}, [el("code", { text: val || "not captured" })])]); };
      var note;
      if (id === "linux") note = el("p", { cls: "plat-cmp muted", text: "Reference for the leaderboard below." });
      else {
        var c = ((cmp[id] || {}).variants || {})["default"];
        if (!c) note = el("p", { cls: "plat-cmp muted", text: "Not compared with Linux yet." });
        else if (!c.differs.length) note = el("p", { cls: "plat-cmp" }, [el("span", { cls: "yes", text: "✓ " }), "Same as Linux on every compared field" + ((cmp[id] || {}).same_version ? "." : " (different Chrome version).")]);
        else note = el("p", { cls: "plat-cmp" }, [el("span", { cls: "vary", text: "Differs from Linux: " }), c.differs.join(", ") + ((cmp[id] || {}).same_version ? "." : " (different Chrome version).")]);
      }
      grid.appendChild(el("div", { cls: "plat" }, [
        el("div", { cls: "plat-head" }, [el("h3", { text: name }), el("span", { cls: "badge v-variant" }, ["Captured ", el("time", { datetime: p.captured_at || "", text: localDate(p.captured_at) || "" })])]),
        el("dl", { cls: "fp small" }, [
          row("Chrome version", verTxt),
          row("TLS JA4, fresh", d.ja4), row("JA4, resumed", d.ja4_resumed), row("HTTP/3 (QUIC) JA4", d.quic_ja4),
          row("HTTP/2 fingerprint", d.h2_akamai),
          row("Trust anchors (ca34)", d.has_trust_anchors == null ? null : d.has_trust_anchors ? "present" : "absent")
        ]),
        note
      ]));
    });
    $("#platform-meta").textContent = captured === OSES.length
      ? "Captured on GitHub's hosted runners. User-agent strings differ by OS by design and aren't part of JA4."
      : "Platforms without a capture are left empty on purpose: we never copy the Linux values over.";
  }

  /* ---------------- 2. Leaderboard ---------------- */
  var VORDER = { exact: 0, exact_variant: 1, close: 2, behind: 3, "not tested": 4 };
  var VLABEL = { exact: "Exact", exact_variant: "Exact, less common variant", close: "Close", behind: "Behind", "not tested": "Not tested" };
  var VCLS = { exact: "v-exact", exact_variant: "v-variant", close: "v-close", behind: "v-behind", "not tested": "v-na" };
  var VARLABEL = { "default": "Chrome's default", no_ca34: "Chrome without ca34", pq: "the post-quantum variant" };
  var state = { sort: "verdict", dir: 1, showOlder: false, open: {} };
  var LIBS = [], REF = {};

  var SHORT = { "ml-dsa": "ML-DSA sigalgs", mlkem: "MLKEM key share", alps: "new ALPS codepoint", h2: "HTTP/2 settings",
    resumption: "resumption", ciphers: "cipher list", certc: "cert compression", sigalgs: "sigalg list", "ext-ca34": "ca34 trust anchors" };
  function shortLabel(i) {
    if (SHORT[i.id]) return SHORT[i.id];
    var m = /^(ext|extra)-(.+)$/.exec(i.id);
    if (m) return (m[1] === "extra" ? "extra ext " : "ext ") + m[2] + (NAMES.ext[m[2]] ? " " + NAMES.ext[m[2]] : "");
    return i.label;
  }
  function pv(l, id) { return ((l.matches || {}).variants || {})[id] || {}; }
  function tlsRank(l) { return pv(l, "default").ja4_fresh ? 0 : pv(l, "no_ca34").ja4_fresh ? 1 : 2; }
  var H3ORDER = { match: 0, variant_match: 1, settings_not_observed: 2, mismatch: 3, failed: 4, not_tested: 5, no_support: 6 };
  function h3Key(l) { var h = l.http3 || {}; return H3ORDER[h.status === "tested" ? h.summary : h.status]; }
  var SORTS = {
    verdict: function (l) { return [VORDER[l.verdict], (l.counted_mismatches || []).length, l.library.toLowerCase(), l.profile]; },
    library: function (l) { return [l.library.toLowerCase(), l.profile]; },
    profile: function (l) { return [l.profile.toLowerCase()]; },
    behind: function (l) { return [l.versions_behind == null ? 999 : l.versions_behind, l.library]; },
    tls: function (l) { return [tlsRank(l), VORDER[l.verdict]]; },
    pq: function (l) { return [pv(l, "pq").ja4_fresh ? 0 : 1, (pv(l, "pq").counted_mismatches || []).length, VORDER[l.verdict]]; },
    h2: function (l) { return [(l.matches || {}).http2 ? 0 : 1, VORDER[l.verdict]]; },
    h3: function (l) { return [h3Key(l), VORDER[l.verdict]]; },
    tested: function (l) { return [l.tested_at ? -Date.parse(l.tested_at) : 0, VORDER[l.verdict]]; }
  };
  function cmp(a, b) {
    for (var i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1;
    }
    return 0;
  }
  function mark(v) {
    if (v === true) return el("span", { cls: "yes", text: "✓" });
    if (v === false) return el("span", { cls: "no", text: "✗" });
    return el("span", { cls: "na", text: "not tested" });
  }
  function td(label, kids, cls) { var t = el("td", { "data-label": label }, [el("div", { cls: "cell" }, kids)]); if (cls) t.className = cls; return t; }

  function h3Cell(l) {
    var h = l.http3 || {};
    if (h.status === "no_support") return [el("span", { cls: "na", title: h.reason || "", text: "no HTTP/3 support" })];
    if (h.status === "not_tested") return [el("span", { cls: "na", title: h.reason || "", text: "not tested" })];
    if (h.status === "failed") return [el("span", { cls: "no", title: h.reason || "", text: "✗ failed" }), el("span", { cls: "sub", text: "no QUIC handshake recorded" })];
    var jm = h.ja4_matches || {};
    var ja4Txt = jm["default"] ? "✓" : jm.no_ca34 ? "✓ without ca34" : jm.pq ? "✓ post-quantum" : "✗";
    var setTxt = h.h3_settings == null ? "not seen" : h.h3_settings_match ? "✓" : "✗";
    return [el("span", { cls: "line" }, ["QUIC JA4 ", el("span", { cls: jm["default"] ? "yes" : (jm.no_ca34 || jm.pq) ? "vary" : "no", text: ja4Txt })]),
      el("span", { cls: "line" }, ["SETTINGS ", el("span", { cls: setTxt === "✓" ? "yes" : setTxt === "✗" ? "no" : "na", text: setTxt })])];
  }
  function vbCell(l) {
    if (l.versions_behind == null) return [el("span", { cls: "na", title: "The profile name doesn't state a Chrome version", text: "unknown" })];
    var by = l.versions_behind_by_platform || {};
    var title = Object.keys(by).map(function (p) { return (PLAT[p] || p) + ": " + (by[p] == null ? "unknown" : by[p]); }).join(", ");
    if (l.versions_behind_uniform) return [el("span", { title: title, text: String(l.versions_behind) })];
    return Object.keys(by).map(function (p) { return el("span", { cls: "line", text: (PLAT[p] || p) + " " + (by[p] == null ? "?" : by[p]) }); });
  }

  function detailRow(l) {
    var f = l.fingerprint || {};
    var info = el("div", { cls: "small" }, [
      el("p", {}, ["JA4 fresh: ", el("code", { text: f.ja4_fresh || "not tested" })]),
      el("p", {}, ["JA4 resumed: ", l.resumption && l.resumption.tested
        ? (l.resumption.resumed ? el("code", { text: f.ja4_resumed }) : document.createTextNode("never resumed (" + l.resumption.attempts + " new connections on the same client)"))
        : document.createTextNode("not tested")]),
      el("p", {}, ["HTTP/2: ", el("code", { text: f.http2_akamai || "not tested" })]),
      el("p", { cls: "muted" }, ["Version " + (l.version || "unknown") + (l.note ? " · " + l.note : "") + " · verdict: " + l.verdict_reason])
    ]);
    var vt = el("table", { cls: "diff-table variant-table" }, [el("thead", {}, [el("tr", {}, [el("th", { text: "Chrome variant" }), el("th", { text: "Chrome JA4" }),
      el("th", { text: "JA4 match" }), el("th", { text: "Counted fields that differ" }), el("th", { text: "Resumed JA4" }), el("th", { text: "QUIC JA4" })])])]);
    var vtb = el("tbody");
    (REF.variants || []).forEach(function (v) {
      var x = pv(l, v.id);
      vtb.appendChild(el("tr", {}, [el("td", { text: v.label + (v.isDefault ? " · verdict basis" : "") }), el("td", {}, [el("code", { text: v.ja4 || "not captured" })]),
        el("td", {}, [mark(x.ja4_fresh)]),
        el("td", { text: x.counted_mismatches ? (x.counted_mismatches.length ? x.counted_mismatches.join(", ") : "none") : "not tested" }),
        el("td", {}, [x.ja4_resumed == null ? el("span", { cls: "na", text: "n/a" }) : mark(x.ja4_resumed)]),
        el("td", {}, [x.quic_ja4 == null ? el("span", { cls: "na", text: "n/a" }) : mark(x.quic_ja4)])]));
    });
    vt.appendChild(vtb);
    var tbl = el("table", { cls: "diff-table" }, [el("thead", {}, [el("tr", {}, [el("th", { text: "Field (vs Chrome's default)" }), el("th", { text: "Status" }), el("th", { text: "Chrome" }), el("th", { text: "Library" })])])]);
    var show = function (v) { return v == null ? "not tested" : Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v); };
    var fill = function (tbody, list) {
      (list || []).forEach(function (d) {
        tbody.appendChild(el("tr", {}, [
          el("td", { text: d.label + (d.counts_toward_verdict ? "" : " (not counted)") }),
          el("td", { cls: "st-" + d.status, text: d.status.replace("_", " ") + (d.note ? " · " + d.note : "") }),
          el("td", {}, [el("code", { text: show(d.chrome) })]),
          el("td", {}, [el("code", { text: show(d.library) })])
        ]));
      });
    };
    var tb = el("tbody"); fill(tb, l.diff); tbl.appendChild(tb);
    var h = l.http3 || {}, h3block;
    if (h.status === "tested") {
      var ht = el("table", { cls: "diff-table" }, [el("thead", {}, [el("tr", {}, [el("th", { text: "HTTP/3 field" }), el("th", { text: "Status" }), el("th", { text: "Chrome" }), el("th", { text: "Library" })])])]);
      var htb = el("tbody"); fill(htb, h.diff); ht.appendChild(htb);
      h3block = el("div", { cls: "small" }, [el("p", {}, ["HTTP/3: QUIC JA4 ", el("code", { text: h.ja4 }), " vs Chrome ", el("code", { text: h.chrome_ja4 }),
        " · SETTINGS ", el("code", { text: h3SettingsText(h.h3_settings, h.h3_grease_settings) || "not seen" }), " · tested " + (localDate(h.tested_at) || "")]), ht]);
    } else {
      h3block = el("p", { cls: "small muted", text: "HTTP/3: " + (h.status === "no_support" ? "no HTTP/3 support" : h.status === "failed" ? "failed" : "not tested") + (h.reason ? " (" + h.reason + ")" : "") });
    }
    var nt = (l.not_tested || []).length ? el("p", { cls: "muted small", text: "Not tested: " + l.not_tested.join("; ") }) : null;
    return el("tr", { cls: "detail" }, [el("td", { colspan: "10" }, [info, vt, tbl, h3block, nt])]);
  }

  function renderTable() {
    var rows = LIBS.filter(function (l) { return state.showOlder || l.is_newest_profile !== false; });
    rows.sort(function (a, b) { return state.dir * cmp(SORTS[state.sort](a), SORTS[state.sort](b)); });
    var tbody = $("#lb tbody"); tbody.innerHTML = "";
    rows.forEach(function (l) {
      var m = l.matches || {};
      var verdictCell = [el("span", { cls: "badge " + (VCLS[l.verdict] || "v-na"), text: VLABEL[l.verdict] || l.verdict })];
      if (l.verdict === "exact") verdictCell.push(el("span", { cls: "pop-note", text: "matches Chrome's default (with ca34)" }));
      else if (l.verdict === "exact_variant") verdictCell.push(el("span", { cls: "pop-note", text: "matches " + (VARLABEL[l.matched_variant] || l.matched_variant) + "; " +
        (l.counted_mismatches.length === 1 ? "1 field differs" : l.counted_mismatches.length + " fields differ") + " from the default" }));
      else if (l.counted_mismatches && l.counted_mismatches.length) verdictCell.push(el("span", { cls: "pop-note", text: l.counted_mismatches.length === 1 ? "1 field differs" : l.counted_mismatches.length + " fields differ" }));
      var chips = (l.missing || []).map(function (i) { return el("span", { cls: "chip", title: i.label, text: shortLabel(i) }); });
      if (!chips.length) chips = [el("span", { cls: "chip none", text: "nothing" })];
      var toggle = el("button", { cls: "diff-toggle", type: "button", "aria-expanded": state.open[l.id] ? "true" : "false", text: state.open[l.id] ? "Hide field diff" : "Field diff" });
      toggle.addEventListener("click", function () { state.open[l.id] = !state.open[l.id]; renderTable(); });
      var d0 = pv(l, "default"), d1 = pv(l, "no_ca34"), d2 = pv(l, "pq");
      var resumedNote = l.resumption && l.resumption.tested
        ? el("span", { cls: "line", text: "resumed JA4 " + (d0.ja4_resumed ? "✓" : d1.ja4_resumed ? "✓ without ca34" : l.resumption.resumed ? "✗" : "✗ (never resumes)") })
        : null;
      var tr = el("tr", { cls: "row" }, [
        td("Library", [el("span", { cls: "lib", text: l.library }), el("span", { cls: "lang", text: l.language + (l.maintainer ? " · " + l.maintainer : "") + (l.version ? " · " + l.version : "") }), toggle], "first"),
        td("Chrome profile", [el("code", { text: l.profile })]),
        td("Versions behind", vbCell(l)),
        td("TLS match (JA4)", [el("span", { cls: "line" }, ["default ", mark(d0.ja4_fresh)]), el("span", { cls: "line" }, ["without ca34 ", mark(d1.ja4_fresh)]), resumedNote], "tls-cell"),
        td("Post-quantum experiment", [mark(d2.ja4_fresh), d2.counted_mismatches ? el("span", { cls: "sub", text: d2.counted_mismatches.length ? (d2.counted_mismatches.length === 1 ? "1 field differs" : d2.counted_mismatches.length + " fields differ") : "all fields match" }) : null]),
        td("HTTP/2 match", [mark(m.http2)]),
        td("HTTP/3", h3Cell(l)),
        td("Verdict", verdictCell),
        td("Missing vs. Chrome", [el("div", { cls: "missing" }, chips)]),
        td("Tested", [el("time", { datetime: l.tested_at || "", text: localDate(l.tested_at) || "not tested" })])
      ]);
      tbody.appendChild(tr);
      if (state.open[l.id]) tbody.appendChild(detailRow(l));
    });
    $$("#lb th[data-sort]").forEach(function (th) {
      th.setAttribute("aria-sort", th.dataset.sort === state.sort ? (state.dir === 1 ? "ascending" : "descending") : "none");
    });
    if ($("#sort-select option[value='" + state.sort + "']")) $("#sort-select").value = state.sort;
    var hidden = LIBS.length - rows.length;
    $("#lb-meta").textContent = rows.length + " of " + LIBS.length + " library profiles shown" + (hidden ? " (" + hidden + " older profiles hidden)" : "") +
      ". Verdicts compare against Chrome " + (REF.version || "?") + "'s default fingerprint. Click a column header to sort.";
  }

  function renderVbNote(lb) {
    var cs = ((lb.reference || {}).current_stable) || {};
    var parts = [], partial = [];
    ["linux", "win", "mac"].forEach(function (p) {
      var s = cs[p]; if (!s) return;
      parts.push(PLAT[p] + " " + (s.highest_full_rollout || "unknown"));
      (s.partial_newer_majors || []).forEach(function (r) { partial.push(r.version + " at " + pct(r.fraction) + " on " + PLAT[p]); });
    });
    var txt = "Versions behind counts from the newest fully rolled-out stable at capture time: " + parts.join(", ") + ".";
    if (partial.length) txt += " Not counted yet (partial rollout): " + partial.join(", ") + ".";
    $("#vb-note").textContent = txt;
  }

  function initTable(lb) {
    LIBS = lb.libraries || [];
    $$("#lb th[data-sort] button").forEach(function (b) {
      b.addEventListener("click", function () {
        var k = b.closest("th").dataset.sort;
        state.dir = state.sort === k ? -state.dir : 1; state.sort = k; renderTable();
      });
    });
    $("#sort-select").addEventListener("change", function (e) { state.sort = e.target.value; state.dir = 1; renderTable(); });
    $("#show-older").addEventListener("change", function (e) { state.showOlder = e.target.checked; renderTable(); });
    renderVbNote(lb);
    renderTable();
  }

  /* ---------------- 3. What changed ---------------- */
  function diffRefs(prev, cur) {
    var out = [];
    function scalar(label, a, b) { if (JSON.stringify(a) !== JSON.stringify(b)) out.push([label, a == null ? "none" : String(a), b == null ? "none" : String(b)]); }
    function set(label, a, b, table) {
      a = a || []; b = b || [];
      var add = b.filter(function (x) { return a.indexOf(x) < 0; }), rem = a.filter(function (x) { return b.indexOf(x) < 0; });
      if (add.length || rem.length) out.push([label, rem.length ? "removed: " + named(rem, table) : "—", add.length ? "added: " + named(add, table) : "—"]);
      else if (JSON.stringify(a) !== JSON.stringify(b)) out.push([label, "order: " + a.join(","), "order: " + b.join(",")]);
    }
    var vj = function (r, id, k) { var v = variantById(r, id); return v ? (k === "quic" ? (v.quic && v.quic.ja4) : v[k]) : null; };
    scalar("Chrome version", prev.version, cur.version);
    scalar("JA4 (fresh)", prev.ja4Fresh, cur.ja4Fresh);
    scalar("JA4 (resumed)", prev.ja4Resumed, cur.ja4Resumed);
    scalar("JA4 without ca34", vj(prev, "no_ca34", "ja4"), vj(cur, "no_ca34", "ja4"));
    scalar("JA4 post-quantum experiment", vj(prev, "pq", "ja4"), vj(cur, "pq", "ja4"));
    scalar("HTTP/2 fingerprint", prev.h2Akamai, cur.h2Akamai);
    set("Extensions", prev.extensions, cur.extensions, NAMES.ext);
    set("Signature algorithms", prev.sigalgs, cur.sigalgs, NAMES.sig);
    set("Supported groups", prev.groups, cur.groups, NAMES.grp);
    set("Key shares", prev.keyShares, cur.keyShares, NAMES.grp);
    set("Cipher suites", prev.ciphers, cur.ciphers, {});
    scalar("ALPS codepoint", prev.alps, cur.alps);
    scalar("Trust anchors (ca34)", prev.trustAnchors, cur.trustAnchors);
    scalar("HTTP/3 QUIC JA4", prev.h3 && prev.h3.ja4, cur.h3 && cur.h3.ja4);
    scalar("HTTP/3 QUIC JA4 without ca34 / post-quantum", [vj(prev, "no_ca34", "quic"), vj(prev, "pq", "quic")].join(" / "), [vj(cur, "no_ca34", "quic"), vj(cur, "pq", "quic")].join(" / "));
    scalar("HTTP/3 SETTINGS", prev.h3 && JSON.stringify(prev.h3.settings), cur.h3 && JSON.stringify(cur.h3.settings));
    var pp = function (r) { var v = variantById(r, "pq"); return v && v.population ? pct(v.population.share) : null; };
    scalar("Post-quantum experiment share", pp(prev), pp(cur));
    return out;
  }
  function renderChanges(ref, index) {
    var body = $("#changes-body"); body.innerHTML = "";
    var caps = ((index && index.captures) || []).filter(function (c) { return c.captured_at && ref.capturedAt && Date.parse(c.captured_at) < Date.parse(ref.capturedAt); });
    caps.sort(function (a, b) { return Date.parse(b.captured_at) - Date.parse(a.captured_at); });
    if (!caps.length) {
      // COPY: Nya (empty state)
      body.appendChild(el("div", { cls: "empty" }, [
        el("p", { text: "Nothing to compare yet." }),
        el("p", { cls: "small", text: "This section lists every fingerprint field that differs between the newest Chrome capture and the one before it. We only have one capture so far, so it will fill in after the next one." })
      ]));
      return Promise.resolve();
    }
    return getJSON("data/history/" + encodeURIComponent(caps[0].file)).then(function (raw) {
      var prev = adaptChromeReference(raw), rows = diffRefs(prev, ref);
      body.appendChild(el("p", { cls: "small muted", text: "Chrome " + (prev.version || "?") + " (" + localDate(prev.capturedAt) + ") → Chrome " + (ref.version || "?") + " (" + localDate(ref.capturedAt) + ")" }));
      var fpRows = rows.filter(function (r) { return r[0] !== "Chrome version"; });
      if (!fpRows.length) { body.appendChild(el("div", { cls: "empty", text: "Nothing that shows up in the fingerprint changed between these two captures." })); return; }
      var t = el("table", { cls: "diff-table" }, [el("thead", {}, [el("tr", {}, [el("th", { text: "Field" }), el("th", { text: "Before" }), el("th", { text: "Now" })])])]);
      var tb = el("tbody");
      rows.forEach(function (r) { tb.appendChild(el("tr", {}, [el("td", { text: r[0] }), el("td", {}, [el("code", { text: r[1] })]), el("td", {}, [el("code", { text: r[2] })])])); });
      t.appendChild(tb); body.appendChild(t);
      if (rows.some(function (r) { return r[0] === "Trust anchors (ca34)"; }))
        body.appendChild(el("p", { cls: "caveat", text: "A ca34 change between captures can come from Chrome switching that feature on or off for some users, not from a new Chrome version." }));
    });
  }

  /* ---------------- misc ---------------- */
  function initCopy() {
    $$("button.copy").forEach(function (b) {
      b.addEventListener("click", function () {
        var v = bound[b.dataset.copy]; if (!v) return;
        var done = function () { toast("Copied"); b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1200); };
        if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(v).then(done, function () { fallbackCopy(v); done(); });
        else { fallbackCopy(v); done(); }
      });
    });
  }
  function fallbackCopy(v) {
    var ta = el("textarea", { readonly: "", style: "position:fixed;left:-9999px" }); ta.value = v;
    document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); } catch (e) { /* ignore */ } ta.remove();
  }
  function initSignup() {
    var form = $("#early-access-form");
    var button = form.querySelector("button[type=submit]");
    var status = $("#signup-status");
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (!form.checkValidity()) { form.reportValidity(); return; }
      button.disabled = true;
      status.className = "muted small";
      status.textContent = "Joining the waitlist…";
      var values = {};
      new FormData(form).forEach(function (value, key) { values[key] = value; });
      fetch(FORMSUBMIT_ENDPOINT, {
        method: "POST",
        headers: { "Accept": "application/json", "Content-Type": "application/json" },
        body: JSON.stringify(values)
      }).then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      }).then(function () {
        status.className = "signup-success small";
        status.textContent = "You're on the list. We'll email you when the feed opens.";
        form.reset();
      }).catch(function () {
        status.className = "signup-error small";
        status.textContent = "Sorry, we couldn't add you right now. Please try again in a moment.";
      }).finally(function () { button.disabled = false; });
    });
  }
  function renderFooter(lb) {
    var r = lb.reference || {};
    bind("chrome_build_long", [r.browser, r.chrome_version, r.channel].filter(Boolean).join(" ") + (r.os ? " on " + r.os : ""));
    bind("endpoints", ((lb.harness || {}).endpoints || []).join(", "));
    bind("generated_at", localTime(lb.generated_at));
    $("#ca34-caveat").textContent = (lb.caveats || [])[0] || "";
    var ml = $("#method-list");
    (lb.caveats || []).slice(1).forEach(function (c) { ml.appendChild(el("li", { text: c })); });
  }

  function init() {
    initCopy(); initSignup();
    Promise.all([getJSON("data/latest.json"), getJSON("data/libraries.json"), getJSON("data/history/index.json").catch(function () { return { captures: [] }; }),
      getJSON("data/platforms.json").catch(function () { return null; })])
      .then(function (res) {
        REF = adaptChromeReference(res[0]);
        renderChrome(REF, res[1]);
        renderPlatforms(REF, res[3]);
        initTable(res[1]);
        renderFooter(res[1]);
        return renderChanges(REF, res[2]);
      })
      .catch(function (err) {
        var box = $("#load-error"); box.hidden = false;
        box.textContent = "Couldn't load the data files (" + err.message + "). Run site/sync.sh and serve the site folder over HTTP.";
      });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
