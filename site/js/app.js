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
      platform_stable_newest: cs.newest, platform_stable_full_rollout: cs.highest_full_rollout, variants: { "default": d, no_ca34: v("no_ca34"), pq: v("pq") } };
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
      var nw = p.platform_stable_newest, full = p.platform_stable_full_rollout, verTxt = p.version || "unknown";
      if (nw && nw !== p.version) verTxt += full === p.version ? " (fully rolled-out " + name + " stable; " + nw + " was rolling out to some users)" : " (newest " + name + " stable then: " + nw + ")";
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
    resumed: function (l) { return [["match", "match_variant", "mismatch", "never", "not_tested"].indexOf(l.resumed_status || "not_tested"), VORDER[l.verdict]]; },
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
  function h2Cell(l, m) {
    var g = l.http2_grade;
    if (!g) return [mark(m.http2)];
    return [el("span", { cls: "line" }, ["settings ", mark(g.settings)]),
      el("span", { cls: "line", title: "Order of the regular headers both send. Shown, not counted in the verdict." }, ["header order ", mark(g.header_order)])];
  }
  var RESUMED = {
    match: ["yes", "✓ matches Chrome", "Resumed handshakes (with pre_shared_key) have the same JA4 as Chrome's default resumed handshake."],
    match_variant: ["vary", "✓ less common variant", "Resumed JA4 matches one of Chrome's less common variants, not the default."],
    mismatch: ["no", "✗ differs", "The library resumes sessions, but its resumed JA4 differs from Chrome's."],
    never: ["no", "✗ never resumes", "Opened new connections on the same client and never sent pre_shared_key; Chrome resumes."],
    not_tested: ["na", "not tested", "Our harness only tests session resumption for some libraries."]
  };
  function resumedCell(l) {
    var r = RESUMED[l.resumed_status] || RESUMED.not_tested;
    return [el("span", { cls: r[0], title: r[2], text: r[1] })];
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
    return el("tr", { cls: "detail" }, [el("td", { colspan: "11" }, [info, vt, tbl, h3block, nt])]);
  }

  var ROWHIST = { entries: [] };
  function rowHistory(id) {
    return (ROWHIST.entries || []).filter(function (e) { return e.rows && e.rows[id]; }).map(function (e) { return { date: e.date, chrome: e.chrome_version, r: e.rows[id] }; });
  }
  function whyRow(l) {
    // Plain-words summary + reasons, generated by leaderboard/build.py from the field diff; notes from leaderboard/notes.json
    var kids = [];
    if (l.behind_text) kids.push(el("p", { cls: "why-head", text: l.behind_text }));
    if (l.recent_match) kids.push(el("p", { cls: "recent-note" }, [el("span", { cls: "badge v-variant", text: "Matches a version real users still run" }),
      " Same fresh JA4 and HTTP/2 fingerprint as our capture of Chrome " + l.recent_match.version + " (within " + l.recent_match.window + " major versions of current " + l.recent_match.current + "). The verdict above still grades against current Chrome."]));
    var f = l.fingerprint || {}, ids = [["JA4", f.ja4_fresh], ["HTTP/2", f.http2_akamai], ["QUIC JA4", f.http3_ja4]].filter(function (x) { return x[1]; });
    if (ids.length) kids.push(el("div", { cls: "fp-ids" }, ids.map(function (x) {
      return el("span", { cls: "fp-id" }, [el("span", { cls: "muted", text: x[0] + " " }), el("code", { text: x[1] }), copyBtn(x[1])]);
    })));
    var hist = rowHistory(l.id);
    if (hist.length) kids.push(el("div", { cls: "hist" }, [el("span", { cls: "muted", text: "History (" + hist.length + " day" + (hist.length === 1 ? "" : "s") + " since " + localDate(hist[0].date + "T12:00:00Z") + "): " })]
      .concat(hist.map(function (h) {
        var t = h.date + ": " + (VLABEL[h.r.verdict] || h.r.verdict) + (h.r.versions_behind != null ? ", " + h.r.versions_behind + " versions behind" : "") + " (vs Chrome " + h.chrome + ")";
        return el("span", { cls: "hc " + (VCLS[h.r.verdict] || "v-na"), title: t, "aria-label": t, text: h.r.versions_behind != null ? String(h.r.versions_behind) : "?" });
      }))));
    var items = (l.why || []).map(function (w) { return el("li", { text: w }); });
    if (items.length) kids.push(el("ul", { cls: "why-list" }, items));
    if (l.release_update) kids.push(el("p", { cls: "release-note", title: "Released " + (localDate(l.release_update.released_at) || "?") + "; we re-tested it the day we saw it.", text: l.release_update.text }));
    if (l.fix) kids.push(el("div", { cls: "fix" }, [el("span", { cls: "fix-label", text: "One-line fix (same library, " + (VLABEL[l.fix.to_verdict] || l.fix.to_verdict) + " in our test): " }),
      el("code", { cls: "fix-old", text: l.fix.old }), " → ", el("code", { cls: "fix-new", text: l.fix.new })]));
    (l.notes || []).forEach(function (n) { kids.push(el("p", { cls: "why-note", text: n })); });
    return el("tr", { cls: "why-row" }, [el("td", { colspan: "11" }, kids)]);
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
      var tr = el("tr", { cls: "row" }, [
        td("Library", [el("span", { cls: "lib", text: l.library }), el("span", { cls: "lang", text: l.language + (l.maintainer ? " · " + l.maintainer : "") + (l.version ? " · " + l.version : "") }), toggle], "first"),
        td("Chrome profile", [el("code", { text: l.profile })]),
        td("Versions behind", vbCell(l)),
        td("TLS match (JA4)", [el("span", { cls: "line" }, ["default ", mark(d0.ja4_fresh)]), el("span", { cls: "line" }, ["without ca34 ", mark(d1.ja4_fresh)])], "tls-cell"),
        td("Resumed connection", resumedCell(l)),
        td("Post-quantum experiment", [mark(d2.ja4_fresh), d2.counted_mismatches ? el("span", { cls: "sub", text: d2.counted_mismatches.length ? (d2.counted_mismatches.length === 1 ? "1 field differs" : d2.counted_mismatches.length + " fields differ") : "all fields match" }) : null]),
        td("HTTP/2 match", h2Cell(l, m)),
        td("HTTP/3", h3Cell(l)),
        td("Verdict", verdictCell),
        td("Missing vs. Chrome", [el("div", { cls: "missing" }, chips)]),
        td("Tested", [el("time", { datetime: l.tested_at || "", text: localDate(l.tested_at) || "not tested" })])
      ]);
      tbody.appendChild(tr);
      tbody.appendChild(whyRow(l));
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
    var rm = (LIBS || []).filter(function (l) { return l.recent_match; }).length;
    txt += " Recent-version check: a row is also marked \"matches a version real users still run\" when its fresh JA4 and HTTP/2 fingerprint equal our capture of a Chrome up to 2 major versions older than current (the strict verdict is unchanged); " +
      (rm ? rm + " row" + (rm === 1 ? "" : "s") + " qualify today." : "no row qualifies today (we have captures of " + ((lb.chrome_timeline || []).map(function (t) { return t.major; }).join(", ") || "?") + ").");
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
    renderUpcoming(lb.upcoming || []);
    renderCatchup(lb.catchup);
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
  var CHLABEL = { beta: "Beta", dev: "Dev", canary: "Canary" };
  function listText(v) { return v == null ? "none" : Array.isArray(v) ? (v.length ? v.join(", ") : "none") : String(v); }
  function renderUpcoming(list) {
    var box = $("#upcoming-body"); box.innerHTML = "";
    if (!list.length || list.every(function (u) { return u.status !== "captured"; })) {
      box.appendChild(el("p", { cls: "muted", text: "No Beta, Dev or Canary capture yet. The first ones arrive with the next daily run." }));
      return;
    }
    list.forEach(function (u) {
      var name = "Chrome " + (CHLABEL[u.channel] || u.channel);
      if (u.status !== "captured") { box.appendChild(el("p", { cls: "muted small", text: name + ": not captured yet." })); return; }
      var head = name + " " + u.version + " (captured " + (localDate(u.captured_at) || "") + ")";
      if (u.same_as_stable) { box.appendChild(el("p", {}, [el("strong", { text: head + ": " }), "same fingerprint as stable " + u.stable_version + ", so nothing is coming yet."])); return; }
      var items = u.differences.map(function (d) {
        if (d.added || d.removed) {
          var parts = [];
          if (d.added.length) parts.push("adds " + d.added.join(", "));
          if (d.removed.length) parts.push("drops " + d.removed.join(", "));
          if (!parts.length && d.reordered) parts.push("same items, new order");
          return el("li", {}, [d.label + ": " + parts.join("; ")]);
        }
        return el("li", {}, [d.label + ": ", el("code", { text: listText(d.stable) }), " → ", el("code", { text: listText(d.channel) })]);
      });
      var brk = u.breaks.length
        ? el("p", {}, ["Will break: " + u.breaks.map(function (b) { return b.library + " " + b.profile + " (" + b.fields.join(", ") + ")"; }).join("; ") + "."])
        : el("p", { cls: "muted", text: "None of the rows that match stable today would stop matching." });
      box.appendChild(el("div", { cls: "up-item" }, [el("p", {}, [el("strong", { text: "Coming in Chrome " + (u.major || "?") + ": " }), head + " differs from stable " + u.stable_version + "."]),
        el("ul", { cls: "why-list" }, items), brk]));
    });
  }
  function renderCatchup(c) {
    var box = $("#catchup-body"); box.innerHTML = "";
    if (!c) { box.appendChild(el("p", { cls: "muted", text: "Not enough data yet." })); return; }
    var meta = "Tracking since " + (c.tracking_since || "?") + " (" + c.days_logged + " daily runs), " +
      (c.fingerprint_changes.length ? c.fingerprint_changes.length + " Chrome fingerprint change" + (c.fingerprint_changes.length === 1 ? "" : "s") + " seen." : "no Chrome fingerprint change seen yet.");
    if (!c.enough_data) box.appendChild(el("p", { cls: "notice", text: "Not enough data yet. " + meta + " The ranking fills in after Chrome's fingerprint next changes and libraries catch up." }));
    else box.appendChild(el("p", { cls: "muted small", text: meta }));
    var t = el("table", { cls: "diff-table" }, [el("thead", {}, [el("tr", {}, [el("th", { text: "#" }), el("th", { text: "Library" }), el("th", { text: "Average days to match" }), el("th", { text: "Still behind on" }), el("th", { text: "Releases re-tested" })])])]);
    var tb = el("tbody"), n = 0;
    c.libraries.forEach(function (r) {
      var behind = r.still_behind.map(function (p) { return "Chrome " + p.chrome_version + " (" + p.days_so_far + " days so far)"; }).join("; ");
      tb.appendChild(el("tr", {}, [el("td", { text: r.enough_data ? String(++n) : "" }), el("td", { text: r.library }),
        el("td", { text: r.enough_data ? r.avg_days + " (" + r.caught_up.length + " change" + (r.caught_up.length === 1 ? "" : "s") + ")" : "not enough data yet" }),
        el("td", { text: behind || "nothing" }),
        el("td", { text: (r.releases || []).length ? r.releases.map(function (x) { return x.version + " (" + (localDate(x.retested_at) || "?") + (x.gap_closed ? ", closed the gap" : "") + ")"; }).join("; ") : "none yet" })]));
    });
    t.appendChild(tb); box.appendChild(t);
    box.appendChild(el("p", { cls: "muted small", text: c.method }));
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

  /* ---------------- 3b. Compare any two captured Chrome versions ---------------- */
  // Only real captures: data/history/<file> (listed in data/history/index.json) plus data/latest.json.
  function plainDiff(r) {
    var nc = function (x) { return x === "none" ? "not captured" : x.replace(/(^| \/ )(?= \/ |$)/g, "$1not captured"); };
    var a = nc(r[1]), b = nc(r[2]);
    if (a === "not captured" || b === "not captured") return r[0] + ": " + (a === "not captured" ? "not captured in the older capture; the newer one has " + b : b + " in the newer capture; the older one had " + a) + ".";
    if (/^removed: |^added: |^—$/.test(a) || /^added: |^—$/.test(b)) {
      var parts = [];
      if (/^added: /.test(b)) parts.push("added " + b.slice(7));
      if (/^removed: /.test(a)) parts.push("removed " + a.slice(9));
      return r[0] + ": " + parts.join("; ") + ".";
    }
    if (/^order: /.test(a)) return r[0] + ": same items, different order.";
    return r[0] + " changed from " + a + " to " + b + ".";
  }
  function initVersionDiff(ref, latestRaw, index, archive) {
    var seen = {}, list = [];
    [["data/history/", index], ["data/archive/", archive]].forEach(function (x) {
      ((x[1] && x[1].captures) || []).forEach(function (c) {
        var id = c.chrome_version + "|" + c.captured_at;   // the same capture can sit in both folders
        if (!c.chrome_version || seen[id] || (c.chrome_version === ref.version && c.captured_at === ref.capturedAt)) return;
        seen[id] = 1; list.push({ key: x[0] + c.file, at: c.captured_at, label: "Chrome " + c.chrome_version + " (" + localDate(c.captured_at) + ")" });
      });
    });
    var opts = list.sort(function (a, b) { return Date.parse(a.at) - Date.parse(b.at); });
    opts.push({ key: "latest", label: "Chrome " + ref.version + " (" + localDate(ref.capturedAt) + ", latest)" });
    var a = $("#vd-a"), b = $("#vd-b"), out = $("#vd-out");
    if (!a || opts.length < 2) { if (out) out.textContent = "Only one capture so far, so there's nothing to compare yet."; return; }
    opts.forEach(function (o) { a.appendChild(el("option", { value: o.key, text: o.label })); b.appendChild(el("option", { value: o.key, text: o.label })); });
    a.value = opts[0].key; b.value = "latest";
    var cache = { latest: Promise.resolve(latestRaw) };
    var load = function (k) { return cache[k] || (cache[k] = getJSON(k)); };
    var run = function () {
      out.innerHTML = ""; out.appendChild(el("p", { cls: "muted", text: "Loading…" }));
      Promise.all([load(a.value), load(b.value)]).then(function (res) {
        var p = adaptChromeReference(res[0]), c = adaptChromeReference(res[1]);
        var rows = diffRefs(p, c).filter(function (r) { return r[0] !== "Chrome version"; });
        out.innerHTML = "";
        out.appendChild(el("p", { cls: "small muted", text: "Chrome " + p.version + " → Chrome " + c.version }));
        if (a.value === b.value) { out.appendChild(el("p", { text: "Pick two different captures." })); return; }
        if (!rows.length) { out.appendChild(el("div", { cls: "empty", text: "Nothing in the fingerprint differs between these two captures." })); return; }
        out.appendChild(el("ul", { cls: "vd-list" }, rows.map(function (r) { return el("li", { cls: "vd-row", text: plainDiff(r) }); })));
      }).catch(function (e) { out.textContent = "Couldn't load a capture (" + e.message + ")."; });
    };
    a.addEventListener("change", run); b.addEventListener("change", run); run();
  }

  /* ---------------- README badges (files built by leaderboard/badges.py at deploy) ---------------- */
  function badgeSlug(id) { return id.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""); }
  function renderBadges(lb) {
    var box = $("#badge-list"); if (!box) return; box.innerHTML = "";
    var base = location.origin + location.pathname.replace(/[^/]*$/, "");
    (lb.libraries || []).filter(function (l) { return l.is_newest_profile !== false; }).forEach(function (l) {
      var ep = base + "api/badges/" + badgeSlug(l.id) + ".json";
      var img = "https://img.shields.io/endpoint?url=" + encodeURIComponent(ep);
      var md = "[![Chrome match](" + img + ")](" + base + "#leaderboard)";
      box.appendChild(el("div", { cls: "badge-item" }, [
        el("span", { cls: "lib", text: l.library + " " }), el("code", { text: l.profile }), " ",
        el("img", { src: img, alt: "Chrome match badge for " + l.library + " " + l.profile, loading: "lazy", height: "20" }),
        el("div", { cls: "code-row" }, [el("code", { cls: "md", text: md }), copyBtn(md)])
      ]));
    });
  }

  /* ---------------- Current Firefox ---------------- */
  function renderFirefox(ff) {
    var box = $("#ff-body"); if (!box || !ff || !ff.ja4) return; box.innerHTML = "";
    var h2 = ff.http2 || {};
    var row = function (label, val, copy) {
      return el("div", { cls: "wide" }, [el("dt", { text: label }), el("dd", { cls: "code-row" }, [el("code", { text: val || "not captured" })].concat(copy && val ? [copyBtn(val)] : []))]);
    };
    box.appendChild(el("dl", { cls: "fp" }, [
      el("div", {}, [el("dt", { text: "Firefox version checked" }), el("dd", { text: ff.version + " (" + ff.channel + ", " + ff.os + ")" })]),
      el("div", {}, [el("dt", { text: "Last checked" }), el("dd", { text: localTime(ff.captured_at) })]),
      row("TLS fingerprint (JA4), fresh connection", ff.ja4, true),
      row("JA4, resumed connection", ff.ja4_resumed, true),
      row("HTTP/2 fingerprint", h2.akamai, true),
      row("HTTP/2 header order", (h2.header_order || []).join(", ")),
      row("User-Agent", ff.user_agent),
      row("HTTP/3 (QUIC) JA4", (ff.http3 || {}).ja4, true),
      row("QUIC transport parameters", ((ff.http3 || {}).transport_params || []).filter(function (t) { return t.name !== "grease"; }).map(function (t) { return t.name + (t.value != null ? "=" + t.value : ""); }).join(", ") || null)
    ]));
    if (ff.http3 && ff.http3.ja4 && !ff.http3.request_over_h3)
      box.appendChild(el("p", { cls: "muted small", text: "HTTP/3: Firefox completed the QUIC handshake with our local endpoint, then sent the page request over TCP, so HTTP/3 SETTINGS and header order are not captured yet. The QUIC JA4 above is from the real QUIC ClientHello." }));
    if ((ff.errors || []).length) box.appendChild(el("p", { cls: "muted small", text: "Capture notes: " + ff.errors.join("; ") }));
  }

  /* Firefox on each OS (data/firefox/platforms.json, capture/merge_firefox.py) */
  function renderFirefoxPlatforms(idx) {
    var box = $("#ff-platforms"); if (!box || !idx || !idx.platforms) return; box.innerHTML = "";
    ["linux", "windows", "macos"].forEach(function (pid) {
      var p = idx.platforms[pid] || {};
      var row = function (label, val) { return el("div", {}, [el("dt", { text: label }), el("dd", {}, [el("code", { text: val || "not captured" })])]); };
      box.appendChild(el("div", { cls: "card plat" }, [el("h3", { text: p.label || pid }),
        el("p", { cls: "muted small", text: p.version ? "Firefox " + p.version + " · " + localDate(p.captured_at) + (p.status === "captured" ? "" : " · " + p.status) : (p.status || "not captured yet") }),
        p.version ? el("dl", { cls: "fp small" }, [row("JA4", p.ja4), row("JA4 resumed", p.ja4_resumed), row("HTTP/2", p.h2_akamai), row("QUIC JA4", p.quic_ja4)]) : null]));
    });
  }

  /* Firefox history + compare (data/firefox/history/index.json, capture/merge_firefox.py) */
  function ffDiff(a, b) {
    var out = [];
    var sc = function (label, x, y) { if (JSON.stringify(x) !== JSON.stringify(y)) out.push(label + " changed from " + (x == null ? "not captured" : x) + " to " + (y == null ? "not captured" : y) + "."); };
    var st = function (label, x, y) {
      x = x || []; y = y || [];
      var add = y.filter(function (v) { return x.indexOf(v) < 0; }), rem = x.filter(function (v) { return y.indexOf(v) < 0; });
      if (add.length || rem.length) out.push(label + ": " + [add.length ? "added " + add.join(", ") : null, rem.length ? "removed " + rem.join(", ") : null].filter(Boolean).join("; ") + ".");
      else if (JSON.stringify(x) !== JSON.stringify(y)) out.push(label + ": same items, different order.");
    };
    var h = function (d) { return d.http2 || {}; }, q = function (d) { return d.http3 || {}; };
    sc("JA4 (fresh)", a.ja4, b.ja4); sc("JA4 (resumed)", a.ja4_resumed, b.ja4_resumed); sc("HTTP/2 fingerprint", h(a).akamai, h(b).akamai);
    st("Extensions", a.extensions, b.extensions); st("Cipher suites", a.ciphers, b.ciphers); st("Signature algorithms", a.sig_algs, b.sig_algs);
    st("Supported groups", a.groups, b.groups); st("HTTP/2 header order", h(a).header_order, h(b).header_order);
    if (q(a).ja4 || q(b).ja4) sc("HTTP/3 (QUIC) JA4", q(a).ja4 || null, q(b).ja4 || null);
    sc("User-Agent", a.user_agent, b.user_agent);
    return out;
  }
  function initFirefoxHistory(index) {
    var caps = (index && index.captures) || [], box = $("#ff-history");
    if (!box) return;
    if (caps.length < 2) { box.appendChild(el("p", { cls: "muted small", text: caps.length ? "History starts " + localDate(caps[0].captured_at) + " (Firefox " + caps[0].firefox_version + "). Comparisons appear after the next daily capture." : "No Firefox history yet." })); return; }
    var a = el("select"), b = el("select"), out = el("div");
    caps.forEach(function (c) { var t = "Firefox " + c.firefox_version + " (" + localDate(c.captured_at) + ")"; a.appendChild(el("option", { value: c.file, text: t })); b.appendChild(el("option", { value: c.file, text: t })); });
    a.value = caps[Math.max(0, caps.length - 2)].file; b.value = caps[caps.length - 1].file;
    box.appendChild(el("p", { cls: "muted small", text: caps.length + " daily Firefox captures since " + localDate(caps[0].captured_at) + "." }));
    box.appendChild(el("div", { cls: "controls" }, [el("label", {}, ["From ", a]), " ", el("label", {}, ["To ", b])])); box.appendChild(out);
    var cache = {}, load = function (f) { return cache[f] || (cache[f] = getJSON("data/firefox/history/" + encodeURIComponent(f))); };
    var run = function () {
      out.innerHTML = "";
      if (a.value === b.value) { out.appendChild(el("p", { text: "Pick two different captures." })); return; }
      Promise.all([load(a.value), load(b.value)]).then(function (r) {
        var rows = ffDiff(r[0], r[1]);
        out.appendChild(rows.length ? el("ul", { cls: "vd-list" }, rows.map(function (t) { return el("li", { cls: "vd-row", text: t }); }))
          : el("div", { cls: "empty", text: "Nothing in the fingerprint differs between these two Firefox captures." }));
      });
    };
    a.addEventListener("change", run); b.addEventListener("change", run); run();
  }

  /* Firefox leaderboard (data/firefox_libraries.json, leaderboard/build_firefox.py) */
  function renderFirefoxBoard(lb) {
    var box = $("#ff-board"); if (!box || !lb || !lb.libraries) return; box.innerHTML = "";
    var r = lb.reference || {};
    box.appendChild(el("p", { cls: "muted small", text: "Graded against real Firefox " + r.firefox_version + " (" + localDate(r.captured_at) + "), same counted fields as the Chrome leaderboard. " + (lb.caveats || []).join(" ") }));
    var base = location.origin + location.pathname.replace(/[^/]*$/, "");
    var t = el("table", { cls: "lb" }, [el("thead", {}, [el("tr", {}, ["Library", "Firefox profile", "Versions behind", "TLS match", "HTTP/2", "Verdict", "Tested"].map(function (h) { return el("th", { text: h }); }))])]);
    var tb = el("tbody");
    lb.libraries.forEach(function (l) {
      var f = l.fingerprint || {}, g = l.http2_grade || {};
      tb.appendChild(el("tr", { cls: "row" }, [
        td("Library", [el("span", { cls: "lib", text: l.library }), el("span", { cls: "lang", text: l.language + (l.version ? " · " + l.version : "") })], "first"),
        td("Firefox profile", [el("code", { text: l.profile })]),
        td("Versions behind", [el("span", { text: l.versions_behind == null ? "unknown" : String(l.versions_behind) })]),
        td("TLS match", [mark(((l.matches || {}).variants || {}).default ? l.matches.variants.default.ja4_fresh : null)]),
        td("HTTP/2", [el("span", { cls: "line" }, ["settings ", mark(g.settings)]), el("span", { cls: "line" }, ["header order ", mark(g.header_order)])]),
        td("Verdict", [el("span", { cls: "badge " + (VCLS[l.verdict] || "v-na"), text: VLABEL[l.verdict] || l.verdict })]),
        td("Tested", [el("time", { text: localDate(l.tested_at) || "not tested" })])
      ]));
      var md = "[![Firefox match](https://img.shields.io/endpoint?url=" + encodeURIComponent(base + "api/badges/firefox/" + badgeSlug(l.id) + ".json") + ")](" + base + "#firefox-board)";
      var ids = [["JA4", f.ja4_fresh], ["HTTP/2", f.http2_akamai]].filter(function (x) { return x[1]; });
      tb.appendChild(el("tr", { cls: "why-row" }, [el("td", { colspan: "7" }, [
        el("p", { cls: "why-head", text: l.behind_text || "" }),
        ids.length ? el("div", { cls: "fp-ids" }, ids.map(function (x) { return el("span", { cls: "fp-id" }, [el("span", { cls: "muted", text: x[0] + " " }), el("code", { text: x[1] }), copyBtn(x[1])]); })) : null,
        (l.why || []).length ? el("ul", { cls: "why-list" }, l.why.map(function (w) { return el("li", { text: w }); })) : null,
        l.release_update ? el("p", { cls: "release-note", title: "Released " + (localDate(l.release_update.released_at) || "?"), text: l.release_update.text }) : null,
        l.fix ? el("div", { cls: "fix" }, [el("span", { cls: "fix-label", text: "One-line fix (same library, " + l.fix.to_diffs + " counted difference" + (l.fix.to_diffs === 1 ? "" : "s") + " instead of " + l.fix.from_diffs + "): " }),
          el("code", { cls: "fix-old", text: l.fix.old }), " → ", el("code", { cls: "fix-new", text: l.fix.new })]) : null
      ].concat((l.notes || []).map(function (n) { return el("p", { cls: "why-note", text: n }); })).concat([
        l.verdict !== "not tested" ? el("div", { cls: "code-row small" }, [el("span", { cls: "muted", text: "Badge " }), el("code", { cls: "md", text: md }), copyBtn(md)]) : null
      ]))]));
    });
    t.appendChild(tb); box.appendChild(el("div", { cls: "table-wrap" }, [t]));
  }

  /* ---------------- Summary at the top ---------------- */
  var SUMVR = { exact: 0, exact_variant: 1, close: 2, behind: 3, "not tested": 4 };
  function sumBoard(boxId, title, lb, browserVersion) {
    var box = $(boxId); if (!box || !lb) return; box.innerHTML = "";
    var rows = (lb.libraries || []).filter(function (l) { return l.is_newest_profile !== false && l.verdict !== "not tested"; });
    var count = function (v) { return rows.filter(function (l) { return l.verdict === v; }).length; };
    var exact = rows.filter(function (l) { return l.verdict === "exact"; });
    var chip = function (n, v, label) { return n ? el("span", { cls: "badge " + VCLS[v], text: n + " " + label }) : null; };
    box.appendChild(el("h3", { text: title + " " + (browserVersion || "") }));
    box.appendChild(el("p", { cls: "sum-chips" }, [chip(count("exact"), "exact", "exact"), " ", chip(count("exact_variant"), "exact_variant", "less common variant"), " ",
      chip(count("close"), "close", "close"), " ", chip(count("behind"), "behind", "behind")]));
    box.appendChild(el("p", { cls: "small", text: exact.length ? "Matching current " + title + " exactly: " + exact.map(function (l) { return l.library + " " + l.profile; }).join(", ") + "."
      : "No library profile matches current " + title + " exactly right now." }));
    box.appendChild(el("p", { cls: "muted small", text: "Counts each library's newest tested profiles (" + rows.length + " in total)." }));
  }
  function sumMovers(hist, lb) {
    var box = $("#sum-movers"); if (!box) return; box.innerHTML = "";
    var es = (hist && hist.entries) || [];
    if (es.length < 2) return;
    var last = es[es.length - 1], cutoff = new Date(Date.parse(last.date) - 7 * 864e5).toISOString().slice(0, 10);
    var first = es.filter(function (e) { return e.date >= cutoff; })[0] || es[0];
    var names = {}; (lb.libraries || []).forEach(function (l) { names[l.id] = l.library + " " + l.profile; });
    var moves = [];
    Object.keys(last.rows || {}).forEach(function (id) {
      var a = (first.rows || {})[id], b = last.rows[id];
      if (!a || !b || a.verdict === "not tested" || b.verdict === "not tested") return;
      var dv = (SUMVR[a.verdict] - SUMVR[b.verdict]), dm = (a.mismatches || 0) - (b.mismatches || 0);
      if (dv || dm) moves.push({ id: id, up: dv > 0 || (!dv && dm > 0), txt: (names[id] || id) + ": " + (VLABEL[a.verdict] || a.verdict) + " → " + (VLABEL[b.verdict] || b.verdict) +
        (dm && !dv ? " (" + a.mismatches + " → " + b.mismatches + " fields differ)" : "") });
    });
    box.appendChild(el("h3", { text: "Movers since " + localDate(first.date + "T12:00:00Z") }));
    if (!moves.length) { box.appendChild(el("p", { cls: "small muted", text: "No library changed its Chrome verdict between " + first.date + " and " + last.date + " (Chrome " + (first.chrome_version || "?") + " → " + (last.chrome_version || "?") + ")." })); return; }
    moves.sort(function (x, y) { return (y.up ? 1 : 0) - (x.up ? 1 : 0); });
    box.appendChild(el("ul", { cls: "why-list" }, moves.slice(0, 5).map(function (m) { return el("li", { text: (m.up ? "▲ " : "▼ ") + m.txt }); })));
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
  function copyBtn(v) {
    var b = el("button", { cls: "copy", type: "button", text: "Copy", "aria-label": "Copy " + v });
    b.addEventListener("click", function () {
      var done = function () { toast("Copied"); b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1200); };
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(v).then(done, function () { fallbackCopy(v); done(); });
      else { fallbackCopy(v); done(); }
    });
    return b;
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
        sumBoard("#sum-chrome", "Chrome", res[1], REF.version);
        getJSON("data/row_history.json").then(function (h) { ROWHIST = h; renderTable(); sumMovers(h, res[1]); }, function () { /* no history yet */ });
        renderBadges(res[1]);
        getJSON("data/firefox.json").then(renderFirefox, function () { /* no Firefox capture yet */ });
        getJSON("data/firefox/history/index.json").then(initFirefoxHistory, function () { initFirefoxHistory(null); });
        getJSON("data/firefox_libraries.json").then(function (f) { renderFirefoxBoard(f); sumBoard("#sum-firefox", "Firefox", f, (f.reference || {}).firefox_version); }, function () { /* Firefox leaderboard not built yet */ });
        getJSON("data/firefox/platforms.json").then(renderFirefoxPlatforms, function () { /* no per-OS Firefox data yet */ });
        renderFooter(res[1]);
        getJSON("data/archive/index.json").catch(function () { return { captures: [] }; }).then(function (arch) { initVersionDiff(REF, res[0], res[2], arch); });
        return renderChanges(REF, res[2]);
      })
      .catch(function (err) {
        var box = $("#load-error"); box.hidden = false;
        box.textContent = "Couldn't load the data files (" + err.message + "). Run site/sync.sh and serve the site folder over HTTP.";
      });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
