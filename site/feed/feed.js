/* Stale Feed docs: fill the examples from the current sample-v1.json. No dependencies. */
(function () {
  "use strict";
  var box = document.getElementById("sample-excerpt");
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  fetch("sample-v1.json", { cache: "no-cache" }).then(function (r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }).then(function (feed) {
    var lin = (feed.platforms || {}).linux || {};
    var d = (lin.variants || {})["default"] || {};
    var fmt = function (v) { return v == null ? "null" : typeof v === "object" ? JSON.stringify(v) : String(v); };
    Array.prototype.forEach.call(document.querySelectorAll("[data-sample]"), function (n) { n.textContent = fmt(d[n.dataset.sample]); });
    var excerpt = {
      schema: feed.schema,
      generated_at: feed.generated_at,
      platforms: { linux: { status: lin.status, version: lin.version, captured_at: lin.captured_at, captured_date: lin.captured_date,
        variants: { "default": { ja4: d.ja4, ja4_resumed: d.ja4_resumed, quic_ja4: d.quic_ja4, h2_akamai: d.h2_akamai, h3_settings: d.h3_settings, has_trust_anchors: d.has_trust_anchors } } } },
      changes: (feed.changes || []).slice(0, 1),
      libraries: (feed.libraries || []).slice(0, 1).map(function (l) { return { id: l.id, verdict: l.verdict, counted_mismatches: l.counted_mismatches, versions_behind: l.versions_behind, http2_match: l.http2_match }; })
    };
    box.innerHTML = "";
    var pre = el("pre"); pre.appendChild(el("code", null, JSON.stringify(excerpt, null, 2)));
    box.appendChild(pre);
    box.appendChild(el("p", "small muted", "Excerpt of the sample (Linux, default variant, newest change, first library). " +
      (feed.libraries || []).length + " library profiles and " + (feed.changes || []).length + " capture comparisons in the full file."));
  }).catch(function (err) {
    box.innerHTML = "";
    box.appendChild(el("p", "small muted", "Couldn't load sample-v1.json (" + err.message + "). Open it directly: "));
    var a = el("a", null, "sample-v1.json"); a.href = "sample-v1.json"; box.lastChild.appendChild(a);
  });
})();
