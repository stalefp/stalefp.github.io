"""Write shields.io endpoint badges (https://shields.io/badges/endpoint-badge) for every leaderboard row.

  python leaderboard/badges.py site/data/libraries.json _site/api/badges
  python leaderboard/badges.py site/data/firefox_libraries.json _site/api/badges/firefox "Firefox match"

One file per row id: <out>/<slug>.json, plus <out>/index.json listing them. Run at deploy time (pages.yml), so badges
always reflect the libraries.json that is being published. Values come only from libraries.json.
"""
import json, os, re, sys


def slug(row_id):
    return re.sub(r"[^a-z0-9]+", "-", row_id.lower()).strip("-")


def badge(l, label="Chrome match"):
    v, vb = l.get("verdict"), l.get("versions_behind")
    if v == "exact":
        msg, color = "matches current", "brightgreen"
    elif v == "not tested":
        msg, color = "not tested", "lightgrey"
    elif vb is not None and vb > 0:
        msg = "%d version%s behind" % (vb, "" if vb == 1 else "s")
        color = "yellow" if v in ("exact_variant", "close") else "red"
    else:
        msg = {"exact_variant": "matches a Chrome variant", "close": "1 field differs", "behind": "%d fields differ" % len(l.get("counted_mismatches") or [])}.get(v, v)
        color = {"exact_variant": "yellowgreen", "close": "yellow"}.get(v, "red")
    return {"schemaVersion": 1, "label": label, "message": msg, "color": color, "cacheSeconds": 3600}


def main(src, out, label="Chrome match"):
    data = json.load(open(src))
    os.makedirs(out, exist_ok=True)
    idx = []
    for l in data["libraries"]:
        s = slug(l["id"])
        b = badge(l, label)
        json.dump(b, open(os.path.join(out, s + ".json"), "w"))
        idx.append(dict(id=l["id"], slug=s, library=l["library"], profile=l["profile"], message=b["message"], file=s + ".json"))
    json.dump({"generated_from": "libraries.json generated_at " + str(data.get("generated_at")), "badges": idx}, open(os.path.join(out, "index.json"), "w"), indent=1)
    print("badges: %d written to %s" % (len(idx), out))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], *(sys.argv[3:4]))
