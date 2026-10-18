#!/usr/bin/env bash
# Download + verify + install the newest official Linux .deb of Microsoft Edge or Brave (stable), for capture_brand.py.
#   capture/install_brand_deb.sh edge|brave <workdir>
# Verification chain: the repo signing key's fingerprint is pinned below -> InRelease must carry a good signature from it
# -> the Packages index must match the SHA256 in InRelease -> the .deb must match the SHA256 in Packages.
# Prints KEY=VALUE lines (BRAND_BIN, BRAND_PKG_VERSION, BRAND_REPO, BRAND_DEB_SHA256, BRAND_KEY) for $GITHUB_ENV.
set -euo pipefail
brand=$1; work=${2:-$(mktemp -d)}; mkdir -p "$work"; cd "$work"
case $brand in
  edge)  KEYURL=https://packages.microsoft.com/keys/microsoft.asc
         REPO=https://packages.microsoft.com/repos/edge; PKG=microsoft-edge-stable; BIN=/opt/microsoft/msedge/msedge
         FPRS="BC528686B50D79E339D3721CEB3E94ADBE1229CF" ;;
  brave) KEYURL=https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
         REPO=https://brave-browser-apt-release.s3.brave.com; PKG=brave-browser; BIN=/opt/brave.com/brave/brave
         FPRS="DBF1A116C220B8C7164F98230686B78420038257 47D32A74E9A9E013A4B4926C68D513D36A73CD96" ;;
  *) echo "unknown brand $brand" >&2; exit 2 ;;
esac
export GNUPGHOME="$work/gnupg"; mkdir -p -m 700 "$GNUPGHOME"
curl -fsSL --retry 3 -o key "$KEYURL"
gpg -q --import key 2>/dev/null
curl -fsSL --retry 3 -o InRelease "$REPO/dists/stable/InRelease"
signer=$(gpg --status-fd 1 --verify InRelease 2>/dev/null | awk '$2=="VALIDSIG"{print $NF}')   # last field = primary key fpr
ok=""; for f in $FPRS; do [ "$signer" = "$f" ] && ok=1; done
[ -n "$ok" ] || { echo "InRelease not signed by a pinned $brand key (got '${signer}')" >&2; exit 1; }
sha=$(awk '/^SHA256:/{f=1;next} /^[A-Za-z]/{f=0} f && $3=="main/binary-amd64/Packages"{print $1}' InRelease)
curl -fsSL --retry 3 -o Packages "$REPO/dists/stable/main/binary-amd64/Packages"
echo "$sha  Packages" | sha256sum -c --quiet >&2
read -r ver file dsha < <(python3 - "$PKG" <<'PY'
import sys, subprocess, functools
recs = [dict(l.split(": ", 1) for l in b.splitlines() if ": " in l and not l.startswith(" ")) for b in open("Packages").read().split("\n\n")]
recs = [r for r in recs if r.get("Package") == sys.argv[1] and r.get("Architecture") == "amd64"]
lt = lambda a, b: subprocess.run(["dpkg", "--compare-versions", a["Version"], "lt", b["Version"]]).returncode == 0
recs.sort(key=functools.cmp_to_key(lambda a, b: -1 if lt(a, b) else 1))
print(recs[-1]["Version"], recs[-1]["Filename"], recs[-1]["SHA256"])
PY
)
curl -fsSL --retry 3 -o pkg.deb "$REPO/$file"
echo "$dsha  pkg.deb" | sha256sum -c --quiet >&2
sudo apt-get install -y -qq ./pkg.deb >&2
[ -x "$BIN" ] || { echo "$BIN missing after install" >&2; exit 1; }
"$BIN" --version >&2
echo "BRAND_BIN=$BIN"; echo "BRAND_PKG_VERSION=$ver"; echo "BRAND_REPO=$REPO"; echo "BRAND_DEB_SHA256=$dsha"; echo "BRAND_KEY=$signer"
