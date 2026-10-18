#!/usr/bin/env bash
# Runs inside reactivecircus/android-emulator-runner (emulator booted, adb connected). See capture/lib/capture_android.py.
#   (a) record the Chrome preinstalled in the Google system image (version + signer),
#   (b) try to update it to the newest Android stable with a Google-signed x86_64 APK (capture/android/fetch_chrome_apk.py),
#   (c) otherwise capture the preinstalled Chrome, labelled with its real version.
# Then capture and run the daily-run check. Never fails the job on its own: the workflow decides from the artifact.
set -uo pipefail
OUT="${OUT:-out/capture-android}"; T="${RUNNER_TEMP:-/tmp}/android"; mkdir -p "$OUT" "$T"
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1); export BUILD_TOOLS="$BT"; echo "build-tools: $BT"
adb wait-for-device
for p in ro.build.fingerprint ro.build.type ro.build.version.release ro.build.version.sdk ro.product.cpu.abi; do echo "$p=$(adb shell getprop $p | tr -d '\r')"; done
pre=$(adb shell dumpsys package com.android.chrome | tr -d '\r' | grep -m1 -oE 'versionName=\S+' | cut -d= -f2)
echo "preinstalled Chrome: ${pre:-none}"
sysapk=$(adb shell pm path com.android.chrome | tr -d '\r' | sed 's/^package://' | grep -m1 'base.apk\|Chrome.*\.apk' || true)
syscert=""
if [ -n "$sysapk" ]; then
  adb pull "$sysapk" "$T/system-chrome.apk" >/dev/null && syscert=$("$BT/apksigner" verify --print-certs "$T/system-chrome.apk" 2>/dev/null | grep -m1 -oE 'certificate SHA-256 digest: [0-9a-f]{64}' | awk '{print $4}')
  "$BT/aapt2" dump badging "$T/system-chrome.apk" 2>/dev/null | grep -E "^package|uses-static-library|native-code" | head -5
  adb shell pm list libraries 2>/dev/null | grep -i trichrome || true
fi
echo "preinstalled Chrome APK: ${sysapk:-?} signer ${syscert:-?}"
src=preinstalled; extra=()
if python capture/android/fetch_chrome_apk.py --out "$T/apk" ${sysapk:+--also-pin-from "$T/system-chrome.apk"} > "$T/apk.env"; then
  set -a; . "$T/apk.env"; set +a
  echo "installing $APK ($APK_VERSION)"
  if adb install -r "$APK" || adb install -r -d "$APK"; then
    src=apk; extra=(--apk-sha256 "$APK_SHA256" --apk-cert "$APK_CERT_SHA256" --apk-url "$APK_SOURCE" --apk-version-code "$APK_VERSION_CODE")
  else
    echo "::warning::could not install the verified APK over the preinstalled Chrome; capturing the preinstalled one"
  fi
else
  echo "::warning::no current Google-signed Chrome APK could be fetched and verified; capturing the preinstalled Chrome ${pre}"
fi
now=$(adb shell dumpsys package com.android.chrome | tr -d '\r' | grep -m1 -oE 'versionName=\S+' | cut -d= -f2)
echo "Chrome to capture: $now (source $src)"
echo "ANDROID_CHROME_VERSION=$now" >> "${GITHUB_ENV:-/dev/null}"
python -W ignore capture/lib/capture_android.py --out "$OUT" --source "$src" --expect-version "$now" \
  --system-cert "$syscert" --preinstalled-version "$pre" "${extra[@]}" || echo "::warning::Android capture script failed"
adb logcat -d -t 400 > "$OUT/logcat-tail.txt" 2>/dev/null || true
exit 0
