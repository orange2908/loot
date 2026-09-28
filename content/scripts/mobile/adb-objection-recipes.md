---
title: "adb, objection and frida-tools Recipes - Task-Oriented Command Sets"
category: mobile
subcategory: tooling
type: script
tags: [adb, objection, frida, frida-trace, frida-ps, recipes, android, ios, workflow, shell, automation, dumpsys, logcat, keystore, memory-search]
summary: "Ready-to-paste command recipes grouped by goal: triage an app, dump its data, bypass a check, trace a method, capture traffic."
tools: [adb, objection, frida, frida-tools, sqlite3]
related: [android-cheatsheet, ios-cheatsheet, frida-script-library, android-frida-basics]
---

## Recipe 0 - bootstrap a session

```bash
#!/bin/sh
# session.sh - bring a device, frida-server and a target package to a known state
set -eu
PKG="${1:?usage: session.sh com.ctf.app}"

adb wait-for-device
echo "api=$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
echo "abi=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
echo "pkg path: $(adb shell pm path "$PKG" | tr -d '\r')"

# start frida-server if it is not already running
if ! adb shell "pidof frida-server" >/dev/null 2>&1; then
  adb shell "su -c '/data/local/tmp/frida-server -D'" 2>/dev/null || \
  adb shell "/data/local/tmp/frida-server -D" &
  sleep 2
fi
frida-ps -U | head -5

# clean slate: stop the app and clear the log
adb shell am force-stop "$PKG"
adb logcat -c
echo "ready: frida -U -f $PKG -l hook.js --no-pause"
```

## Recipe 1 - full static triage of an installed app

```bash
#!/bin/sh
# triage-installed.sh - pull an installed app off the device and decompile it
set -eu
PKG="${1:?usage: triage-installed.sh com.ctf.app}"
OUT="${2:-triage-$PKG}"
mkdir -p "$OUT" && cd "$OUT"

# 1. pull every split
adb shell pm path "$PKG" | tr -d '\r' | sed 's/^package://' | while read -r p; do
  echo "pulling $p"
  adb pull "$p" .
done

APK="$(ls -S ./*.apk | head -1)"          # the largest split is base.apk
echo "base apk: $APK"

# 2. metadata without decoding
aapt2 dump badging "$APK" | grep -E 'package|launchable|sdkVersion|uses-permission'

# 3. three views
apktool d -f -o out-apktool "$APK"
jadx -d out-jadx --deobf --show-bad-code "$APK" 2>/dev/null || true
unzip -q -o "$APK" -d out-zip

# 4. the manifest answers that matter
grep -oE 'android:(debuggable|allowBackup|usesCleartextTraffic|exported|authorities)="[^"]*"' \
  out-apktool/AndroidManifest.xml | sort | uniq -c

# 5. first grep pass
grep -rIn -E 'flag\{|CTF\{' out-jadx out-apktool 2>/dev/null | head -20
grep -rIoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' out-jadx 2>/dev/null | sort -u | head -30
grep -rIn -iE 'api[_-]?key|secret|token|password' out-jadx/sources 2>/dev/null | head -30

# 6. native libs
find out-zip/lib -name '*.so' -exec sh -c 'echo "== $1"; strings -n 8 "$1" | head -20' _ {} \; 2>/dev/null
echo "done: $OUT"
```

## Recipe 2 - enumerate and hit the IPC surface

```bash
# every exported component, from the device's own view of the package
adb shell dumpsys package com.ctf.app | sed -n '/Activity Resolver Table/,/Service Resolver/p'
adb shell dumpsys package com.ctf.app | grep -E 'Provider|authority'

# launch every activity in turn and screenshot the result
for A in $(grep -oE 'android:name="[^"]*Activity"' out-apktool/AndroidManifest.xml |
           cut -d'"' -f2); do
  echo "== $A"
  adb shell am start -n "com.ctf.app/$A" 2>&1 | head -3
  sleep 2
  adb shell screencap -p "/sdcard/$(echo "$A" | tr './' '__').png"
done
adb pull /sdcard/ ./shots/ 2>/dev/null

# every declared broadcast action
for ACT in $(grep -A2 '<receiver' out-apktool/AndroidManifest.xml |
             grep -oE '<action android:name="[^"]*"' | cut -d'"' -f2); do
  echo "== broadcast $ACT"
  adb shell am broadcast -a "$ACT" --es cmd test
done

# every provider authority, queried at a few common paths
for AUTH in $(grep -oE 'android:authorities="[^"]*"' out-apktool/AndroidManifest.xml |
              cut -d'"' -f2 | tr ';' ' '); do
  for P in "" /1 /files /notes /users /data; do
    echo "== content://$AUTH$P"
    adb shell content query --uri "content://$AUTH$P" 2>&1 | head -5
  done
done
```

## Recipe 3 - dump all app data

```bash
#!/bin/sh
# dump-data.sh - get /data/data off the device by whichever route works
set -eu
PKG="${1:?usage: dump-data.sh com.ctf.app}"
OUT="${2:-data-$PKG}"
mkdir -p "$OUT"

if adb shell "su -c id" 2>/dev/null | grep -q 'uid=0'; then
  echo "[*] using root"
  adb exec-out "su -c 'tar -C /data/data -cf - $PKG'" > "$OUT/appdata.tar"
elif adb shell "run-as $PKG id" 2>/dev/null | grep -q uid; then
  echo "[*] using run-as (app is debuggable)"
  adb exec-out "run-as $PKG tar -cf - ." > "$OUT/appdata.tar"
else
  echo "[*] no root and not debuggable - trying adb backup"
  adb backup -f "$OUT/app.ab" -noapk "$PKG"
  echo "    unpack with: python3 unab.py $OUT/app.ab $OUT/app.tar"
fi

# external storage needs neither
adb pull "/sdcard/Android/data/$PKG" "$OUT/external" 2>/dev/null || true

if [ -f "$OUT/appdata.tar" ]; then
  tar -xf "$OUT/appdata.tar" -C "$OUT"
  echo "== shared_prefs"
  find "$OUT" -name '*.xml' -path '*shared_prefs*' -exec sh -c 'echo "-- $1"; cat "$1"' _ {} \;
  echo "== databases"
  find "$OUT" -name '*.db' | while read -r db; do
    echo "-- $db"
    sqlite3 "$db" "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || true
    sqlite3 "$db" ".tables" 2>/dev/null
  done
  echo "== flag-ish strings"
  grep -rIa -oE '[A-Za-z0-9_]{2,10}\{[ -~]{4,60}\}' "$OUT" | sort -u | head -20
fi
```

## Recipe 4 - bypass a check without writing a script

```bash
# ssl pinning
objection -g com.ctf.app explore -s "android sslpinning disable"

# root detection
objection -g com.ctf.app explore -s "android root disable"

# both at once, then drop into the shell
objection -g com.ctf.app explore \
  -s "android sslpinning disable" -s "android root disable"

# non-rooted device: repackage with the gadget first
objection patchapk -s app.apk
adb install -r app.objection.apk
objection -g com.ctf.app explore

# ios equivalents
objection --gadget com.ctf.app explore -s "ios sslpinning disable"
objection --gadget com.ctf.app explore -s "ios jailbreak disable"
```

## Recipe 5 - objection interactive session (the commands worth memorising)

```bash
objection -g com.ctf.app explore
```

```text
# --- orientation ---
env                                         # every app directory
android hooking list classes                # all loaded classes
android hooking search classes Checker      # find a class by substring
android hooking search methods verify       # find a method by substring
android hooking list class_methods com.ctf.app.Checker

# --- watching ---
android hooking watch class com.ctf.app.Checker
android hooking watch class_method com.ctf.app.Checker.verify --dump-args --dump-return --dump-backtrace
android hooking set return_value com.ctf.app.Checker.verify true

# --- data ---
ls /data/data/com.ctf.app/shared_prefs
cat /data/data/com.ctf.app/shared_prefs/prefs.xml
file download /data/data/com.ctf.app/databases/app.db
sqlite connect /data/data/com.ctf.app/databases/app.db
sqlite schema
sqlite query "select * from users"
android keystore list
android keystore watch
android shared_preferences get

# --- memory ---
memory list modules
memory list exports libnative-lib.so
memory search --string "flag{" --offsets-only
memory dump all ./memdump
memory dump from_base 0x7f00000000 2048 ./chunk.bin

# --- intents ---
android intent launch_activity com.ctf.app.SecretActivity
android intent launch_service com.ctf.app.FlagService

# --- misc ---
android ui screenshot shot.png
android ui FLAG_SECURE false                # allow screenshots of a protected screen
android clipboard monitor
jobs list
exit
```

## Recipe 6 - trace with frida-trace (no script writing)

```bash
# every method of every class in the app package
frida-trace -U -f com.ctf.app -j 'com.ctf.app.*!*' --no-pause

# one class, all methods
frida-trace -U -n com.ctf.app -j 'com.ctf.app.Checker!*'

# crypto and hashing across the whole app
frida-trace -U -n com.ctf.app -j 'javax.crypto.Cipher!*' -j 'java.security.MessageDigest!*'

# native exports by pattern
frida-trace -U -n com.ctf.app -i 'Java_*'
frida-trace -U -n com.ctf.app -i 'strcmp' -i 'strstr' -i 'memcmp'
frida-trace -U -n com.ctf.app -i 'libnative-lib.so!*'

# ios objective-c
frida-trace -U -n MyApp -m '-[NSURLSession *]'
frida-trace -U -n MyApp -m '*[* *Password*]'
frida-trace -U -n MyApp -m '-[NSFileManager fileExistsAtPath:]'

# frida-trace writes editable handler stubs into ./__handlers__/ -
# edit one to print args properly, it reloads automatically
ls __handlers__/
```

## Recipe 7 - capture traffic end to end

```bash
#!/bin/sh
# capture.sh - proxy over usb, bypass pinning, and record the session
set -eu
PKG="${1:?usage: capture.sh com.ctf.app}"

# 1. proxy reachable from the device over usb
adb reverse tcp:8080 tcp:8080
adb shell settings put global http_proxy 127.0.0.1:8080

# 2. start mitmproxy writing a flow file
mitmdump -w flows.mitm --listen-port 8080 &
MITM=$!
sleep 1

# 3. launch with the pinning bypass in place
frida -U -f "$PKG" -l pinning-bypass.js --no-pause -o frida.log &
FRIDA=$!

echo "exercise the app, then press enter"
read -r _

kill "$FRIDA" "$MITM" 2>/dev/null || true
adb shell settings put global http_proxy :0
adb reverse --remove tcp:8080

# 4. what did we get
mitmdump -nr flows.mitm | head -60
mitmdump -nr flows.mitm "~u /api/" | head -40
```

## Recipe 8 - brute force through the app as an oracle

```bash
# 1. write an agent that exposes the check (see frida-script-library snippet 27)
# 2. drive it from python
python3 frida_rpc.py com.ctf.app rpc-agent.js --brute

# quick one-liner variant using the frida REPL
frida -U -n com.ctf.app -q -e '
Java.perform(function () {
  var C = Java.use("com.ctf.app.Checker").$new();
  var A = "abcdefghijklmnopqrstuvwxyz0123456789_{}";
  var k = "flag{";
  for (var i = 0; i < 40; i++) {
    var hit = false;
    for (var j = 0; j < A.length; j++) {
      if (C.verifyPrefix(k + A[j])) { k += A[j]; console.log(k); hit = true; break; }
    }
    if (!hit) break;
  }
  console.log("done " + k);
});'
```

## Recipe 9 - find the flag when you have no idea where it is

```bash
# 1. strings across everything static
grep -rIa -oE '[A-Za-z0-9_]{2,10}\{[ -~]{4,80}\}' out-jadx out-apktool out-zip | sort -u

# 2. runtime memory search
objection -g com.ctf.app explore -s "memory search --string flag{ --offsets-only"

# 3. log every string comparison and interact with the app
frida -U -f com.ctf.app -l string-compare.js --no-pause 2>&1 | tee cmp.log
grep -i 'flag' cmp.log

# 4. log every crypto operation
frida -U -f com.ctf.app -l crypto-logger.js --no-pause 2>&1 | tee crypto.log

# 5. dump the heap and carve
frida -U -n com.ctf.app -l memdump.js
adb pull /data/local/tmp/ ./memdump/
grep -rIa -oE 'flag\{[ -~]{4,60}\}' ./memdump/ | sort -u

# 6. check every file the app writes
frida -U -f com.ctf.app -l file-monitor.js --no-pause 2>&1 | tee files.log
sort -u files.log | grep '/data/data'
```

## Recipe 10 - Python wrapper around adb

```python
#!/usr/bin/env python3
"""adb_helper.py - thin, dependency-free wrapper over adb for scripted app attacks.

Usage:
  python3 adb_helper.py info com.ctf.app
  python3 adb_helper.py pull-apk com.ctf.app ./out
  python3 adb_helper.py components com.ctf.app
  python3 adb_helper.py launch-all com.ctf.app
"""
from __future__ import annotations

import os
import re
import subprocess
import sys


def adb(*args: str, binary: bool = False):
    cmd = ["adb", *args]
    res = subprocess.run(cmd, capture_output=True, check=False)
    if binary:
        return res.stdout
    return res.stdout.decode("utf-8", "replace").replace("\r\n", "\n").strip()


def shell(cmd: str) -> str:
    return adb("shell", cmd)


def info(pkg: str) -> None:
    print("api      :", shell("getprop ro.build.version.sdk"))
    print("abi      :", shell("getprop ro.product.cpu.abi"))
    print("model    :", shell("getprop ro.product.model"))
    print("debuggable:", shell("getprop ro.debuggable"))
    print("paths    :", shell(f"pm path {pkg}"))
    print("pid      :", shell(f"pidof -s {pkg}") or "(not running)")
    print("run-as   :", "ok" if "uid=" in shell(f"run-as {pkg} id") else "denied")
    print("root     :", "ok" if "uid=0" in shell("su -c id") else "denied")


def pull_apk(pkg: str, out: str) -> list[str]:
    os.makedirs(out, exist_ok=True)
    paths = [ln.split(":", 1)[1] for ln in shell(f"pm path {pkg}").splitlines() if ":" in ln]
    got = []
    for p in paths:
        dest = os.path.join(out, os.path.basename(p))
        adb("pull", p, dest)
        got.append(dest)
        print("pulled", dest)
    return got


COMP_RE = re.compile(r"([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)")


def components(pkg: str) -> list[str]:
    dump = shell(f"dumpsys package {pkg}")
    found = sorted({m for m in COMP_RE.findall(dump) if m.startswith(pkg + "/")})
    for c in found:
        print(c)
    return found


def launch_all(pkg: str) -> None:
    for comp in components(pkg):
        out = shell(f"am start -n {comp}")
        status = "ok" if "Error" not in out else out.splitlines()[-1]
        print(f"{comp:<70} {status}")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    action, pkg = argv[1], argv[2]
    if action == "info":
        info(pkg)
    elif action == "pull-apk":
        pull_apk(pkg, argv[3] if len(argv) > 3 else "./apk")
    elif action == "components":
        components(pkg)
    elif action == "launch-all":
        launch_all(pkg)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sample = ("Activity Resolver Table:\n"
                  "  com.ctf.app/.MainActivity filter\n"
                  "  com.ctf.app/com.ctf.app.SecretActivity filter\n")
        hits = sorted({m for m in COMP_RE.findall(sample) if m.startswith("com.ctf.app/")})
        assert hits == ["com.ctf.app/.MainActivity",
                        "com.ctf.app/com.ctf.app.SecretActivity"], hits
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```
