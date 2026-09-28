---
title: "Frida on Android - Setup and the Ten Hooks You Always Need"
category: mobile
subcategory: android-runtime
type: technique
tags: [frida, frida-server, frida-tools, android, hooking, instrumentation, java-perform, java-use, java-choose, interceptor, objection, adb, dynamic-analysis, runtime, spawn, attach]
difficulty: medium
summary: "Get frida-server running on a device or emulator, attach to the target, and apply the ten hook patterns that solve most Android challenges."
when_to_use:
  - "Static analysis stalls because the value is computed at runtime"
  - "You need to see the plaintext going into a crypto call"
  - "You want to call the app's own functions as an oracle"
tools: [frida, frida-tools, objection, adb, python]
related: [android-ssl-pinning-bypass, android-root-detection-bypass, android-native-jni, android-deobfuscation]
---

## TL;DR

Push a matching `frida-server` to `/data/local/tmp`, run it as root, then
`frida -U -f com.pkg -l hook.js --no-pause`. Inside `Java.perform`, `Java.use('cls')`
gives you the class, `.method.implementation = function(...)` replaces it,
`this.method(...)` calls the original. The version of `frida-server` must match your
host `frida` exactly.

## Recognise it

- The check is `native`, obfuscated, or depends on server state.
- You need the value of a variable, not the algorithm.
- The app compares your input against something computed at runtime.
- You want to bypass a check but do not want to re-sign the APK.

## Theory

Frida injects a JS runtime (QuickJS/V8) into the target process and exposes two bridges:

- **Java bridge** - reflection over ART. `Java.perform(cb)` runs `cb` on a thread attached
  to the VM. `Java.use(name)` returns a wrapper class; `Java.choose(name, cbs)` scans the
  heap for live instances.
- **Native bridge** - `Module`, `Interceptor`, `Memory`, `NativeFunction`, `Process`.

Method replacement rules that trip everyone up:

- `.implementation = function (a, b) { ... }` - `this` is the instance; call the original
  with `this.method(a, b)`; you **must** return a value if the method is non-void.
- Overloads: `.overload('java.lang.String', 'int').implementation = ...`.
  Use `.overloads` to list them.
- Constructors: `.$init.implementation`.
- Static fields: `Cls.FIELD.value`; instance fields: `inst.field.value`
  (append `_` if the name collides with a method: `inst._name.value`).
- Java objects coming back are wrappers; use `.toString()`, or `Java.cast(obj, Cls)`.

Spawn vs attach:

- `-f pkg` **spawns** and holds the process at the loader - required to hook code that runs
  in `Application.onCreate` / `<clinit>` / `JNI_OnLoad`.
- `-n pkg` / `-p pid` **attaches** to a running process - fine for UI-triggered code.

## Attack

1. `adb shell getprop ro.product.cpu.abi` -> pick `arm64`, `arm`, `x86_64`, `x86`.
2. `frida --version` on the host -> download the same `frida-server` version.
3. Push, chmod, run as root, in the background.
4. `frida-ps -U` to confirm the connection.
5. Write the hook, iterate with `-l` and `--no-pause`.
6. Escalate to `objection` when you want a shell rather than a script.

## Code

### Setup

```bash
#!/bin/sh
# frida-setup.sh - install and start frida-server matching the host frida version
set -eu

VER="$(frida --version)"
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
case "$ABI" in
  arm64*) ARCH=arm64 ;;
  armeabi*) ARCH=arm ;;
  x86_64) ARCH=x86_64 ;;
  x86) ARCH=x86 ;;
  *) echo "unknown abi $ABI"; exit 1 ;;
esac

FILE="frida-server-${VER}-android-${ARCH}"
echo "need $FILE (download it from the frida releases page for version $VER)"

# push and run (device must be rooted, or use an emulator with `adb root`)
adb push "$FILE" /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server -D'" || \
  adb shell "/data/local/tmp/frida-server -D"

# confirm
frida-ps -U | head
```

```bash
# list attached devices frida can see
frida-ls-devices

# running processes / installed apps on the usb device
frida-ps -U
frida-ps -Ua           # only running apps, with identifiers
frida-ps -Uai          # all installed apps

# spawn the app and hold it until the script is loaded
frida -U -f com.ctf.app -l hook.js --no-pause

# attach to an already running app
frida -U -n com.ctf.app -l hook.js

# attach by pid
frida -U -p 12345 -l hook.js

# log the session to a file instead of the terminal
frida -U -f com.ctf.app -l hook.js --no-pause -o out.log

# frida-server on a non-default port (useful when 27042 is being scanned for)
adb shell "/data/local/tmp/frida-server -l 0.0.0.0:31337 -D"
adb forward tcp:31337 tcp:31337
frida -H 127.0.0.1:31337 -f com.ctf.app -l hook.js

# objection: instrumented REPL, no script needed
objection -g com.ctf.app explore
```

### The ten hooks

```js
// ten-hooks.js - the patterns that cover most Android CTF work
// run: frida -U -f com.ctf.app -l ten-hooks.js --no-pause
'use strict';

Java.perform(function () {

  // --- 1. replace an instance method and see both sides -----------------------
  var Checker = Java.use('com.ctf.app.Checker');
  Checker.verify.implementation = function (input) {
    var orig = this.verify(input);
    console.log('[1] verify("' + input + '") = ' + orig);
    return true;                       // force success
  };

  // --- 2. pick one specific overload ------------------------------------------
  var Crypto = Java.use('com.ctf.app.Crypto');
  Crypto.decrypt.overload('java.lang.String', 'int').implementation = function (s, mode) {
    var r = this.decrypt(s, mode);
    console.log('[2] decrypt("' + s + '", ' + mode + ') = ' + r);
    return r;
  };

  // --- 3. constructor ----------------------------------------------------------
  var Key = Java.use('javax.crypto.spec.SecretKeySpec');
  Key.$init.overload('[B', 'java.lang.String').implementation = function (bytes, alg) {
    console.log('[3] SecretKeySpec(' + alg + ') key=' + bytesToHex(bytes));
    return this.$init(bytes, alg);
  };

  // --- 4. read and write fields ------------------------------------------------
  var Cfg = Java.use('com.ctf.app.Config');
  console.log('[4] static DEBUG = ' + Cfg.DEBUG.value);
  Cfg.DEBUG.value = true;

  // --- 5. static method --------------------------------------------------------
  var Util = Java.use('com.ctf.app.Util');
  Util.isProduction.implementation = function () {
    console.log('[5] isProduction -> forcing false');
    return false;
  };

  // --- 6. override a return value without touching the body --------------------
  var Pm = Java.use('android.app.ActivityManager');
  Pm.isUserAMonkey.implementation = function () { return false; };

  // --- 7. find live instances and use them as an oracle ------------------------
  Java.choose('com.ctf.app.Session', {
    onMatch: function (inst) {
      console.log('[7] live Session token=' + inst.getToken());
    },
    onComplete: function () { console.log('[7] scan done'); }
  });

  // --- 8. enumerate classes to find the obfuscated one -------------------------
  var hits = [];
  Java.enumerateLoadedClassesSync().forEach(function (name) {
    if (name.indexOf('com.ctf') === 0) { hits.push(name); }
  });
  console.log('[8] app classes: ' + hits.length);
  hits.slice(0, 20).forEach(function (n) { console.log('    ' + n); });

  // --- 9. catch exceptions thrown inside a hooked method -----------------------
  var Net = Java.use('com.ctf.app.Net');
  Net.fetch.implementation = function (url) {
    try {
      return this.fetch(url);
    } catch (e) {
      console.log('[9] fetch threw: ' + e);
      return null;
    }
  };

  // --- 10. native side: hook a C export from the same script -------------------
  var strstr = Module.findExportByName('libc.so', 'strstr');
  if (strstr !== null) {
    Interceptor.attach(strstr, {
      onEnter: function (args) {
        var needle = args[1].readCString();
        if (needle && needle.indexOf('frida') !== -1) {
          console.log('[10] anti-frida strstr("' + needle + '")');
          this.block = true;
        }
      },
      onLeave: function (ret) {
        if (this.block) { ret.replace(ptr(0)); }
      }
    });
  }

  function bytesToHex(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) {
      s += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
    }
    return s;
  }
});
```

### Useful helpers

```js
// helpers.js - stack traces, main-thread work, and calling app methods on demand
'use strict';

Java.perform(function () {

  // print a Java stack trace from inside any hook
  function stack() {
    return Java.use('android.util.Log')
      .getStackTraceString(Java.use('java.lang.Throwable').$new());
  }

  var File = Java.use('java.io.File');
  File.exists.implementation = function () {
    var path = this.getAbsolutePath();
    var r = this.exists();
    if (path.indexOf('/su') !== -1 || path.indexOf('magisk') !== -1) {
      console.log('[file] ' + path + ' -> ' + r + '\n' + stack());
    }
    return r;
  };

  // run something on the UI thread (needed for Toast, View access)
  Java.scheduleOnMainThread(function () {
    var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var Toast = Java.use('android.widget.Toast');
    Toast.makeText(ctx, Java.use('java.lang.String').$new('frida attached'), 1).show();
  });

  // expose functions to the Python side
  rpc.exports = {
    solve: function (candidate) {
      var out = null;
      Java.perform(function () {
        var C = Java.use('com.ctf.app.Checker');
        out = C.$new().verify(candidate);
      });
      return out;
    },
    classes: function (prefix) {
      var res = [];
      Java.perform(function () {
        Java.enumerateLoadedClassesSync().forEach(function (n) {
          if (n.indexOf(prefix) === 0) { res.push(n); }
        });
      });
      return res;
    }
  };
});
```

### Python driver

```python
#!/usr/bin/env python3
"""frida_drive.py - spawn a package, inject a script, and optionally brute force via rpc.

Usage:
  python3 frida_drive.py com.ctf.app hook.js
  python3 frida_drive.py com.ctf.app helpers.js --brute
"""
from __future__ import annotations

import argparse
import sys
import time

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_{}-"


def on_message(message: dict, data: bytes | None) -> None:
    if message.get("type") == "send":
        print("[send]", message.get("payload"))
    elif message.get("type") == "error":
        print("[error]", message.get("stack", message.get("description")), file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description="frida spawn + inject helper")
    ap.add_argument("package")
    ap.add_argument("script")
    ap.add_argument("--attach", action="store_true", help="attach instead of spawn")
    ap.add_argument("--brute", action="store_true", help="drive rpc.exports.solve as an oracle")
    ap.add_argument("--prefix", default="flag{")
    args = ap.parse_args()

    try:
        import frida  # type: ignore
    except ImportError:
        print("pip install frida-tools", file=sys.stderr)
        return 1

    device = frida.get_usb_device(timeout=10)
    if args.attach:
        session = device.attach(args.package)
        pid = None
    else:
        pid = device.spawn([args.package])
        session = device.attach(pid)

    with open(args.script, encoding="utf-8") as fh:
        source = fh.read()
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    if pid is not None:
        device.resume(pid)
        time.sleep(1.0)

    if args.brute:
        known = args.prefix
        for _ in range(64):
            for ch in ALPHABET:
                if script.exports_sync.solve(known + ch):
                    known += ch
                    print("[+]", known)
                    break
            else:
                break
        print("[done]", known)
        return 0

    print("[*] script loaded; ctrl-c to detach")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        session.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants & pitfalls

- **Version mismatch** - an instant disconnect almost always means
  `frida-server` != host `frida`. Keep them pinned.
- **`Java.perform` required** - any `Java.use` outside it throws "Java API not available".
- **Non-void hooks must return.** Returning `undefined` from a hooked `boolean` method
  makes ART throw.
- **Hooking too late** - use `-f ... --no-pause`. For code in `<clinit>` of a class loaded
  by a custom loader, hook `ClassLoader.loadClass` first.
- **Multi-classloader apps** (packed, or Instant Apps): `Java.use` fails until you
  `Java.enumerateClassLoaders` and `Java.classFactory.loader = <the right one>`.
- **Anti-Frida**: the app scans `/proc/self/maps` for `frida-agent`, checks port 27042,
  or looks for the `LIBFRIDA` string. Run frida-server on a custom port with a renamed
  binary, or use `frida-gadget` embedded in a patched APK.
- **String arguments may be `java.lang.String` wrappers**, not JS strings. Concatenation
  usually works because of `toString`, but `indexOf` may not - wrap with `'' + arg`.
- On a non-rooted device, embed `frida-gadget.so` in the APK and add
  `System.loadLibrary("frida-gadget")` - or let `objection patchapk` do it.

## Tools

- `frida`, `frida-ps`, `frida-trace`, `frida-ls-devices` (the `frida-tools` package).
- `objection` - a ready-made REPL on top of Frida (memory search, keystore dump, pinning bypass).
- `frida-gadget` - non-rooted injection via a repackaged APK.
- `jnitrace` - JNI call tracing.
- `fridump` - process memory dumping driven by Frida.

## References

- Frida documentation: JavaScript API (Java, Interceptor, Module, Memory) and the Android guide.
- `objection` project documentation for its command set.
