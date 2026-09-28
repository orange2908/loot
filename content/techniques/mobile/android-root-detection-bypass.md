---
title: "Android Root, Emulator and Debug Detection - Bypass Catalogue"
category: mobile
subcategory: anti-analysis
type: technique
tags: [root-detection, rootbeer, magisk, zygisk, denylist, frida, objection, emulator-detection, anti-debug, ptrace, safetynet, play-integrity, build-tags, su, proc-maps, xposed, apktool]
difficulty: medium
summary: "Enumerate every root/emulator/debugger/Frida check an Android app can make, and the Frida, Magisk or smali bypass for each."
when_to_use:
  - "The app exits, shows 'device not supported', or hides the flag on your test device"
  - "Frida attaches and the app immediately dies"
  - "The app behaves differently on an emulator than on hardware"
tools: [frida, objection, magisk, apktool, adb, rootbeer]
related: [android-frida-basics, android-ssl-pinning-bypass, android-smali-patching, android-deobfuscation]
---

## TL;DR

Detection is a list of cheap observations: files that exist, properties that are set,
processes that run, ports that listen. Hook the observation, not the decision. One Frida
script covering `File.exists`, `Runtime.exec`, `Build.TAGS`, `PackageManager`, `System.getProperty`
and `fopen`/`access`/`strstr` on the native side kills 95% of implementations.
For the rest: Magisk DenyList, or patch the smali.

## Recognise it

- App closes instantly on launch with a toast, or a dialog "rooted device detected".
- jadx shows `RootBeer`, `isDeviceRooted`, `checkSuBinary`, `detectTestKeys`,
  `isEmulator`, `isDebuggerConnected`.
- The app dies the moment `frida-server` is running, even before you attach.
- `strings` on a native lib shows `/system/bin/su`, `magisk`, `frida`, `27042`, `TracerPid`.
- Logcat shows a `ptrace` failure or `SIGTRAP`.

## Theory

### Root checks

| Check | Implementation |
|---|---|
| su binary | `new File("/system/bin/su").exists()` over a path list |
| `which su` | `Runtime.getRuntime().exec("which su")` / `exec("su")` |
| test-keys | `Build.TAGS.contains("test-keys")` |
| dangerous packages | `PackageManager.getPackageInfo("com.topjohnwu.magisk", 0)` |
| root management apps | `eu.chainfire.supersu`, `com.noshufou.android.su`, `com.koushikdutta.superuser` |
| root cloaking apps | `de.robv.android.xposed.installer`, `com.devadvance.rootcloak` |
| writable system paths | `new File("/system").canWrite()`, remount test |
| dangerous props | `ro.debuggable=1`, `ro.secure=0`, `service.adb.root=1` |
| busybox | `/system/xbin/busybox` |
| mount table | `/proc/mounts` containing `magisk` or a rw `/system` |
| SELinux | `/sys/fs/selinux/enforce` == 0 |
| native | `access("/system/bin/su", F_OK)`, `fopen`, `stat`, `popen` |
| attestation | SafetyNet `basicIntegrity`/`ctsProfileMatch`, Play Integrity verdicts |

### Emulator checks

`Build.FINGERPRINT` starting `generic`/`unknown`, `Build.MODEL` containing
`google_sdk`/`Emulator`/`Android SDK built for x86`, `Build.MANUFACTURER == "Genymotion"`,
`Build.HARDWARE` in `goldfish|ranchu|vbox86`, props `ro.kernel.qemu=1`,
`ro.boot.qemu`, files `/dev/socket/qemud`, `/dev/qemu_pipe`, `/system/lib/libc_malloc_debug_qemu.so`,
IMEI all zeros, no telephony, sensor list empty, battery always 50%, `/proc/cpuinfo` saying `Goldfish`.

### Debugger / Frida checks

- `android.os.Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`.
- `ApplicationInfo.FLAG_DEBUGGABLE` on itself.
- `/proc/self/status` -> `TracerPid: != 0`.
- `ptrace(PTRACE_TRACEME, 0, 0, 0)` in a `.init_array` constructor, so a second tracer
  cannot attach.
- `/proc/self/maps` containing `frida-agent`, `gadget`, `gum-js-loop`, `linjector`.
- Thread names `gmain`, `gum-js-loop`, `pool-frida` in `/proc/self/task/*/comm`.
- A TCP connect to `127.0.0.1:27042`, or reading `/proc/net/tcp` for that port.
- Scanning loaded modules for the `LIBFRIDA` magic string.

### Signature / integrity checks

`PackageManager.getPackageInfo(pkg, GET_SIGNATURES).signatures[0].hashCode()` compared to
a constant; `getPackageInfo(..., GET_SIGNING_CERTIFICATES)` on API 28+; CRC of
`classes.dex` read from the app's own APK; installer package check
(`getInstallerPackageName() == "com.android.vending"`).

## Attack

1. Find the decision point with jadx (`grep -ri root`, `grep -ri emulator`).
2. Try the broad Frida script first - it hooks the *observations*, so it works even when
   the decision is obfuscated.
3. If the app kills itself before your script loads, use `-f pkg --no-pause` (spawn) so
   hooks land before `Application.onCreate`.
4. If the check is native and runs in `.init_array`, hook `dlopen`/`ptrace` from the
   earliest possible point, or patch the `.so`.
5. If Frida itself is detected, move frida-server to a random port and rename the binary,
   or use Magisk DenyList + a gadget-free approach.
6. Last resort: patch the smali to return false, rebuild, re-sign, and also patch the
   signature check you just broke.

## Code

### Frida: broad root/emulator/debug bypass

```js
// anti-detect.js - neutralise root, emulator, debugger and frida detection
// run: frida -U -f com.ctf.app -l anti-detect.js --no-pause
'use strict';

var ROOT_PATHS = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su', '/system/app/Superuser.apk',
  '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su', '/system/sd/xbin/su',
  '/system/bin/failsafe/su', '/system/xbin/busybox', '/system/bin/magisk', '/sbin/magisk',
  '/data/adb/magisk', '/data/adb/modules', '/dev/com.koushikdutta.superuser.daemon'
];
var BAD_PKGS = [
  'com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.noshufou.android.su',
  'com.koushikdutta.superuser', 'com.thirdparty.superuser', 'com.yellowes.su',
  'de.robv.android.xposed.installer', 'com.saurik.substrate', 'com.devadvance.rootcloak',
  'com.formyhm.hideroot', 'com.zachspong.temprootremovejb'
];
var BAD_TOKENS = ['su', 'magisk', 'supersu', 'busybox', 'xposed', 'frida', 'gum-js', 'gadget',
                  'linjector', 're.frida.server'];

function looksBad(s) {
  if (!s) { return false; }
  var low = ('' + s).toLowerCase();
  for (var i = 0; i < ROOT_PATHS.length; i++) {
    if (low.indexOf(ROOT_PATHS[i]) !== -1) { return true; }
  }
  for (var j = 0; j < BAD_TOKENS.length; j++) {
    if (low.indexOf(BAD_TOKENS[j]) !== -1) { return true; }
  }
  return false;
}

Java.perform(function () {

  // ---- java.io.File.exists / canRead / canWrite -------------------------------
  var JFile = Java.use('java.io.File');
  ['exists', 'canRead', 'canWrite', 'isFile', 'isDirectory'].forEach(function (m) {
    if (!JFile[m]) { return; }
    JFile[m].implementation = function () {
      var p = this.getAbsolutePath();
      if (looksBad(p)) {
        console.log('[root] File.' + m + '("' + p + '") -> false');
        return false;
      }
      return this[m]();
    };
  });

  // ---- Runtime.exec ------------------------------------------------------------
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overloads.forEach(function (ov) {
    ov.implementation = function () {
      var a = arguments[0];
      var desc = Array.isArray(a) ? a.join(' ') : '' + a;
      if (looksBad(desc) || desc.indexOf('which') === 0) {
        console.log('[root] blocked exec: ' + desc);
        throw Java.use('java.io.IOException').$new('No such file or directory');
      }
      return ov.apply(this, arguments);
    };
  });

  // ---- Build fields ------------------------------------------------------------
  var Build = Java.use('android.os.Build');
  Build.TAGS.value = 'release-keys';
  Build.FINGERPRINT.value = 'google/redfin/redfin:13/TQ3A.230805.001/10316531:user/release-keys';
  Build.MODEL.value = 'Pixel 5';
  Build.MANUFACTURER.value = 'Google';
  Build.BRAND.value = 'google';
  Build.DEVICE.value = 'redfin';
  Build.PRODUCT.value = 'redfin';
  Build.HARDWARE.value = 'redfin';
  Build.BOARD.value = 'redfin';

  // ---- System properties --------------------------------------------------------
  var SystemProperties = Java.use('android.os.SystemProperties');
  var SAFE = {
    'ro.debuggable': '0', 'ro.secure': '1', 'ro.build.tags': 'release-keys',
    'ro.kernel.qemu': '0', 'ro.boot.qemu': '0', 'service.adb.root': '0',
    'ro.build.selinux': '1', 'ro.hardware': 'redfin'
  };
  SystemProperties.get.overload('java.lang.String').implementation = function (k) {
    if (SAFE.hasOwnProperty(k)) {
      console.log('[root] SystemProperties.get(' + k + ') -> ' + SAFE[k]);
      return SAFE[k];
    }
    return this.get(k);
  };

  // ---- PackageManager ------------------------------------------------------------
  var PM = Java.use('android.app.ApplicationPackageManager');
  PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
    if (BAD_PKGS.indexOf(pkg) !== -1) {
      console.log('[root] hiding package ' + pkg);
      throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
    }
    return this.getPackageInfo(pkg, flags);
  };

  // ---- RootBeer -------------------------------------------------------------------
  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    ['isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
     'detectPotentiallyDangerousApps', 'checkForSuBinary', 'checkForBusyBoxBinary',
     'checkForDangerousProps', 'checkForRWPaths', 'detectTestKeys',
     'checkSuExists', 'checkForRootNative', 'checkForMagiskBinary'].forEach(function (m) {
      if (RootBeer[m]) {
        RootBeer[m].implementation = function () {
          console.log('[root] RootBeer.' + m + ' -> false');
          return false;
        };
      }
    });
  } catch (e) { /* rootbeer not bundled */ }

  // ---- debugger -----------------------------------------------------------------
  var Debug = Java.use('android.os.Debug');
  Debug.isDebuggerConnected.implementation = function () { return false; };
  Debug.waitingForDebugger.implementation = function () { return false; };

  // ---- reading /proc/self/status, /proc/self/maps, /proc/net/tcp ------------------
  var BufferedReader = Java.use('java.io.BufferedReader');
  BufferedReader.readLine.overload().implementation = function () {
    var line = this.readLine();
    if (line !== null && looksBad(line)) {
      console.log('[root] filtered line: ' + line);
      return '';
    }
    if (line !== null && line.indexOf('TracerPid:') === 0) {
      return 'TracerPid:\t0';
    }
    return line;
  };

  console.log('[root] java hooks installed');
});

// ---- native layer ----------------------------------------------------------------
(function nativeHooks() {
  ['fopen', 'open', 'access', 'stat', '__xstat', 'lstat'].forEach(function (fn) {
    var addr = Module.findExportByName('libc.so', fn);
    if (addr === null) { return; }
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          var p = args[0].readCString();
          this.bad = looksBad(p);
          if (this.bad) { console.log('[native] ' + fn + '("' + p + '") -> fail'); }
        } catch (e) { this.bad = false; }
      },
      onLeave: function (ret) {
        if (this.bad) { ret.replace(fn === 'fopen' ? ptr(0) : ptr(-1)); }
      }
    });
  });

  var strstr = Module.findExportByName('libc.so', 'strstr');
  if (strstr !== null) {
    Interceptor.attach(strstr, {
      onEnter: function (args) {
        try { this.bad = looksBad(args[1].readCString()); } catch (e) { this.bad = false; }
      },
      onLeave: function (ret) { if (this.bad) { ret.replace(ptr(0)); } }
    });
  }

  var ptrace = Module.findExportByName(null, 'ptrace');
  if (ptrace !== null) {
    Interceptor.replace(ptrace, new NativeCallback(function () {
      return 0;    // PTRACE_TRACEME always "succeeds", so the app thinks it owns itself
    }, 'long', ['int', 'int', 'pointer', 'pointer']));
    console.log('[native] ptrace neutralised');
  }

  // block connect() to the frida control port
  var connect = Module.findExportByName('libc.so', 'connect');
  if (connect !== null) {
    Interceptor.attach(connect, {
      onEnter: function (args) {
        var sa = args[1];
        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        this.frida = (port === 27042 || port === 27043);
      },
      onLeave: function (ret) { if (this.frida) { ret.replace(ptr(-1)); } }
    });
  }
})();
```

### Magisk-side hardening (no script)

```bash
# 1. Magisk > Settings > enable Zygisk, enable "Enforce DenyList"
# 2. Configure DenyList -> tick the target package and all its processes
adb shell su -c 'magisk --denylist add com.ctf.app'
adb shell su -c 'magisk --denylist ls'

# 3. Hide the Magisk app itself (repackages it with a random package name)
#    Magisk app > Settings > Hide the Magisk app

# 4. Useful Magisk modules for this: Shamiko (stronger hiding), LSPosed + HideMyApplist
#    Install via: Magisk > Modules > Install from storage

# 5. run frida-server on a non-standard port under a non-obvious name
adb shell su -c 'cp /data/local/tmp/frida-server /data/local/tmp/sysmon'
adb shell su -c '/data/local/tmp/sysmon -l 127.0.0.1:31337 -D'
adb forward tcp:31337 tcp:31337
frida -H 127.0.0.1:31337 -f com.ctf.app -l anti-detect.js --no-pause
```

### objection one-liners

```bash
# built-in root bypass (hooks the common java checks)
objection -g com.ctf.app explore -s "android root disable"

# simulate root instead (for apps that require root to show a feature)
objection -g com.ctf.app explore -s "android root simulate"

# combine with pinning bypass in one session
objection -g com.ctf.app explore \
  -s "android root disable" -s "android sslpinning disable"
```

### Static patch when Frida is blocked outright

```bash
# find the decision method
grep -rn --include='*.smali' -iE 'isRooted|rootDetect|checkRoot|isEmulator|isDebuggerConnected' out-apktool/

# patch it to return false (see android-smali-patching for the full rebuild chain)
python3 smali_patch.py out-apktool/smali/com/ctf/app/Security.smali isRooted false
python3 smali_patch.py out-apktool/smali/com/ctf/app/Security.smali isEmulator false

# the app may now fail its own signature check - patch that too
grep -rn --include='*.smali' 'GET_SIGNATURES\|getPackageInfo' out-apktool/
```

## Variants & pitfalls

- **The check runs before your script.** Always spawn (`-f`), never attach, for
  launch-time checks. For `.init_array` native checks, even spawn can be too late -
  then patch the `.so` or use `LD_PRELOAD` via a Magisk module.
- **Delayed / random checks**: the app checks again 60 seconds in, or on a background
  thread, specifically to catch late hooking. Keep hooks installed, do not just flip one
  boolean.
- **Multiple independent checks** where only one is obvious. Log, do not guess:
  hook `File.exists` and print everything so you see the whole path list.
- **Server-side attestation**: SafetyNet/Play Integrity verdicts are signed by Google and
  validated on the backend. You cannot hook that from the client; you need the backend to
  accept a failing verdict, or to replay a good one. Usually out of scope for CTF.
- **`BufferedReader.readLine` hook is heavy-handed** and can corrupt legitimate parsing.
  Narrow it to the calling class if the app misbehaves.
- **Property reads via `__system_property_get`** (native) bypass the Java
  `SystemProperties` hook - hook the libc symbol too.
- **Overwriting `Build` fields is global**; some apps read them for legitimate UI and will
  render oddly. That is fine.
- If the app exits with no message, check `logcat -b crash` and `adb shell dmesg` -
  the detection may be a native `abort()`.

## Tools

- `frida` / `objection` - runtime.
- `Magisk` + `Zygisk` + `DenyList` (+ `Shamiko`) - the platform-level hide.
- `LSPosed` + `HideMyApplist` - hides packages from `PackageManager`.
- `apktool` + `apksigner` - the static route.
- `RootBeer` source - read it to learn the canonical check list.

## References

- `RootBeer` project source for the canonical Android root-check list.
- Magisk documentation on Zygisk and DenyList.
- Android developer documentation on Play Integrity API verdicts.
