---
title: "iOS Runtime - Frida, objection and Jailbreak Detection Bypass"
category: mobile
subcategory: ios-runtime
type: technique
tags: [ios, frida, objection, frida-gadget, objc, method-swizzling, interceptor, jailbreak-detection, keychain, nsurlsession, cycript, ssl-pinning, trustkit, patchipa, sileo, runtime]
difficulty: hard
summary: "Hook Objective-C and Swift methods at runtime, explore live objects, dump the keychain and defeat jailbreak detection and pinning on iOS."
when_to_use:
  - "The app refuses to run because it detects a jailbreak"
  - "You need the plaintext a method computes, not the algorithm"
  - "You have class-dump output and want to call or patch those methods"
tools: [frida, objection, ios-deploy, iproxy, class-dump]
related: [ios-static-analysis, mobile-traffic-interception, android-frida-basics, android-root-detection-bypass]
---

## TL;DR

On a jailbroken device install `frida` from a package manager and use
`frida -U -f com.ctf.app -l s.js`. Without a jailbreak, repackage the IPA with
FridaGadget (`objection patchipa`) and side-load it. `ObjC.classes.Foo["- bar:"]`
is the handle for every Objective-C method; `Interceptor.attach` logs it,
`.implementation = ...` replaces it. Jailbreak detection is `fileExistsAtPath`,
`canOpenURL`, `fork`, `stat` - hook those, not the decision.

## Recognise it

- The app shows "This device is jailbroken" and exits.
- class-dump headers contain `-(BOOL)isJailbroken`, `+ (BOOL)detectJB`.
- `strings` shows `/Applications/Cydia.app`, `/bin/bash`, `/etc/apt`, `cydia://`.
- Proxying gives TLS errors -> an `NSURLSession` delegate implementing
  `URLSession:didReceiveChallenge:`, or TrustKit / AFNetworking pinning.

## Theory

### Frida on iOS

| Model | Requirement | Command |
|---|---|---|
| jailbroken | `re.frida.server` package installed (Sileo/Cydia) | `frida -U -f com.ctf.app -l s.js` |
| non-jailbroken | FridaGadget.dylib injected into the IPA + re-sign | `frida -U -n Gadget -l s.js` |

`objection patchipa --source app.ipa --codesign-signature <TEAMID>` inserts
`Frameworks/FridaGadget.dylib`, adds an `LC_LOAD_DYLIB` and re-signs, giving a
side-loadable IPA (`ios-deploy -b app-frida-codesigned.ipa`).

### The Objective-C bridge

- `ObjC.classes.NSString["- stringByAppendingString:"]` - a method handle; `-` instance,
  `+` class.
- `Interceptor.attach(method.implementation, {...})` - observe. In `onEnter`, `args[0]` is
  `self`, `args[1]` is the selector, `args[2]` is the first real argument.
- `.implementation = ObjC.implement(method, function (self, sel, arg) {...})` - replace.
- `ObjC.choose(cls, {onMatch, onComplete})` - live instances; `new ObjC.Object(ptr)` wraps
  a raw pointer; `.toString()` renders an `NSString*`.

Swift classes inheriting `NSObject` appear as `Module.ClassName`. Pure Swift structs and
`final` classes do not; hook those by symbol (`nm` + `swift demangle`) or by offset.

### Jailbreak detection surface

| Check | Symbol to hook |
|---|---|
| file existence | `-[NSFileManager fileExistsAtPath:]`, `stat`, `lstat`, `access`, `fopen`, `open` |
| can open cydia:// | `-[UIApplication canOpenURL:]` |
| fork succeeds | `fork`, `vfork`, `popen`, `system` |
| suspicious dylibs | `_dyld_image_count`, `_dyld_get_image_name` |
| environment | `getenv("DYLD_INSERT_LIBRARIES")` |
| debugger / anti-attach | `sysctl` (`KERN_PROC` + `P_TRACED`), `ptrace(PT_DENY_ATTACH)` |

Paths to filter: `/Applications/Cydia.app`, `/Applications/Sileo.app`,
`/Library/MobileSubstrate`, `/usr/sbin/sshd`, `/etc/apt`, `/bin/bash`, `/var/jb`,
`/private/var/lib/cydia`, `/taurine`, `/electra`, `/.installed_unc0ver`.

## Attack

1. Get Frida onto the device (jailbroken: package; otherwise: gadget-patched IPA).
2. `frida-ps -Ua` to confirm, then spawn (not attach, so launch-time checks are covered).
3. Dump classes matching the bundle prefix so you know what to hook.
4. Hook the interesting method and log arguments and return.
5. Use `ObjC.choose` to grab a live object and call its methods as an oracle.
6. For network work, add the NSURLSession logger and the pinning bypass.

## Code

### Setup

```bash
# jailbroken device: Sileo/Cydia -> Sources -> add the frida repo -> install "Frida"
frida-ps -U                         # processes
frida-ps -Ua                        # running apps with bundle ids
frida -U -f com.ctf.app -l hook.js --no-pause    # spawn (needed for launch-time checks)
frida -U -n MyApp -l hook.js                     # attach to a running app

# ssh over usb (device port 22 -> host port 2222)
iproxy 2222 22 &
ssh -p 2222 root@127.0.0.1          # default password on legacy jailbreaks: alpine

# non-jailbroken: inject FridaGadget into the ipa and re-sign, then side-load
objection patchipa --source app.ipa --codesign-signature ABCDE12345
ios-deploy -b app-frida-codesigned.ipa
frida -U -n Gadget -l hook.js

# objection: the fastest path to a working session
objection --gadget com.ctf.app explore
#   ios jailbreak disable          |  ios sslpinning disable
#   ios keychain dump              |  ios nsuserdefaults get
#   ios plist cat Info.plist       |  ios cookies get
#   ios hooking list classes       |  ios hooking search methods login
#   ios hooking watch method "-[LoginVC check:]" --dump-args --dump-return --dump-backtrace
#   memory search --string "flag{" --offsets-only
#   file download /var/mobile/Containers/Data/Application/<UUID>/Documents/db.sqlite
```

### Explore the runtime (cycript replacement)

```js
// ios-explore.js - enumerate classes, methods and live instances
// run: frida -U -n MyApp -l ios-explore.js
'use strict';

if (!ObjC.available) {
  console.log('[-] Objective-C runtime not available');
} else {
  var PREFIX = 'CTF';   // bundle class prefix, or the swift module name

  // 1. classes belonging to the app (a Swift class name contains a dot)
  var appClasses = Object.keys(ObjC.classes).filter(function (n) {
    return n.indexOf(PREFIX) === 0 || n.indexOf('.') !== -1;
  });
  console.log('[*] app classes: ' + appClasses.length);
  appClasses.slice(0, 40).forEach(function (n) { console.log('    ' + n); });

  // 2. every method of a class, with its implementation address
  function dumpClass(cls) {
    var c = ObjC.classes[cls];
    if (!c) { console.log('[-] no such class: ' + cls); return; }
    console.log('== ' + cls + ' : ' + c.$superClass.$className);
    c.$ownMethods.forEach(function (m) { console.log('   ' + m + '  @ ' + c[m].implementation); });
  }
  if (appClasses.length > 0) { dumpClass(appClasses[0]); }

  // 3. search app classes for a selector matching a keyword
  ['flag', 'verify', 'jailbr'].forEach(function (kw) {
    appClasses.forEach(function (cname) {
      try {
        ObjC.classes[cname].$ownMethods.forEach(function (m) {
          if (m.toLowerCase().indexOf(kw) !== -1) { console.log('[find] ' + cname + ' ' + m); }
        });
      } catch (e) { /* some classes throw on $ownMethods */ }
    });
  });

  // 4. live instances - the cycript "choose" workflow
  ObjC.choose(ObjC.classes.UIViewController, {
    onMatch: function (inst) { console.log('[live] ' + inst.$className + ' @ ' + inst.handle); },
    onComplete: function () { console.log('[live] scan done'); }
  });

  // 5. expose helpers to the python side
  rpc.exports = {
    classes: function (p) {
      return Object.keys(ObjC.classes).filter(function (n) { return n.indexOf(p) === 0; });
    },
    call0: function (cls, sel) { return '' + ObjC.classes[cls][sel](); }
  };
}
```

### Hooking and replacing methods

```js
// ios-hooks.js - observe, replace and swizzle Objective-C methods
// run: frida -U -f com.ctf.app -l ios-hooks.js --no-pause
'use strict';

if (ObjC.available) {

  // ---- 1. observe an instance method and override its return -------------------
  var LoginVC = ObjC.classes.CTFLoginViewController;
  if (LoginVC && LoginVC['- checkPassword:']) {
    Interceptor.attach(LoginVC['- checkPassword:'].implementation, {
      // args[0]=self  args[1]=_cmd  args[2]=first real argument
      onEnter: function (args) { this.pw = new ObjC.Object(args[2]).toString(); },
      onLeave: function (retval) {
        console.log('[hook] checkPassword("' + this.pw + '") = ' + retval);
        retval.replace(ptr(1));          // force YES
      }
    });
  }

  // ---- 2. replace an implementation, keeping a callable original ---------------
  if (LoginVC && LoginVC['- isPremiumUser']) {
    var meth = LoginVC['- isPremiumUser'];
    var orig = new NativeFunction(meth.implementation, 'bool', ['pointer', 'pointer']);
    meth.implementation = ObjC.implement(meth, function (self, sel) {
      console.log('[hook] isPremiumUser -> YES (was ' + orig(self, sel) + ')');
      return 1;
    });
  }

  // ---- 3. swizzle a framework method to log every string comparison ------------
  var isEqual = ObjC.classes.NSString['- isEqualToString:'];
  var origEq = new NativeFunction(isEqual.implementation, 'bool',
                                  ['pointer', 'pointer', 'pointer']);
  isEqual.implementation = ObjC.implement(isEqual, function (self, sel, other) {
    var a = new ObjC.Object(self).toString();
    if (a.length > 3 && a.length < 80) {
      console.log('[cmp] "' + a + '" == "' + new ObjC.Object(other).toString() + '"');
    }
    return origEq(self, sel, other);
  });

  // ---- 4. NSURLSession request logging ------------------------------------------
  var dt = ObjC.classes.NSURLSession &&
           ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'];
  if (dt) {
    Interceptor.attach(dt.implementation, {
      onEnter: function (args) {
        var req = new ObjC.Object(args[2]);
        console.log('[net] ' + req.HTTPMethod() + ' ' + req.URL().absoluteString());
        var headers = req.allHTTPHeaderFields();
        if (headers) { console.log('[net] headers: ' + headers.toString()); }
        var body = req.HTTPBody();
        if (body && !body.isNull()) {
          console.log('[net] body: ' +
            ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4).toString());
        }
      }
    });
  }

  // ---- 5. NSUserDefaults and NSLog ----------------------------------------------
  Interceptor.attach(ObjC.classes.NSUserDefaults['- objectForKey:'].implementation, {
    onEnter: function (args) { this.key = new ObjC.Object(args[2]).toString(); },
    onLeave: function (ret) {
      if (!ret.isNull()) {
        console.log('[def] ' + this.key + ' = ' + new ObjC.Object(ret).toString());
      }
    }
  });
  var nslog = Module.findExportByName('Foundation', 'NSLog');
  if (nslog !== null) {
    Interceptor.attach(nslog, {
      onEnter: function (args) { console.log('[NSLog] ' + new ObjC.Object(args[0]).toString()); }
    });
  }

  console.log('[+] ios hooks installed');
}
```

### Jailbreak detection bypass

```js
// ios-jb-bypass.js - hide the jailbreak from file, url, fork, dyld and sysctl checks
// run: frida -U -f com.ctf.app -l ios-jb-bypass.js --no-pause
'use strict';

var JB = ['/applications/cydia.app', '/applications/sileo.app', '/applications/zebra.app',
  '/library/mobilesubstrate', '/usr/sbin/sshd', '/usr/bin/ssh', '/etc/apt', '/bin/bash',
  '/bin/sh', '/private/var/lib/apt', '/private/var/lib/cydia', '/private/var/stash',
  '/usr/libexec/cydia', '/var/cache/apt', '/var/jb', '/.bootstrapped', '/.installed_unc0ver',
  '/taurine', '/electra', '/chimera', 'frida', 'cynject', 'libcycript', 'mobilesubstrate',
  'substrateloader', 'tweakinject', 'libhooker', 'substitute'];

function isJB(s) {
  if (!s) { return false; }
  var low = ('' + s).toLowerCase();
  for (var i = 0; i < JB.length; i++) {
    if (low.indexOf(JB[i]) !== -1) { return true; }
  }
  return false;
}

// ---- native file syscalls: report "not found" for every jailbreak artefact ----
['stat', 'stat64', 'lstat', 'lstat64', 'access', 'fopen', 'open', 'opendir',
 'faccessat', 'statfs'].forEach(function (fn) {
  var addr = Module.findExportByName(null, fn);
  if (addr === null) { return; }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try {
        var p = args[0].readUtf8String();
        this.bad = isJB(p);
        if (this.bad) { console.log('[jb] ' + fn + '("' + p + '") -> fail'); }
      } catch (e) { this.bad = false; }
    },
    onLeave: function (ret) {
      if (this.bad) { ret.replace(fn === 'fopen' || fn === 'opendir' ? ptr(0) : ptr(-1)); }
    }
  });
});

// ---- fork must fail in a sandboxed app; ptrace(PT_DENY_ATTACH) must succeed ---
['fork', 'vfork'].forEach(function (fn) {
  var addr = Module.findExportByName(null, fn);
  if (addr !== null) {
    Interceptor.replace(addr, new NativeCallback(function () { return -1; }, 'int', []));
  }
});
var ptrace = Module.findExportByName(null, 'ptrace');
if (ptrace !== null) {
  Interceptor.replace(ptrace, new NativeCallback(function () { return 0; },
    'int', ['int', 'int', 'pointer', 'int']));
}

// ---- hide DYLD_INSERT_LIBRARIES from getenv ----------------------------------
Interceptor.attach(Module.findExportByName(null, 'getenv'), {
  onEnter: function (args) {
    try { this.name = args[0].readUtf8String(); } catch (e) { this.name = ''; }
  },
  onLeave: function (ret) { if (this.name === 'DYLD_INSERT_LIBRARIES') { ret.replace(ptr(0)); } }
});

// ---- Objective-C layer --------------------------------------------------------
if (ObjC.available) {
  Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) { this.bad = isJB(new ObjC.Object(args[2]).toString()); },
    onLeave: function (ret) { if (this.bad) { ret.replace(ptr(0)); } }
  });

  Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
    onEnter: function (args) {
      this.bad = /^(cydia|sileo|zbra|filza|undecimus)/
        .test(new ObjC.Object(args[2]).absoluteString().toString());
    },
    onLeave: function (ret) { if (this.bad) { ret.replace(ptr(0)); } }
  });

  // the app's own detector, whatever class it lives in
  var SELS = ['isJailbroken', 'isJailBroken', 'jailbroken', 'isDeviceJailbroken',
              'detectJailbreak', 'isCompromised'];
  Object.keys(ObjC.classes).forEach(function (cname) {
    SELS.forEach(function (sel) {
      ['- ' + sel, '+ ' + sel].forEach(function (full) {
        try {
          if (!ObjC.classes[cname][full]) { return; }
          Interceptor.attach(ObjC.classes[cname][full].implementation, {
            onLeave: function (ret) { console.log('[jb] ' + cname + ' ' + full); ret.replace(ptr(0)); }
          });
        } catch (e) { /* ignore */ }
      });
    });
  });
}

console.log('[+] jailbreak bypass installed');
```

### iOS SSL pinning bypass

```js
// ios-pinning.js - neutralise SecTrust, TrustKit and AFNetworking pinning
// run: frida -U -f com.ctf.app -l ios-pinning.js --no-pause
'use strict';

['SecTrustEvaluate', 'SecTrustEvaluateWithError'].forEach(function (fn) {
  var addr = Module.findExportByName('Security', fn);
  if (addr === null) { return; }
  Interceptor.attach(addr, {
    onLeave: function (ret) { ret.replace(fn === 'SecTrustEvaluate' ? ptr(0) : ptr(1)); }
  });
});

if (ObjC.available) {
  var TK = ObjC.classes.TSKPinningValidator;            // TrustKit
  if (TK && TK['- evaluateTrust:forHostname:']) {
    Interceptor.attach(TK['- evaluateTrust:forHostname:'].implementation, {
      onLeave: function (ret) { ret.replace(ptr(0)); }  // ShouldAllowConnection
    });
  }
  var AF = ObjC.classes.AFSecurityPolicy;               // AFNetworking
  if (AF && AF['- evaluateServerTrust:forDomain:']) {
    Interceptor.attach(AF['- evaluateServerTrust:forDomain:'].implementation, {
      onLeave: function (ret) { ret.replace(ptr(1)); }
    });
  }
}
```

`objection --gadget com.ctf.app explore -s "ios sslpinning disable"` does the same in one
command. See `mobile-traffic-interception` for the proxy and CA side.

## Variants & pitfalls

- **Attach is too late.** Jailbreak checks usually run in
  `application:didFinishLaunchingWithOptions:` or a `+load`. Always spawn (`-f --no-pause`).
- **C constructors and `+load` run before even spawn hooks** in some apps - then patch the
  binary or use a `MobileSubstrate`/`libhooker` tweak.
- **`ObjC.classes.Foo` undefined** - lazily loaded framework; hook `dlopen`/`objc_getClass`.
- **Pure Swift** is not in `ObjC.classes`: get the mangled symbol from `nm`, demangle it to
  confirm, then `Interceptor.attach(Module.findExportByName(null, mangled))`.
- **`retval.replace()` on a `BOOL`** takes `ptr(1)`/`ptr(0)`, not `true`/`false`.
- **`ObjC.implement` loses the original** unless you wrap it in a `NativeFunction` first.

## Tools

- `frida` / `frida-tools`; `frida-ps -Ua` for bundle ids.
- `objection` - `ios jailbreak disable`, `ios sslpinning disable`, `ios keychain dump`.
- `ios-deploy`, `iproxy`, `idevicepair` (libimobiledevice) - install and connect.
- `class-dump` - supplies the selector names your hooks need.
- `frida-ios-dump` - decrypted binary, which is what makes class-dump work.

## References

- Frida documentation: the Objective-C API (`ObjC.classes`, `ObjC.implement`, `ObjC.choose`).
- `objection` documentation for its iOS command set.
- Apple developer documentation on `NSURLSession` authentication challenges.
