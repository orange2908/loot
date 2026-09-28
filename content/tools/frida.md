---
title: "Tool - Frida"
category: mobile
subcategory: instrumentation
type: tool
tags: [frida, dynamic-instrumentation, hooking, android, ios, interceptor, javascript, ssl-pinning, frida-trace, objection, runtime, rev, mobile, native-hook]
summary: "Inject JavaScript into a running process to hook functions, read arguments, change return values and dump memory, on desktop or mobile."
related: [jadx, rev-triage, gdb-pwndbg-gef, burpsuite]
---

## What it is

Frida injects a JavaScript engine into a live process and lets you hook any function - native or, on Android, Java/Kotlin - to log arguments, rewrite return values, dump memory, or call functions yourself. It is the fastest way to answer "what value is actually being compared here?" without static reversing, and the standard tool for bypassing SSL pinning and root detection in mobile challenges.

## Install

```sh
pipx install frida-tools           # CLI: frida, frida-ps, frida-trace, frida-discover
python3 -m pip install frida       # the Python bindings, if you script it
# Android: push the matching frida-server for your device architecture
#   (download the frida-server release matching `frida --version` exactly)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
# verify
frida --version
frida-ps -U                        # processes on the USB device
```
Rooted device or an emulator is normally required for Android; alternatively repackage the APK with the Frida gadget.

## The invocations that matter

```sh
# 1. list processes
frida-ps                       # local
frida-ps -U                    # USB device
frida-ps -Ua                   # only apps, with identifiers

# 2. attach to a running process with a script
frida -U -n com.example.app -l hook.js

# 3. spawn and hold the app so you hook before any init code runs
frida -U -f com.example.app -l hook.js --no-pause

# 4. attach to a local binary
frida ./chal -l hook.js
frida -p 1234 -l hook.js

# 5. auto-generate hooks for everything matching a pattern (great for recon)
frida-trace -U -f com.example.app -i "*crypt*"
frida-trace -U -n com.example.app -j "com.example.*!*"       # Java methods
frida-trace ./chal -i "strcmp" -i "memcmp" -i "open"

# 6. find candidate functions to hook
frida-discover -f ./chal

# 7. run a one-liner without a script file
frida -U -n app -e 'Java.perform(() => { console.log(Java.enumerateLoadedClassesSync().length) })'

# 8. objection (built on Frida) for common mobile tasks
pipx install objection
objection -g com.example.app explore
#   then: android sslpinning disable
#         android root disable
#         android hooking list classes
#         android hooking watch class_method com.example.Check.verify --dump-args --dump-return
#         memory dump all /tmp/dump

# 9. drive Frida from Python
python3 - <<'PY'
import frida, sys
session = frida.get_usb_device().attach("com.example.app")
script = session.create_script(open("hook.js").read())
script.on("message", lambda m, d: print(m))
script.load()
sys.stdin.read()
PY

# 10. inject into an already-spawned local process by name
frida -n chal -l hook.js
```

The hook patterns you will reuse:

```javascript
// hook.js

// --- native: log arguments and change the return value ---
Interceptor.attach(Module.getExportByName(null, "strcmp"), {
    onEnter(args) {
        this.a = args[0].readUtf8String();
        this.b = args[1].readUtf8String();
        console.log("strcmp(" + this.a + ", " + this.b + ")");
    },
    onLeave(retval) {
        if (this.a && this.a.indexOf("flag") !== -1) retval.replace(0);
    }
});

// --- native: hook by module + offset (for stripped binaries) ---
const base = Module.findBaseAddress("libnative.so");
Interceptor.attach(base.add(0x1234), {
    onEnter(args) { console.log("hit, arg0 =", args[0]); }
});

// --- native: replace a function entirely ---
Interceptor.replace(Module.getExportByName(null, "check"),
    new NativeCallback(() => 1, "int", []));

// --- call a native function yourself ---
const f = new NativeFunction(Module.getExportByName(null, "decrypt"),
                             "pointer", ["pointer", "int"]);
console.log(f(Memory.allocUtf8String("abc"), 3).readUtf8String());

// --- Android Java: hook a method ---
Java.perform(function () {
    const C = Java.use("com.example.Checker");
    C.verify.implementation = function (input) {
        console.log("verify(" + input + ")");
        const r = this.verify(input);
        console.log("  -> " + r);
        return true;                       // force success
    };
});

// --- Android: enumerate loaded classes and find the interesting one ---
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch(name) { if (name.toLowerCase().includes("flag")) console.log(name); },
        onComplete() {}
    });
});

// --- Android: find live instances of a class and read their fields ---
Java.perform(function () {
    Java.choose("com.example.Session", {
        onMatch(inst) { console.log(inst.token.value); },
        onComplete() {}
    });
});

// --- dump memory ---
console.log(hexdump(ptr("0x7fff0000"), { length: 128, ansi: true }));

// --- scan memory for a pattern ---
Memory.scan(Module.findBaseAddress("libc.so"), 0x100000, "66 6c 61 67 7b", {
    onMatch(addr) { console.log("flag at", addr, addr.readUtf8String()); },
    onComplete() {}
});
```

## Gotchas

- **The `frida-server` version on the device must match your `frida` client version exactly.** A mismatch fails with confusing errors.
- Use `-f <package>` (spawn) rather than `-n` (attach) when the interesting code runs at startup; attaching is always too late for init-time checks.
- `Java.perform()` is mandatory around any Java API use; outside it, `Java.use` throws.
- Overloaded Java methods need `.overload("java.lang.String")` to disambiguate; Frida's error message lists the available overloads.
- Native hooks on ARM need the correct Thumb/ARM mode; if a hook crashes the app, the address is likely off by one bit.
- Many apps detect Frida (checking for `frida-server`, the default port 27042, `/proc/self/maps` entries). Countermeasures: rename the server binary, use a non-default port (`frida-server -l 0.0.0.0:1337`), or use an anti-anti-Frida script.
- Hooking `open`/`read` on a busy process produces a firehose. Filter inside `onEnter` before logging.
- `retval.replace()` only works inside `onLeave`, and must match the return type width.
- On iOS you need a jailbroken device or a re-signed app with the Frida gadget embedded.
- Frida changes program timing; race-sensitive code may behave differently under instrumentation.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Static analysis is enough | `jadx` for Android, Ghidra for native (`ctfbrain search jadx ghidra`) |
| Linux process tracing only | `ltrace`, `strace`, `gdb` with breakpoints and commands |
| You cannot root the device | repackage the APK with the Frida gadget, or use an emulator |
| Just want to see HTTP traffic | mitmproxy/Burp with a user CA + `network_security_config` patch |
| SSL pinning bypass specifically | `objection`, or patch the pinning code in smali and rebuild |
| Windows userland hooking | `x64dbg` scripting, Detours, or `frida` (it works on Windows too) |
| Kernel-level behaviour | `eBPF`/`bpftrace` on Linux |
