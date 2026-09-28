---
title: "Android Native Libraries - JNI, RegisterNatives and Reversing the .so"
category: mobile
subcategory: android-native
type: technique
tags: [jni, ndk, android, native, so, shared-library, loadlibrary, jni-onload, registernatives, ghidra, radare2, frida, interceptor, arm64, elf, dynamic-registration, name-mangling]
difficulty: hard
summary: "Find the native function behind a Java `native` method - static name mangling or dynamic RegisterNatives - then reverse or hook it."
when_to_use:
  - "jadx shows `public native String check(String)` and no Java logic"
  - "The APK ships lib/arm64-v8a/*.so and the flag check lives there"
  - "Strings are decrypted in native code"
tools: [ghidra, radare2, frida, readelf, nm, objdump, jnitrace]
related: [android-apk-triage, android-frida-basics, android-deobfuscation, android-smali-patching]
---

## TL;DR

A Java `native` method resolves to a C function in a `.so` two ways: **static** (the
exported symbol `Java_pkg_Class_method`) or **dynamic** (`JNI_OnLoad` calls
`RegisterNatives` with a table of `{name, signature, fnPtr}`). If `nm -D` shows no
`Java_*` export, it is dynamic - read the `RegisterNatives` table, or let Frida tell you.
Every JNI function's first two args are `JNIEnv *env` and `jobject thiz` (or `jclass`).

## Recognise it

- jadx: `static { System.loadLibrary("native-lib"); }` and `public native ... foo(...)`.
- `lib/arm64-v8a/libnative-lib.so`, `lib/armeabi-v7a/...`, sometimes `x86_64` for emulators.
- `readelf -d` on the `.so` shows `NEEDED liblog.so`, `libc.so`.
- `nm -D --defined-only lib.so | grep Java_` is empty but `JNI_OnLoad` exists -> dynamic registration.
- Strings in the `.so` include the Java class path (`com/ctf/app/Checker`) - those feed
  `FindClass`/`RegisterNatives`.

## Theory

### Static registration

JVM resolves `pkg.Class.method` to the export:

```
Java_ + package_with_underscores + _ + ClassName + _ + methodName
```

Escaping rules in the mangled name:

| Java char | Mangled |
|---|---|
| `.` or `/` | `_` |
| `_` | `_1` |
| `;` | `_2` |
| `[` | `_3` |
| unicode | `_0XXXX` |

Overloaded methods append `__` + the mangled argument signature, e.g.
`Java_com_ctf_A_check__Ljava_lang_String_2` for `check(String)`.

So `com.ctf.app.Checker.verify` -> `Java_com_ctf_app_Checker_verify`.

### C signature

```c
jstring Java_com_ctf_app_Checker_verify(JNIEnv *env, jobject thiz, jstring input);
//                                       ^arg0       ^arg1         ^arg2 = first real arg
```

For a `static` Java method, arg1 is a `jclass` instead of `jobject`. In a decompiler
this means **your first interesting argument is `param_3` on arm64** (x0=env, x1=thiz, x2=arg).

`JNIEnv` is a pointer to a table of ~230 function pointers. In Ghidra, calls look like
`(**(code **)(*param_1 + 0x548))(...)`. The offset identifies the call:
`GetStringUTFChars` is index 169 (`0x2A4` on 32-bit, `0x548` on 64-bit),
`NewStringUTF` is index 167 (`0x538` on 64-bit), `FindClass` index 6,
`RegisterNatives` index 215 (`0x6B8` on 64-bit). Apply the `jni.h` header in Ghidra
(`File > Parse C Source`) and retype `param_1` to `JNIEnv *` - the decompilation becomes readable.

### Dynamic registration

```c
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env; (*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6);
    jclass c = (*env)->FindClass(env, "com/ctf/app/Checker");
    static const JNINativeMethod m[] = {
        { "verify", "(Ljava/lang/String;)Z", (void *)real_verify },
    };
    (*env)->RegisterNatives(env, c, m, 1);
    return JNI_VERSION_1_6;
}
```

The table is three pointers per entry in `.data.rel.ro`: name string, signature string,
function pointer. Find the two adjacent string pointers in a data blob and the third
pointer is your target function. Frida does this for you (script below).

## Attack

1. Pick the ABI you will actually run: arm64-v8a on a real device, x86_64 on an emulator.
2. `readelf -h` / `file` to confirm arch; `nm -D` for exports.
3. If `Java_*` exists -> open it directly in Ghidra.
4. Else find `JNI_OnLoad`, follow `RegisterNatives`, or run the Frida resolver.
5. Retype args (`JNIEnv *`, `jobject`, `jstring`) and parse `jni.h` for readable decompilation.
6. Cross-check with runtime: hook the function, log args and return.
7. If the algorithm is opaque, do not reverse it - call it. `Java.use(...).verify(x)`
   from Frida turns the app into your oracle.

## Code

### Frida: resolve dynamically registered natives

```js
// dump-registernatives.js - print every {class, method, signature, address} passed to RegisterNatives
// run: frida -U -f com.ctf.app -l dump-registernatives.js --no-pause
'use strict';

function readCString(ptr_) {
  try { return ptr_.isNull() ? '<null>' : ptr_.readUtf8String(); } catch (e) { return '<bad>'; }
}

function hookRegisterNatives() {
  // libart exports the JNI bridge symbol for RegisterNatives
  var symbols = Module.enumerateSymbols('libart.so');
  var target = null;
  for (var i = 0; i < symbols.length; i++) {
    var n = symbols[i].name;
    if (n.indexOf('RegisterNatives') !== -1 && n.indexOf('CheckJNI') === -1) {
      target = symbols[i];
      break;
    }
  }
  if (target === null) {
    console.log('[-] RegisterNatives symbol not found in libart.so');
    return;
  }
  console.log('[+] hooking ' + target.name + ' @ ' + target.address);

  Interceptor.attach(target.address, {
    onEnter: function (args) {
      // (JNIEnv* env, jclass clazz, const JNINativeMethod* methods, jint nMethods)
      var methods = args[2];
      var count = args[3].toInt32();
      var ptrSize = Process.pointerSize;
      for (var i = 0; i < count; i++) {
        var entry = methods.add(i * ptrSize * 3);
        var name = readCString(entry.readPointer());
        var sig = readCString(entry.add(ptrSize).readPointer());
        var fn = entry.add(ptrSize * 2).readPointer();
        var mod = Process.findModuleByAddress(fn);
        var where = mod ? (mod.name + '!0x' + fn.sub(mod.base).toString(16)) : fn.toString();
        console.log('[native] ' + name + ' ' + sig + '  ->  ' + where);
      }
    }
  });
}

// RegisterNatives usually fires during System.loadLibrary, so hook before the app runs
hookRegisterNatives();
```

### Frida: hook a native export and log its arguments

```js
// hook-native-export.js - log args/return of a statically registered JNI function
// run: frida -U -n com.ctf.app -l hook-native-export.js
'use strict';

var LIB = 'libnative-lib.so';
var SYM = 'Java_com_ctf_app_Checker_verify';

function jstringToJs(env, jstr) {
  // GetStringUTFChars is index 169 in the JNIEnv function table
  var idx = 169;
  var fnTable = env.readPointer();
  var getUtf = fnTable.add(idx * Process.pointerSize).readPointer();
  var f = new NativeFunction(getUtf, 'pointer', ['pointer', 'pointer', 'pointer']);
  var chars = f(env, jstr, NULL);
  return chars.isNull() ? '<null>' : chars.readUtf8String();
}

function attach() {
  var addr = Module.findExportByName(LIB, SYM);
  if (addr === null) {
    console.log('[-] export not found: ' + SYM);
    return;
  }
  console.log('[+] ' + SYM + ' @ ' + addr);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.env = args[0];
      console.log('[>] verify("' + jstringToJs(args[0], args[2]) + '")');
    },
    onLeave: function (retval) {
      console.log('[<] ret = ' + retval);
      // uncomment to force success:
      // retval.replace(ptr(1));
    }
  });
}

// wait for the library to be loaded, then attach
var mod = Process.findModuleByName(LIB);
if (mod !== null) {
  attach();
} else {
  var dlopen = Module.findExportByName(null, 'android_dlopen_ext') ||
               Module.findExportByName(null, 'dlopen');
  Interceptor.attach(dlopen, {
    onEnter: function (args) { this.path = args[0].readCString(); },
    onLeave: function () {
      if (this.path && this.path.indexOf(LIB) !== -1) { attach(); }
    }
  });
}
```

### Calling the native check as an oracle

```js
// native-oracle.js - brute force a flag char-by-char by calling the app's own checker
// run: frida -U -n com.ctf.app -l native-oracle.js
'use strict';

Java.perform(function () {
  var Checker = Java.use('com.ctf.app.Checker');
  var inst = Checker.$new();
  var alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789_{}';
  var known = 'flag{';

  for (var pos = 0; pos < 40; pos++) {
    var progressed = false;
    for (var i = 0; i < alphabet.length; i++) {
      var candidate = known + alphabet[i];
      if (inst.verify(candidate)) {       // assumes a prefix-checking oracle
        known = candidate;
        console.log('[+] ' + known);
        progressed = true;
        break;
      }
    }
    if (!progressed) { break; }
  }
  console.log('[done] ' + known);
});
```

### Static inspection helper

```python
#!/usr/bin/env python3
"""jni_mangle.py - map Java native methods to their expected C export names, and
check which of them actually exist in a .so (via `nm -D`).

Usage:
  python3 jni_mangle.py com.ctf.app.Checker verify decrypt
  python3 jni_mangle.py com.ctf.app.Checker verify --so lib/arm64-v8a/libnative-lib.so
"""
from __future__ import annotations

import subprocess
import sys


def mangle(name: str) -> str:
    out = []
    for ch in name:
        if ch in "./":
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ch.isalnum():
            out.append(ch)
        else:
            out.append("_0%04x" % ord(ch))
    return "".join(out)


def export_name(class_fqn: str, method: str, arg_sig: str | None = None) -> str:
    base = "Java_" + mangle(class_fqn) + "_" + mangle(method)
    if arg_sig:
        base += "__" + mangle(arg_sig)
    return base


def so_exports(path: str) -> set[str]:
    try:
        res = subprocess.run(["nm", "-D", "--defined-only", path],
                             capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return set()
    names = set()
    for line in res.stdout.splitlines():
        parts = line.split()
        if parts:
            names.add(parts[-1])
    return names


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    so = None
    args = argv[1:]
    if "--so" in args:
        k = args.index("--so")
        so = args[k + 1]
        args = args[:k] + args[k + 2:]
    cls, methods = args[0], args[1:]
    exports = so_exports(so) if so else set()
    for m in methods:
        sym = export_name(cls, m)
        if so:
            status = "FOUND" if sym in exports else "missing (dynamic RegisterNatives?)"
            print(f"{sym}  [{status}]")
        else:
            print(sym)
    if so and not any(e.startswith("Java_") for e in exports):
        print("\n[!] no Java_* exports at all -> the library registers natives in JNI_OnLoad")
        print("    use the Frida RegisterNatives dumper")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        assert mangle("com.ctf.app.Checker") == "com_ctf_app_Checker"
        assert mangle("my_method") == "my_1method"
        assert export_name("com.ctf.app.Checker", "verify") == "Java_com_ctf_app_Checker_verify"
        assert export_name("a.B", "f", "Ljava/lang/String;") == "Java_a_B_f__Ljava_lang_String_2"
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Shell recon on the .so

```bash
# which architectures ship
file out-zip/lib/*/*.so

# exported JNI entry points (empty => dynamic registration)
nm -D --defined-only out-zip/lib/arm64-v8a/libnative-lib.so | grep -E ' T .*(Java_|JNI_OnLoad)'

# imports: tells you if it uses crypto, dlopen, ptrace (anti-debug), or /proc
readelf -d out-zip/lib/arm64-v8a/libnative-lib.so | head -30
nm -D --undefined-only out-zip/lib/arm64-v8a/libnative-lib.so | grep -iE 'ptrace|fork|dlopen|AES|SHA|MD5'

# strings that look like class paths feeding FindClass
strings -n 6 out-zip/lib/arm64-v8a/libnative-lib.so | grep -E '^[a-z]+(/[A-Za-z0-9_$]+)+$'

# JNI signatures present in the binary reveal the method table
strings -n 3 out-zip/lib/arm64-v8a/libnative-lib.so | grep -E '^\(.*\)[VZBSCIJFDL\[]'

# headless Ghidra analysis
analyzeHeadless /tmp/proj ctf -import out-zip/lib/arm64-v8a/libnative-lib.so -analysisTimeoutPerFile 600

# jnitrace: log every JNIEnv call the library makes (needs frida)
jnitrace -l libnative-lib.so -m spawn com.ctf.app
```

## Variants & pitfalls

- **Wrong ABI**: you reversed `armeabi-v7a` but the device runs `arm64-v8a` - offsets will
  not match your Frida hooks. Check `adb shell getprop ro.product.cpu.abi`.
- **`param_1` is `JNIEnv *`, not data.** Beginners spend an hour reversing the JNI vtable.
  Parse `jni.h` in Ghidra first.
- **Function pointer offsets differ 32 vs 64 bit** - index * 4 vs index * 8.
- **Stripped libraries**: no symbol names, only `JNI_OnLoad` (it must be exported).
  Start there.
- **`.init_array` constructors** run before `JNI_OnLoad` and often contain anti-debug or
  string decryption. Check `readelf -x .init_array`.
- **ptrace-based anti-debug**: the lib calls `ptrace(PTRACE_TRACEME)` in a constructor so a
  debugger cannot attach. Hook `ptrace` and return 0.
- **OLLVM obfuscation** (control-flow flattening, bogus control flow) - do not fight it
  statically; use the oracle approach or emulate with Unicorn/Qiling.
- **The check may be split**: Java does part, native does part. Log both boundaries.
- Frida `Module.findExportByName` returns `null` until the library is loaded; hook `dlopen`.

## Tools

- `ghidra` - best free Mach-O/ELF decompiler; parse `jni.h` for typed JNI calls.
- `radare2` / `rizin` + `cutter` - quick triage, `iE` for exports.
- `frida` - `Interceptor.attach`, `NativeFunction`, RegisterNatives dumping.
- `jnitrace` - automatic JNI API call tracing.
- `readelf` / `nm` / `objdump` - static ELF facts.
- `unicorn` / `qiling` - emulate a single function when hooking is blocked.

## References

- Oracle JNI specification: name mangling rules and the JNIEnv function table.
- Android NDK documentation on JNI tips and `JNI_OnLoad`.
- Ghidra documentation on parsing C headers to apply function prototypes.
