---
title: "Android Deobfuscation - ProGuard, R8, String Encryption and Packers"
category: mobile
subcategory: obfuscation
type: technique
tags: [proguard, r8, dexguard, obfuscation, deobfuscation, mapping-txt, retrace, string-encryption, packer, dexclassloader, frida-dexdump, dynamic-dex, reflection, jadx, apktool, ollvm]
difficulty: hard
summary: "Recognise which obfuscator is in play, recover names from mapping.txt, decrypt string constants, and dump dynamically loaded DEX out of memory."
when_to_use:
  - "jadx shows a.a.a(b.c) and every string is a call to some decrypt(int)"
  - "classes.dex is tiny and the real code appears only at runtime"
  - "The app uses reflection for every interesting call"
tools: [jadx, apktool, frida, retrace, python]
related: [android-apk-triage, android-frida-basics, android-native-jni, android-static-secrets]
---

## TL;DR

Identify the layer first: **renaming** (harmless, work around it), **string encryption**
(reimplement or hook the decryptor), **reflection** (hook `Method.invoke`),
**packing/dynamic DEX** (dump from memory), **native obfuscation** (oracle it).
The universal answer to all of them is: run the app and let it deobfuscate itself.

## Recognise it

| Signal | Layer |
|---|---|
| Classes named `a`, `b`, `a.a.b`, fields `a`, methods `a(int)` | ProGuard/R8 renaming |
| Every string is `f.a(1234)` or `c("E...")` | string encryption |
| `Class.forName(x).getMethod(y).invoke(z)` everywhere | reflection hiding |
| `classes.dex` is a few hundred KB of a single `Application` subclass | packer |
| `attachBaseContext` doing file IO, `DexClassLoader`, `InMemoryDexClassLoader` | dynamic DEX |
| `assets/*.jar`, `*.dat`, `*.dex` with high entropy | packed payload |
| `libjiagu.so`, `libDexHelper.so`, `libshell*.so`, `libexec.so` | commercial packer |
| Deeply nested `switch` with a state variable in native code | OLLVM flattening |
| `mapping.txt` shipped by accident in the APK or in the repo | jackpot |

## Theory

### ProGuard / R8

R8 (the default since AGP 3.4) does shrinking, optimisation and renaming in one pass.
It emits `build/outputs/mapping/release/mapping.txt`:

```
com.ctf.app.LoginActivity -> a.b.c:
    java.lang.String token -> a
    boolean verify(java.lang.String) -> a
```

`retrace` maps a stack trace back. jadx can consume the same file
(`jadx --deobf --deobf-rewrite-cfg ... ` or the gui's "Load mapping").
Without `mapping.txt`, renaming is **not reversible** - but it is also not a real
obstacle: use jadx `--deobf`, which assigns stable synthetic names, and navigate by
string/API references instead of names.

Renaming never touches: framework class names, anything reachable by reflection that was
kept via `-keep`, `Serializable` field names, native method names (they must match the
`.so` export), and resource ids.

### String encryption

DexGuard and the home-made equivalents replace each constant with a call:

```java
String url = C.a(0x2f, 0x11);   // or: String url = C.decrypt("1B...");
```

The decryptor is always present in the APK (it has to be). Three ways to get plaintext:

1. **Reimplement** in Python - fastest for simple XOR/table schemes.
2. **Hook it** with Frida and log every `(input, output)` pair - works regardless of
   complexity.
3. **Call it** from Frida over the whole constant space
   (`for i in 0..N: log(C.a(i))`) - gives you the entire string table at once.

### Reflection

```java
Class<?> c = Class.forName(d(1));
Method m = c.getDeclaredMethod(d(2), String.class);
m.invoke(null, arg);
```

Hook `java.lang.reflect.Method.invoke` and `Class.forName` and print the resolved names;
the control flow becomes readable immediately.

### Packers and dynamic DEX

A packer ships a stub `classes.dex` whose `Application.attachBaseContext` decrypts the
real DEX from `assets/` and loads it with `DexClassLoader` or `InMemoryDexClassLoader`,
or hands the raw bytes to ART via `DefineClass`. Once loaded, the DEX is in the process's
memory with the `dex\n035\0` / `dex\n038\0` magic, so you can:

- hook `InMemoryDexClassLoader.$init` / `DexFile.loadDex` and dump the buffer, or
- scan the heap for the DEX magic and validate the header (`frida-dexdump` does this), or
- hook `libart`'s `DefineClass` / `OpenAndReadMagic`.

The DEX header gives you `file_size` at offset 0x20 and a checksum at 0x08, which lets you
carve exact-length blobs out of a memory dump.

## Attack

1. `jadx --deobf` and see whether the structure alone is enough.
2. Search for a `mapping.txt` in the APK, in `assets/`, in any shipped `.zip`, and in the
   CTF's public repo.
3. Identify the string decryptor: find a static method called from everywhere returning
   `String`.
4. Dump the whole string table by calling the decryptor from Frida.
5. Hook `Method.invoke`/`Class.forName` to resolve reflection.
6. If the code is not there at all, dump DEX from memory and re-run jadx on the dump.
7. For native obfuscation, do not deobfuscate - use the function as an oracle.

## Code

### Reimplementing a string decryptor

```python
#!/usr/bin/env python3
"""str_decrypt.py - reimplement the three string-obfuscation schemes you meet most.

1. positional XOR:      c[i] ^= (key + i)
2. AES-ECB with a key hidden in the class:  AES(key).decrypt(base64(ct))
3. table lookup:        out[i] = TABLE[(c[i] - base) % len(TABLE)]

Run with no arguments for a self-test, or:
  python3 str_decrypt.py xor 0x5a "<cipher>"
  python3 str_decrypt.py aes <hexkey> <base64ct>
"""
from __future__ import annotations

import base64
import sys


def xor_pos_decrypt(cipher: str, key: int) -> str:
    return "".join(chr(ord(c) ^ ((key + i) & 0xFF)) for i, c in enumerate(cipher))


def xor_pos_encrypt(plain: str, key: int) -> str:
    return xor_pos_decrypt(plain, key)


def xor_key_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def aes_ecb_decrypt(ct_b64: str, key_hex: str) -> bytes:
    """Requires pycryptodome. Mirrors Cipher.getInstance("AES/ECB/PKCS5Padding")."""
    from Crypto.Cipher import AES  # type: ignore

    pt = AES.new(bytes.fromhex(key_hex), AES.MODE_ECB).decrypt(base64.b64decode(ct_b64))
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    return pt


def table_decrypt(cipher: str, table: str, base: int = 0x20) -> str:
    return "".join(table[(ord(c) - base) % len(table)] for c in cipher)


def brute_single_xor(data: bytes, hint: bytes = b"http") -> list[tuple[int, bytes]]:
    out = []
    for k in range(256):
        cand = bytes(b ^ k for b in data)
        if hint in cand or all(9 <= b < 127 for b in cand):
            out.append((k, cand))
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    mode = argv[1]
    if mode == "xor" and len(argv) == 4:
        print(xor_pos_decrypt(argv[3], int(argv[2], 0)))
    elif mode == "aes" and len(argv) == 4:
        print(aes_ecb_decrypt(argv[3], argv[2]).decode("utf-8", "replace"))
    elif mode == "brute" and len(argv) == 3:
        for k, v in brute_single_xor(bytes.fromhex(argv[2])):
            print(f"0x{k:02x}: {v!r}")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        secret = "https://api.ctf.example/v1/flag"
        ct = xor_pos_encrypt(secret, 0x5A)
        assert xor_pos_decrypt(ct, 0x5A) == secret

        raw = b"flag{obfuscation_is_not_encryption}"
        xk = xor_key_decrypt(raw, b"KEY")
        assert xor_key_decrypt(xk, b"KEY") == raw

        hits = [v for k, v in brute_single_xor(bytes(b ^ 0x42 for b in b"http://x"), b"http")]
        assert b"http://x" in hits

        alphabet = "abcdefghijklmnopqrstuvwxyz"
        enc = "".join(chr(0x20 + alphabet.index(c)) for c in "flag")
        assert table_decrypt(enc, alphabet) == "flag"
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Frida: log every decrypt call and every reflective invoke

```js
// deobf-trace.js - log string-decryptor results, reflection targets and classloaders
// run: frida -U -f com.ctf.app -l deobf-trace.js --no-pause
'use strict';

Java.perform(function () {

  // 1. any static method returning String from an app class: log input -> output
  var TARGET = 'com.ctf.app.C';
  try {
    var C = Java.use(TARGET);
    Object.getOwnPropertyNames(C).forEach(function (name) {
      var m = C[name];
      if (!m || !m.overloads) { return; }
      m.overloads.forEach(function (ov) {
        if (ov.returnType && ov.returnType.className === 'java.lang.String') {
          ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var out = ov.apply(this, args);
            console.log('[str] ' + name + '(' + args.join(', ') + ') = ' + out);
            return out;
          };
        }
      });
    });
  } catch (e) { console.log('[-] ' + TARGET + ' not loaded yet'); }

  // 2. reflection
  var Method = Java.use('java.lang.reflect.Method');
  Method.invoke.implementation = function (recv, args) {
    var owner = this.getDeclaringClass().getName();
    console.log('[refl] ' + owner + '.' + this.getName() + '()');
    return this.invoke(recv, args);
  };

  var Class_ = Java.use('java.lang.Class');
  Class_.forName.overload('java.lang.String').implementation = function (n) {
    console.log('[refl] Class.forName("' + n + '")');
    return this.forName(n);
  };

  // 3. classloaders: catch dynamically loaded dex
  var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
  DexClassLoader.$init.implementation = function (dexPath, optDir, libPath, parent) {
    console.log('[dex] DexClassLoader(' + dexPath + ', ' + optDir + ')');
    return this.$init(dexPath, optDir, libPath, parent);
  };

  try {
    var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
    IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
      .implementation = function (buf, parent) {
        console.log('[dex] InMemoryDexClassLoader buffer of ' + buf.remaining() + ' bytes');
        dumpBuffer(buf);
        return this.$init(buf, parent);
      };
  } catch (e) { /* api < 26 */ }

  var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
  PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader')
    .implementation = function (p, parent) {
      console.log('[dex] PathClassLoader(' + p + ')');
      return this.$init(p, parent);
    };

  function dumpBuffer(buf) {
    var n = buf.remaining();
    var arr = Java.array('byte', new Array(n).fill(0));
    buf.mark();
    buf.get(arr);
    buf.reset();
    var b64 = Java.use('android.util.Base64').encodeToString(arr, 2);
    send({ kind: 'dex', size: n }, null);
    console.log('[dex] base64 (first 120 chars): ' + b64.substring(0, 120) + '...');
  }
});
```

### Dumping DEX from process memory

```js
// dex-dump.js - scan process memory for dex headers and write each one to /data/local/tmp
// run: frida -U -n com.ctf.app -l dex-dump.js
'use strict';

function u32(addr) { return addr.readU32(); }

function dumpDex() {
  var magics = ['64 65 78 0a 30 33 35 00',   // dex\n035\0
                '64 65 78 0a 30 33 37 00',
                '64 65 78 0a 30 33 38 00',
                '64 65 78 0a 30 33 39 00'];
  var ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true });
  var count = 0;

  ranges.forEach(function (range) {
    magics.forEach(function (magic) {
      var results;
      try {
        results = Memory.scanSync(range.base, range.size, magic);
      } catch (e) { return; }
      results.forEach(function (hit) {
        try {
          var size = u32(hit.address.add(0x20));       // header.file_size
          if (size < 0x70 || size > 64 * 1024 * 1024) { return; }
          if (hit.address.add(size).compare(range.base.add(range.size)) > 0) { return; }
          var bytes = hit.address.readByteArray(size);
          var path = '/data/local/tmp/dump_' + hit.address.toString(16) + '_' + size + '.dex';
          var f = new File(path, 'wb');
          f.write(bytes);
          f.flush();
          f.close();
          count++;
          console.log('[dex] ' + path + ' (' + size + ' bytes)');
        } catch (e) { /* unreadable page */ }
      });
    });
  });
  console.log('[dex] dumped ' + count + ' file(s); adb pull /data/local/tmp/');
}

setTimeout(dumpDex, 3000);   // give the packer time to load the real dex
```

```bash
# pull and re-analyse the dumped dex
adb pull /data/local/tmp/ ./dexdump/
for f in dexdump/*.dex; do jadx -d "out-$(basename "$f" .dex)" "$f"; done

# frida-dexdump does the same thing with better heuristics
frida-dexdump -U -f com.ctf.app -o ./dexout

# rebuild a browsable apk from a dumped dex so jadx-gui resolves resources
cp app.apk repacked.apk
zip -j repacked.apk dexdump/dump_xxx.dex   # rename it classes.dex first

# ---- mapping.txt, if it was shipped by accident ----
unzip -l app.apk | grep -i mapping
find . -name 'mapping*.txt'
retrace mapping.txt crash.txt              # restore a stack trace
grep -n 'LoginActivity' mapping.txt        # forward lookup
grep -n '\-> a\.b\.c:' mapping.txt         # reverse lookup
jadx -d out --deobf app.apk                # jadx-gui: File > Open mappings
```

## Variants & pitfalls

- **The decryptor is itself native**: `C.a(int)` is a `native` method. The Frida
  "call it in a loop" trick still works - you never need to read the native code.
- **Packer detects Frida before loading the real DEX** - combine with
  `android-root-detection-bypass` and spawn (`-f`).
- **Dumped DEX fails to open in jadx** - the packer may have wiped the header, nulled
  `string_ids`, or split the payload. Fix `file_size`/`header_size`/`checksum`
  (`baksmali` is more tolerant than jadx).
- **OLLVM-flattened native code**: do not deobfuscate. Hook the function boundary, or
  emulate it with Unicorn/Qiling and treat it as a black box.
- **Multi-classloader**: after the packer loads the real DEX, `Java.use` fails until you
  switch classloaders:
  `Java.enumerateClassLoaders({ onMatch: function (l) { Java.classFactory.loader = l; } , onComplete: function(){} })`.

## Tools

- `jadx` (`--deobf`, mapping import) and `jadx-gui` (rename + persist).
- `apktool` / `baksmali` - never fails, even when jadx does.
- `frida` + `frida-dexdump` - memory DEX recovery.
- `retrace` (ProGuard/R8 distribution) - stack-trace restoration.
- `unicorn` / `qiling` - emulating an obfuscated native routine.
- `strings` + `binwalk` - spotting the packed payload in `assets/`.

## References

- Android developer documentation on R8 shrinking, obfuscation and `mapping.txt`.
- ProGuard manual for `retrace` and keep rules.
- Dalvik executable (DEX) format specification for the header fields used when carving.
