---
title: "Java and Android Bytecode - jadx, smali and Patching a JAR"
category: rev
subcategory: java
type: technique
tags: [java, jvm, bytecode, jadx, procyon, cfr, fernflower, javap, krakatau, recaf, android, apk, smali, apktool, dex, dex2jar, frida, proguard, jdwp, jni]
difficulty: easy
summary: "JVM and Dalvik bytecode keep full names and types: decompile with jadx/CFR, patch in smali or with Krakatau, repack, re-sign, run."
when_to_use:
  - "The challenge is a .jar, .class, .apk or .dex file"
  - "jadx output has bad code / obfuscated names and you need the bytecode instead"
  - "You must change a check and re-run rather than recover an input"
  - "An Android app hides the check in a native .so or behind runtime string decryption"
tools: [jadx, cfr, procyon, javap, krakatau, recaf, apktool, dex2jar, frida, apksigner]
related: [dotnet-reversing, python-bytecode-pyinstaller, obfuscation-deobfuscation, crackme-patterns, triage-unknown-binary, dynamic-analysis-ltrace-ldpreload]
---

## TL;DR

Java compiles to a stack-machine bytecode that keeps class, method, field and type names, so
decompilers reconstruct readable source. Read it with `jadx`, cross-check confusing regions
with `javap -c`, patch either at the source level (recompile), the bytecode level
(Krakatau/Recaf), or - on Android - in smali, then repack and re-sign.

## Recognise it

```sh
file chall.jar          # -> Java archive data (JAR)
file Main.class         # -> compiled Java class data, version 55.0 (Java 11)
file classes.dex        # -> Dalvik dex file version 035
unzip -l chall.jar | head -30          # a JAR is a zip: look for META-INF/MANIFEST.MF
unzip -p chall.jar META-INF/MANIFEST.MF        # Main-Class tells you where to start
# class file version -> JDK:  52=8, 53=9, 55=11, 61=17, 65=21
xxd -l 8 Main.class    # cafebabe 0000 0037  -> minor 0, major 0x37 = 55 = Java 11
```

## Decompiling

```sh
# --- jadx: best all-rounder, handles JAR, class, APK and DEX ---------------
jadx -d out/ chall.jar
jadx --deobf -d out/ chall.apk          # rename obfuscated a/b/c identifiers consistently
jadx --show-bad-code -d out/ chall.jar  # emit even code jadx failed on (as comments/partial)
jadx-gui chall.apk                      # GUI: Ctrl+Shift+F full-text search, Ctrl+B bytecode

# --- CFR: often recovers what jadx cannot (lambdas, switch-on-string) ------
java -jar cfr.jar chall.jar --outputdir out_cfr

# --- Procyon and Fernflower: third and fourth opinions ---------------------
java -jar procyon-decompiler.jar -jar-file chall.jar -o out_procyon
java -jar fernflower.jar chall.jar out_ff/

# --- javap: the ground truth, from the JDK, no third-party tool -----------
unzip -o chall.jar -d unpacked/
javap -c -p -constants -l unpacked/com/example/Check.class
#   -c constants disassemble bytecode   -p include private members
#   -constants show static final values  -l line numbers and local variable tables
javap -v unpacked/com/example/Check.class | head -60     # full constant pool
```

Always run at least two decompilers before concluding "the code is broken" - each fails on
different constructs.

## Reading JVM bytecode

```
  public static boolean check(java.lang.String);
    Code:
       0: aload_0                          // push arg0 (the String) onto the stack
       1: invokevirtual #7                 // String.length()  -> pushes int
       4: bipush        16                 // push the byte constant 16
       6: if_icmpne     34                 // pop 2 ints; if != jump to 34 (return false)
       9: aload_0                          // push arg0 again
      10: invokevirtual #13                // String.getBytes() -> byte[]
      13: astore_1                         // store into local 1
      14: iconst_0                         // push 0
      15: istore_2                         // i = 0
      16: iload_2                          // push i
      17: aload_1                          // push the byte[]
      18: arraylength                      // -> length
      19: if_icmpge     32                 // loop exit
      22: aload_1 / iload_2 / baload        // b[i]
      ...
      32: iconst_1                         // push 1 (true)
      33: ireturn                          // return it
      34: iconst_0
      35: ireturn
```

The mental model: everything is a stack machine with typed prefixes -
`a` reference, `i` int, `l` long, `f` float, `d` double, `b` byte.
`aload_0` in an instance method is `this`; in a static method it is the first parameter.
`#7` is a constant-pool index - `javap -v` prints the pool so you can resolve it.
`invokevirtual`/`invokestatic`/`invokespecial` (constructors and super calls)/
`invokeinterface`/`invokedynamic` (lambdas and string concatenation since Java 9).

## Code - dump every string in a .class without any tooling

```python
#!/usr/bin/env python3
"""classstrings.py - parse a .class constant pool and print all CONSTANT_Utf8 entries.

Works on any class file version; pure stdlib. Useful when a decompiler chokes but you
just want the literals (flags, URLs, keys).

Usage: python3 classstrings.py Main.class [--all]
"""
import struct
import sys

# tag -> (size in bytes after the tag, description). -1 means variable (Utf8).
TAGS = {
    1: (-1, "Utf8"), 3: (4, "Integer"), 4: (4, "Float"), 5: (8, "Long"),
    6: (8, "Double"), 7: (2, "Class"), 8: (2, "String"), 9: (4, "Fieldref"),
    10: (4, "Methodref"), 11: (4, "InterfaceMethodref"), 12: (4, "NameAndType"),
    15: (3, "MethodHandle"), 16: (2, "MethodType"), 17: (4, "Dynamic"),
    18: (4, "InvokeDynamic"), 19: (2, "Module"), 20: (2, "Package"),
}

JDK = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7",
       52: "8", 53: "9", 54: "10", 55: "11", 56: "12", 57: "13", 58: "14",
       59: "15", 60: "16", 61: "17", 62: "18", 63: "19", 64: "20", 65: "21"}


def parse(path: str, show_all: bool) -> int:
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"\xca\xfe\xba\xbe":
        print("[-] not a .class file (bad magic)")
        return 1
    minor, major = struct.unpack_from(">HH", data, 4)
    count = struct.unpack_from(">H", data, 8)[0]
    print(f"[*] class version {major}.{minor} (JDK {JDK.get(major, '?')}), "
          f"{count - 1} constant pool entries")

    off = 10
    index = 1
    strings: list[tuple[int, str]] = []
    string_refs: set[int] = set()
    while index < count:
        tag = data[off]
        off += 1
        if tag == 1:
            length = struct.unpack_from(">H", data, off)[0]
            off += 2
            raw = data[off:off + length]
            off += length
            strings.append((index, raw.decode("utf-8", errors="replace")))
        elif tag == 8:                                  # CONSTANT_String -> Utf8 index
            string_refs.add(struct.unpack_from(">H", data, off)[0])
            off += 2
        else:
            size = TAGS.get(tag, (2, "?"))[0]
            off += size
        if tag in (5, 6):                               # long/double take two pool slots
            index += 2
        else:
            index += 1

    print("\n[*] string literals (CONSTANT_String targets):")
    for idx, text in strings:
        if idx in string_refs:
            print(f"  #{idx:<5} {text!r}")
    if show_all:
        print("\n[*] all Utf8 entries (names, descriptors, literals):")
        for idx, text in strings:
            print(f"  #{idx:<5} {text!r}")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: classstrings.py <Main.class> [--all]")
        return 1
    return parse(sys.argv[1], "--all" in sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
```

## Code - dump every string in classes.dex

```python
#!/usr/bin/env python3
"""dexstrings.py - list all strings in an Android classes.dex by parsing string_ids.

The DEX header gives string_ids_size/off; each entry is a u32 offset to a
string_data_item = ULEB128 length (in UTF-16 code units) + MUTF-8 bytes + NUL.

Usage: python3 dexstrings.py classes.dex [--min 4] [--grep flag]
"""
import struct
import sys


def uleb128(data: bytes, off: int) -> tuple[int, int]:
    """Decode a ULEB128 at `off`; return (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: dexstrings.py classes.dex [--min N] [--grep TEXT]")
        return 1
    path = sys.argv[1]
    minlen = int(sys.argv[sys.argv.index("--min") + 1]) if "--min" in sys.argv else 1
    needle = sys.argv[sys.argv.index("--grep") + 1] if "--grep" in sys.argv else None

    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"dex\n":
        print("[-] not a DEX file")
        return 1
    version = data[4:7].decode(errors="replace")
    # header: magic[8] checksum[4] sig[20] file_size[4] header_size[4] endian[4]
    # link_size[4] link_off[4] map_off[4] string_ids_size[4] string_ids_off[4] ...
    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 56)
    type_ids_size = struct.unpack_from("<I", data, 64)[0]
    method_ids_size = struct.unpack_from("<I", data, 88)[0]
    print(f"[*] DEX v{version}: {string_ids_size} strings, {type_ids_size} types, "
          f"{method_ids_size} methods")

    shown = 0
    for i in range(string_ids_size):
        (data_off,) = struct.unpack_from("<I", data, string_ids_off + i * 4)
        length, p = uleb128(data, data_off)
        end = data.index(b"\x00", p)
        text = data[p:end].decode("utf-8", errors="replace")
        if len(text) < minlen:
            continue
        if needle and needle.lower() not in text.lower():
            continue
        print(f"  [{i:>6}] ({length:>3}) {text!r}")
        shown += 1
    print(f"\n[+] {shown} string(s) shown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Patching a JAR

```sh
# 1. Unpack (a JAR is a zip; `jar xf` and `unzip` are equivalent)
mkdir work && cd work && unzip -o ../chall.jar

# 2a. Source-level: fix the .java, recompile just that class against the rest of the jar
javac -cp ../chall.jar -d . com/example/Check.java

# 2b. Bytecode-level with Krakatau (no recompilation, exact control)
python3 krakatau/disassemble.py -out asm/ com/example/Check.class
#   edit asm/com/example/Check.j:  change `ifne LABEL` to `ifeq LABEL`,
#   or replace a method body with:  iconst_1 / ireturn
python3 krakatau/assemble.py -out . asm/com/example/Check.j

# 3. Remove the signature, or the JVM rejects the modified jar
rm -f META-INF/*.SF META-INF/*.RSA META-INF/*.DSA META-INF/*.EC

# 4. Repack, keeping the manifest
jar cfm ../patched.jar META-INF/MANIFEST.MF .
#   or: zip -r ../patched.jar . -x '.*'

# 5. Run
java -jar ../patched.jar
# If the Main-Class is missing from the manifest, invoke the class directly:
java -cp ../patched.jar com.example.Main
```

**Recaf** does all of the above in a GUI: open the JAR, edit either the decompiled source
(it recompiles in place) or the bytecode instruction list, then `File > Export`. It is the
fastest path for a one-line change.

## Debugging a JVM program

```sh
# Start the target suspended, listening for a debugger on 5005
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:5005 -jar chall.jar

# Attach the JDK's command-line debugger
jdb -attach localhost:5005
# > stop in com.example.Check.check          set a method breakpoint
# > stop at com.example.Check:42             set a line breakpoint
# > run
# > locals                                   print local variables
# > print input                              evaluate an expression
# > dump this                                dump all fields
# > step / next / cont
# > eval new String(bytes)                   call methods live

# Or attach IntelliJ IDEA / Eclipse ("Remote JVM Debug", port 5005) and use the sources
# jadx produced - breakpoints work even on decompiled code if line numbers survived.
```

## Deobfuscation

| Obfuscator | Symptom | Approach |
|---|---|---|
| ProGuard / R8 | classes named `a`, `b`, `c$a`; no strings changed | `retrace mapping.txt stacktrace.txt` if you have the mapping; otherwise `jadx --deobf` |
| Allatori | string encryption + flow obfuscation | `java-deobfuscator` with the Allatori transformer |
| Zelix KlassMaster | flow obfuscation + string encryption | `java-deobfuscator`; or call the decryptor reflectively |
| Stringer | encrypted strings, anti-debug | run and dump |
| DashO | renaming + control flow | `java-deobfuscator` |
| Generic packers | a tiny loader class + an encrypted resource | dump the ClassLoader input at runtime |

The universal string-decryption trick - call the obfuscator's own decryptor:

```java
// Decrypt.java
//   javac -cp chall.jar Decrypt.java && java -cp .:chall.jar Decrypt
import java.lang.reflect.Method;

public class Decrypt {
    public static void main(String[] args) throws Exception {
        Class<?> c = Class.forName("com.example.a");   // the obfuscated helper class
        for (Method m : c.getDeclaredMethods()) {
            Class<?>[] p = m.getParameterTypes();
            if (m.getReturnType() == String.class && p.length == 1 && p[0] == String.class) {
                m.setAccessible(true);                  // it is private: force access
                System.out.println("[+] trying " + m);
                // feed it every encrypted literal you scraped out of the class file
                for (String enc : new String[] { "E3", "" }) {
                    try {
                        System.out.println("  " + enc.hashCode() + " -> " + m.invoke(null, enc));
                    } catch (Throwable t) { /* wrong method */ }
                }
            }
        }
    }
}
```

Run it in a VM - you are executing the challenge's code.

## Android

```sh
# --- Structure -------------------------------------------------------------
unzip -l app.apk
#   AndroidManifest.xml (binary XML), classes.dex (+classes2.dex... multidex),
#   resources.arsc, res/, lib/<abi>/*.so, assets/, META-INF/ (signature)

# --- Decompile straight to Java -------------------------------------------
jadx -d out/ app.apk
# Start at the manifest's launcher activity:
jadx -d out/ app.apk && grep -A3 'android.intent.action.MAIN' out/resources/AndroidManifest.xml

# --- Or go through a jar --------------------------------------------------
d2j-dex2jar.sh app.apk -o app.jar     # then any Java decompiler

# --- apktool: decode resources + smali, the only route for repacking -------
apktool d app.apk -o work/            # work/smali/, work/AndroidManifest.xml (readable XML)
#   ... edit work/smali/com/example/MainActivity.smali ...
apktool b work/ -o patched.apk
zipalign -p -f 4 patched.apk aligned.apk
keytool -genkey -v -keystore debug.ks -alias a -keyalg RSA -keysize 2048 -validity 10000 \
        -storepass password -keypass password -dname "CN=a"
apksigner sign --ks debug.ks --ks-pass pass:password --out signed.apk aligned.apk
apksigner verify -v signed.apk
adb install -r signed.apk
```

### Smali patches that always work

```smali
# Original: bail out when the check returns false
    invoke-static {v1}, Lcom/example/Check;->verify(Ljava/lang/String;)Z
    move-result v0
    if-eqz v0, :cond_fail          # branch if v0 == 0

# Patch A - invert the branch (one word, same size)
    if-nez v0, :cond_fail

# Patch B - stub the whole method to return true.
# Replace the body of verify() with:
.method public static verify(Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
# NOTE: .locals must be >= the registers you use. `const/4` only holds -8..7;
# use `const/16 v0, 0x100` or `const v0, 0x12345678` for bigger values.

# Patch C - log a value instead of guessing (add before the check)
    invoke-static {v1}, Lcom/example/Check;->verify(Ljava/lang/String;)Z
    const-string v2, "CTF"
    invoke-static {v2, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
```

Then `adb logcat -s CTF:D`.

### Native code (JNI)

```sh
# The check often lives in a .so, called via `static { System.loadLibrary("native-lib"); }`
unzip -o app.apk 'lib/*' -d libs/
file libs/lib/arm64-v8a/libnative-lib.so
# Statically registered JNI functions are named by convention - just look at the exports
nm -D --defined-only libs/lib/arm64-v8a/libnative-lib.so | grep Java_
#   Java_com_example_MainActivity_check  <- com.example.MainActivity.check()
# Dynamically registered ones are NOT named: look for JNI_OnLoad and the
# RegisterNatives(env, clazz, JNINativeMethod*, count) call. The JNINativeMethod array is
# { const char *name; const char *signature; void *fnPtr; } - three pointers per entry,
# so read the array in your disassembler to map names to addresses.
objdump -d libs/lib/arm64-v8a/libnative-lib.so | grep -A20 'JNI_OnLoad'
```

Load the `.so` in Ghidra like any AArch64 ELF. Method signatures follow JNI type descriptors:
`(Ljava/lang/String;)Z` = takes a String, returns boolean; the native function's first two
parameters are always `JNIEnv *env, jobject thiz`.

### Frida hooks

```javascript
// hook.js -  frida -U -f com.example.app -l hook.js
Java.perform(function () {
    var Check = Java.use('com.example.Check');

    // Overload selection is required when the method is overloaded
    Check.verify.overload('java.lang.String').implementation = function (input) {
        console.log('[+] verify("' + input + '")');
        var result = this.verify(input);          // call the original
        console.log('    original returned ' + result);
        return true;                              // ... and lie
    };

    // Dump every String the app compares
    var String = Java.use('java.lang.String');
    String.equals.overload('java.lang.Object').implementation = function (other) {
        console.log('[cmp] "' + this + '" == "' + other + '"');
        return this.equals(other);
    };

    // Native function hooking (statically registered JNI)
    var addr = Module.getExportByName('libnative-lib.so',
                                      'Java_com_example_MainActivity_check');
    Interceptor.attach(addr, {
        onEnter: function (args) { console.log('[native] called'); },
        onLeave: function (retval) { console.log('  -> ' + retval); retval.replace(1); }
    });
});
```

## Variants & pitfalls

- **`jar cfm` without the original manifest** loses `Main-Class`; keep
  `META-INF/MANIFEST.MF` and pass it explicitly.
- **Signature files left in place** cause `SecurityException: Invalid signature file digest`.
  Delete `META-INF/*.SF|*.RSA|*.DSA|*.EC`.
- **Android refuses unaligned or unsigned APKs**: always `zipalign` *before* `apksigner`.
- **`.locals` in smali must cover every register you use**, and `const/4` is a 4-bit literal.
  Getting either wrong yields a `VerifyError` at class load.
- **Multidex**: the class you want may be in `classes2.dex`/`classes3.dex`. jadx merges them;
  apktool keeps them as `smali_classes2/`.
- **String concatenation since Java 9** compiles to `invokedynamic makeConcatWithConstants` -
  decompilers handle it, `javap` output looks alien.
- **Lambdas** are `invokedynamic` + a synthetic `lambda$main$0` method; the real body is in
  that synthetic method, not at the call site.
- **The flag may be in resources**: `res/values/strings.xml`, `assets/`, or `resources.arsc`.
  `apktool d` decodes all of them; check before reversing any code.
- **Root/emulator/debug detection** in Android apps: patch the smali check or hook it with
  Frida rather than fighting it.
- **Runtime DEX loading** (`DexClassLoader`, `InMemoryDexClassLoader`) means the real code is
  not in `classes.dex`. Hook the loader with Frida and dump the buffer it receives.

## Tools

- `jadx` / `jadx-gui` - the default; handles APK, DEX, JAR, class.
- `cfr`, `procyon`, `fernflower` - alternative decompilers for stubborn methods.
- `javap` - JDK-native disassembly and full constant-pool dumps.
- `Krakatau` - the only round-trip JVM assembler/disassembler worth using.
- `Recaf` - GUI bytecode editor with live recompilation.
- `apktool`, `dex2jar`, `zipalign`, `apksigner`, `keytool` - the Android repack chain.
- `java-deobfuscator` - transformer-based removal of commercial obfuscation.
- `frida` / `objection` - runtime hooking on a device or emulator.

## References

- The Java Virtual Machine Specification, chapter 4 (class file format, constant pool tags
  used by the script above) and chapter 6 (instruction set).
- Android source documentation: "Dalvik Executable format" (DEX header and string_ids
  layout) and "Dalvik bytecode".
- JDWP documentation for the `-agentlib:jdwp` transport options.
