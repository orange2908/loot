---
title: "Tool - jadx"
category: mobile
subcategory: android
type: tool
tags: [jadx, android, apk, dex, decompiler, smali, androidmanifest, jadx-gui, apktool, mobile, java, kotlin, reverse-engineering, resources]
summary: "Decompile an APK or DEX straight to readable Java; the first and usually only tool you need on an Android challenge."
related: [frida, rev-triage, source-code-given, unknown-file]
---

## What it is

`jadx` converts Android DEX bytecode back into Java source. It handles APKs, AABs, DEX, JAR and class files, extracts and decodes the resources and `AndroidManifest.xml`, and its GUI has search, cross-references and a built-in deobfuscator. On an Android CTF challenge, `jadx -d out/ app.apk` is step one.

## Install

```sh
# macOS
brew install jadx
# Debian/Kali
sudo apt install jadx
# Otherwise: download the release zip from the jadx GitHub releases page and unzip;
# the launchers are in bin/ (requires a JRE 11+).
# verify
jadx --version
```

## The invocations that matter

```sh
APK=app.apk

# 1. decompile everything to a source tree
jadx -d out/ "$APK"

# 2. the GUI - search, xrefs, and jumping between Java and smali
jadx-gui "$APK"

# 3. keep going when some classes fail (very common on obfuscated apps)
jadx -d out/ --show-bad-code "$APK"

# 4. deobfuscate short/meaningless names
jadx -d out/ --deobf --deobf-min 3 --deobf-max 64 "$APK"

# 5. resources only (manifest, strings.xml, assets) - fast
jadx -d res_out/ --no-src "$APK"

# 6. source only, skip resources
jadx -d src_out/ --no-res "$APK"

# 7. produce smali instead of Java for a method jadx cannot decompile
jadx -d out/ --export-gradle "$APK"      # a buildable project
apktool d "$APK" -o smali_out/           # apktool for real smali + rebuildable resources

# 8. then grep the decompiled tree - this is where the answers are
grep -rniE 'flag|ctf\{|secret|password|api[_-]?key|token' out/sources/ | head -40
grep -rniE 'https?://|\.amazonaws\.com|firebaseio|/api/' out/sources/ | sort -u | head -40
grep -rniE 'AES|DES|Cipher\.getInstance|SecretKeySpec|IvParameterSpec|MessageDigest' out/sources/
grep -rn 'native ' out/sources/ | head              # JNI methods -> reverse the .so
grep -rniE 'checkSignature|isRooted|isDebuggerConnected|SafetyNet' out/sources/

# 9. read the manifest for the attack surface
cat out/resources/AndroidManifest.xml
grep -E 'android:exported="true"|<activity|<service|<receiver|<provider|permission' out/resources/AndroidManifest.xml

# 10. pull the native libraries out and reverse them separately
unzip -o "$APK" 'lib/*' -d libs/ && file libs/lib/*/*.so
# then: ghidra / radare2 on libs/lib/arm64-v8a/libnative.so
```

Where the flag usually is, in order:

| Location | How to check |
|---|---|
| `res/values/strings.xml` | `grep -ri flag out/resources/res/values/` |
| A hardcoded constant in a Java class | `grep -rn 'flag{' out/sources/` |
| Assembled from character arrays / a decrypt routine | read the method, re-implement it in Python |
| `assets/` (a file, a DB, an encrypted blob) | `unzip -l app.apk`, then examine |
| A native library (`libnative.so`) | Ghidra; the Java side just calls `stringFromJNI()` |
| Built at runtime from device properties | hook it with Frida instead of reversing |
| In the `AndroidManifest` as meta-data | `grep meta-data out/resources/AndroidManifest.xml` |
| Behind a server call | the URL and any API key are in the source; use them |
| In a `BuildConfig` field | `grep -rn 'BuildConfig' out/sources/` |

Companion commands:
```sh
unzip -l app.apk                       # an APK is a ZIP - list it first
apksigner verify --print-certs app.apk # signing info
aapt dump badging app.apk              # package name, permissions, launchable activity
adb install app.apk && adb shell am start -n com.example/.MainActivity
adb logcat | grep -i example           # apps print a surprising amount
```

## Gotchas

- jadx **fails on some methods** and emits a comment instead of code. `--show-bad-code` shows the partial output plus the raw bytecode; often that is enough. For a specific method, read the smali via apktool or jadx-gui's smali pane.
- Obfuscated apps (ProGuard/R8/DexGuard) yield `a.b.c` names. `--deobf` assigns stable synthetic names, which at least makes cross-referencing workable.
- Kotlin decompiles to Java with a lot of noise (`Intrinsics.checkNotNullParameter`, synthetic classes). Look past it.
- Multi-dex APKs (`classes2.dex`, `classes3.dex`) are handled automatically, but confirm all of them decompiled.
- String encryption is common: the constant you want is computed at runtime. Either re-implement the decrypt function or hook it with Frida.
- jadx does **not** touch native code. If the check is in a `.so`, extract it and use Ghidra.
- `apktool` and `jadx` serve different purposes: jadx gives readable Java (not rebuildable), apktool gives smali plus decoded resources (rebuildable). To patch and reinstall an app you need apktool + `apksigner`.
- Large APKs take minutes and a lot of RAM; raise the JVM heap with `JAVA_OPTS="-Xmx8g" jadx ...` if it OOMs.
- An AAB or a split APK set needs merging (`bundletool`) before analysis.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| jadx cannot decompile a class | `apktool d` for smali; `cfr`/`procyon` on a converted JAR (`dex2jar`) |
| You need to patch and rebuild | `apktool d` -> edit smali -> `apktool b` -> `apksigner sign` |
| Runtime values, not static code | **Frida** (`ctfbrain search frida`), `objection` |
| The logic is in native code | Ghidra / radare2 on the `.so` |
| iOS app instead | `class-dump`, Hopper, Ghidra, Frida |
| Flutter / React Native app | `blutter` for Flutter snapshots; for RN, unpack `index.android.bundle` (it is JavaScript) |
| Unity app | `Il2CppDumper` with `global-metadata.dat`, or dnSpy on `Assembly-CSharp.dll` |
