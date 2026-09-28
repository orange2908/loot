---
title: "Android Static Secrets - API Keys, Firebase and Endpoints in an APK"
category: mobile
subcategory: android-static
type: technique
tags: [android, apk, secrets, api-key, firebase, google-services, aizasy, jwt, aws-keys, hardcoded-credentials, apkleaks, jadx, grep, base64, entropy, string-resources]
difficulty: easy
summary: "Systematically pull API keys, Firebase configs, JWTs and internal endpoints out of an APK's resources, strings, smali and native libs."
when_to_use:
  - "The challenge hints that a credential or endpoint is baked into the app"
  - "You triaged the APK and need the actual loot pass"
  - "You found a backend host and need the key that talks to it"
tools: [jadx, apktool, apkleaks, ripgrep, strings, curl]
related: [android-apk-triage, android-deobfuscation, android-native-jni, mobile-traffic-interception]
---

## TL;DR

Everything an APK ships is readable. Secrets hide in five places and only five:
`res/values/strings.xml`, `assets/`, the dex string pool, `AndroidManifest.xml`
`<meta-data>`, and native `.so` `.rodata`. Sweep all five with regex + entropy,
then validate the interesting ones against their service.

## Recognise it

- `google-services.json` in `assets/` or a `res/values/strings.xml` containing
  `google_api_key`, `google_app_id`, `firebase_database_url`, `gcm_defaultSenderId`.
- Keys matching well-known shapes: `AIza...` (Google), `AKIA...` (AWS), `sk_live_`/`pk_live_`
  (Stripe), `xox[baprs]-` (Slack), `ghp_`/`github_pat_` (GitHub), `eyJ...` (JWT).
- A `BuildConfig` class with `public static final String API_SECRET = "..."`.
  Gradle `buildConfigField` is the #1 source of leaked keys.
- Long base64 / hex constants passed straight into `SecretKeySpec` or `Base64.decode`.
- A `Retrofit.Builder().baseUrl(...)` or `OkHttpClient` with an `Interceptor` adding a
  static `Authorization` header.

## Theory

Android has no secure place to store a shipped secret. Every "protection" is obfuscation:

| Storage | How to read it |
|---|---|
| `strings.xml` resource | `apktool d`, plain XML |
| `BuildConfig` constant | jadx, appears as a `static final` field |
| `assets/*.json` | `unzip` |
| `<meta-data>` in manifest | `apktool d` / `aapt2 dump xmltree` |
| String in Java code | dex string pool, always recoverable |
| XOR/AES-encrypted string | decryptor ships with the app; run it or hook it |
| Native `.so` constant | `strings`, or Ghidra `.rodata` |
| NDK + JNI + white-box crypto | Frida hook on the JNI boundary |
| Fetched from server at runtime | intercept traffic instead |

The useful consequence: if the app can use the secret, you can extract it - at worst by
running the app under Frida and logging the value at the point of use
(see `android-frida-basics`).

### Firebase specifics

`google-services.json` gives you `project_id`, `api_key`, `firebase_url`, `storage_bucket`.
Three classic misconfigurations to test:

1. **Realtime Database open read** - `GET https://<project>.firebaseio.com/.json`
   returns the whole tree if rules are `".read": true`.
2. **Firestore via REST with the web API key** - anonymous sign-in
   (`identitytoolkit` `signUp` with `returnSecureToken`) then read collections.
3. **Cloud Storage bucket listing** - `GET https://firebasestorage.googleapis.com/v0/b/<bucket>/o`.

Do this only against hosts that are in scope for the CTF.

## Attack

1. Decode with `apktool` (resources) and `jadx` (Java) into separate trees.
2. Run the regex sweep (script below) over both trees plus the raw ZIP.
3. Dump the dex string pool directly - jadx sometimes drops strings it cannot place.
4. Read `res/values/strings.xml` in full; it is short and always worth it.
5. Read `AndroidManifest.xml` `<meta-data>` entries in full.
6. `strings -n 8` every `lib/*/*.so`.
7. Sort candidates by entropy, then validate the top ones.
8. If nothing static: the secret is derived or encrypted -> hook `SecretKeySpec`,
   `Cipher.doFinal` and `String` constructors with Frida.

## Code

```python
#!/usr/bin/env python3
"""apk_secrets.py - regex + entropy secret sweep over an APK (or an extracted tree).

Scans zip members and/or a directory, applies named credential regexes, then reports
high-entropy leftovers that no regex caught (the ones that are usually the flag).

Usage:
  python3 apk_secrets.py app.apk
  python3 apk_secrets.py out-jadx/
"""
from __future__ import annotations

import math
import os
import re
import sys
import zipfile
from collections import defaultdict
from typing import Iterable

RULES: list[tuple[str, re.Pattern[bytes]]] = [
    ("google-api-key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("google-oauth-id", re.compile(rb"[0-9]{10,14}-[0-9a-z]{32}\.apps\.googleusercontent\.com")),
    ("firebase-rtdb", re.compile(rb"https://[a-z0-9-]+\.firebase(?:io|database)\.com")),
    ("firebase-storage", re.compile(rb"[a-z0-9.-]+\.appspot\.com")),
    ("aws-access-key", re.compile(rb"(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}")),
    ("aws-secret", re.compile(rb"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("slack-token", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("github-token", re.compile(rb"gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}")),
    ("stripe-key", re.compile(rb"[sp]k_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("basic-auth-url", re.compile(rb"https?://[^/\s:@]{1,64}:[^/\s:@]{1,64}@[A-Za-z0-9.-]+")),
    ("twilio-sid", re.compile(rb"AC[0-9a-fA-F]{32}")),
    ("sendgrid", re.compile(rb"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}")),
    ("mailgun", re.compile(rb"key-[0-9a-zA-Z]{32}")),
    ("generic-assign", re.compile(
        rb"(?i)(api[_-]?key|secret|token|passwd|password|auth)\s*[:=]\s*['\"]([ -~]{8,80})['\"]")),
    ("http-url", re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{6,120}")),
]

B64_RE = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
HEX_RE = re.compile(rb"(?:[0-9a-fA-F]{2}){16,}")
SKIP_EXT = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".ttf", ".otf", ".mp3", ".mp4")


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def members(path: str) -> Iterable[tuple[str, bytes]]:
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for f in files:
                if f.lower().endswith(SKIP_EXT):
                    continue
                full = os.path.join(root, f)
                try:
                    if os.path.getsize(full) > 12 * 1024 * 1024:
                        continue
                    with open(full, "rb") as fh:
                        yield os.path.relpath(full, path), fh.read()
                except OSError:
                    continue
    else:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir() or info.filename.lower().endswith(SKIP_EXT):
                    continue
                if info.file_size > 12 * 1024 * 1024:
                    continue
                try:
                    yield info.filename, z.read(info)
                except (RuntimeError, zipfile.BadZipFile):
                    continue


def scan(path: str, entropy_floor: float = 4.3) -> dict[str, set[str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for name, blob in members(path):
        for label, rx in RULES:
            for m in rx.findall(blob):
                val = m if isinstance(m, bytes) else b":".join(x for x in m if x)
                found[label].add(f"{val.decode('utf-8', 'replace')[:180]}  <- {name}")
        for rx in (B64_RE, HEX_RE):
            for m in rx.findall(blob):
                if 24 <= len(m) <= 512 and shannon(m) >= entropy_floor:
                    found["high-entropy"].add(f"{m.decode('ascii', 'replace')[:180]}  <- {name}")
    return found


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    found = scan(argv[1])
    order = [lbl for lbl, _ in RULES] + ["high-entropy"]
    for label in order:
        hits = sorted(found.get(label, ()))
        if not hits:
            continue
        print(f"\n### {label} ({len(hits)})")
        for h in hits[:60]:
            print("  " + h)
    return 0


def _selftest() -> None:
    import io
    import tempfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("assets/google-services.json",
                   b'{"api_key":[{"current_key":"AIza' + b"B" * 35 + b'"}],'
                   b'"firebase_url":"https://demo-app.firebaseio.com"}')
        z.writestr("res/values/strings.xml",
                   b'<resources><string name="s">AKIAABCDEFGHIJKLMNOP</string></resources>')
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.apk")
        with open(p, "wb") as fh:
            fh.write(buf.getvalue())
        res = scan(p)
    assert res["google-api-key"], "google key rule failed"
    assert res["aws-access-key"], "aws key rule failed"
    assert res["firebase-rtdb"], "firebase rule failed"
    print("selftest ok")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _selftest()
    else:
        sys.exit(main(sys.argv))
```

### Manual sweeps that the script does not replace

```bash
# dex string pool straight from the binary - catches strings jadx drops
strings -n 6 -a out-zip/classes*.dex | sort -u > dex-strings.txt

# every string resource, in full (it is small, read all of it)
cat out-apktool/res/values/strings.xml

# manifest meta-data (keys are routinely parked here)
grep -A2 '<meta-data' out-apktool/AndroidManifest.xml

# BuildConfig constants - gradle buildConfigField leaks live here
find out-jadx -name 'BuildConfig.java' -exec grep -H 'static final' {} +

# retrofit / okhttp base urls and static auth headers
grep -rIn -E 'baseUrl\(|addHeader\("Authorization|\.header\("Authorization' out-jadx/sources

# native library constants
strings -n 8 out-zip/lib/arm64-v8a/*.so | grep -iE 'key|token|secret|http' | sort -u

# firebase realtime db open-read check (only against in-scope hosts)
curl -s 'https://demo-app.firebaseio.com/.json' | head -c 400
```

### Decrypting an obfuscated string constant

When the key is built at runtime from a XOR table, reimplement it rather than hooking:

```python
#!/usr/bin/env python3
"""deobf_xor.py - reimplement the classic 'decrypt(String, int)' string obfuscator.

Pattern seen in DexGuard-lite / home-made obfuscators:

    static String d(String s, int k) {
        char[] c = s.toCharArray();
        for (int i = 0; i < c.length; i++) c[i] = (char) (c[i] ^ (k + i));
        return new String(c);
    }
"""
from __future__ import annotations


def encrypt(plain: str, key: int) -> str:
    return "".join(chr(ord(ch) ^ ((key + i) & 0xFF)) for i, ch in enumerate(plain))


def decrypt(cipher: str, key: int) -> str:
    return "".join(chr(ord(ch) ^ ((key + i) & 0xFF)) for i, ch in enumerate(cipher))


def brute(cipher: str, wanted: str = "http") -> list[tuple[int, str]]:
    """Try every single-byte key and keep results that look like text."""
    out = []
    for k in range(256):
        cand = decrypt(cipher, k)
        if wanted in cand or all(32 <= ord(c) < 127 for c in cand):
            out.append((k, cand))
    return out


if __name__ == "__main__":
    secret = "https://api.internal.ctf/v1/flag"
    ct = encrypt(secret, 0x5A)
    assert decrypt(ct, 0x5A) == secret
    hits = [(k, v) for k, v in brute(ct, "https://") if v == secret]
    assert hits and hits[0][0] == 0x5A, hits
    print(f"recovered key=0x{hits[0][0]:02x} -> {hits[0][1]}")
    print("selftest ok")
```

## Variants & pitfalls

- **Entropy false positives**: resource IDs, certificate blobs in `META-INF`, and
  `.png` chunks all look random. Filter by file type first.
- **Keys split across constants** - `"AIza" + PART2 + PART3`. Grep for the prefix alone.
- **Keys in native code only** - the Java side just calls `getKey()` (a `native` method).
  `strings` on the `.so`, then Frida hook on the JNI export.
- **Restricted vs unrestricted Google keys**: an `AIza` key may be locked to a package
  name + signing cert. The SHA-1 of the signing cert is in `META-INF`; get it with
  `apksigner verify --print-certs app.apk`.
- **`google-services.json` absent but values present** - the Gradle plugin inlines them
  into `res/values/strings.xml` as `google_api_key`, `google_app_id`, `firebase_database_url`.
- **Do not stop at the first key.** CTF apps often plant a decoy key and hide the real
  endpoint in an unrelated asset.
- If the secret is genuinely only present at runtime, stop reversing and go to
  `android-frida-basics` + `mobile-traffic-interception`.

## Tools

- `apkleaks` - bundles a large ruleset; good first pass.
- `jadx` / `ripgrep` - the actual search.
- `strings` - dex and `.so` string pools.
- `apksigner verify --print-certs` - signing cert SHA-1/SHA-256 (needed for API key restrictions).
- `trufflehog` / `gitleaks` - generic secret scanners, work on an extracted tree.

## References

- Firebase documentation on security rules and the REST API surface.
- Google Cloud documentation on API key restrictions.
- `apkleaks` project README for its ruleset format.
