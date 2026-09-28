---
title: "Reference - Regex Recipes for CTF"
category: misc
subcategory: regex
type: reference
tags: [regex, grep, grep-p, ripgrep, python-re, extraction, hashes, api-keys, ips, base64, jwt, urls, emails, flag-regex, pcre, recipes, secrets-scanning]
summary: "Copy-paste regexes for extracting hashes, keys, IPs, base64 blobs, JWTs, URLs and flags, in grep -P and Python forms."
related: [flag-formats, encoding-detection, source-code-given, linux-useful-paths]
---

## 0. The three tools

```sh
# GNU grep with PCRE (-P), recursive, binary-safe, show only the match
grep -rPoa 'PATTERN' .
# ripgrep: faster, respects .gitignore by default (use -u -u to ignore that), PCRE2 with -P
rg -P -o --no-heading --binary 'PATTERN' .
# Python: re.findall over bytes
python3 -c "import re,sys;print(re.findall(rb'PATTERN', open(sys.argv[1],'rb').read()))" file
```

Useful grep flags: `-a` (treat binary as text), `-o` (only the match), `-i` (ignore case), `-r` (recursive), `-n` (line numbers), `-h` (no filename), `-E` (ERE), `-P` (PCRE), `-z` (null-separated, lets `.` cross newlines), `--include='*.py'`.

macOS note: BSD `grep` has no `-P`. Install GNU grep (`brew install grep`, then use `ggrep`) or use `rg -P`, or `perl -nle 'print $& while /PATTERN/g'`.

---

## 1. Flags

```sh
# generic flag shape
grep -rPoa '[A-Za-z0-9_\-]{2,20}\{[^}\n]{3,150}\}' .
# specific formats
grep -rPoa '(?i)(flag|ctf|key|pico[Cc][Tt][Ff]|HTB|THM)\{[^}\n]+\}' .
# hash-style flags
grep -rPoa '\b[0-9a-f]{32}\b' .
```
Python:
```python
import re
FLAG = re.compile(rb"[A-Za-z0-9_\-]{2,20}\{[^}\n]{3,150}\}")
```
`ctfbrain search flag-formats`

---

## 2. Hashes

| Hash | Regex | Length |
|---|---|---|
| MD5 / NTLM / MD4 | `\b[a-f0-9]{32}\b` | 32 |
| SHA-1 | `\b[a-f0-9]{40}\b` | 40 |
| SHA-224 | `\b[a-f0-9]{56}\b` | 56 |
| SHA-256 | `\b[a-f0-9]{64}\b` | 64 |
| SHA-384 | `\b[a-f0-9]{96}\b` | 96 |
| SHA-512 | `\b[a-f0-9]{128}\b` | 128 |
| CRC32 | `\b[a-f0-9]{8}\b` | 8 (very noisy) |
| bcrypt | `\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}` | 60 |
| sha256crypt | `\$5\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}` | - |
| sha512crypt | `\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}` | - |
| md5crypt | `\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}` | - |
| yescrypt | `\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+` | - |
| argon2 | `\$argon2(id\|i\|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[^$]+\$[^\s]+` | - |
| PHPass / WordPress | `\$P\$[./A-Za-z0-9]{31}` | 34 |
| Django pbkdf2 | `pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+` | - |
| LM | `\b[A-F0-9]{32}\b` (uppercase) | 32 |
| NTLM pair (pwdump) | `^[^:]+:\d+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::` | - |
| NetNTLMv2 | `^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$` | - |
| MySQL 4.1+ | `\*[A-F0-9]{40}` | 41 |
| Cisco type 7 | `\b[0-9]{2}[A-F0-9]{4,}\b` | - |

```sh
# pull every hash-shaped token out of a dump
grep -rPoa '\$(2[abxy]|1|5|6|y|argon2(id|i|d)|P)\$[^\s:"'"'"']+' .
grep -rPoa '\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b' . | sort -u
```
Identify with `hashid '<hash>'` or `hash-identifier`, then `ctfbrain search hashcat john`.

---

## 3. Keys, tokens and secrets

```sh
# PEM blocks (multi-line): -z makes . match newlines
grep -rPzoa '(?s)-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE|PUBLIC KEY)-----.*?-----END [A-Z ]*(PRIVATE KEY|CERTIFICATE|PUBLIC KEY)-----' .
# SSH public keys
grep -rPoa 'ssh-(rsa|ed25519|dss) AAAA[0-9A-Za-z+/]+[=]{0,3}' .
# AWS access key id
grep -rPoa '\b(AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b' .
# AWS secret access key (shape only - noisy)
grep -rPoa '(?i)aws(.{0,20})?(secret|access).{0,20}[\x27"][0-9a-zA-Z/+]{40}[\x27"]' .
# Google API key
grep -rPoa '\bAIza[0-9A-Za-z_\-]{35}\b' .
# Slack token
grep -rPoa '\bxox[baprs]-[0-9A-Za-z\-]{10,}\b' .
# GitHub token
grep -rPoa '\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b' .
# Stripe
grep -rPoa '\b(sk|pk|rk)_(live|test)_[0-9A-Za-z]{24,}\b' .
# Generic assignment of a secret-looking variable
grep -rPoia '(?:api[_\-]?key|secret|passwd|password|token|auth)["\x27]?\s*[:=]\s*["\x27][^"\x27\s]{8,}["\x27]' .
# Private key file in a directory listing
grep -rPoa 'BEGIN (OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY' .
```

---

## 4. Network identifiers

```sh
# IPv4 (correct, not just \d{1,3})
grep -rPoa '\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b' .
# IPv4 with an optional CIDR
grep -rPoa '\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/\d{1,2})?\b' .
# IPv6 (permissive, catches most real forms)
grep -rPoa '\b(?:[A-Fa-f0-9]{1,4}:){2,7}(?::|[A-Fa-f0-9]{1,4})\b' .
# MAC address
grep -rPoa '\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b' .
# Hostname / FQDN
grep -rPoa '\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b' .
# host:port
grep -rPoa '\b[a-zA-Z0-9.\-]+:\d{2,5}\b' .
```

---

## 5. URLs, emails, paths

```sh
# URLs
grep -rPoa 'https?://[^\s"\x27<>)\]}]+' . | sort -u
# URLs including scheme-relative and other schemes
grep -rPoa '(?:[a-z][a-z0-9+.\-]*:)?//[^\s"\x27<>)\]}]+' .
# email addresses
grep -rPoa '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b' . | sort -u
# absolute unix paths
grep -rPoa '(?:/[A-Za-z0-9._\-]+){2,}' . | sort -u | head -50
# windows paths
grep -rPoa '[A-Za-z]:\\\\(?:[^\\\\\s"\x27<>|:*?]+\\\\)*[^\\\\\s"\x27<>|:*?]*' .
# UNC paths
grep -rPoa '\\\\\\\\[A-Za-z0-9._\-]+\\\\[^\s"\x27]+' .
```

---

## 6. Encoded blobs

```sh
# base64 blob (length 20+, correct padding)
grep -rPoa '(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})' . | awk 'length($0)>=24'
# simpler and good enough in practice
grep -rPoa '[A-Za-z0-9+/]{24,}={0,2}' .
# base64url (JWT-safe alphabet)
grep -rPoa '[A-Za-z0-9_\-]{24,}={0,2}' .
# base32
grep -rPoa '[A-Z2-7]{16,}={0,6}' .
# hex blob (even length, 20+ chars)
grep -rPoa '\b(?:[0-9a-fA-F]{2}){10,}\b' .
# base58 (no 0 O I l)
grep -rPoa '\b[1-9A-HJ-NP-Za-km-z]{26,}\b' .
# ascii85 delimited
grep -rPzoa '(?s)<~.*?~>' .
# percent-encoded run
grep -rPoa '(?:%[0-9A-Fa-f]{2}){4,}' .
# HTML entity run
grep -rPoa '(?:&#x?[0-9A-Fa-f]{2,6};){4,}' .
# binary text
grep -rPoa '\b[01]{32,}\b' .
```
`ctfbrain search encoding-detection`

Decode everything a grep finds:
```sh
grep -rhPoa '[A-Za-z0-9+/]{24,}={0,2}' . | sort -u | while read -r b; do
  d=$(printf '%s' "$b" | base64 -d 2>/dev/null | tr -d '\0')
  case "$d" in *[!\ -~]*|"") ;; *) printf '%s\t->\t%s\n' "${b:0:32}" "${d:0:120}" ;; esac
done
```

---

## 7. JWT

```sh
# a JWT is three base64url segments; the header almost always starts with eyJ
grep -rPoa '\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*\b' .
```
```python
#!/usr/bin/env python3
"""Find and decode every JWT in a file or a tree."""
import base64
import json
import os
import re
import sys

JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")


def b64url(seg: bytes) -> bytes:
    return base64.urlsafe_b64decode(seg + b"=" * (-len(seg) % 4))


def decode(tok: bytes):
    parts = tok.split(b".")
    header = json.loads(b64url(parts[0]))
    payload = json.loads(b64url(parts[1]))
    return header, payload, parts[2].decode()


def scan(path: str):
    data = open(path, "rb").read()
    for m in JWT.finditer(data):
        try:
            h, p, sig = decode(m.group())
        except Exception:
            continue
        print(f"{path}\n  alg={h.get('alg')} kid={h.get('kid')} typ={h.get('typ')}")
        print("  payload:", json.dumps(p)[:300])
        print("  sig:", sig[:32], "(empty)" if not sig else "")


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    if os.path.isfile(root):
        scan(root)
    else:
        for d, _, names in os.walk(root):
            for n in names:
                try:
                    scan(os.path.join(d, n))
                except Exception:
                    pass
```
`ctfbrain search jwt-tool`

---

## 8. Source-code patterns

```sh
# calls to a dangerous function with a variable argument
grep -rPna '\b(eval|exec|system|popen|assert|Function|unserialize|pickle\.loads)\s*\(\s*[^"\x27)]' .
# SQL built by concatenation
grep -rPna '(?i)(select|insert|update|delete)\b[^;]{0,120}(\+|\.|%s|\$\{|\bformat\b|f["\x27])' .
# printf with a non-literal first argument (format string bug)
grep -rPna '\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*(?!["\x27])[A-Za-z_]' .
# unbounded string functions in C
grep -rPna '\b(gets|strcpy|strcat|sprintf|vsprintf|scanf)\s*\(' .
# hardcoded credentials
grep -rPnia '(?:user(?:name)?|login|pass(?:word|wd)?)\s*[:=]\s*["\x27][^"\x27]{3,}["\x27]' .
# TODO markers (authors leave hints)
grep -rPna '(?i)\b(TODO|FIXME|XXX|HACK|BACKDOOR|DEBUG|REMOVE ME)\b' .
# comments in HTML/JS
grep -rPzoa '(?s)<!--.*?-->' . | head
grep -rPna '//\s*(?i)(todo|password|key|secret|flag)' .
```

---

## 9. Forensics and log parsing

```sh
# Apache/Nginx combined log line
grep -rPoa '^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) ([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"' access.log
# requests that returned 200 with a large body
awk '$9==200 && $10>10000' access.log
# find the one weird User-Agent
grep -oP '"[^"]*"$' access.log | sort | uniq -c | sort -n | head
# ISO timestamps
grep -rPoa '\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?' .
# syslog timestamps
grep -rPoa '^[A-Z][a-z]{2}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}' .
# unix timestamps (10 digits, plausible range)
grep -rPoa '\b1[5-9]\d{8}\b' .
# UUIDs
grep -rPoa '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b' .
# credit-card shaped (for bulk_extractor-style sweeps)
grep -rPoa '\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b' .
# bitcoin address
grep -rPoa '\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b' .
# ethereum address
grep -rPoa '\b0x[a-fA-F0-9]{40}\b' .
```

---

## 10. Python idioms

```python
import re

# compile once, reuse
FLAG = re.compile(rb"[A-Za-z0-9_\-]{2,20}\{[^}\n]{3,150}\}")
B64  = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
IPV4 = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
JWT  = re.compile(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
HEX  = re.compile(rb"\b(?:[0-9a-fA-F]{2}){10,}\b")
PEM  = re.compile(rb"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S)

data = open("target.bin", "rb").read()
print(FLAG.findall(data))

# named groups make the result self-documenting
LOG = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+)'
)
for m in LOG.finditer(open("access.log").read()):
    d = m.groupdict()
    if d["status"] == "200" and d["size"].isdigit() and int(d["size"]) > 10_000:
        print(d)

# re.finditer over a memory-mapped file for huge inputs
import mmap
with open("mem.raw", "rb") as fh:
    mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    for m in FLAG.finditer(mm):
        print(m.start(), m.group())
```

Flags worth knowing: `re.I` (ignore case), `re.S` (`.` matches newline), `re.M` (`^`/`$` per line), `re.X` (verbose, allows comments), `re.A` (ASCII-only `\w`/`\d`).

---

## 11. Regex as the vulnerability

| Pattern | Bug |
|---|---|
| `^` or `$` missing in a validator | `evil.com/?x=https://allowed.com` passes an unanchored check |
| `.` not escaped in a domain check | `alloweda.com` matches `allowed.com` |
| `re.match` instead of `re.fullmatch` in Python | only anchors the start |
| `$` in Python matches before a trailing newline | `"admin\n"` passes `^admin$` - use `\Z` |
| Alternation without grouping: `^a\|b$` | means `(^a)\|(b$)`, not `^(a\|b)$` |
| `(a+)+$` on a long non-matching input | catastrophic backtracking (ReDoS) |
| `(.*)*`, `(\w+\s?)*` | ReDoS |
| A blocklist regex | always bypassable: case, encoding, nesting, unicode |
| `preg_replace` with the `/e` modifier (old PHP) | direct code execution |
| User-controlled regex | ReDoS, or `$where`-style injection in NoSQL |

```python
# test a validator for the anchoring bug before trusting it
import re
pat = re.compile(r"^https://allowed\.com")   # no $ -> bypassable
print(bool(pat.match("https://allowed.com.evil.com/x")))   # True
```
