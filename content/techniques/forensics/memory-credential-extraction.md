---
title: "Memory Forensics - Credentials, Command Lines, Clipboard and Browser Artifacts"
category: forensics
subcategory: memory
type: technique
tags: [volatility3, volatility, hashdump, lsadump, cachedump, pypykatz, mimikatz, lsass, dpapi, clipboard, cmdline, consoles, browser-history, sqlite, bulk-extractor, strings, memory-dump, dfir, ntlm]
difficulty: medium
summary: "Pull NTLM hashes, plaintext passwords, typed commands, clipboard text and browser history straight out of a RAM image."
when_to_use:
  - "The challenge asks for a user's password, a hash, or 'what did the attacker type'"
  - "You need to unlock a KeePass/VeraCrypt/zip file and the key was in RAM"
  - "The flag is browser history, a visited URL, or a form field"
  - "lsass.exe is present in pslist and the scenario is credential theft"
tools: [volatility3, volatility, pypykatz, bulk-extractor, hashcat, john, sqlite3, strings]
related: [memory-volatility3-workflow, memory-volatility2, memory-injected-code, docs-sqlite-forensics]
---

## TL;DR

Four independent routes to credentials in RAM: registry-derived hashes (`hashdump`/`lsadump`/
`cachedump`), a dump of `lsass.exe` parsed by `pypykatz`, typed-command artefacts
(`cmdline`/`consoles`/`envars`), and brute-force string scanning (`strings -el` + `bulk_extractor`).
Try them in that order; the last one works even when symbols fail.

## Recognise it

- `windows.pslist` shows `lsass.exe`, `mimikatz.exe`, `procdump.exe`, `rundll32.exe comsvcs.dll`.
- `windows.filescan` shows `lsass.DMP`, `*.kdbx`, `Login Data`, `places.sqlite`, `key4.db`.
- The prompt mentions "the analyst logged in", "recover the password", "what did they exfiltrate".
- Console scrollback references `net user`, `runas`, `ssh`, `mysql -p`, `psexec`.

## Route 1 - registry-derived credential material

```sh
# local account NT hashes straight from SAM+SYSTEM resident in RAM
vol3 -f mem.raw windows.hashdump.Hashdump
# LSA secrets: service account passwords, DPAPI machine key, autologon password, cached VPN creds
vol3 -f mem.raw windows.lsadump.Lsadump
# domain cached credentials (MSCACHE / DCC2) for users who logged in without a DC present
vol3 -f mem.raw windows.cachedump.Cachedump
# the vol2 equivalents
vol.py -f mem.raw --profile=Win7SP1x64 hashdump
vol.py -f mem.raw --profile=Win7SP1x64 lsadump
vol.py -f mem.raw --profile=Win7SP1x64 cachedump
```

Cracking what you get:

```sh
# NTLM from hashdump: user:rid:lmhash:nthash:::  -> feed the whole line to hashcat with --username
hashcat -m 1000 --username hashes.txt rockyou.txt
# john equivalent
john --format=nt --wordlist=rockyou.txt hashes.txt
# domain cached credentials v2 (Vista+)
hashcat -m 2100 dcc2.txt rockyou.txt
# if the hash is a known one, check it against a local NTLM lookup before spending GPU time
grep -i "$(cut -d: -f4 hashes.txt | head -1)" /opt/wordlists/ntlm-pwned.txt
```

**Why `hashdump` often fails on Windows 10 1607+ / 11**: the SAM hashes are still there, but the
plugin's offsets and the bootkey derivation changed, and many builds return all-`31d6cfe0...`
(the empty-password hash). When that happens, move to Route 2.

## Route 2 - dump lsass and parse it offline

```sh
# find lsass
vol3 -f mem.raw windows.pslist | grep -i lsass
# dump its full address space (NOT just the PE image) into ./dumps
vol3 -f mem.raw -o ./dumps windows.memmap --pid 644 --dump
# vol2 equivalent
vol.py -f mem.raw --profile=Win7SP1x64 memdump -p 644 -D ./dumps/
# parse the resulting raw dump with pypykatz
pip install pypykatz
pypykatz lsa minidump ./dumps/pid.644.dmp
# pypykatz can also read the RAW (non-minidump) form via the rekall/volatility bridges
pypykatz lsa rekall ./dumps/pid.644.dmp
# if the challenge gave you a real MiniDump (lsass.DMP from Task Manager / procdump)
pypykatz lsa minidump lsass.DMP -o creds.txt
# the same file in mimikatz on Windows
mimikatz # sekurlsa::minidump lsass.DMP
mimikatz # sekurlsa::logonPasswords full
```

If the challenge dropped an `lsass.DMP` inside the image, find and extract it instead of dumping
the live process:

```sh
# locate the cached file object
vol3 -f mem.raw windows.filescan | grep -iE '\.dmp$'
# extract it by its virtual address
vol3 -f mem.raw -o ./dumps windows.dumpfiles --virtaddr 0x8e1d2a3b4c50
```

DPAPI material, when the flag is an encrypted blob:

```sh
# masterkeys live under %APPDATA%\Microsoft\Protect\<SID>\<guid>
vol3 -f mem.raw windows.filescan | grep -i 'Microsoft\\Protect'
# LSA secrets gives you DPAPI_SYSTEM, which decrypts machine-scope blobs
vol3 -f mem.raw windows.lsadump.Lsadump | grep -i dpapi
# offline decryption once you have masterkey + user password/SID
pypykatz dpapi masterkey /path/masterkey --password 'Passw0rd!' --sid S-1-5-21-...
pypykatz dpapi blob /path/blob --key <decrypted-masterkey-hex>
```

## Route 3 - what the human typed

```sh
# full argv of every process: passwords passed on the command line live here
vol3 -f mem.raw windows.cmdline
# conhost scrollback: BOTH the commands and their output
vol3 -f mem.raw windows.consoles
# older builds keep a separate command history buffer
vol3 -f mem.raw windows.cmdscan
# environment variables can hold API keys and proxy credentials
vol3 -f mem.raw windows.envars | grep -iE '(pass|key|token|secret|proxy)'
# last clipboard contents, per session and per window station
vol3 -f mem.raw windows.clipboard
vol.py -f mem.raw --profile=Win7SP1x64 clipboard
# PowerShell transcript / history files cached in RAM
vol3 -f mem.raw windows.filescan | grep -i 'ConsoleHost_history.txt'
```

Grep patterns that pay off on `cmdline`/`consoles` output:

```sh
# credentials on a command line
grep -iE '(-p[ =]|--password|/user:|net user |runas |psexec |sshpass|mysql -u)' out.txt
# encoded powershell: decode the blob after -enc
grep -oiE '(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}' out.txt \
  | awk '{print $2}' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

## Route 4 - browser artefacts and raw strings

```sh
# find browser databases cached in the page pool
vol3 -f mem.raw windows.filescan | grep -iE '(places\.sqlite|History|Cookies|Login Data|key4\.db|logins\.json|Web Data|Bookmarks|favicons)'
# dump each one by virtual address, then read it with sqlite3
vol3 -f mem.raw -o ./dumps windows.dumpfiles --virtaddr 0x9c0a1b2c3d40
file ./dumps/*.dat
sqlite3 ./dumps/file.0x9c0a1b2c3d40.dat \
  "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url, title FROM urls ORDER BY 1 DESC LIMIT 50;"
# firefox
sqlite3 places.sqlite \
  "SELECT datetime(v.visit_date/1000000,'unixepoch'), p.url, p.title FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id ORDER BY 1 DESC LIMIT 50;"
# raw URL scrape, both encodings, with byte offsets
strings -a -t d mem.raw | grep -aoE 'https?://[^[:space:]"'"'"'<>]{6,200}' | sort -u > urls_ascii.txt
strings -a -t d -el mem.raw | grep -aoE 'https?://[^[:space:]"'"'"'<>]{6,200}' | sort -u > urls_utf16.txt
# the blunt instrument that closes a lot of challenges
strings -a mem.raw    | grep -aoE '[A-Za-z0-9_]{2,16}\{[^}]{4,120}\}' | sort -u
strings -a -el mem.raw | grep -aoE '[A-Za-z0-9_]{2,16}\{[^}]{4,120}\}' | sort -u
# bulk_extractor builds feature files for email, url, domain, ccn, aes keys, json, windirs
bulk_extractor -o be_out mem.raw
column -t be_out/url_histogram.txt | head -40
cat be_out/email.txt be_out/domain.txt | head
# bulk_extractor can also recover AES key schedules left in RAM
grep -c . be_out/aes_keys.txt
```

## Code

```python
#!/usr/bin/env python3
"""Scan a raw memory image for credential-shaped strings in ASCII and UTF-16LE.

Usage:
    python3 memcreds.py mem.raw [--min 6] [--context 60]

Streams the file in overlapping chunks so a 16 GB dump does not need 16 GB of RAM.
Prints: file offset, encoding, matched pattern name, and the surrounding text.
"""
from __future__ import annotations

import argparse
import re
import sys

CHUNK = 8 * 1024 * 1024
OVERLAP = 4096

PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("flag", re.compile(rb"[A-Za-z0-9_]{2,16}\{[\x20-\x7e]{4,120}\}")),
    ("url", re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}")),
    ("email", re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{2,64}\.[A-Za-z]{2,12}")),
    ("basic-auth", re.compile(rb"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}")),
    ("bearer", re.compile(rb"(?i)authorization:\s*bearer\s+[A-Za-z0-9._~+/-]{16,}")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("password-kv", re.compile(rb"(?i)(pass(word|wd)?|pwd|passphrase|secret|api[_-]?key|token)"
                              rb"\s*[:=]\s*[\x21-\x7e]{4,80}")),
    ("cmdline-pw", re.compile(rb"(?i)(?:/user:|--password[ =]|-p[ =])[\x21-\x7e]{3,60}")),
    ("connstr", re.compile(rb"(?i)(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://"
                           rb"[^\s\"'<>]{6,160}")),
    ("ntlm-line", re.compile(rb"[A-Za-z0-9_.$-]{1,20}:\d{3,6}:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::")),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    ("aws-key", re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}")),
]


def widen(pat: re.Pattern[bytes]) -> re.Pattern[bytes]:
    """Crude UTF-16LE variant: allow a NUL after every byte of the ASCII pattern."""
    src = pat.pattern.decode("latin-1")
    out = []
    i = 0
    while i < len(src):
        ch = src[i]
        if ch == "\\" and i + 1 < len(src):
            out.append(src[i:i + 2])
            i += 2
        elif ch in "[](){}|^$.*+?":
            out.append(ch)
            i += 1
            continue
        else:
            out.append(ch)
            i += 1
        out.append("\\x00?")
    return re.compile("".join(out).encode("latin-1"))


def decode_hit(raw: bytes) -> str:
    if b"\x00" in raw:
        try:
            return raw.decode("utf-16-le", "replace").strip("\x00")
        except UnicodeDecodeError:
            pass
    return raw.decode("latin-1", "replace")


def scan(path: str, context: int) -> int:
    ascii_pats = PATTERNS
    wide_pats = [(f"{name}/utf16", widen(p)) for name, p in PATTERNS]
    seen: set[tuple[str, bytes]] = set()
    hits = 0
    with open(path, "rb") as fh:
        base = 0
        tail = b""
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            buf = tail + chunk
            start = base - len(tail)
            for name, pat in list(ascii_pats) + wide_pats:
                for m in pat.finditer(buf):
                    key = (name, m.group(0)[:160])
                    if key in seen:
                        continue
                    seen.add(key)
                    off = start + m.start()
                    lo = max(0, m.start() - context // 2)
                    ctx = decode_hit(buf[lo:m.end() + context // 2])
                    ctx = "".join(c if 32 <= ord(c) < 127 else "." for c in ctx)
                    print(f"0x{off:012x}  {name:16s}  {ctx}")
                    hits += 1
            base += len(chunk)
            tail = buf[-OVERLAP:]
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", nargs="?", default="mem.raw")
    ap.add_argument("--context", type=int, default=80)
    args = ap.parse_args()
    try:
        n = scan(args.image, args.context)
    except FileNotFoundError:
        print(f"no such file: {args.image}", file=sys.stderr)
        return 1
    print(f"\n[+] {n} unique hits", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Carve SQLite databases (browser history, cookies, chat logs) out of a memory image.

SQLite files start with the 16-byte magic 'SQLite format 3\\x00'. The page size is a
big-endian u16 at offset 16 and the page count a big-endian u32 at offset 28, so the
on-disk length is computable without a footer.

Usage:
    python3 carve_sqlite.py mem.raw outdir
"""
from __future__ import annotations

import os
import sqlite3
import struct
import sys

MAGIC = b"SQLite format 3\x00"
CHUNK = 8 * 1024 * 1024


def candidate_offsets(path: str):
    with open(path, "rb") as fh:
        base, tail = 0, b""
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                return
            buf = tail + chunk
            start = base - len(tail)
            pos = 0
            while True:
                idx = buf.find(MAGIC, pos)
                if idx < 0:
                    break
                yield start + idx
                pos = idx + 1
            base += len(chunk)
            tail = buf[-len(MAGIC):]


def header_length(hdr: bytes) -> int | None:
    if len(hdr) < 100 or not hdr.startswith(MAGIC):
        return None
    page_size = struct.unpack_from(">H", hdr, 16)[0]
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size & (page_size - 1):
        return None
    pages = struct.unpack_from(">I", hdr, 28)[0]
    if not 1 <= pages <= 1_000_000:
        return None
    return page_size * pages


def describe(db_path: str) -> str:
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        names = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        con.close()
    except sqlite3.Error as exc:
        return f"unreadable ({exc})"
    if not names:
        return "no tables"
    hint = ""
    lowered = {n.lower() for n in names}
    if {"moz_places", "moz_historyvisits"} & lowered:
        hint = "  <- firefox places.sqlite"
    elif {"urls", "visits"} <= lowered:
        hint = "  <- chromium History"
    elif "logins" in lowered:
        hint = "  <- chromium Login Data"
    elif "cookies" in lowered:
        hint = "  <- cookie jar"
    return f"{len(names)} tables: {', '.join(names[:8])}{hint}"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    image = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else "carved_sqlite"
    os.makedirs(outdir, exist_ok=True)
    found = 0
    with open(image, "rb") as fh:
        for off in candidate_offsets(image):
            fh.seek(off)
            hdr = fh.read(100)
            length = header_length(hdr)
            if length is None:
                continue
            fh.seek(off)
            data = fh.read(length)
            if len(data) < length:
                continue
            out = os.path.join(outdir, f"sqlite_{off:012x}.db")
            with open(out, "wb") as o:
                o.write(data)
            print(f"0x{off:012x}  {length:>10d} bytes  {out}  {describe(out)}")
            found += 1
    print(f"[+] carved {found} sqlite candidates into {outdir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- A carved SQLite database from RAM is almost always **partial**. `sqlite3` may refuse it; run
  `.recover` or `sqlite3 db ".dump"`, or parse the freelist pages manually.
- Browser databases in RAM often appear as their **WAL** (`-wal`) content rather than the main
  file; search for `\x37\x7f\x06\x82`/`\x37\x7f\x06\x83` WAL magic too.
- `windows.clipboard` returns nothing if the clipboard held a non-text format; the bitmap may
  still be carveable with `binwalk`/`foremost` on the session's memory.
- Passwords typed into a GUI field are in the **process heap**, not in `cmdline`. Dump that
  process with `windows.memmap --pid N --dump` and grep the dump.
- `strings` misses UTF-16 by default. Always run both `strings -a` and `strings -a -el`.
  Use `-eb` for big-endian (rare, but Java/network buffers do it).
- Recovered NTLM hash `31d6cfe0d16ae931b73c59d7e0c089c0` means empty password, not a bug.
- Treat everything you pull as evidence: hash the dump first (`sha256sum mem.raw`).

## Tools

`volatility3`, `volatility`, `pypykatz`, `mimikatz`, `bulk_extractor`, `hashcat`, `john`,
`sqlite3`, `strings`, `binwalk`, `MemProcFS`, `RegRipper` (for dumped hives).

## References

- `pypykatz --help` and `pypykatz lsa minidump --help` for the current subcommand set.
- `vol3 -f img windows.hashdump.Hashdump -h` for the plugin's requirements.
