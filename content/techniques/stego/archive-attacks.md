---
title: "Archive Attacks - bkcrack, Cracking, Bombs and Zip Slip"
category: stego
subcategory: archive
type: technique
tags: [zip, zipcrypto, bkcrack, known-plaintext, zip2john, john, hashcat, rar, 7z, zip-bomb, zip-slip, symlink, path-traversal, corrupted-archive, repair, stego]
difficulty: hard
summary: "ZipCrypto falls to a 12-byte known plaintext with bkcrack; AES zips need a password crack; the rest is repair, traversal and bombs."
when_to_use:
  - "A password-protected ZIP where you know (or can guess) one file's contents"
  - "unzip says 'incorrect password' and you have a wordlist"
  - "An archive extracts outside the target directory, or contains symlinks"
  - "The archive is corrupt: bad CRC, truncated, or missing the central directory"
tools: [bkcrack, zip2john, rar2john, 7z2john, john, hashcat, unzip, zip, 7z, zipdetails, python3, binwalk]
related: [polyglot-files, stego-bruteforce, image-triage, stego-cheatsheet, misc-classics, ctf-general-cheatsheet]
---

## TL;DR

First determine the encryption: **ZipCrypto** (legacy, breakable with 12 bytes of known
plaintext, no password needed) or **AES-256** (only a password crack works). `zipdetails` or
`7z l -slt` tells you which. Then: `bkcrack` for ZipCrypto, `zip2john` + `john`/`hashcat` for
AES/RAR/7z, `zip -FF` for corruption.

## Recognise it

```bash
# which encryption? look for 'AES' or 'ZipCrypto' / 'Strong Encryption'
7z l -slt chal.zip | grep -E 'Method|Encrypted'
zipdetails -v chal.zip | grep -iE 'general purpose|extra field|strong|aes'
unzip -v chal.zip          # 'Method' column shows AES-256 vs Defl:N
```

- `Method = ZipCrypto Deflate` -> bkcrack territory, **no password required**.
- `Method = AES-256 Deflate` (extra field `0x9901`) -> password crack only.
- General purpose bit 0 set = encrypted; bit 3 set = sizes are in a data descriptor after the
  file, which is why some tools report size 0.
- Entry **names are never encrypted** in a standard ZIP - the listing itself is often the hint.

## Theory

### ZipCrypto known-plaintext (the Biham-Kocher attack, implemented by bkcrack)

ZipCrypto keeps three 32-bit keys updated by a CRC-32-based stream cipher. Given **12 bytes of
contiguous known plaintext** (at a known offset within the *compressed* stream) the internal
keys can be recovered in minutes; from the keys every file in the archive can be decrypted, and
`bkcrack -U` can even re-key the archive to a password of your choice.

Key subtlety: bkcrack needs the plaintext of the **deflate stream**, not the original file,
unless the entry is *stored* (method 0). Two practical ways to get it:

1. The archive contains a file whose exact bytes you can reproduce (a known logo, a standard
   `README`, a file also present unencrypted elsewhere). Deflate it with the same parameters and
   use that as the plaintext.
2. The entry is **stored**, so plaintext == file content. Common for already-compressed data
   such as a PNG or PDF inside the zip: the first bytes (`\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR`)
   give you far more than 12 known bytes for free.

### Password cracking

| Target | Extractor | hashcat mode |
| --- | --- | --- |
| PKZIP / ZipCrypto (1 file, compressed) | `zip2john` | 17200 |
| PKZIP (1 file, uncompressed) | `zip2john` | 17210 |
| PKZIP (multi-file) | `zip2john` | 17220 |
| PKZIP (mixed, "chk desc") | `zip2john` | 17225 |
| PKZIP master key | - | 20500 |
| WinZip / AES zip | `zip2john` | 13600 |
| RAR3-hp (header+data encrypted) | `rar2john` | 12500 |
| RAR5 | `rar2john` | 13000 |
| 7-Zip | `7z2john` | 11600 |
| PDF 1.7 AES-256 | `pdf2john` | 10700 |

John the Ripper formats: `zip`, `pkzip`, `rar`, `rar5`, `7z`.

### Zip bombs

- **Nested**: 42.zip - 42 KB expanding to 4.5 PB through recursive layers.
- **Non-recursive overlapping** (Fifield, 2019): one compressed kernel shared by many entries
  via quoted overlapping local headers; a single pass expands enormously.
- Defend yourself: always extract with a size cap and into a fresh directory.

### Zip slip and symlinks

Entry names may contain `../` or be absolute (`/etc/cron.d/x`). Naive extractors write outside
the destination. A ZIP entry can also be a **symlink** (external attributes with `S_IFLNK`),
so extracting then following it reads an arbitrary host file. In CTF both directions appear:
you exploit it against a service, or you must notice it to understand the archive.

## Attack

### bkcrack workflow

```bash
# 0. list entries with their compressed sizes and methods
bkcrack -L chal.zip

# 1. build the known plaintext. Case A: a 'stored' entry (method 0)
#    known bytes == file bytes, e.g. a PNG header
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' > plain.bin

#    Case B: you have the original file and the entry is deflated -
#    deflate it and strip the 2-byte zlib header / 4-byte adler trailer
python3 - <<'PY'
import zlib
raw = open("known_original.txt","rb").read()
c = zlib.compressobj(9, zlib.DEFLATED, -15)   # -15 = raw deflate, no header
open("plain.bin","wb").write(c.compress(raw) + c.flush())
PY

# 2. recover the internal keys (needs >= 12 contiguous known bytes)
bkcrack -C chal.zip -c secret.txt -p plain.bin

#    ... with an offset, if the known bytes start later in the stream
bkcrack -C chal.zip -c secret.txt -p plain.bin -o 100

#    ... or with sparse known bytes at given offsets
bkcrack -C chal.zip -c secret.txt -x 0 504b0304 -x 30 666c6167

# 3. use the keys: decrypt one entry
bkcrack -C chal.zip -c secret.txt -k 12345678 9abcdef0 13579bdf -d secret.out

# 4. or re-key the whole archive to a password you choose, then unzip normally
bkcrack -C chal.zip -k 12345678 9abcdef0 13579bdf -U cracked.zip newpassword
unzip -P newpassword cracked.zip

# 5. recover the original password from the keys (optional, up to length ~10)
bkcrack -k 12345678 9abcdef0 13579bdf -r 10 '?p'
```

### Password cracking workflow

```bash
# extract the hash
zip2john chal.zip > hash.txt
rar2john chal.rar > hash.txt
7z2john.pl chal.7z > hash.txt

# john with a wordlist and rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Jumbo hash.txt
john --show hash.txt

# hashcat (pick the mode from the table above)
hashcat -m 13600 -a 0 hash.txt rockyou.txt
hashcat -m 17200 -a 3 hash.txt '?l?l?l?l?l?d?d'     # mask attack

# brute-force with fcrackzip for tiny keyspaces (ZipCrypto only)
fcrackzip -u -D -p rockyou.txt chal.zip
fcrackzip -u -b -c a1 -l 1-6 chal.zip
```

### Repair

```bash
# rebuild a zip whose central directory is damaged or offset (prefix polyglot)
zip -FF broken.zip --out fixed.zip
zip -F  broken.zip --out fixed.zip      # lighter-touch fix

# 7z often reads what unzip refuses
7z x -y broken.zip

# carve local file headers directly when the central directory is gone
binwalk -e broken.zip
python3 archive_tool.py headers broken.zip      # see the code below

# check and list without extracting
unzip -t chal.zip
zipdetails -v chal.zip | less
```

## Code

```python
#!/usr/bin/env python3
"""ZIP structure tool: parse local headers, report encryption, detect slip/symlinks and bombs.

Works even when the central directory is missing, by scanning for local file headers.

Usage:
  python3 archive_tool.py headers chal.zip
  python3 archive_tool.py audit   chal.zip
  python3 archive_tool.py --selftest
"""
from __future__ import annotations

import io
import os
import struct
import sys
import zipfile

LFH = b"PK\x03\x04"
CDH = b"PK\x01\x02"
EOCD = b"PK\x05\x06"

METHODS = {0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 99: "AES"}


def parse_local_headers(data: bytes) -> list[dict]:
    """Scan the whole file for local file headers; survives a destroyed central directory."""
    out: list[dict] = []
    pos = 0
    while True:
        idx = data.find(LFH, pos)
        if idx == -1:
            break
        if idx + 30 > len(data):
            break
        (ver, flags, method, mtime, mdate, crc, csize, usize, nlen, elen) = struct.unpack(
            "<HHHHHIIIHH", data[idx + 4:idx + 30])
        name = data[idx + 30:idx + 30 + nlen]
        extra = data[idx + 30 + nlen:idx + 30 + nlen + elen]
        out.append({
            "offset": idx,
            "name": name.decode("utf-8", "replace"),
            "raw_name": name,
            "method": METHODS.get(method, str(method)),
            "method_id": method,
            "encrypted": bool(flags & 0x1),
            "data_descriptor": bool(flags & 0x8),
            "utf8_name": bool(flags & 0x800),
            "crc32": crc,
            "csize": csize,
            "usize": usize,
            "extra_ids": [struct.unpack("<H", extra[i:i + 2])[0] for i in range(0, max(0, len(extra) - 3), 4)
                          if i + 2 <= len(extra)],
            "extra": extra,
        })
        pos = idx + 4
    return out


def aes_entry(entry: dict) -> bool:
    """AES entries use method 99 and carry a 0x9901 extra field."""
    if entry["method_id"] == 99:
        return True
    return b"\x01\x99" in entry["extra"] or 0x9901 in entry["extra_ids"]


def zip_offset_delta(data: bytes) -> int | None:
    idx = data.rfind(EOCD)
    if idx == -1 or idx + 22 > len(data):
        return None
    cd_size, cd_off = struct.unpack("<II", data[idx + 12:idx + 20])
    return (idx - cd_size) - cd_off


def unsafe_name(name: str) -> str | None:
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return "absolute path"
    parts = name.replace("\\", "/").split("/")
    if ".." in parts:
        return "path traversal (zip slip)"
    return None


def audit(path: str) -> list[str]:
    data = open(path, "rb").read()
    notes: list[str] = []
    entries = parse_local_headers(data)
    notes.append(f"{len(entries)} local file headers, file is {len(data)} bytes")

    delta = zip_offset_delta(data)
    if delta:
        notes.append(f"!! central directory offsets shifted by {delta} bytes "
                     f"-> prefix polyglot; fix with: zip -FF {path} --out fixed.zip")
    elif delta is None:
        notes.append("!! no End Of Central Directory record: truncated or carved archive. "
                     "Recover with `zip -FF` or by reading the local headers above.")

    total_u = total_c = 0
    for e in entries:
        total_u += e["usize"]
        total_c += e["csize"]
        flags = []
        if e["encrypted"]:
            flags.append("AES" if aes_entry(e) else "ZipCrypto")
        if e["data_descriptor"]:
            flags.append("data-descriptor (sizes after data)")
        reason = unsafe_name(e["name"])
        if reason:
            flags.append("!! " + reason)
        notes.append(f"  @0x{e['offset']:08x} {e['name']!r} {e['method']} "
                     f"csize={e['csize']} usize={e['usize']} {' '.join(flags)}")

    enc = [e for e in entries if e["encrypted"]]
    if enc:
        if all(aes_entry(e) for e in enc):
            notes.append("=> AES encryption: bkcrack will NOT help. Crack the password: "
                         "zip2john + john, or hashcat -m 13600")
        else:
            stored = [e for e in enc if e["method_id"] == 0]
            notes.append("=> ZipCrypto: known-plaintext attack applies (bkcrack). "
                         "You need 12 contiguous known bytes of the COMPRESSED stream.")
            if stored:
                notes.append(f"   entries stored uncompressed (plaintext == file bytes): "
                             f"{[e['name'] for e in stored]}")

    if total_c and total_u / max(1, total_c) > 200:
        notes.append(f"!! compression ratio {total_u / total_c:.0f}x -> possible zip bomb; "
                     f"extract with a size cap")

    # symlinks are visible through the external attributes in the central directory
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        for info in zf.infolist():
            mode = info.external_attr >> 16
            if mode and (mode & 0xF000) == 0xA000:
                notes.append(f"!! symlink entry {info.filename!r} -> {zf.read(info)!r}")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        notes.append(f"(zipfile could not open it: {exc})")
    return notes


def safe_extract(path: str, dest: str, max_total: int = 200 * 1024 * 1024) -> list[str]:
    """Extract with traversal and size-bomb protection."""
    os.makedirs(dest, exist_ok=True)
    dest_abs = os.path.abspath(dest)
    written: list[str] = []
    total = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            target = os.path.abspath(os.path.join(dest_abs, info.filename))
            if not target.startswith(dest_abs + os.sep) and target != dest_abs:
                print(f"[!] refusing traversal entry {info.filename!r}")
                continue
            total += info.file_size
            if total > max_total:
                print(f"[!] size cap hit at {info.filename!r} ({total} bytes) - stopping")
                break
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                dst.write(src.read())
            written.append(target)
    return written


def deflate_raw(data: bytes, level: int = 9) -> bytes:
    """Raw deflate stream (no zlib header/trailer) - the plaintext format bkcrack wants."""
    import zlib
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def main() -> int:
    cmd = sys.argv[1]
    if cmd == "headers":
        for e in parse_local_headers(open(sys.argv[2], "rb").read()):
            print(f"@0x{e['offset']:08x} {e['name']!r} {e['method']} "
                  f"enc={e['encrypted']} csize={e['csize']} usize={e['usize']}")
    elif cmd == "audit":
        for line in audit(sys.argv[2]):
            print(line)
    elif cmd == "extract":
        for p in safe_extract(sys.argv[2], sys.argv[3]):
            print("[+] " + p)
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    import tempfile

    tmp = tempfile.mkdtemp()
    zpath = os.path.join(tmp, "t.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", "hello world\n" * 10)
        zf.writestr("../../escape.txt", "traversal")
        zf.writestr("big.txt", "A" * 500000)
        info = zipfile.ZipInfo("stored.bin")
        info.compress_type = zipfile.ZIP_STORED
        zf.writestr(info, b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

    data = open(zpath, "rb").read()
    entries = parse_local_headers(data)
    names = [e["name"] for e in entries]
    assert "readme.txt" in names and "../../escape.txt" in names, names
    assert unsafe_name("../../escape.txt") == "path traversal (zip slip)"
    assert unsafe_name("/etc/passwd") == "absolute path"
    assert unsafe_name("ok/fine.txt") is None
    stored = [e for e in entries if e["method_id"] == 0]
    assert stored and stored[0]["name"] == "stored.bin"
    assert zip_offset_delta(data) == 0

    notes = audit(zpath)
    assert any("zip slip" in n for n in notes), notes
    assert any("compression ratio" in n for n in notes), notes

    out = os.path.join(tmp, "out")
    written = safe_extract(zpath, out)
    assert all(os.path.abspath(p).startswith(os.path.abspath(out)) for p in written)
    assert not any("escape.txt" in p for p in written), written

    # prefix polyglot detection
    poly_path = os.path.join(tmp, "poly.zip")
    with open(poly_path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\nJUNKJUNK" + data)
    assert zip_offset_delta(open(poly_path, "rb").read()) == 16

    assert deflate_raw(b"AAAA" * 20)[:1] != b"\x78"
    print(f"selftest ok: {len(entries)} headers parsed, zip slip blocked, bomb ratio flagged, "
          f"polyglot delta detected")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--selftest":
        sys.exit(main())
    _selftest()
```

## Variants and pitfalls

- **bkcrack needs the compressed plaintext.** The single most common mistake is feeding it the
  original file when the entry is deflated. Use `-L` to check the method first; if it is
  `Deflate`, deflate your known bytes with a raw deflate stream.
- **12 bytes is the minimum, but more is much faster.** With only 12 bytes expect a long run;
  with 30+ bytes it is usually under a minute.
- **AES zips are immune** to the known-plaintext attack. If `zipdetails` shows extra field
  `0x9901`, stop and crack the password.
- **`unzip` on macOS/BSD vs Info-ZIP** differ in what they accept. Have both `unzip` and `7z`.
- **Entry names leak the answer.** A ZIP listing does not require the password; sometimes the
  filenames alone are the flag.
- **Data descriptors** (general purpose bit 3) mean `csize`/`usize` in the local header are
  zero and the real values follow the data with signature `PK\x07\x08`. Parsers that trust the
  local header report nonsense.
- **`zip -FF` asks interactively**; feed it `y` or use `--out` with `-q`.
- **Never extract an unknown archive into your working directory.** Use a fresh directory and a
  size cap, exactly as `safe_extract` does.
- **RAR5 vs RAR3** need different john formats; `rar2john` picks automatically but hashcat
  needs the right `-m`.
- **Self-extracting archives** (`.exe`) are a PE with a zip appended - carve it, then treat it
  as a normal zip.

## Tools

`bkcrack`, `zip2john`/`rar2john`/`7z2john`, `john` (jumbo), `hashcat`, `fcrackzip`, `unzip`,
`zip` (Info-ZIP, for `-FF`/`-F`/`-A`), `7z`, `zipdetails` (ships with Perl), `binwalk`,
Python `zipfile`.

## References

- PKWARE APPNOTE.TXT - ZIP local file header, central directory, data descriptor, and the
  AES extra field `0x9901`.
- Biham and Kocher, "A Known Plaintext Attack on the PKZIP Stream Cipher" (1994) - the basis
  for bkcrack.
- David Fifield, "A better zip bomb" (2019) - the non-recursive overlapping construction.
- hashcat's `--help` output is the authoritative list of the mode numbers tabulated above.
