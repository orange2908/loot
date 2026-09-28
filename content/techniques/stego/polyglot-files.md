---
title: "Polyglots and Appended Data"
category: stego
subcategory: polyglot
type: technique
tags: [polyglot, appended-data, magic-bytes, carving, binwalk, foremost, dd, zip, phar, gzip, tar, pdf, gif, file-signature, zip-central-directory, stego]
difficulty: medium
summary: "Most parsers ignore leading or trailing garbage, so one file can be a valid PNG and a valid ZIP at once; carve by magic, then fix offsets."
when_to_use:
  - "file reports one type but the size or content suggests another"
  - "binwalk shows a second file signature at a non-zero offset"
  - "unzip/7z succeeds on something that is not named .zip"
  - "A challenge hints at 'two files in one' or the same file has two valid uses"
tools: [binwalk, foremost, dd, file, unzip, 7z, zipdetails, python3, xxd, gzip, tar]
related: [image-triage, archive-attacks, png-structure-attacks, jpeg-structure-attacks, stego-cheatsheet, misc-classics]
---

## TL;DR

A polyglot is one byte string that is simultaneously valid in two or more formats. It works
because format parsers are permissive in complementary ways: PNG/JPEG/GIF read from the *start*
and stop at their end marker, while ZIP/RAR read the central directory from the *end*. Appending
a ZIP to a PNG therefore yields a file both `display` and `unzip` accept.

## Recognise it

- `binwalk chal.png` lists a second signature at a non-zero offset.
- `unzip -l chal.png` prints a file listing.
- The image renders but is 10x bigger than similar images.
- `file` says `JPEG image data` and `7z l` also says `7-Zip archive`.
- The last bytes are not the format's terminator (`IEND`, `FFD9`, `\x00\x3b`).
- `gzip -t` succeeds on something that is not a `.gz`.

## Theory

### Why it works

| Format | Anchored at | Tolerates |
| --- | --- | --- |
| PNG | start (8-byte signature) | anything after `IEND` |
| JPEG | start (`FFD8`) | anything after `FFD9`; also `COM`/`APPn` payloads |
| GIF | start (`GIF8?a`) | anything after the `0x3B` trailer |
| ZIP | **end** (End of Central Directory record, scanned backwards) | anything before the first local header |
| RAR/7z | start marker, but 7z tolerates a prefix in some tools | |
| PDF | `%PDF` within the first 1024 bytes; `startxref` at the end | leading and trailing junk |
| PHAR | a `__HALT_COMPILER();` stub anywhere, manifest after it | any prefix, which is why `phar+jpg` works |
| gzip | start (`1f 8b`) | concatenated members (`gzip` decompresses all of them) |
| TAR | 512-byte blocks with a checksum in each header | |
| Java class / jar | jar is a zip, so same end-anchoring | |

The ZIP specification says offsets in the central directory are relative to the **start of the
archive**, and tools locate the archive by scanning back for the EOCD signature `PK\x05\x06`.
When you append a ZIP to an image, all the stored offsets are now short by the image's length.
Most tools cope (`unzip` prints a warning about "extra bytes at beginning") but strict ones do
not; `zip -FF` or `zip -A` (adjust offsets for a self-extracting archive) rewrites them.

### Common CTF polyglots

- `png + zip` / `jpg + zip` - the single most common one.
- `gif + js` - a GIF header is `GIF89a`, which in JS is a valid identifier expression if you
  define `GIF89a=1`, so the same bytes are a script and an image (used in XSS challenges).
- `jpg + phar` - PHP's phar parser scans for `__HALT_COMPILER();` so the JPEG can be the prefix;
  used for deserialization RCE via `phar://`.
- `pdf + zip` - both tolerate their content anywhere, making an extremely common pair.
- `gzip` chains / `tar` chains - the challenge gives you `flag.gz`, which decompresses to
  another `.gz`, 1000 times. Script it.
- `iso + everything` - an ISO's first 32 KB is unused, so any header fits.

## Attack

```bash
# 1. identify every signature in the file, with offsets
binwalk chal.png
binwalk -B chal.png        # signature scan only, quieter

# 2. auto-extract (writes _chal.png.extracted/)
binwalk -e --dd='.*' chal.png

# 3. header-based carving when binwalk misses it
foremost -i chal.png -o foremost_out
scalpel -c /etc/scalpel/scalpel.conf -o out chal.png

# 4. manual carve at a known offset (bs=1 is slow but exact)
dd if=chal.png bs=1 skip=54321 of=carved.zip
# faster equivalent in python: open(...).read()[54321:]

# 5. try the archive tools directly - they will find the EOCD themselves
unzip -l chal.png
7z l chal.png
7z x chal.png -oout/

# 6. fix a ZIP whose offsets are shifted by the prefix
zip -FF chal.png --out fixed.zip
zip -A fixed.zip                 # adjust offsets of a self-extracting archive
zipdetails -v fixed.zip | head -50

# 7. decompression chains
while file flag | grep -q 'gzip\|bzip2\|XZ\|Zip'; do
  mv flag flag.bin
  7z x -y flag.bin -oout >/dev/null && mv out/* flag
done
```

## Code

```python
#!/usr/bin/env python3
"""Polyglot carver: scan for every known magic, carve candidates, unwrap chains.

Usage:
  python3 polyglot.py scan  chal.png
  python3 polyglot.py carve chal.png outdir
  python3 polyglot.py chain flag.gz outdir
  python3 polyglot.py --selftest
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import struct
import sys
import zlib

# magic -> (name, extension). Longer magics first so the scan prefers specific matches.
MAGICS: list[tuple[bytes, str, str]] = [
    (b"\x89PNG\r\n\x1a\n", "png", "png"),
    (b"\xff\xd8\xff", "jpeg", "jpg"),
    (b"GIF87a", "gif", "gif"),
    (b"GIF89a", "gif", "gif"),
    (b"PK\x03\x04", "zip-local-header", "zip"),
    (b"PK\x05\x06", "zip-eocd", "zip"),
    (b"Rar!\x1a\x07\x00", "rar4", "rar"),
    (b"Rar!\x1a\x07\x01\x00", "rar5", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7z"),
    (b"\x1f\x8b\x08", "gzip", "gz"),
    (b"BZh9", "bzip2", "bz2"),
    (b"\xfd7zXZ\x00", "xz", "xz"),
    (b"%PDF-", "pdf", "pdf"),
    (b"\x7fELF", "elf", "elf"),
    (b"MZ", "pe-dos", "exe"),
    (b"\xca\xfe\xba\xbe", "java-class", "class"),
    (b"OggS", "ogg", "ogg"),
    (b"RIFF", "riff", "riff"),
    (b"ID3", "mp3-id3", "mp3"),
    (b"\x00\x00\x00\x18ftyp", "mp4", "mp4"),
    (b"\x1aE\xdf\xa3", "matroska", "mkv"),
    (b"SQLite format 3\x00", "sqlite", "db"),
    (b"-----BEGIN ", "pem", "pem"),
    (b"__HALT_COMPILER();", "phar-stub", "phar"),
    (b"ustar", "tar(at offset 257)", "tar"),
]

TRAILERS = {
    "png": b"IEND\xaeB`\x82",
    "jpeg": b"\xff\xd9",
    "gif": b"\x00\x3b",
}


def scan(data: bytes, min_offset: int = 0) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    for magic, name, ext in MAGICS:
        if len(magic) < 3:
            continue
        pos = min_offset
        while True:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            hits.append((idx, name, ext))
            pos = idx + 1
    return sorted(hits)


def container_kind(data: bytes) -> str | None:
    for magic, name, _ext in MAGICS:
        if data.startswith(magic):
            return name
    return None


def trailing_after_marker(data: bytes, kind: str) -> tuple[int, bytes]:
    trailer = TRAILERS.get(kind)
    if not trailer:
        return 0, b""
    idx = data.rfind(trailer)
    if idx == -1:
        return 0, b""
    end = idx + len(trailer)
    return end, data[end:]


def find_eocd(data: bytes) -> int:
    """Offset of the ZIP End Of Central Directory record, searching backwards."""
    idx = data.rfind(b"PK\x05\x06")
    return idx


def zip_offset_delta(data: bytes) -> int | None:
    """How far the real archive start is from what the EOCD claims (the prefix length)."""
    eocd = find_eocd(data)
    if eocd == -1 or eocd + 22 > len(data):
        return None
    cd_size, cd_off = struct.unpack("<II", data[eocd + 12:eocd + 20])
    real_cd = eocd - cd_size
    return real_cd - cd_off


def carve(data: bytes, outdir: str) -> list[str]:
    os.makedirs(outdir, exist_ok=True)
    written: list[str] = []
    kind = container_kind(data)
    if kind:
        end, tail = trailing_after_marker(data, kind)
        if tail:
            p = os.path.join(outdir, f"trailing_at_{end}.bin")
            with open(p, "wb") as fh:
                fh.write(tail)
            written.append(p)
    for off, name, ext in scan(data, min_offset=1):
        if off == 0:
            continue
        p = os.path.join(outdir, f"{off:08x}_{name.replace('(', '').replace(')', '').replace(' ', '_')}.{ext}")
        with open(p, "wb") as fh:
            fh.write(data[off:])
        written.append(p)
    return written


def unwrap_once(data: bytes) -> tuple[bytes, str] | None:
    """Decompress one layer if the data is a known single-file compression format."""
    if data.startswith(b"\x1f\x8b\x08"):
        return gzip.decompress(data), "gzip"
    if data.startswith(b"BZh"):
        return bz2.decompress(data), "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return lzma.decompress(data), "xz"
    if data.startswith(b"\x78\x01") or data.startswith(b"\x78\x9c") or data.startswith(b"\x78\xda"):
        return zlib.decompress(data), "zlib"
    if data.startswith(b"PK\x03\x04"):
        import zipfile
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
        if len(names) == 1:
            return zf.read(names[0]), f"zip:{names[0]}"
    return None


def unwrap_chain(data: bytes, max_depth: int = 2000) -> tuple[bytes, list[str]]:
    """Peel nested compression layers until the data is no longer a known archive."""
    trail: list[str] = []
    for _ in range(max_depth):
        step = unwrap_once(data)
        if step is None:
            break
        data, kind = step
        trail.append(kind)
    return data, trail


def main() -> int:
    cmd = sys.argv[1]
    if cmd == "scan":
        data = open(sys.argv[2], "rb").read()
        print(f"container: {container_kind(data)} ({len(data)} bytes)")
        delta = zip_offset_delta(data)
        if delta is not None:
            print(f"zip EOCD present; offsets are shifted by {delta} bytes "
                  f"({'prefix polyglot' if delta else 'plain zip'})")
        for off, name, _ext in scan(data, 1):
            print(f"  @0x{off:08x} ({off:>10}) {name}")
    elif cmd == "carve":
        data = open(sys.argv[2], "rb").read()
        for p in carve(data, sys.argv[3]):
            print("[+] " + p)
    elif cmd == "chain":
        data = open(sys.argv[2], "rb").read()
        out, trail = unwrap_chain(data)
        print(f"peeled {len(trail)} layers: {' -> '.join(trail[:20])}{' ...' if len(trail) > 20 else ''}")
        dest = os.path.join(sys.argv[3] if len(sys.argv) > 3 else ".", "final.bin")
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(out)
        print(f"[+] {dest}: {out[:120]!r}")
    else:
        print(__doc__)
        return 1
    return 0


def _make_png() -> bytes:
    def ch(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes([i % 256] * 6) for i in range(2))
    return b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", ihdr) + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b"")


def _selftest() -> None:
    import tempfile
    import zipfile

    png = _make_png()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("flag.txt", "flag{polyglot}")
    zdata = buf.getvalue()
    poly = png + zdata

    assert container_kind(poly) == "png"
    hits = dict((name, off) for off, name, _ in scan(poly, 1))
    assert "zip-local-header" in hits and hits["zip-local-header"] == len(png)
    assert zip_offset_delta(poly) == len(png), zip_offset_delta(poly)
    end, tail = trailing_after_marker(poly, "png")
    assert tail == zdata and end == len(png)

    # the appended zip is still readable by the standard library
    zf = zipfile.ZipFile(io.BytesIO(poly))
    assert zf.read("flag.txt") == b"flag{polyglot}"

    tmp = tempfile.mkdtemp()
    written = carve(poly, tmp)
    assert any(p.endswith(".zip") for p in written), written

    # compression chain
    blob = b"flag{deep}"
    for _ in range(25):
        blob = gzip.compress(blob)
    out, trail = unwrap_chain(blob)
    assert out == b"flag{deep}" and len(trail) == 25, (out, len(trail))
    print(f"selftest ok: png+zip polyglot detected (delta={len(png)}), 25-layer gzip chain peeled")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--selftest":
        sys.exit(main())
    _selftest()
```

## Variants and pitfalls

- **`binwalk -e` writes into `_file.extracted/`** and silently skips signatures it cannot
  extract. Always cross-check with `binwalk` (no `-e`) plus a manual carve.
- **False positives are the norm.** Short magics (`MZ`, `BM`, `RIFF`) appear in random data
  constantly. Trust hits whose offset lands right after a format terminator.
- **`unzip` warning "extra bytes at beginning or within zipfile"** is the confirmation that you
  have a prefix polyglot; `zip -FF in.png --out fixed.zip` normalises it.
- **Carving from the magic to EOF is usually enough.** Archive and image parsers stop at their
  own end marker, so you rarely need an exact end offset.
- **`dd bs=1` is O(n) syscalls** and painfully slow on large files. Use `bs=1M skip=N
  iflag=skip_bytes` (GNU) or just Python slicing.
- **Nested chains** can be thousands deep; always loop rather than doing it by hand, and set a
  depth limit so a zip bomb does not fill your disk (see `archive-attacks`).
- **A phar polyglot needs the stub**, not just the magic - PHP looks for `__HALT_COMPILER();`
  followed by the manifest. The file extension is irrelevant to `phar://`.
- **PDF polyglots** may have the `%PDF` header at a nonzero offset (legal within the first 1024
  bytes), which defeats naive `file` checks.
- **Do not overwrite the original.** Carving is lossless only if you keep the source file.

## Tools

`binwalk`, `foremost`, `scalpel`, `dd`, `file`, `unzip`/`zip`/`7z`, `zipdetails`, `gzip`,
`tar`, `xxd`, Python `zipfile`/`gzip`/`bz2`/`lzma`/`zlib`.

## References

- PKWARE APPNOTE.TXT (the ZIP file format specification) for the End Of Central Directory
  record and the offset semantics that make prefix polyglots work.
- Ange Albertini's published work on file format polyglots (the "Corkami" file format posters)
  documents many of the format-tolerance rules above.
- PHP manual, Phar file format: the `__HALT_COMPILER();` stub requirement.
