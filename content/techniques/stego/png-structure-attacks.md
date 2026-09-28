---
title: "PNG - Structure and Chunk Attacks"
category: stego
subcategory: png
type: technique
tags: [png, ihdr, idat, iend, crc32, chunk, pngcheck, zlib, deflate, adler32, dimensions, text-chunk, ztxt, itxt, corrupted-header, stego]
difficulty: medium
summary: "PNG is a chunk container with CRCs. Fix the CRCs, brute the real dimensions, unpack the IDAT zlib stream, and read what was hidden between chunks."
when_to_use:
  - "pngcheck reports a CRC error on IHDR or an unexpected chunk"
  - "The image renders but looks cropped or the wrong aspect ratio"
  - "file says 'data' but the first 8 bytes are almost the PNG signature"
  - "There is data after IEND or between IDAT chunks"
tools: [pngcheck, exiftool, zlib, python3, binwalk, convert]
related: [image-triage, lsb-extraction, metadata-hiding, polyglot-files, stego-cheatsheet, image-forensics-cheatsheet]
---

## TL;DR

A PNG is `signature + a sequence of length/type/data/CRC32 chunks`. Every field is checkable,
so every edit an author made is detectable. The four classic attacks are: a broken signature,
a lying `IHDR` width/height (CRC will not match, and the true size is brute-forceable), payload
smuggled in ancillary chunks or between `IDAT`s, and hand-crafted zlib inside `IDAT`.

## Recognise it

- `pngcheck -vv` prints `CRC error in chunk IHDR (computed XXXXXXXX, expected YYYYYYYY)`.
- The image opens but is squat/stretched, or the bottom is missing.
- `pngcheck` lists a chunk type you do not recognise (`stEG`, `haXX`, a lowercase-first type).
- Multiple `IDAT` chunks where one is a wildly different size from its neighbours.
- `zlib.decompress` on the concatenated IDAT data leaves trailing bytes (`decompressobj.unused_data`).
- Bytes present after the `IEND` chunk.

## Theory

### Layout

```text
89 50 4E 47 0D 0A 1A 0A        8-byte signature
<chunk> <chunk> ... <chunk>

chunk = length(4, big-endian, of DATA only)
        type(4 ASCII)
        data(length bytes)
        crc(4, CRC-32 of TYPE+DATA, not of length)
```

Chunk type casing is meaningful:

| Bit | Position | 0 (uppercase) | 1 (lowercase) |
| --- | --- | --- | --- |
| 5 of byte 0 | ancillary | critical | ancillary (safe to ignore) |
| 5 of byte 1 | private | public | private |
| 5 of byte 2 | reserved | must be uppercase | invalid |
| 5 of byte 3 | safe-to-copy | not safe | safe to copy |

So `stEG` is an ancillary, private, safe-to-copy chunk - exactly what a challenge author would
invent to carry a payload, and decoders silently ignore it.

### IHDR

13 bytes, always the first chunk:

```text
width      4 bytes (big-endian, must be > 0)
height     4 bytes
bit depth  1 byte (1,2,4,8,16)
colour typ 1 byte (0 gray, 2 rgb, 3 palette, 4 gray+alpha, 6 rgba)
compress   1 byte (always 0)
filter     1 byte (always 0)
interlace  1 byte (0 none, 1 Adam7)
```

If the author edited width or height, the stored CRC is the one for the *original* values.
That means you can brute-force the true dimensions: iterate candidate widths/heights, recompute
the CRC over `b"IHDR" + candidate_data`, and stop when it equals the stored CRC.

### IDAT

All `IDAT` chunk data concatenated forms **one** zlib stream. After inflating you get scanlines:
each row is `1 filter byte + width * bytes_per_pixel` bytes. Filters are None/Sub/Up/Average/Paeth.
Tricks authors use:

- Extra bytes appended to the zlib stream (visible as `unused_data`).
- A second, independent zlib stream concatenated after the first.
- Deliberately wrong Adler-32 (use `zlib.decompressobj(-15)` raw inflate to ignore it).
- Payload in the padding of the final scanline when width is not byte-aligned at bit depth 1/2/4.

## Attack

1. `pngcheck -vv file.png` and read every line. It names the broken chunk.
2. If the signature is wrong, restore `89 50 4E 47 0D 0A 1A 0A` verbatim.
3. If `IHDR` CRC is bad, brute width/height against the stored CRC, patch, re-render.
4. Dump every chunk. Print all ancillary chunk data as text and as hex.
5. Concatenate IDATs, raw-inflate, and inspect `unused_data` and the tail of the output.
6. Carve anything after `IEND`.
7. Only then move on to LSB (`zsteg -a`).

## Code

Complete chunk parser, CRC checker, dimension brute-forcer and repair tool.

```python
#!/usr/bin/env python3
"""PNG structure toolkit: parse, verify, brute-force dimensions, repair, extract.

Usage:
  python3 png_tool.py list    chal.png
  python3 png_tool.py brute   chal.png [--max 4000]
  python3 png_tool.py fix     chal.png out.png
  python3 png_tool.py extract chal.png outdir
  python3 png_tool.py --selftest
"""
from __future__ import annotations

import os
import struct
import sys
import zlib

SIG = b"\x89PNG\r\n\x1a\n"


class Chunk:
    def __init__(self, offset: int, length: int, typ: bytes, data: bytes, crc: int):
        self.offset = offset
        self.length = length
        self.typ = typ
        self.data = data
        self.crc = crc

    @property
    def computed_crc(self) -> int:
        return zlib.crc32(self.typ + self.data) & 0xFFFFFFFF

    @property
    def ok(self) -> bool:
        return self.crc == self.computed_crc

    @property
    def ancillary(self) -> bool:
        return bool(self.typ[0] & 0x20)

    def raw(self) -> bytes:
        return (
            struct.pack(">I", len(self.data))
            + self.typ
            + self.data
            + struct.pack(">I", self.computed_crc)
        )

    def __repr__(self) -> str:
        flag = "OK " if self.ok else "BAD"
        return (
            f"{flag} @0x{self.offset:08x} {self.typ.decode('latin1'):>4} "
            f"len={self.length:<8} crc={self.crc:08x} computed={self.computed_crc:08x}"
        )


def parse(data: bytes) -> tuple[list[Chunk], bytes]:
    """Return (chunks, trailing_bytes). Tolerates a broken signature."""
    if not data.startswith(SIG):
        print(f"[!] bad signature: {data[:8].hex()} (expected {SIG.hex()})", file=sys.stderr)
    pos = 8
    chunks: list[Chunk] = []
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        typ = data[pos + 4:pos + 8]
        if length > len(data):  # nonsense length -> stop, rest is trailing junk
            break
        body = data[pos + 8:pos + 8 + length]
        crc_bytes = data[pos + 8 + length:pos + 12 + length]
        if len(crc_bytes) < 4:
            break
        (crc,) = struct.unpack(">I", crc_bytes)
        chunks.append(Chunk(pos, length, typ, body, crc))
        pos += 12 + length
        if typ == b"IEND":
            break
    return chunks, data[pos:]


def brute_dimensions(ihdr: Chunk, max_dim: int = 4096) -> list[tuple[int, int]]:
    """Find (w, h) pairs whose IHDR reproduces the stored CRC."""
    tail = ihdr.data[8:]  # depth, colour, compression, filter, interlace
    target = ihdr.crc
    found: list[tuple[int, int]] = []
    # Fast path: one dimension is usually correct. Try holding each fixed.
    w0, h0 = struct.unpack(">II", ihdr.data[:8])
    for h in range(1, max_dim + 1):
        cand = struct.pack(">II", w0, h) + tail
        if zlib.crc32(b"IHDR" + cand) & 0xFFFFFFFF == target:
            found.append((w0, h))
    for w in range(1, max_dim + 1):
        cand = struct.pack(">II", w, h0) + tail
        if zlib.crc32(b"IHDR" + cand) & 0xFFFFFFFF == target:
            found.append((w, h0))
    return sorted(set(found))


def fix_crcs(data: bytes) -> bytes:
    """Rebuild the file with every CRC recomputed and the signature restored."""
    chunks, trailing = parse(data)
    out = SIG + b"".join(c.raw() for c in chunks)
    if trailing:
        print(f"[i] dropping {len(trailing)} trailing bytes (saved separately)", file=sys.stderr)
    return out


def idat_stream(chunks: list[Chunk]) -> bytes:
    return b"".join(c.data for c in chunks if c.typ == b"IDAT")


def inflate_report(stream: bytes) -> tuple[bytes, bytes]:
    """Raw-inflate the IDAT stream, returning (pixels, leftover)."""
    d = zlib.decompressobj()
    try:
        out = d.decompress(stream)
        out += d.flush()
        return out, d.unused_data
    except zlib.error:
        d = zlib.decompressobj(-15)  # raw deflate, ignores zlib header and adler32
        out = d.decompress(stream[2:])
        return out, d.unused_data


def decode_text_chunk(c: Chunk) -> str:
    if c.typ == b"tEXt":
        key, _, val = c.data.partition(b"\x00")
        return f"{key.decode('latin1')}={val.decode('latin1')}"
    if c.typ == b"zTXt":
        key, _, rest = c.data.partition(b"\x00")
        try:
            val = zlib.decompress(rest[1:])
        except zlib.error:
            val = rest[1:]
        return f"{key.decode('latin1')}={val.decode('latin1', 'replace')}"
    if c.typ == b"iTXt":
        parts = c.data.split(b"\x00", 5)
        return "iTXt:" + "|".join(p.decode("utf-8", "replace") for p in parts)
    return ""


def cmd_list(path: str) -> None:
    data = open(path, "rb").read()
    chunks, trailing = parse(data)
    for c in chunks:
        print(c)
        if c.typ in (b"tEXt", b"zTXt", b"iTXt"):
            print("    " + decode_text_chunk(c))
        elif c.ancillary and c.typ not in (b"pHYs", b"gAMA", b"cHRM", b"sRGB", b"bKGD", b"tIME", b"sBIT"):
            print(f"    unusual ancillary chunk, first bytes: {c.data[:48]!r}")
    if chunks and chunks[0].typ == b"IHDR":
        w, h, depth, ctype, _, _, inter = struct.unpack(">IIBBBBB", chunks[0].data)
        print(f"[i] IHDR {w}x{h} depth={depth} colour={ctype} interlace={inter}")
    if trailing:
        print(f"[!] {len(trailing)} bytes after IEND: {trailing[:32]!r}")
    stream = idat_stream(chunks)
    if stream:
        pixels, leftover = inflate_report(stream)
        print(f"[i] IDAT inflates to {len(pixels)} bytes; leftover={len(leftover)}")
        if leftover:
            print(f"[!] leftover bytes: {leftover[:64]!r}")


def cmd_brute(path: str, max_dim: int) -> None:
    data = open(path, "rb").read()
    chunks, _ = parse(data)
    ihdr = chunks[0]
    if ihdr.ok:
        print("[i] IHDR CRC is valid, dimensions were not tampered with")
    for w, h in brute_dimensions(ihdr, max_dim):
        print(f"[+] CRC matches for {w}x{h}")


def cmd_fix(path: str, out: str) -> None:
    data = open(path, "rb").read()
    open(out, "wb").write(fix_crcs(data))
    print(f"[+] wrote {out}")


def cmd_extract(path: str, outdir: str) -> None:
    data = open(path, "rb").read()
    chunks, trailing = parse(data)
    os.makedirs(outdir, exist_ok=True)
    for i, c in enumerate(chunks):
        if c.typ in (b"IHDR", b"IDAT", b"IEND", b"PLTE"):
            continue
        p = os.path.join(outdir, f"{i:03d}_{c.typ.decode('latin1')}.bin")
        open(p, "wb").write(c.data)
        print(f"[+] {p} ({len(c.data)} bytes)")
    if trailing:
        p = os.path.join(outdir, "trailing.bin")
        open(p, "wb").write(trailing)
        print(f"[+] {p} ({len(trailing)} bytes)")
    stream = idat_stream(chunks)
    if stream:
        pixels, leftover = inflate_report(stream)
        open(os.path.join(outdir, "idat_inflated.bin"), "wb").write(pixels)
        if leftover:
            open(os.path.join(outdir, "idat_leftover.bin"), "wb").write(leftover)


def _mkpng(w: int, h: int) -> bytes:
    raw = b"".join(b"\x00" + bytes([(x * 7 + y * 3) % 256 for x in range(w * 3)]) for y in range(h))

    def ch(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return SIG + ch(b"IHDR", ihdr) + ch(b"tEXt", b"Comment\x00flag{chunky}") + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b"")


def _selftest() -> None:
    png = _mkpng(37, 21)
    chunks, trailing = parse(png)
    assert all(c.ok for c in chunks), "fresh PNG must have valid CRCs"
    assert trailing == b""
    assert "flag{chunky}" in decode_text_chunk(chunks[1])

    # Tamper with the height, leaving the CRC alone, then recover it.
    ihdr_data = chunks[0].data
    bad = ihdr_data[:4] + struct.pack(">I", 5) + ihdr_data[8:]
    tampered = Chunk(8, 13, b"IHDR", bad, chunks[0].crc)
    assert not tampered.ok
    found = brute_dimensions(tampered, max_dim=64)
    assert (37, 21) in found, f"expected 37x21 in {found}"

    pixels, leftover = inflate_report(idat_stream(chunks))
    assert leftover == b""
    assert len(pixels) == 21 * (1 + 37 * 3)
    print("selftest ok: parse, crc, text chunk, dimension brute-force, inflate")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    cmd = sys.argv[1]
    if cmd == "list":
        cmd_list(sys.argv[2])
    elif cmd == "brute":
        m = int(sys.argv[4]) if len(sys.argv) > 4 else 4096
        cmd_brute(sys.argv[2], m)
    elif cmd == "fix":
        cmd_fix(sys.argv[2], sys.argv[3])
    elif cmd == "extract":
        cmd_extract(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Shell recipes

```bash
# full structural dump with CRC verification and chunk offsets
pngcheck -vv chal.png

# repair a mangled signature in place (first 8 bytes)
printf '\x89PNG\r\n\x1a\n' | dd of=chal.png bs=1 seek=0 conv=notrunc

# patch width to 0x00000190 (400) at offset 16, height at offset 20
printf '\x00\x00\x01\x90' | dd of=chal.png bs=1 seek=16 conv=notrunc

# pull all text chunks
exiftool -PNG:all -a -u chal.png

# after fixing, confirm it renders
convert chal.png fixed.ppm && identify fixed.ppm
```

## Variants and pitfalls

- **Height too small, not width.** Authors usually shrink the height so the flag is below the
  visible area. Try holding the width fixed first; it is a 4096-iteration loop, instant.
- **Interlaced (Adam7) PNGs** scramble the scanline order. If your inflated data looks like
  seven shrinking passes, that is why; use PIL rather than hand-decoding.
- **Bit depth 1 with colour type 3** is a common LSB-free carrier: the "image" is literally a
  bitmap of the message. Just upscale it and look.
- **Recomputing CRCs hides evidence.** Copy the file before running a `fix` command, because the
  original CRC is the only record of the original dimensions.
- **Two zlib streams in IDAT:** `zlib.decompressobj()` stops at the end of the first stream and
  puts the rest in `unused_data`. Inflate that separately.
- **Ancillary chunks after IEND** are legal to write but no decoder reads them, which makes it a
  favourite hiding spot. `parse()` above stops at IEND and reports the rest as trailing.
- **`pngcheck` exits non-zero** on a valid file that merely has an unknown private chunk. Read
  the message, do not just check the exit code.

## Tools

`pngcheck`, `exiftool`, `binwalk`, Python `zlib`/`struct`, `convert`/`identify` (ImageMagick),
`zsteg` for the pixel-level follow-up, `stegsolve` for visual plane inspection.

## References

- PNG (Portable Network Graphics) Specification, Version 1.2 - chunk layout, CRC, filter types:
  http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html
- RFC 1950 (zlib) and RFC 1951 (DEFLATE) for the IDAT stream format.
