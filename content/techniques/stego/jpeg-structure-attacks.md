---
title: "JPEG - Markers, DCT Stego and Thumbnail Tricks"
category: stego
subcategory: jpeg
type: technique
tags: [jpeg, jpg, markers, soi, eoi, sos, dqt, dht, sof, exif, thumbnail, dct, jsteg, outguess, steghide, jphide, f5, stegseek, stegdetect, stego]
difficulty: medium
summary: "JPEG hides data in APPn segments, after EOI, in a stale EXIF thumbnail, or in DCT coefficients - never in pixel LSBs."
when_to_use:
  - "You have a .jpg and zsteg finds nothing (it cannot work on JPEG)"
  - "exiftool shows a thumbnail that differs from the visible image"
  - "The JPEG is far larger than its visual complexity justifies"
  - "file reports 'JPEG image data' but the image will not open"
tools: [exiftool, stegseek, steghide, outguess, jsteg, stegdetect, binwalk, djpeg, jpeginfo]
related: [image-triage, metadata-hiding, stego-bruteforce, polyglot-files, stego-cheatsheet, image-forensics-cheatsheet]
---

## TL;DR

A JPEG is a stream of marker segments. Payloads live in four places: an `APPn`/`COM` segment,
after the `FFD9` end marker, inside the EXIF thumbnail (which is a *separate* JPEG that is not
regenerated when someone edits the main image), or in the quantised DCT coefficients where
`jsteg`, `steghide`, `outguess`, `jphide` and `F5` write. Pixel-LSB tools are useless here.

## Recognise it

- `exiftool -b -ThumbnailImage chal.jpg > t.jpg` produces a picture that shows *more* than the
  main image. This is the single highest-yield JPEG check.
- `xxd chal.jpg | tail` shows bytes after `FF D9`.
- A `COM` segment or `APP12`/`APP13`/`APP14` segment full of base64 or high-entropy bytes.
- `steghide info chal.jpg` says "the file appears to contain embedded data" when given the
  right passphrase (or `stegseek` cracks it in seconds).
- Unusually flat or duplicated quantisation tables, or a file whose size is far above what
  `identify -verbose` quality suggests.

## Theory

### Marker structure

Every marker is `FF xx`. Most are followed by a 2-byte big-endian length that **includes the
length field itself but not the marker**. `FF 00` inside entropy-coded data is a stuffed byte,
not a marker. `FFD8` (SOI) and `FFD9` (EOI) have no payload.

| Marker | Bytes | Meaning |
| --- | --- | --- |
| SOI | FFD8 | start of image, always the first two bytes |
| APP0 | FFE0 | JFIF header |
| APP1 | FFE1 | EXIF (`Exif\0\0` + a TIFF structure) or XMP (`http://ns.adobe.com/xap/1.0/\0`) |
| APP2 | FFE2 | ICC profile chunks |
| APP13 | FFED | Photoshop IRB / IPTC |
| DQT | FFDB | quantisation table |
| SOF0 | FFC0 | baseline DCT frame header (height, width, components) |
| SOF2 | FFC2 | progressive DCT |
| DHT | FFC4 | Huffman table |
| SOS | FFDA | start of scan; entropy-coded data follows until the next marker |
| DRI | FFDD | restart interval |
| RSTn | FFD0-FFD7 | restart markers inside scan data, no length |
| COM | FFFE | comment, free-form bytes |
| EOI | FFD9 | end of image |

`SOF0` payload: `precision(1) height(2) width(2) ncomponents(1)` then 3 bytes per component.
Editing height/width here is the JPEG analogue of the PNG IHDR attack - but JPEG has no CRC,
so you cannot brute-force the original; you infer it from the number of MCUs in the scan.

### DCT-domain stego

Each 8x8 block is DCT-transformed, quantised, and Huffman-coded. Embedding tools modify the
*quantised coefficients* before entropy coding, so the payload survives the file round-trip but
is invisible to pixel-level tools.

| Tool | Carrier | Password | Detect |
| --- | --- | --- | --- |
| `jsteg` | JPEG only | none | histogram of coefficient values loses its odd/even symmetry |
| `steghide` | JPEG, BMP, WAV, AU | yes (Blowfish + CRC32) | `stegseek`, `stegdetect` |
| `outguess` | JPEG (and PNM) | yes | preserves first-order statistics, harder |
| `jphide`/`jpseek` | JPEG | yes | `stegdetect -tj` |
| `F5` | JPEG | yes | matrix encoding, shrinkage |

`steghide` is by far the most common in CTFs, and `stegseek` cracks the whole of rockyou in a
few seconds because it attacks the seed rather than doing full decryptions.

## Attack

```bash
# 1. structure + every tag, including the thumbnail's own EXIF
exiftool -a -u -g1 chal.jpg

# 2. THE check: extract the embedded thumbnail and look at it
exiftool -b -ThumbnailImage chal.jpg > thumb.jpg && open thumb.jpg
exiftool -b -PreviewImage   chal.jpg > prev.jpg   2>/dev/null

# 3. anything after EOI
xxd chal.jpg | tail -5
binwalk -e chal.jpg

# 4. steghide with no password, then with a wordlist
steghide info -p '' chal.jpg
stegseek chal.jpg /usr/share/wordlists/rockyou.txt

# 5. the other DCT tools
outguess -r chal.jpg out.txt
jsteg reveal chal.jpg out.txt
stegdetect -tjopi chal.jpg

# 6. structural validation
djpeg -verbose chal.jpg > /dev/null
jpeginfo -c chal.jpg
```

If the image will not open at all: the SOI is probably damaged. Restore `FF D8 FF E0` (JFIF) or
`FF D8 FF E1` (EXIF) and re-check; also confirm the file ends in `FF D9`.

## Code

A complete marker walker that reports every segment, extracts APPn payloads and the EXIF
thumbnail, and flags data after EOI.

```python
#!/usr/bin/env python3
"""JPEG marker walker and payload extractor.

Usage:
  python3 jpeg_tool.py list chal.jpg
  python3 jpeg_tool.py dump chal.jpg outdir
  python3 jpeg_tool.py --selftest
"""
from __future__ import annotations

import os
import struct
import sys

MARKER_NAMES = {
    0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT", 0xC4: "DHT",
    0xDD: "DRI", 0xFE: "COM", 0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2",
    0xC3: "SOF3", 0xC5: "SOF5", 0xC6: "SOF6", 0xC7: "SOF7", 0xC9: "SOF9",
    0xCA: "SOF10", 0xCB: "SOF11", 0xCD: "SOF13", 0xCE: "SOF14", 0xCF: "SOF15",
    0x01: "TEM",
}
for _i in range(16):
    MARKER_NAMES[0xE0 + _i] = f"APP{_i}"
for _i in range(8):
    MARKER_NAMES[0xD0 + _i] = f"RST{_i}"

STANDALONE = set(range(0xD0, 0xDA)) | {0xD8, 0xD9, 0x01}


class Segment:
    def __init__(self, offset: int, marker: int, payload: bytes):
        self.offset = offset
        self.marker = marker
        self.payload = payload

    @property
    def name(self) -> str:
        return MARKER_NAMES.get(self.marker, f"FF{self.marker:02X}")

    def __repr__(self) -> str:
        return f"@0x{self.offset:06x} {self.name:<6} len={len(self.payload)}"


def walk(data: bytes) -> tuple[list[Segment], bytes, bytes]:
    """Return (segments, scan_data, trailing_after_eoi)."""
    if not data.startswith(b"\xff\xd8"):
        print(f"[!] no SOI, file starts with {data[:4].hex()}", file=sys.stderr)
    segs: list[Segment] = []
    scan = b""
    pos = 0
    n = len(data)
    while pos < n - 1:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0x00, 0xFF):  # byte stuffing / fill byte
            pos += 1
            continue
        if marker in STANDALONE:
            segs.append(Segment(pos, marker, b""))
            if marker == 0xD9:
                return segs, scan, data[pos + 2:]
            pos += 2
            continue
        if pos + 4 > n:
            break
        (length,) = struct.unpack(">H", data[pos + 2:pos + 4])
        payload = data[pos + 4:pos + 2 + length]
        segs.append(Segment(pos, marker, payload))
        pos += 2 + length
        if marker == 0xDA:  # entropy-coded data runs until the next real marker
            start = pos
            while pos < n - 1:
                if data[pos] == 0xFF and data[pos + 1] not in (0x00, 0xFF) and data[pos + 1] not in range(0xD0, 0xD8):
                    break
                pos += 1
            scan = data[start:pos]
    return segs, scan, b""


def parse_sof(seg: Segment) -> str:
    if len(seg.payload) < 6:
        return "truncated SOF"
    precision, height, width, ncomp = struct.unpack(">BHHB", seg.payload[:6])
    return f"{width}x{height} precision={precision} components={ncomp}"


def describe_app(seg: Segment) -> str:
    p = seg.payload
    if p.startswith(b"Exif\x00\x00"):
        return "EXIF (TIFF structure follows)"
    if p.startswith(b"JFIF\x00"):
        return "JFIF header"
    if p.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
        return "XMP packet"
    if p.startswith(b"ICC_PROFILE\x00"):
        return "ICC profile chunk"
    if p.startswith(b"Photoshop 3.0\x00"):
        return "Photoshop IRB / IPTC"
    printable = sum(1 for b in p[:64] if 32 <= b < 127)
    return f"unknown, {printable}/64 printable, head={p[:32]!r}"


def find_thumbnail(data: bytes) -> bytes | None:
    """A nested JPEG inside an APP1/APP segment is the EXIF thumbnail."""
    start = data.find(b"\xff\xd8\xff", 2)
    while start != -1:
        end = data.find(b"\xff\xd9", start)
        if end != -1:
            return data[start:end + 2]
        start = data.find(b"\xff\xd8\xff", start + 2)
    return None


def cmd_list(path: str) -> None:
    data = open(path, "rb").read()
    segs, scan, trailing = walk(data)
    for s in segs:
        line = repr(s)
        if s.name.startswith("SOF"):
            line += "  " + parse_sof(s)
        elif s.name.startswith("APP"):
            line += "  " + describe_app(s)
        elif s.name == "COM":
            line += "  " + repr(s.payload[:120])
        print(line)
    print(f"[i] entropy-coded scan: {len(scan)} bytes")
    if trailing:
        print(f"[!] {len(trailing)} bytes AFTER EOI: {trailing[:48]!r}")
    thumb = find_thumbnail(data)
    if thumb:
        print(f"[i] nested JPEG (thumbnail) found, {len(thumb)} bytes -> dump it and LOOK at it")


def cmd_dump(path: str, outdir: str) -> None:
    data = open(path, "rb").read()
    segs, _scan, trailing = walk(data)
    os.makedirs(outdir, exist_ok=True)
    for i, s in enumerate(segs):
        if not s.payload:
            continue
        if s.name.startswith("APP") or s.name == "COM":
            p = os.path.join(outdir, f"{i:03d}_{s.name}.bin")
            open(p, "wb").write(s.payload)
            print(f"[+] {p}")
    if trailing:
        p = os.path.join(outdir, "after_eoi.bin")
        open(p, "wb").write(trailing)
        print(f"[+] {p}")
    thumb = find_thumbnail(data)
    if thumb:
        p = os.path.join(outdir, "thumbnail.jpg")
        open(p, "wb").write(thumb)
        print(f"[+] {p}")


def _make_jpeg() -> bytes:
    """Hand-build a minimal, structurally valid JPEG-like stream for testing."""
    def seg(marker: int, payload: bytes) -> bytes:
        return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload

    out = b"\xff\xd8"
    out += seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    out += seg(0xFE, b"flag{marker_walk}")
    out += seg(0xE1, b"Exif\x00\x00" + b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9")
    out += seg(0xDB, bytes([0]) + bytes(64))
    out += seg(0xC0, struct.pack(">BHHB", 8, 16, 24, 1) + bytes([1, 0x11, 0]))
    out += seg(0xC4, bytes([0x00]) + bytes(16) + b"")
    out += seg(0xDA, bytes([1, 1, 0, 0, 63, 0]))
    out += b"\x12\x34\xff\x00\x56"  # scan data with a stuffed FF00
    out += b"\xff\xd9"
    out += b"APPENDED-ZIP-HERE"
    return out


def _selftest() -> None:
    data = _make_jpeg()
    segs, scan, trailing = walk(data)
    names = [s.name for s in segs]
    assert names[0] == "SOI" and names[-1] == "EOI", names
    assert "COM" in names and "APP0" in names and "SOF0" in names
    com = next(s for s in segs if s.name == "COM")
    assert com.payload == b"flag{marker_walk}"
    sof = next(s for s in segs if s.name == "SOF0")
    assert parse_sof(sof).startswith("24x16"), parse_sof(sof)
    assert trailing == b"APPENDED-ZIP-HERE", trailing
    assert scan == b"\x12\x34\xff\x00\x56", scan
    thumb = find_thumbnail(data)
    assert thumb is not None and thumb.startswith(b"\xff\xd8\xff")
    print("selftest ok: markers, SOF dims, COM payload, trailing data, thumbnail")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    if sys.argv[1] == "list":
        cmd_list(sys.argv[2])
    elif sys.argv[1] == "dump":
        cmd_dump(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **`zsteg` does not support JPEG.** Neither does pixel-LSB extraction; lossy compression
  destroys spatial LSBs. Anyone telling you to "check the LSB of a JPEG" means DCT coefficients.
- **The thumbnail is stale by design.** Cameras and editors do not always regenerate it, so a
  cropped/redacted image can still carry the original in `-ThumbnailImage`. Also try
  `-PreviewImage`, `-JpgFromRaw`, and `-OtherImage`.
- **`steghide` requires the exact passphrase**, including an empty one. `steghide info -p ''`
  is a free first try.
- **`stegseek` is 1000x faster than `stegcracker`.** Always reach for `stegseek` first;
  `stegseek --crack -f chal.jpg wordlist.txt` writes the payload to `chal.jpg.out`.
- **Progressive JPEGs (SOF2)** break some older tools (`jsteg` expects baseline). Convert with
  `jpegtran -revert` style operations only if you are sure you are not destroying the payload -
  usually you should not re-encode at all.
- **A "corrupt" JPEG may be a polyglot.** If `binwalk` shows a ZIP at offset 0 and a JPEG later,
  the file is a zip that happens to contain JPEG bytes. See `polyglot-files`.
- **Do not re-save the JPEG in any editor.** Re-encoding rewrites every DCT coefficient and
  destroys the payload irrecoverably.
- **Height/width edits** in SOF0 hide the bottom of the image. Compare the declared size with
  the number of MCUs you can actually decode (`djpeg -verbose` reports decode errors).

## Tools

`exiftool`, `stegseek`, `steghide`, `outguess`, `jsteg`, `stegdetect`, `binwalk`, `djpeg` /
`jpegtran` (libjpeg-turbo), `jpeginfo`, `stegoveritas`.

## References

- ITU-T T.81 (JPEG) defines the marker set and segment layout.
- ExifTool tag documentation for `ThumbnailImage`, `PreviewImage`, `JpgFromRaw`:
  https://exiftool.org/
- The `steghide` manual page for the exact carrier formats it supports (JPEG, BMP, WAV, AU).
