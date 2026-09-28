---
title: "Metadata Hiding - EXIF, GPS, ICC and XMP"
category: stego
subcategory: metadata
type: technique
tags: [exif, metadata, exiftool, gps, geotag, xmp, icc, iptc, maker-notes, thumbnail, tiff-ifd, docprops, base64, stego, osint]
difficulty: easy
summary: "Metadata is the first place to look and the last place people clean: GPS, comments, ICC/XMP blobs and stale thumbnails all survive editing."
when_to_use:
  - "Any image, PDF, or Office document in a stego or OSINT challenge"
  - "The challenge asks 'where was this taken' or 'who made this'"
  - "exiftool shows an unusually long tag value or a base64-looking string"
  - "The file is much bigger than its visible content"
tools: [exiftool, identify, strings, python3, pdfinfo, oletools, binwalk]
related: [image-triage, jpeg-structure-attacks, png-structure-attacks, osint-geolocation, osint-documents-and-code, stego-cheatsheet]
---

## TL;DR

`exiftool -a -u -g1 file` is the highest-value single command in stego. It decodes EXIF, IPTC,
XMP, ICC, maker notes and container-specific metadata, including tags most GUIs never show.
Payloads hide in comment fields, in GPS coordinates, in an ICC profile description, in an XMP
packet full of base64, and in the stale embedded thumbnail.

## Recognise it

- `exiftool` output contains a tag whose value is hundreds of characters long.
- `Software`, `Artist`, `Copyright`, `UserComment`, `ImageDescription`, `XPComment`,
  `XPKeywords` are populated with something that is not a camera string.
- GPS tags present on an image that "should not" have them.
- `ICC Profile Description` or `Profile Copyright` contains a non-standard string.
- An XMP packet (`<?xpacket begin=...`) with a custom namespace.
- Binary bytes visible in `strings` between `Exif\0\0` and the image data.

## Theory

### Where metadata lives per container

| Container | Metadata carriers |
| --- | --- |
| JPEG | APP1 (EXIF, XMP), APP2 (ICC), APP13 (Photoshop IRB/IPTC), COM |
| PNG | `tEXt`, `zTXt` (zlib-compressed), `iTXt` (UTF-8, optionally compressed), `eXIf`, `iCCP` |
| GIF | comment extension, application extension |
| TIFF | the IFD itself; `ExifIFD` (0x8769) and `GPSIFD` (0x8825) sub-IFDs |
| WEBP | `EXIF`, `XMP `, `ICCP` chunks |
| PDF | `/Info` dictionary, XMP metadata stream, per-object metadata |
| OOXML (docx/xlsx/pptx) | `docProps/core.xml`, `docProps/app.xml`, `docProps/custom.xml` |
| MP3/FLAC | ID3v1/ID3v2 frames, Vorbis comments, embedded album art |

### EXIF internals

EXIF inside a JPEG APP1 is literally a TIFF file: `Exif\0\0` then `II*\0` or `MM\0*`, then the
offset to IFD0. All internal offsets are relative to the start of the TIFF header, **not** the
start of the JPEG. Tags are 12-byte entries `(tag, type, count, value-or-offset)`; if the value
is longer than 4 bytes the field holds an offset instead. A tag with an enormous `count` points
at a blob anywhere in the APP1 segment - that is how binaries get smuggled into `UserComment`
or `MakerNote`.

### GPS

GPS coordinates are stored as three RATIONALs (degrees, minutes, seconds), each a pair of
32-bit unsigned ints, plus a reference character (`N`/`S`, `E`/`W`).

$$ \text{decimal} = \pm\left(D + \frac{M}{60} + \frac{S}{3600}\right) $$

Negative for `S` latitude and `W` longitude. `GPSAltitudeRef` 0 = above sea level, 1 = below.
`GPSDateStamp` and `GPSTimeStamp` are UTC and often survive when `DateTimeOriginal` is stripped.

## Attack

```bash
# 1. everything, grouped, including unknown and duplicate tags
exiftool -a -u -g1 chal.jpg

# 2. machine-readable, for scripting
exiftool -json -a -u -g1 chal.jpg > meta.json

# 3. GPS as decimal degrees, ready to paste into a map
exiftool -n -GPSLatitude -GPSLongitude -GPSAltitude chal.jpg
exiftool -c '%.8f' -GPSPosition chal.jpg

# 4. dump a binary tag to disk (works for ANY tag with -b)
exiftool -b -ThumbnailImage chal.jpg > thumb.jpg
exiftool -b -PreviewImage   chal.jpg > prev.jpg
exiftool -b -ICC_Profile    chal.jpg > profile.icc
exiftool -b -UserComment    chal.jpg > comment.bin
exiftool -b -MakerNotes     chal.jpg > maker.bin

# 5. the XMP packet as raw XML
exiftool -xmp -b chal.jpg > packet.xmp

# 6. PNG text chunks
exiftool -PNG:all -a -u chal.png

# 7. documents
exiftool -a -u -g1 chal.pdf
unzip -o chal.docx -d docx_out && cat docx_out/docProps/core.xml

# 8. write/remove (for building your own tests, and for checking what a tool strips)
exiftool -Comment='flag{in_a_tag}' out.jpg
exiftool -all= stripped.jpg
```

Always `-b` any tag whose value exiftool renders as `(Binary data NNNN bytes, use -b option to
extract)`. That message is the giveaway.

## Code

```python
#!/usr/bin/env python3
"""Metadata sweep: exiftool JSON if available, plus a dependency-free EXIF/GPS parser.

Usage:
  python3 meta_sweep.py chal.jpg
  python3 meta_sweep.py --selftest
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import shutil
import struct
import subprocess
import sys

GPS_TAGS = {
    0x0000: "GPSVersionID", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude", 0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude", 0x0007: "GPSTimeStamp", 0x0012: "GPSMapDatum",
    0x001D: "GPSDateStamp",
}
EXIF_TAGS = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
    0x013B: "Artist", 0x8298: "Copyright", 0x9286: "UserComment", 0x9003: "DateTimeOriginal",
    0x927C: "MakerNote", 0x8769: "ExifIFD", 0x8825: "GPSIFD", 0x02BC: "XMP",
    0x8773: "ICCProfile",
}
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

B64_RE = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,15}\{[^}\n]{3,120}\}")


def find_tiff(data: bytes) -> int:
    """Offset of the TIFF header inside a JPEG APP1 segment, or 0 for a bare TIFF."""
    if data[:2] in (b"II", b"MM"):
        return 0
    idx = data.find(b"Exif\x00\x00")
    if idx != -1:
        return idx + 6
    idx = data.find(b"II*\x00")
    if idx != -1:
        return idx
    idx = data.find(b"MM\x00*")
    return idx if idx != -1 else -1


def read_ifd(data: bytes, base: int, offset: int, endian: str) -> list[tuple[int, int, int, bytes, int]]:
    """Return (tag, type, count, raw_value_bytes, next_ifd_offset_placeholder)."""
    entries = []
    if base + offset + 2 > len(data):
        return entries
    (count,) = struct.unpack(endian + "H", data[base + offset:base + offset + 2])
    for i in range(count):
        e = base + offset + 2 + i * 12
        if e + 12 > len(data):
            break
        tag, typ, cnt = struct.unpack(endian + "HHI", data[e:e + 8])
        size = TYPE_SIZE.get(typ, 1) * cnt
        if size <= 4:
            raw = data[e + 8:e + 8 + size]
        else:
            (voff,) = struct.unpack(endian + "I", data[e + 8:e + 12])
            raw = data[base + voff:base + voff + size]
        entries.append((tag, typ, cnt, raw, 0))
    nxt_pos = base + offset + 2 + count * 12
    nxt = 0
    if nxt_pos + 4 <= len(data):
        (nxt,) = struct.unpack(endian + "I", data[nxt_pos:nxt_pos + 4])
    return entries + [(-1, 0, 0, b"", nxt)]


def rationals(raw: bytes, endian: str) -> list[float]:
    out = []
    for i in range(0, len(raw) - 7, 8):
        num, den = struct.unpack(endian + "II", raw[i:i + 8])
        out.append(num / den if den else 0.0)
    return out


def dms_to_decimal(dms: list[float], ref: str) -> float:
    d = dms[0] if len(dms) > 0 else 0.0
    m = dms[1] if len(dms) > 1 else 0.0
    s = dms[2] if len(dms) > 2 else 0.0
    val = d + m / 60.0 + s / 3600.0
    if ref.upper() in ("S", "W"):
        val = -val
    return val


def parse_exif(data: bytes) -> dict:
    base = find_tiff(data)
    if base < 0:
        return {}
    endian = "<" if data[base:base + 2] == b"II" else ">"
    (first,) = struct.unpack(endian + "I", data[base + 4:base + 8])
    result: dict = {"_endian": endian}
    gps_off = None
    exif_off = None
    offset = first
    seen = set()
    while offset and offset not in seen:
        seen.add(offset)
        entries = read_ifd(data, base, offset, endian)
        nxt = entries[-1][4]
        for tag, typ, cnt, raw, _ in entries[:-1]:
            name = EXIF_TAGS.get(tag, f"Tag0x{tag:04X}")
            if tag == 0x8825:
                (gps_off,) = struct.unpack(endian + "I", raw[:4])
                continue
            if tag == 0x8769:
                (exif_off,) = struct.unpack(endian + "I", raw[:4])
                continue
            if typ in (2, 7):  # ASCII, or UNDEFINED (UserComment/MakerNote live here)
                result[name] = raw.rstrip(b"\x00").decode("latin1", "replace")
            else:
                result[name] = raw if len(raw) > 16 else raw.hex()
        offset = nxt
    for sub_off, prefix in ((exif_off, ""), (gps_off, "GPS:")):
        if not sub_off:
            continue
        entries = read_ifd(data, base, sub_off, endian)
        for tag, typ, cnt, raw, _ in entries[:-1]:
            table = GPS_TAGS if prefix else EXIF_TAGS
            name = prefix + table.get(tag, f"Tag0x{tag:04X}")
            if typ == 2:
                result[name] = raw.rstrip(b"\x00").decode("latin1", "replace")
            elif typ == 5:
                result[name] = rationals(raw, endian)
            else:
                result[name] = raw.hex() if len(raw) <= 16 else raw
    lat = result.get("GPS:GPSLatitude")
    lon = result.get("GPS:GPSLongitude")
    if isinstance(lat, list) and isinstance(lon, list):
        result["GPS:decimal"] = (
            dms_to_decimal(lat, str(result.get("GPS:GPSLatitudeRef", "N"))),
            dms_to_decimal(lon, str(result.get("GPS:GPSLongitudeRef", "E"))),
        )
    return result


def exiftool_json(path: str) -> list[dict]:
    if shutil.which("exiftool") is None:
        return []
    p = subprocess.run(["exiftool", "-json", "-a", "-u", "-g1", path],
                       capture_output=True, timeout=120)
    try:
        return json.loads(p.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return []


def hunt_blobs(data: bytes) -> list[str]:
    """Report flag-shaped strings and decodable base64 blobs anywhere in the file."""
    notes = []
    for m in FLAG_RE.finditer(data):
        notes.append(f"flag-shaped string: {m.group(0)!r} @0x{m.start():x}")
    for m in B64_RE.finditer(data):
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            dec = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        printable = sum(1 for c in dec if 32 <= c < 127 or c in (9, 10, 13))
        if printable >= len(dec) * 0.9 and len(dec) >= 8:
            notes.append(f"base64 @0x{m.start():x} -> {dec[:120]!r}")
    return notes


def main() -> int:
    path = sys.argv[1]
    data = open(path, "rb").read()
    print("== embedded exif (pure python) ==")
    for k, v in sorted(parse_exif(data).items()):
        if k.startswith("_"):
            continue
        shown = v if not isinstance(v, bytes) else f"<{len(v)} bytes> {v[:32]!r}"
        print(f"  {k}: {shown}")
    print("\n== exiftool ==")
    for group in exiftool_json(path):
        for k, v in group.items():
            print(f"  {k}: {v}")
    print("\n== blob hunt ==")
    for note in hunt_blobs(data):
        print("  " + note)
    return 0


def _build_exif_jpeg(lat_dms, lon_dms, comment: bytes) -> bytes:
    """Hand-build a JPEG with an EXIF APP1 carrying GPS and a UserComment."""
    endian = b"II"

    def rat(nd):
        return b"".join(struct.pack("<II", n, d) for n, d in nd)

    lat_bytes = rat(lat_dms)
    lon_bytes = rat(lon_dms)

    # Layout: TIFF header (8) | IFD0 | IFD0 values | GPS IFD | GPS values
    ifd0_entries = 2                      # UserComment, GPSIFD pointer
    ifd0_start = 8
    ifd0_size = 2 + ifd0_entries * 12 + 4
    comment_off = ifd0_start + ifd0_size
    gps_ifd_off = comment_off + len(comment)
    gps_count = 4
    gps_size = 2 + gps_count * 12 + 4
    lat_off = gps_ifd_off + gps_size
    lon_off = lat_off + len(lat_bytes)

    ifd0 = struct.pack("<H", ifd0_entries)
    ifd0 += struct.pack("<HHII", 0x9286, 7, len(comment), comment_off)
    ifd0 += struct.pack("<HHII", 0x8825, 4, 1, gps_ifd_off)
    ifd0 += struct.pack("<I", 0)

    gps = struct.pack("<H", gps_count)
    gps += struct.pack("<HHI", 0x0001, 2, 2) + b"N\x00\x00\x00"
    gps += struct.pack("<HHII", 0x0002, 5, 3, lat_off)
    gps += struct.pack("<HHI", 0x0003, 2, 2) + b"E\x00\x00\x00"
    gps += struct.pack("<HHII", 0x0004, 5, 3, lon_off)
    gps += struct.pack("<I", 0)

    tiff = endian + struct.pack("<HI", 42, ifd0_start) + ifd0 + comment + gps + lat_bytes + lon_bytes
    app1 = b"Exif\x00\x00" + tiff
    seg = b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    return b"\xff\xd8" + seg + b"\xff\xd9"


def _selftest() -> None:
    lat = [(48, 1), (51, 1), (2999, 100)]   # 48 deg 51' 29.99"
    lon = [(2, 1), (17, 1), (4000, 100)]    # 2 deg 17' 40.00"
    jpg = _build_exif_jpeg(lat, lon, b"flag{exif_gps}")
    meta = parse_exif(jpg)
    assert meta.get("UserComment") == "flag{exif_gps}", meta.get("UserComment")
    dec = meta["GPS:decimal"]
    assert abs(dec[0] - 48.858331) < 1e-4, dec
    assert abs(dec[1] - 2.294444) < 1e-4, dec
    assert dms_to_decimal([48.0, 51.0, 29.99], "S") < 0
    notes = hunt_blobs(jpg)
    assert any("flag-shaped" in n for n in notes), notes
    print(f"selftest ok: GPS decoded to {dec[0]:.5f}, {dec[1]:.5f}; flag string found")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--selftest":
        sys.exit(main())
    _selftest()
```

## Variants and pitfalls

- **`exiftool` hides binary tags by default.** `(Binary data 4096 bytes, use -b option)` means
  there is a payload. Always `-b` it.
- **Maker notes are vendor-specific and huge.** `exiftool -a -u -g1` decodes many of them;
  anything undecoded should be `-b` dumped and `file`-checked.
- **ICC profiles** are a TIFF-like structure with a `desc` tag; a 200 KB ICC profile on a
  30 KB image is a payload.
- **XMP is XML** - look for custom namespaces and `rdf:Description` attributes carrying base64.
- **Stripping is not deleting.** `exiftool -all=` rewrites the file but leaves the APP segment
  gaps in some writers; `binwalk` may still find the old bytes in a "cleaned" file you were given.
- **Two dates that disagree** (`DateTimeOriginal` vs `FileModifyDate` vs `GPSDateStamp`) is
  itself the puzzle in many OSINT challenges.
- **PNG `zTXt` is zlib-compressed**; `strings` will not show it. Use exiftool or inflate it.
- **Altitude reference and negative rationals**: `GPSAltitudeRef == 1` means the altitude value
  is *below* sea level even though the rational itself is unsigned.
- **Document metadata is a separate world**: `docProps/core.xml` inside a `.docx` zip holds
  `dc:creator` and `cp:lastModifiedBy`; PDFs keep an `/Info` dict plus every previous revision
  if the file was incrementally updated.

## Tools

`exiftool` (the reference tool - nothing else is close), `identify -verbose`, `strings`,
`pdfinfo`/`pdftk`/`qpdf`, `oletools` (`olemeta`, `oleid`) for legacy Office, `exiv2`,
Python: `Pillow.Image.getexif()`, `piexif`.

## References

- ExifTool tag name reference and the `-b`/`-a`/`-u`/`-g1` option semantics: https://exiftool.org/
- EXIF 2.3 specification for GPS IFD tag numbering and RATIONAL encoding.
- TIFF 6.0 specification for the IFD entry layout that EXIF reuses.
