---
title: "GIF, BMP, WEBP and TIFF - Format-Specific Tricks"
category: stego
subcategory: image
type: technique
tags: [gif, bmp, webp, tiff, riff, animation, frames, palette, local-color-table, comment-extension, ifd, multipage, apng, stego, pillow]
difficulty: medium
summary: "Each container has its own dead space: GIF comment blocks and per-frame palettes, BMP row padding, WEBP RIFF chunks, TIFF extra IFDs."
when_to_use:
  - "The challenge image is not a PNG or JPEG"
  - "An animation plays too fast to read, or one frame looks different"
  - "identify reports more frames/pages than the image appears to have"
  - "A BMP is larger than width*height*bpp + 54 bytes"
tools: [exiftool, identify, convert, gifsicle, ffmpeg, python3, pillow, binwalk, tiffinfo, webpinfo]
related: [image-triage, lsb-extraction, png-structure-attacks, video-stego, stego-cheatsheet, image-forensics-cheatsheet]
---

## TL;DR

PNG and JPEG get all the attention, so authors hide in the other four. GIF gives you per-frame
palettes, frame delays and a free-form comment extension. BMP gives you the gap between the
header and the pixel array plus up to 3 padding bytes on every row. WEBP is RIFF, so any chunk
type you invent is skipped silently. TIFF lets you chain IFDs, so a second image can hang off
the first.

## Recognise it

- `identify chal.gif` prints more than one frame, or frames with odd `delay` values.
- `exiftool` shows `Frame Count` larger than what you see playing.
- A BMP whose `bfOffBits` (offset to pixel data) is much larger than 54.
- `webpinfo` / `exiftool` lists an unknown WEBP chunk FourCC.
- `tiffinfo` reports multiple directories, or an IFD offset pointing past the "end" of the image.

## GIF

### Structure

```text
'GIF89a'                       header
Logical Screen Descriptor      7 bytes: width, height, flags, bg index, aspect
[Global Color Table]           3 * 2^(N+1) bytes if the flag bit is set
blocks...
  0x21 0xF9  Graphic Control Extension  (delay in 1/100s, transparent index, disposal)
  0x21 0xFE  Comment Extension          <-- free-form payload, any length
  0x21 0xFF  Application Extension      (NETSCAPE2.0 loop count; also abusable)
  0x21 0x01  Plain Text Extension       (rarely rendered, so rarely noticed)
  0x2C       Image Descriptor           per-frame: left, top, w, h, flags
             [Local Color Table]        per-frame palette
             LZW minimum code size + sub-blocks
0x3B                            trailer
```

### Tricks

- **Comment extension** (`21 FE`) holds arbitrary bytes and no viewer displays it.
- **Per-frame local colour tables**: a frame can use a palette where two entries are visually
  identical but index-distinct - the index plane is the message.
- **Frame delays as a channel**: delay values map to bits/characters (e.g. delay 1 = `0`,
  delay 2 = `1`, or delay = ASCII code).
- **Sub-frame positioning**: frames smaller than the canvas placed off to one side, only
  visible if you extract frames individually.
- **Disposal method 1 vs 2**: a frame drawn then immediately cleared is invisible at playback
  speed but present in the file.

```bash
# frame-by-frame dump
convert chal.gif -coalesce frames/%03d.png

# structural listing including per-frame delay, disposal and local palettes
identify -verbose chal.gif | grep -E 'Delay|Dispose|Scene|Colors|Geometry'

# gifsicle is the surgical tool: explode, inspect, re-time
gifsicle --explode chal.gif
gifsicle --info chal.gif

# comment extension
exiftool -Comment chal.gif
gifsicle --info chal.gif | grep -i comment
```

## BMP

### Structure

```text
'BM'                 2   signature
bfSize               4   file size (often lies)
reserved             4
bfOffBits            4   offset to the pixel array  <-- gap before it is free space
biSize               4   40 = BITMAPINFOHEADER, 124 = V5
biWidth              4   signed
biHeight             4   signed; POSITIVE means bottom-up row order
biPlanes             2
biBitCount           2   1,4,8,16,24,32
biCompression        4   0 = BI_RGB uncompressed
biSizeImage          4   often 0 for BI_RGB
...
```

### Tricks

- **Rows are padded to a 4-byte boundary.** A 24bpp image of width 3 uses 9 bytes of pixels and
  3 bytes of padding *per row* - those bytes are never rendered and survive every viewer.
- **Bottom-up storage**: positive `biHeight` means the first row in the file is the *bottom*
  row of the image. Extraction order matters for LSB.
- **`bfOffBits` gap**: set the offset past the header and stuff data in between.
- **`bfSize` lying** hides trailing data from naive tools.
- BMP is fully supported by `zsteg`, so run it.

```bash
# header fields, including the pixel-data offset
exiftool chal.bmp
xxd -l 64 chal.bmp

# zsteg handles BMP natively
zsteg -a chal.bmp
```

## WEBP

RIFF container: `'RIFF' size 'WEBP'` followed by chunks of `FourCC + size + data (+1 pad byte
if size is odd)`.

| Chunk | Meaning |
| --- | --- |
| `VP8 ` | lossy bitstream (note the trailing space) |
| `VP8L` | lossless bitstream |
| `VP8X` | extended: flags for ICC/alpha/EXIF/XMP/animation |
| `ANIM`/`ANMF` | animation parameters and per-frame data |
| `ALPH` | separate alpha plane |
| `ICCP`/`EXIF`/`XMP ` | metadata payloads |

Any unknown FourCC is skipped by decoders, so an invented chunk is a perfect hiding place.
Lossless WEBP (`VP8L`) preserves exact pixel values, so LSB works there; lossy does not.

```bash
# chunk listing
webpinfo -summary chal.webp
exiftool -a -u -g1 chal.webp

# convert to PNG so the rest of your toolchain works (only safe for VP8L)
dwebp chal.webp -o chal.png
ffmpeg -i chal.webp frames/%03d.png     # animated webp
```

## TIFF

`II*\0` (little-endian) or `MM\0*` (big-endian), then a 4-byte offset to the first IFD.
An IFD is `count(2)` entries of 12 bytes (`tag, type, count, value-or-offset`) then a 4-byte
offset to the *next* IFD (0 = end). Multi-page TIFFs chain IFDs; an extra IFD nobody renders
is the hiding place. Strips/tiles can also be stored out of order, leaving gaps.

```bash
# every directory, every tag, every strip offset
tiffinfo -D chal.tif
exiftool -a -u -g1 chal.tif

# split pages
convert chal.tif page-%02d.png
tiffsplit chal.tif page_
```

## Code

```python
#!/usr/bin/env python3
"""Format-specific inspectors for GIF / BMP / WEBP / TIFF.

Usage:
  python3 other_formats.py chal.gif
  python3 other_formats.py --selftest
"""
from __future__ import annotations

import struct
import sys


def inspect_gif(data: bytes) -> list[str]:
    out = [f"GIF version {data[:6].decode('latin1')}"]
    w, h, flags, bg, aspect = struct.unpack("<HHBBB", data[6:13])
    out.append(f"canvas {w}x{h} flags=0x{flags:02x} bg={bg} aspect={aspect}")
    pos = 13
    if flags & 0x80:
        gct = 3 * (2 ** ((flags & 0x07) + 1))
        out.append(f"global color table: {gct} bytes ({gct // 3} colours)")
        pos += gct
    frame = 0
    delays: list[int] = []
    while pos < len(data):
        b = data[pos]
        if b == 0x3B:
            out.append(f"trailer at 0x{pos:x}; {len(data) - pos - 1} trailing bytes")
            break
        if b == 0x21:  # extension
            label = data[pos + 1]
            pos += 2
            blocks = bytearray()
            while pos < len(data) and data[pos] != 0:
                n = data[pos]
                blocks += data[pos + 1:pos + 1 + n]
                pos += 1 + n
            pos += 1
            if label == 0xFE:
                out.append(f"!! COMMENT extension: {bytes(blocks)!r}")
            elif label == 0xF9 and len(blocks) >= 4:
                disposal = (blocks[0] >> 2) & 0x07
                delay = struct.unpack("<H", blocks[1:3])[0]
                delays.append(delay)
                out.append(f"GCE frame {frame}: delay={delay} disposal={disposal} transp_idx={blocks[3]}")
            elif label == 0xFF:
                out.append(f"application extension: {bytes(blocks[:11])!r}")
            elif label == 0x01:
                out.append(f"!! PLAIN TEXT extension: {bytes(blocks)!r}")
        elif b == 0x2C:  # image descriptor
            left, top, fw, fh, fflags = struct.unpack("<HHHHB", data[pos + 1:pos + 10])
            pos += 10
            note = ""
            if fflags & 0x80:
                lct = 3 * (2 ** ((fflags & 0x07) + 1))
                note = f" local palette {lct // 3} colours"
                pos += lct
            out.append(f"frame {frame} at ({left},{top}) {fw}x{fh}{note}")
            frame += 1
            pos += 1  # LZW minimum code size
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
        else:
            pos += 1
    if delays and len(set(delays)) > 1:
        out.append(f"!! non-uniform frame delays -> possible channel: {delays[:40]}")
        try:
            out.append("   as ascii: " + "".join(chr(d) for d in delays if 32 <= d < 127))
        except ValueError:
            pass
    return out


def inspect_bmp(data: bytes) -> list[str]:
    if len(data) < 54:
        return ["too short for a BMP"]
    bf_size, off_bits = struct.unpack("<I4xI", data[2:14])
    hdr_size, width, height, planes, bpp, comp, size_img = struct.unpack("<IiiHHII", data[14:38])
    out = [
        f"bfSize={bf_size} actual={len(data)}",
        f"bfOffBits={off_bits} headerSize={hdr_size}",
        f"{width}x{abs(height)} bpp={bpp} planes={planes} compression={comp} sizeImage={size_img}",
        "row order: bottom-up" if height > 0 else "row order: top-down",
    ]
    gap = off_bits - (14 + hdr_size)
    if bpp <= 8:
        pal = 4 * (2 ** bpp)
        gap -= pal
        out.append(f"palette: {2 ** bpp} entries ({pal} bytes)")
    if gap > 0:
        blob = data[off_bits - gap:off_bits]
        out.append(f"!! {gap} unexplained bytes before the pixel array: {blob[:48]!r}")
    row_bytes = (width * bpp + 31) // 32 * 4
    used = (width * bpp + 7) // 8
    if row_bytes > used:
        out.append(f"!! {row_bytes - used} padding bytes per row x {abs(height)} rows "
                   f"= {(row_bytes - used) * abs(height)} bytes of dead space")
    expected = off_bits + row_bytes * abs(height)
    if len(data) > expected:
        out.append(f"!! {len(data) - expected} bytes after the pixel array: {data[expected:expected + 32]!r}")
    return out


def inspect_riff(data: bytes) -> list[str]:
    out = [f"RIFF form: {data[8:12].decode('latin1')}, declared size {struct.unpack('<I', data[4:8])[0]}, actual {len(data) - 8}"]
    pos = 12
    known = {b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF", b"ICCP", b"EXIF", b"XMP "}
    while pos + 8 <= len(data):
        fourcc = data[pos:pos + 4]
        (size,) = struct.unpack("<I", data[pos + 4:pos + 8])
        body = data[pos + 8:pos + 8 + size]
        flag = "" if fourcc in known else "  !! unknown chunk"
        out.append(f"@0x{pos:06x} {fourcc.decode('latin1', 'replace')} size={size}{flag}")
        if fourcc not in known or fourcc in (b"EXIF", b"XMP "):
            out.append(f"    head={body[:48]!r}")
        pos += 8 + size + (size & 1)
    return out


def inspect_tiff(data: bytes) -> list[str]:
    endian = "<" if data[:2] == b"II" else ">"
    (magic,) = struct.unpack(endian + "H", data[2:4])
    (first,) = struct.unpack(endian + "I", data[4:8])
    out = [f"TIFF endian={'little' if endian == '<' else 'big'} magic={magic} firstIFD=0x{first:x}"]
    seen = set()
    offset = first
    idx = 0
    while offset and offset not in seen and offset + 2 <= len(data):
        seen.add(offset)
        (count,) = struct.unpack(endian + "H", data[offset:offset + 2])
        out.append(f"IFD {idx} at 0x{offset:x}: {count} entries")
        for i in range(count):
            e = offset + 2 + i * 12
            if e + 12 > len(data):
                break
            tag, typ, cnt = struct.unpack(endian + "HHI", data[e:e + 8])
            out.append(f"   tag=0x{tag:04x} type={typ} count={cnt}")
        nxt_off = offset + 2 + count * 12
        if nxt_off + 4 > len(data):
            break
        (offset,) = struct.unpack(endian + "I", data[nxt_off:nxt_off + 4])
        idx += 1
        if offset:
            out.append(f"   -> next IFD at 0x{offset:x} (extra pages hide here)")
    return out


def inspect(path: str) -> list[str]:
    data = open(path, "rb").read()
    if data[:3] == b"GIF":
        return inspect_gif(data)
    if data[:2] == b"BM":
        return inspect_bmp(data)
    if data[:4] == b"RIFF":
        return inspect_riff(data)
    if data[:2] in (b"II", b"MM"):
        return inspect_tiff(data)
    return [f"unrecognised magic {data[:8]!r}"]


def _selftest() -> None:
    # Minimal GIF89a: canvas, global palette, comment extension, one frame.
    gif = b"GIF89a" + struct.pack("<HHBBB", 2, 2, 0x80, 0, 0)
    gif += bytes([0, 0, 0, 255, 255, 255])  # 2-colour GCT
    gif += b"\x21\xfe" + bytes([12]) + b"flag{gifcom}" + b"\x00"
    gif += b"\x21\xf9" + bytes([4]) + bytes([0x04, 0x41, 0x00, 0x00]) + b"\x00"
    gif += b"\x2c" + struct.pack("<HHHHB", 0, 0, 2, 2, 0)
    gif += bytes([2]) + bytes([2, 0x44, 0x01]) + b"\x00"
    gif += b"\x3b"
    rep = inspect_gif(gif)
    assert any("flag{gifcom}" in line for line in rep), rep
    assert any("delay=65" in line for line in rep), rep

    # Minimal 24bpp 1x1 BMP with 3 padding bytes per row and 8 trailing bytes.
    px = b"\x00\x00\xff" + b"HIDDEN!!"[:3]
    hdr = b"BM" + struct.pack("<I4xI", 54 + 4, 54)
    hdr += struct.pack("<IiiHHII", 40, 1, 1, 1, 24, 0, 0) + bytes(16)
    bmp = hdr + px + b"TRAILING"
    rep = inspect_bmp(bmp)
    assert any("padding bytes per row" in line for line in rep), rep
    assert any("after the pixel array" in line for line in rep), rep

    # RIFF/WEBP with an invented chunk.
    body = b"WEBP" + b"VP8L" + struct.pack("<I", 4) + b"ABCD" + b"SEcR" + struct.pack("<I", 5) + b"flag!" + b"\x00"
    riff = b"RIFF" + struct.pack("<I", len(body)) + body
    rep = inspect_riff(riff)
    assert any("unknown chunk" in line for line in rep), rep

    # TIFF with two chained IFDs.
    tif = bytearray(b"II" + struct.pack("<HI", 42, 8))
    tif += struct.pack("<H", 1) + struct.pack("<HHII", 0x0100, 3, 1, 16)
    ifd2 = len(tif) + 4
    tif += struct.pack("<I", ifd2)
    tif += struct.pack("<H", 1) + struct.pack("<HHII", 0x0101, 3, 1, 16) + struct.pack("<I", 0)
    rep = inspect_tiff(bytes(tif))
    assert any("IFD 1" in line for line in rep), rep
    print("selftest ok: gif comment+delays, bmp padding+trailing, riff unknown chunk, tiff second ifd")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--selftest":
        for line in inspect(sys.argv[1]):
            print(line)
    else:
        _selftest()
```

## Variants and pitfalls

- **`convert chal.gif frames/%03d.png` without `-coalesce`** gives you the raw sub-frames, which
  is sometimes what you want (off-canvas content) and sometimes confusing. Do both.
- **Animated WEBP and APNG** need `ffmpeg` or `webpmux -get frame N`; Pillow handles APNG via
  `ImageSequence`.
- **BMP with negative height** stores rows top-down; get this wrong and your extracted LSB
  stream is row-reversed, which looks like garbage but is trivially fixable.
- **16bpp BMP** uses 5-5-5 or 5-6-5 packing; the "LSB" of a channel is not the LSB of a byte.
- **TIFF tag 0x8769 (ExifIFD) and 0x8825 (GPSIFD)** point at sub-IFDs - exiftool walks them,
  a naive parser does not.
- **GIF LZW sub-blocks** can contain a final sub-block with trailing garbage after the LZW end
  code; decoders stop early and never notice.
- **`file` reports the first frame's geometry only.** Always use `identify` for frame counts.

## Tools

`identify`/`convert` (ImageMagick), `gifsicle`, `ffmpeg`, `webpinfo`/`webpmux`/`dwebp`
(libwebp), `tiffinfo`/`tiffsplit` (libtiff), `exiftool`, `zsteg` (BMP and PNG), Pillow.

## References

- GIF89a specification (CompuServe, 1990) for the block and extension layout.
- Microsoft BITMAPINFOHEADER documentation for BMP field semantics and row padding.
- RIFF container container rules and the WebP container chunk list (libwebp documentation).
- TIFF 6.0 specification for the IFD chain and tag encoding.
