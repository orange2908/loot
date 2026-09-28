---
title: "Image Stego - Triage Order"
category: stego
subcategory: image
type: technique
tags: [image-triage, stego, file, exiftool, binwalk, zsteg, stegsolve, strings, pngcheck, steghide, stegoveritas, aperisolve, foremost, lsb, magic-bytes, triage]
difficulty: easy
summary: "The fixed command order to run on any CTF image before guessing: identify, metadata, appended data, LSB, visual planes, strings."
when_to_use:
  - "You are handed a PNG/JPG/GIF/BMP and the only hint is 'find the flag'"
  - "You want a repeatable order so you never skip the cheap checks"
  - "A tool said 'nothing found' and you need to know what it did NOT check"
tools: [file, exiftool, binwalk, zsteg, steghide, stegseek, stegsolve, pngcheck, foremost, strings, stegoveritas, aperisolve, xxd]
related: [png-structure-attacks, jpeg-structure-attacks, lsb-extraction, metadata-hiding, polyglot-files, stego-cheatsheet, image-forensics-cheatsheet, lsb-extractor, stego-bruteforce]
---

## TL;DR

Image stego challenges are won by discipline, not cleverness. Run the same six passes in the
same order every time: **identify -> metadata -> appended/embedded data -> structure validation
-> LSB/bit-plane -> visual and statistical**. Ninety percent of CTF images fall in the first
three passes. Only start brute-forcing passwords once all six are clean.

## Recognise it

- The challenge gives you exactly one image and a flag format, nothing else.
- The image is suspiciously large for its dimensions (a 200x200 PNG that is 4 MB has payload in it).
- `file` output disagrees with the extension, or reports trailing data.
- The image renders fine but `pngcheck`/`jpeginfo` complain.
- The description mentions a word that smells like a password ("my cat Mittens", "the key is obvious").

## The six passes

### Pass 0 - work on a copy, record the hash

Never mutate the original. Keep `sha256sum` in your notes so you can prove which file you
extracted what from.

```bash
# keep the pristine original, work on a copy
mkdir -p work && cp chal.png work/ && cd work
sha256sum chal.png | tee hash.txt
```

### Pass 1 - Identify

```bash
# what is it really (magic bytes), not what the extension claims
file chal.png

# first 64 bytes: signature, and for PNG the IHDR that follows immediately
xxd chal.png | head -8

# last 64 bytes: IEND / EOI should be the very last bytes. Anything after = appended data
xxd chal.png | tail -8

# real dimensions and bit depth straight from the header
identify -verbose chal.png | head -40
```

What you are looking for:

| Signal | Meaning |
| --- | --- |
| `file` says "data" or the wrong type | header corrupted or polyglot, go to the format technique |
| trailing bytes after `IEND` (`49 45 4E 44 AE 42 60 82`) | appended payload, carve it |
| trailing bytes after `FFD9` in a JPEG | same |
| bit depth 8, colour type 3 (palette) PNG | palette-index LSB is in play, `zsteg` handles it |
| alpha channel present but image looks opaque | payload very likely in the alpha plane |

### Pass 2 - Metadata

```bash
# every tag exiftool knows, including maker notes and XMP
exiftool -a -u -g1 chal.png

# raw dump of one suspicious tag to a file (e.g. an embedded thumbnail or ICC blob)
exiftool -b -ThumbnailImage chal.jpg > thumb.jpg

# PNG text chunks specifically (tEXt/zTXt/iTXt) - zTXt is zlib-compressed
exiftool -PNG:all chal.png
```

Metadata is the single most common hiding place in beginner/intermediate challenges. Check
comments, `Artist`, `Software`, `XPComment`, GPS, and any base64-looking blob.

### Pass 3 - Appended and embedded data

```bash
# signature scan of the whole file; -e shows entropy transitions too
binwalk chal.png

# extract everything binwalk found into _chal.png.extracted/
binwalk -e --dd='.*' chal.png

# header-based carving, often catches what binwalk misses
foremost -i chal.png -o foremost_out

# manual carve once you know the offset of the embedded file
dd if=chal.png bs=1 skip=123456 of=payload.zip

# is the appended blob an archive? try it directly
7z l chal.png ; unzip -l chal.png
```

`unzip` and `7z` work directly on `image+zip` polyglots because the ZIP central directory is
located from the **end** of the file. If `unzip -l chal.png` lists entries, you are done thinking.

### Pass 4 - Structure validation

```bash
# PNG: CRC errors, wrong dimensions, junk chunks, data after IEND
pngcheck -vv chal.png

# JPEG: structural sanity
jpeginfo -c chal.jpg
djpeg -verbose chal.jpg > /dev/null

# generic: ImageMagick will shout about malformed structures
identify -verbose chal.png > /dev/null
```

A CRC error on `IHDR` almost always means the width/height were edited to crop content out of
view. See `png-structure-attacks`.

### Pass 5 - LSB and bit planes

```bash
# the workhorse for PNG/BMP: tries every channel/bit/order combination
zsteg -a chal.png

# same, but also dumps every candidate payload to disk
zsteg -E 'b1,rgb,lsb,xy' chal.png > payload.bin

# ImageMagick bit-plane isolation (bit 0 of each channel, stretched to visible)
convert chal.png -channel R -separate -fx '(floor(u*255) % 2)' -normalize r_lsb.png
```

`zsteg` only handles PNG and BMP. For JPEG the LSB of the *pixels* is meaningless (lossy
recompression destroys it) - JPEG payloads live in DCT coefficients, so use
`steghide`/`stegseek`/`outguess`/`jsteg` instead (see `jpeg-structure-attacks`).

### Pass 6 - Visual and statistical

```bash
# Stegsolve: cycle planes with the arrow keys; also Analyse > Data Extract / Frame Browser
java -jar stegsolve.jar chal.png

# everything-at-once automation (writes a results dir)
stegoveritas chal.png

# difference two nearly identical images - the classic 'spot the difference' challenge
compare -metric AE a.png b.png diff.png
convert a.png b.png -compose difference -composite -auto-level diff.png
```

If there is a second, visually identical image anywhere in the challenge, the difference of the
two **is** the answer nine times out of ten.

## Code

A single triage driver that runs the whole order and writes a report. It skips tools that are
not installed rather than dying.

```python
#!/usr/bin/env python3
"""Image stego triage driver.

Runs the standard triage order over an image, tolerating missing tools.
Usage: python3 image_triage.py chal.png [-o outdir]
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

# (tool, argv-template, needs_output_dir)
PASSES: list[tuple[str, list[str]]] = [
    ("file", ["file", "{f}"]),
    ("exiftool", ["exiftool", "-a", "-u", "-g1", "{f}"]),
    ("binwalk", ["binwalk", "{f}"]),
    ("pngcheck", ["pngcheck", "-vv", "{f}"]),
    ("zsteg", ["zsteg", "-a", "{f}"]),
    ("steghide", ["steghide", "info", "-p", "", "{f}"]),
    ("identify", ["identify", "-verbose", "{f}"]),
]

MAGICS: dict[bytes, str] = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"BM": "bmp",
    b"RIFF": "riff/webp/wav",
    b"PK\x03\x04": "zip",
    b"Rar!\x1a\x07": "rar",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x1f\x8b\x08": "gzip",
    b"%PDF": "pdf",
    b"\x42\x5a\x68": "bzip2",
    b"\xfd7zXZ\x00": "xz",
    b"II*\x00": "tiff-le",
    b"MM\x00*": "tiff-be",
}

TRAILERS: dict[str, bytes] = {
    "png": b"IEND\xaeB`\x82",
    "jpeg": b"\xff\xd9",
    "gif": b"\x00\x3b",
}


def run(name: str, argv: list[str], path: str) -> str:
    """Run one tool, returning its combined output or a skip marker."""
    if shutil.which(argv[0]) is None:
        return f"[skip] {name} not installed"
    cmd = [a.replace("{f}", path) for a in argv]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired:
        return f"[timeout] {' '.join(cmd)}"
    out = (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")
    return out.strip()


def identify_magic(data: bytes) -> str:
    for magic, name in MAGICS.items():
        if data.startswith(magic):
            return name
    return "unknown"


def scan_embedded(data: bytes, skip_start: int = 1) -> list[tuple[int, str]]:
    """Find every known magic at a non-zero offset (embedded/appended files)."""
    hits: list[tuple[int, str]] = []
    for magic, name in MAGICS.items():
        if len(magic) < 3:  # 'BM' is far too short, it false-positives everywhere
            continue
        start = skip_start
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            hits.append((idx, name))
            start = idx + 1
    return sorted(hits)


def trailing_data(data: bytes, kind: str) -> int:
    """Bytes present after the format's end-of-file marker, or 0."""
    trailer = TRAILERS.get(kind)
    if not trailer:
        return 0
    idx = data.rfind(trailer)
    if idx == -1:
        return 0
    return len(data) - (idx + len(trailer))


def main() -> int:
    ap = argparse.ArgumentParser(description="image stego triage")
    ap.add_argument("image")
    ap.add_argument("-o", "--outdir", default="triage_out")
    args = ap.parse_args()

    with open(args.image, "rb") as fh:
        data = fh.read()

    os.makedirs(args.outdir, exist_ok=True)
    report: list[str] = []
    kind = identify_magic(data)
    report.append(f"== magic: {kind} ({len(data)} bytes)")

    extra = trailing_data(data, kind)
    if extra > 0:
        report.append(f"!! {extra} bytes AFTER the end-of-file marker -> carve them")
        tail = data[len(data) - extra:]
        tail_path = os.path.join(args.outdir, "trailing.bin")
        with open(tail_path, "wb") as fh:
            fh.write(tail)
        report.append(f"   wrote {tail_path} (starts with {tail[:8]!r})")

    for off, name in scan_embedded(data):
        report.append(f"!! embedded {name} magic at offset {off} (0x{off:x})")

    for name, argv in PASSES:
        out = run(name, argv, args.image)
        report.append(f"\n== {name} ==\n{out}")

    text = "\n".join(report)
    report_path = os.path.join(args.outdir, "report.txt")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)
    print(f"\n[+] report written to {report_path}")
    return 0


def _selftest() -> None:
    """Build a PNG with an appended ZIP and confirm both are detected."""
    import io
    import zipfile
    import zlib

    def chunk(typ: bytes, payload: bytes) -> bytes:
        return (
            len(payload).to_bytes(4, "big")
            + typ
            + payload
            + zlib.crc32(typ + payload).to_bytes(4, "big")
        )

    ihdr = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    raw = b"\x00\xff\x00\x00"
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("flag.txt", "flag{appended}")
    blob = png + buf.getvalue()

    assert identify_magic(blob) == "png"
    assert trailing_data(blob, "png") == len(buf.getvalue())
    assert any(name == "zip" for _, name in scan_embedded(blob))
    print("selftest ok: png magic, trailing zip detected")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        sys.exit(main())
```

## Decision tree after triage

```text
file says PNG  -> pngcheck -vv  -> CRC/dimension error? -> png-structure-attacks
               -> zsteg -a      -> hit? -> lsb-extraction
               -> tEXt/zTXt?    -> metadata-hiding
file says JPEG -> exiftool thumbnail differs from image? -> metadata-hiding
               -> stegseek with rockyou              -> stego-bruteforce
               -> outguess -r / jsteg reveal
file says GIF  -> frames differ? -> other-image-formats
file says BMP  -> zsteg -a (BMP supported) -> lsb-extraction
appended data  -> polyglot-files / archive-attacks
nothing at all -> is there a SECOND image? difference them.
               -> is the flag in the pixels visually (contrast stretch)?
```

## Variants and pitfalls

- **`zsteg` on a JPEG is meaningless.** It will still print noise. Do not chase it.
- **`binwalk -e` false positives** are constant; a "LZMA compressed data" hit inside pixel noise
  is usually nothing. Trust hits that land on a clean 4-byte-aligned offset near the end.
- **`steghide info` with an empty passphrase** tells you whether the file is a steghide carrier
  at all, before you spend an hour on a wordlist.
- **Resaving the image destroys LSB payloads.** If you opened it in an editor and saved, go back
  to the original.
- **Screenshots of images** (someone pasted the challenge into Discord) are re-encoded and lose
  every LSB payload. Always get the original artifact.
- **The flag may be visually present** but at 1% contrast. `convert -auto-level` or Stegsolve's
  plane cycling finds those in seconds.
- **Check for a second file first.** `difference of two images` is a whole challenge class and
  the triage above will never find it if you only look at one file.

## Tools

`file`, `xxd`, `exiftool`, `binwalk`, `foremost`, `pngcheck`, `jpeginfo`, `zsteg`, `steghide`,
`stegseek`, `outguess`, `stegsolve` (Java), `stegoveritas`, `aperisolve` (web front end that
runs zsteg/steghide/binwalk/outguess at once), ImageMagick (`convert`, `identify`, `compare`).

## References

- PNG specification, chunk layout and CRC definition (libpng.org PNG spec 1.2).
- ExifTool documentation at https://exiftool.org/
- `zsteg` documentation shipped with the gem (`zsteg --help` lists every channel/bit selector).
