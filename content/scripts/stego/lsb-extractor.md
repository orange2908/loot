---
title: "Script - Universal LSB Extractor"
category: stego
subcategory: lsb
type: script
tags: [lsb, bit-plane, extractor, zsteg, pillow, pil, numpy, channel-order, msb, palette, alpha, brute-force, printable, stego, script]
summary: "Tries every channel/bit/bit-order/pixel-order permutation on an image, scores each stream and dumps the plausible ones."
tools: [python3, pillow, numpy]
related: [lsb-extraction, image-triage, stego-cheatsheet, image-forensics-cheatsheet, other-image-formats]
---

## What it does

Enumerates the full LSB parameter space that `zsteg` covers, plus the orders `zsteg` does not
(column-major, snake, reversed), and scores every resulting byte stream by:

1. a known file magic at the start (ZIP/PNG/JPEG/gzip/PDF/...),
2. a flag-shaped regex match anywhere,
3. the longest printable-ASCII run,
4. a plausible 32-bit length header followed by printable data.

It works on PNG, BMP, GIF, TIFF and any other lossless format Pillow can open, handles palette
images (index-plane *and* palette-entry LSB), grayscale, and the alpha channel.

## Usage

```bash
pip install pillow
python3 lsb_extractor.py chal.png                      # rank every permutation
python3 lsb_extractor.py chal.png --bits 0 1 2 --top 40
python3 lsb_extractor.py chal.png --dump out/          # write the top candidates to disk
python3 lsb_extractor.py chal.png --only 'b0,rgb,msb,xy'
python3 lsb_extractor.py --selftest
```

Output is one line per candidate, best first:

```text
 10000  b0,rgb,msb,xy          magic:zip        'PK\x03\x04\x14\x00...'
   231  b0,b,msb,xy            text(0.99)       'flag{...}'
```

## Script

```python
#!/usr/bin/env python3
"""Universal LSB extractor.

Enumerates channel sets, bit indices, bit orders and pixel traversal orders,
scores each extracted byte stream and reports/dumps the plausible ones.

Dependencies: Pillow (pip install pillow). numpy is used when available for speed
but is not required.
"""
from __future__ import annotations

import argparse
import itertools
import os
import re
import struct
import sys

from PIL import Image

try:
    import numpy as np
except ImportError:  # pure-python fallback
    np = None

MAGICS: dict[bytes, str] = {
    b"PK\x03\x04": "zip", b"PK\x05\x06": "zip-empty", b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg", b"GIF87a": "gif", b"GIF89a": "gif", b"%PDF-": "pdf",
    b"\x1f\x8b\x08": "gzip", b"BZh": "bzip2", b"\xfd7zXZ\x00": "xz",
    b"7z\xbc\xaf\x27\x1c": "7z", b"Rar!\x1a\x07": "rar", b"\x7fELF": "elf",
    b"OggS": "ogg", b"RIFF": "riff", b"ID3": "mp3", b"SQLite format 3\x00": "sqlite",
    b"-----BEGIN": "pem", b"{\"": "json", b"<?xml": "xml", b"<!DOCTYPE": "html",
}

FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,16}\{[ -~]{2,200}\}")
PRINTABLE = set(range(32, 127)) | {9, 10, 13}

CHANNEL_SETS: dict[str, tuple[int, ...]] = {
    "r": (0,), "g": (1,), "b": (2,), "a": (3,),
    "rgb": (0, 1, 2), "rbg": (0, 2, 1), "grb": (1, 0, 2),
    "gbr": (1, 2, 0), "brg": (2, 0, 1), "bgr": (2, 1, 0),
    "rgba": (0, 1, 2, 3), "abgr": (3, 2, 1, 0),
}

ORDERS = ("xy", "yx", "snake", "snake-col", "xy-rev")


# --------------------------------------------------------------------------- #
# pixel traversal
# --------------------------------------------------------------------------- #
def pixel_order(w: int, h: int, order: str):
    if order == "xy":
        for y in range(h):
            for x in range(w):
                yield x, y
    elif order == "yx":
        for x in range(w):
            for y in range(h):
                yield x, y
    elif order == "snake":
        for y in range(h):
            xs = range(w) if y % 2 == 0 else range(w - 1, -1, -1)
            for x in xs:
                yield x, y
    elif order == "snake-col":
        for x in range(w):
            ys = range(h) if x % 2 == 0 else range(h - 1, -1, -1)
            for y in ys:
                yield x, y
    elif order == "xy-rev":
        for y in range(h - 1, -1, -1):
            for x in range(w - 1, -1, -1):
                yield x, y
    else:
        raise ValueError(f"unknown order: {order}")


# --------------------------------------------------------------------------- #
# bit collection and packing
# --------------------------------------------------------------------------- #
def collect_bits(pixels, w: int, h: int, channels: tuple[int, ...], bit: int,
                 nbits: int, order: str, single_band: bool, max_bits: int) -> list[int]:
    bits: list[int] = []
    for x, y in pixel_order(w, h, order):
        px = pixels[x, y]
        vals = (px,) if single_band else px
        for c in channels:
            if c >= len(vals):
                continue
            v = vals[c]
            for k in range(nbits):
                bits.append((v >> (bit + k)) & 1)
        if len(bits) >= max_bits:
            break
    return bits


def pack_bits(bits: list[int], msb_first: bool) -> bytes:
    out = bytearray()
    n = len(bits) - (len(bits) % 8)
    if msb_first:
        for i in range(0, n, 8):
            v = 0
            for b in bits[i:i + 8]:
                v = (v << 1) | b
            out.append(v)
    else:
        for i in range(0, n, 8):
            v = 0
            for j, b in enumerate(bits[i:i + 8]):
                v |= b << j
            out.append(v)
    return bytes(out)


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #
def longest_printable_run(data: bytes) -> tuple[int, bytes]:
    best = cur = start = best_start = 0
    for i, c in enumerate(data):
        if c in PRINTABLE:
            if cur == 0:
                start = i
            cur += 1
            if cur > best:
                best, best_start = cur, start
        else:
            cur = 0
    return best, data[best_start:best_start + best]


def length_header(data: bytes) -> str | None:
    """A 32-bit length that plausibly describes the rest of the stream."""
    if len(data) < 8:
        return None
    for endian, label in ((">I", "be"), ("<I", "le")):
        (n,) = struct.unpack(endian, data[:4])
        if 1 <= n <= len(data) - 4:
            body = data[4:4 + n]
            printable = sum(1 for c in body if c in PRINTABLE)
            if n >= 4 and printable >= 0.9 * len(body):
                return f"len32-{label}({n}):{body[:60]!r}"
    return None


def score(data: bytes) -> tuple[int, str, bytes]:
    for magic, name in MAGICS.items():
        if data.startswith(magic):
            return 100000, f"magic:{name}", data[:64]
    m = FLAG_RE.search(data)
    if m:
        return 50000, "flag-regex", m.group(0)[:120]
    lh = length_header(data)
    if lh:
        return 20000, lh, data[:64]
    run, sample = longest_printable_run(data)
    return run, f"text-run({run})", sample[:120]


# --------------------------------------------------------------------------- #
# palette handling
# --------------------------------------------------------------------------- #
def palette_streams(im: Image.Image) -> list[tuple[str, bytes]]:
    """LSB of the palette entries themselves, and the raw index plane."""
    out: list[tuple[str, bytes]] = []
    pal = im.getpalette()
    if pal:
        for name, off in (("pal-r", 0), ("pal-g", 1), ("pal-b", 2)):
            bits = [(pal[i] & 1) for i in range(off, len(pal), 3)]
            out.append((name, pack_bits(bits, True)))
            out.append((name + ",lsb", pack_bits(bits, False)))
    idx = list(im.tobytes())
    for msb in (True, False):
        bits = [(v & 1) for v in idx]
        out.append((f"index-plane,{'msb' if msb else 'lsb'}", pack_bits(bits, msb)))
    # the whole index byte stream, which is the payload when the palette is a lookup table
    out.append(("index-bytes", bytes(idx[:65536])))
    return out


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def candidates(path: str, bits_to_try: tuple[int, ...] = (0, 1, 2, 7),
               nbits_to_try: tuple[int, ...] = (1, 2),
               orders: tuple[str, ...] = ORDERS,
               max_bytes: int = 8192) -> list[tuple[int, str, str, bytes, bytes]]:
    """Return (score, tag, note, sample, full_data) sorted best first."""
    im = Image.open(path)
    results: list[tuple[int, str, str, bytes, bytes]] = []

    if im.mode == "P":
        for name, data in palette_streams(im):
            sc, note, sample = score(data)
            results.append((sc, name, note, sample, data))
        im = im.convert("RGB")
    elif im.mode not in ("RGB", "RGBA", "L", "LA"):
        im = im.convert("RGBA" if "A" in im.mode else "RGB")

    bands = im.getbands()
    nband = len(bands)
    single_band = nband == 1
    w, h = im.size
    pixels = im.load()
    max_bits = max_bytes * 8

    names = ["gray"] if single_band else [n for n, cs in CHANNEL_SETS.items() if max(cs) < nband]
    if single_band:
        CHANNEL_SETS.setdefault("gray", (0,))

    for cname, bit, nb, order, msb in itertools.product(
            names, bits_to_try, nbits_to_try, orders, (True, False)):
        chans = CHANNEL_SETS[cname]
        if bit + nb > 8:
            continue
        raw = collect_bits(pixels, w, h, chans, bit, nb, order, single_band, max_bits)
        data = pack_bits(raw, msb)
        sc, note, sample = score(data)
        tag = f"b{bit}" + (f"x{nb}" if nb > 1 else "") + f",{cname},{'msb' if msb else 'lsb'},{order}"
        results.append((sc, tag, note, sample, data))

    results.sort(key=lambda r: -r[0])
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="universal LSB extractor")
    ap.add_argument("image")
    ap.add_argument("--bits", type=int, nargs="+", default=[0, 1, 2, 7],
                    help="bit indices to start from (0 = LSB)")
    ap.add_argument("--nbits", type=int, nargs="+", default=[1, 2],
                    help="how many bits per sample to take")
    ap.add_argument("--orders", nargs="+", default=list(ORDERS))
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--min-score", type=int, default=8)
    ap.add_argument("--max-bytes", type=int, default=8192)
    ap.add_argument("--dump", metavar="DIR", help="write the top candidates here")
    ap.add_argument("--only", help="run a single tag, e.g. 'b0,rgb,msb,xy'")
    args = ap.parse_args(argv)

    res = candidates(args.image, tuple(args.bits), tuple(args.nbits),
                     tuple(args.orders), args.max_bytes)
    if args.only:
        res = [r for r in res if r[1] == args.only]
        if not res:
            print(f"[-] no candidate with tag {args.only!r}", file=sys.stderr)
            return 1

    shown = 0
    for sc, tag, note, sample, _data in res:
        if sc < args.min_score or shown >= args.top:
            break
        print(f"{sc:>7}  {tag:<26} {note:<22} {sample!r}")
        shown += 1
    if shown == 0:
        print("[-] nothing above the score threshold. Try --min-score 4, more --bits, "
              "or check that the image is lossless (LSB cannot survive JPEG).")

    if args.dump:
        os.makedirs(args.dump, exist_ok=True)
        for sc, tag, _note, _sample, data in res[:max(5, args.top)]:
            if sc < args.min_score:
                break
            safe = tag.replace(",", "_")
            p = os.path.join(args.dump, f"{sc:07d}_{safe}.bin")
            with open(p, "wb") as fh:
                fh.write(data)
            print(f"[+] {p}")
    return 0


# --------------------------------------------------------------------------- #
# embedding side (for building test cases and verifying a theory)
# --------------------------------------------------------------------------- #
def embed(src: str, dst: str, payload: bytes, bit: int = 0,
          channels: tuple[int, ...] = (0, 1, 2), order: str = "xy",
          msb_first: bool = True, length_prefix: bool = False) -> None:
    im = Image.open(src).convert("RGB")
    w, h = im.size
    pixels = im.load()
    blob = (struct.pack(">I", len(payload)) + payload) if length_prefix else payload
    bits: list[int] = []
    for byte in blob:
        rng = range(7, -1, -1) if msb_first else range(8)
        bits.extend((byte >> i) & 1 for i in rng)
    it = iter(bits)
    mask = 1 << bit
    for x, y in pixel_order(w, h, order):
        vals = list(pixels[x, y])
        changed = False
        for c in channels:
            try:
                b = next(it)
            except StopIteration:
                if changed:
                    pixels[x, y] = tuple(vals)
                im.save(dst)
                return
            vals[c] = (vals[c] & ~mask) | (b << bit)
            changed = True
        pixels[x, y] = tuple(vals)
    im.save(dst)


def _selftest() -> None:
    import tempfile

    tmp = tempfile.mkdtemp(prefix="lsbtest_")
    cover = os.path.join(tmp, "cover.png")
    im = Image.new("RGB", (96, 96))
    px = im.load()
    for y in range(96):
        for x in range(96):
            px[x, y] = ((x * 3 + y) % 256, (y * 5) % 256, (x * 7 + y * 2) % 256)
    im.save(cover)

    cases = [
        ("b0,rgb,msb,xy", dict(bit=0, channels=(0, 1, 2), order="xy", msb_first=True)),
        ("b0,b,msb,xy", dict(bit=0, channels=(2,), order="xy", msb_first=True)),
        ("b1,rgb,msb,yx", dict(bit=1, channels=(0, 1, 2), order="yx", msb_first=True)),
        ("b0,rgb,lsb,snake", dict(bit=0, channels=(0, 1, 2), order="snake", msb_first=False)),
    ]
    secret = b"flag{universal_lsb_extractor_works}"
    for expected_tag, kwargs in cases:
        dst = os.path.join(tmp, "stego.png")
        embed(cover, dst, secret, **kwargs)
        res = candidates(dst, bits_to_try=(0, 1), nbits_to_try=(1,))
        tags = [r[1] for r in res]
        by_tag = {r[1]: r for r in res}
        assert expected_tag in by_tag, f"{expected_tag} was not enumerated"
        sc, _tag, _note, _sample, data = by_tag[expected_tag]
        assert secret in data, f"{expected_tag}: payload not recovered"
        assert sc >= 50000, f"{expected_tag}: scored only {sc}"
        # Equivalent orders can tie (a short payload confined to row 0 reads the same
        # under xy and snake), so require a top-3 rank rather than an exact match.
        assert tags.index(expected_tag) < 3, f"{expected_tag} ranked {tags.index(expected_tag)}"
        assert res[0][0] >= 50000, f"best score only {res[0][0]} ({res[0][1]})"

    # length-prefixed payload is recognised by the header heuristic
    dst = os.path.join(tmp, "lenpfx.png")
    embed(cover, dst, b"secret text payload here", bit=0, channels=(0, 1, 2),
          order="xy", msb_first=True, length_prefix=True)
    res = candidates(dst, bits_to_try=(0,), nbits_to_try=(1,))
    assert any("len32-be" in r[2] for r in res[:3]), [r[2] for r in res[:3]]

    # scoring primitives
    assert score(b"PK\x03\x04" + b"\x00" * 20)[1] == "magic:zip"
    assert score(b"\x00\x01" + b"CTF{abc}" + b"\xff")[1] == "flag-regex"
    run, sample = longest_printable_run(b"\x00\x00hello world\x00")
    assert run == 11 and sample == b"hello world", (run, sample)

    # packing is the inverse of itself under bit reversal
    data = bytes(range(64))
    bits = [(b >> (7 - i)) & 1 for b in data for i in range(8)]
    assert pack_bits(bits, True) == data

    print("selftest ok: 4 embed/extract round trips, length header, scoring, bit packing")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        sys.exit(main())
```

## Reading the output

- **`magic:*`** - you are done. Write the stream out with `--dump` and `file` it.
- **`flag-regex`** - the flag is printed in the sample column.
- **`len32-be(N)`** - the payload is length-prefixed; strip the first four bytes.
- **`text-run(N)`** with N in the hundreds - almost certainly the payload; N in the single
  digits is noise (random bytes produce printable runs of ~3 by chance).

## Extending it

- **More bit indices**: `--bits 0 1 2 3 4 5 6 7` if a higher plane is used (rare, visible).
- **Sparse embedding**: add a `stride` argument to `collect_bits` and loop strides 2..8; a
  PRNG-seeded position list needs the seed, which means the challenge gives you a password.
- **Per-plane rather than per-pixel interleaving**: collect all of channel R, then all of G,
  then all of B. Add `"plane"` as an order and iterate channels in the outer loop.
- **16-bit PNGs**: Pillow gives mode `I;16`; take bit 0 of the 16-bit sample, and remember the
  byte order.

## Gotchas

- LSB **cannot** survive JPEG, WebP-lossy, or any resize/resave. Verify the file is lossless.
- Palette (`P`) images: convert-to-RGB destroys the index plane, which is why
  `palette_streams()` runs before the conversion.
- The script caps extraction at `--max-bytes` per candidate (default 8 KB) so a large image
  does not take minutes. Raise it once you know which tag is correct.
- A "hit" on `b7` (the MSB plane) just means the image itself is visible in that plane - it is
  not a payload.
