---
title: "LSB Steganography - Exhaustive Extraction"
category: stego
subcategory: lsb
type: technique
tags: [lsb, least-significant-bit, bit-plane, zsteg, stegsolve, channel-order, msb, rgb, alpha, palette, chi-square, sample-pairs, pil, pillow, stego, numpy]
difficulty: medium
summary: "Enumerate every (channel, bit, bit-order, pixel-order) combination instead of guessing; a printable-run detector finds the right one automatically."
when_to_use:
  - "A lossless image (PNG, BMP, GIF, TIFF) with no metadata and no appended data"
  - "zsteg reports a hit you want to reproduce or extend"
  - "The image has an alpha channel that is uniformly 255 except for noise"
  - "Pixel noise looks structured when you view a single bit plane"
tools: [zsteg, stegsolve, python3, pillow, numpy, stegoveritas]
related: [image-triage, png-structure-attacks, other-image-formats, lsb-extractor, stego-cheatsheet, image-forensics-cheatsheet]
---

## TL;DR

LSB stego replaces the low bit(s) of pixel samples with message bits. The message is only
recoverable if you pick the same *channel set*, *bit index*, *bit order within a byte* and
*pixel traversal order* the embedder used. There are only a few hundred sensible combinations,
so enumerate all of them and score each output for printability.

## Recognise it

- PNG/BMP/GIF/TIFF (never JPEG - lossy compression destroys spatial LSBs).
- `zsteg -a` prints something like `b1,rgb,lsb,xy .. text: "flag{...}"`.
- Viewing bit plane 0 of a channel in Stegsolve shows text, a QR, or a sharp region in an
  otherwise random field.
- The bottom-right of a bit plane is clean noise while the top-left is structured - that is the
  payload ending partway through the image in row-major order.
- Alpha channel histogram has values 254 and 255 only.

## Theory

### The parameter space

| Parameter | Typical values |
| --- | --- |
| channels | `r`, `g`, `b`, `a`, `rgb`, `bgr`, `rgba`, `abgr`, grayscale, palette index |
| bit index | 0 (LSB) through 7 (MSB); `b1` in zsteg means "1 bit per sample from the LSB" |
| bits per sample | 1, 2, 4 (zsteg's `b1`, `b2`, `b4`) |
| bit order in byte | MSB-first (most common) or LSB-first |
| pixel order | row-major `xy` (default), column-major `yx`, boustrophedon/snake, spiral |
| channel interleave | per pixel (`r0 g0 b0 r1 g1 b1 ...`) or per plane (`all r, then all g`) |
| direction | forward or reversed |
| start offset | 0, or after a length/magic header |

zsteg names them exactly this way: `b1,r,lsb,xy` = 1 bit, red channel, LSB-first bit packing,
row-major. `b1,bgr,msb,yx` is the mirror case. Its `-a` flag tries the full standard grid.

### Bit packing

Given a bit stream `b0 b1 b2 ...`, MSB-first packing produces
`byte = b0<<7 | b1<<6 | ... | b7`. LSB-first produces `byte = b0 | b1<<1 | ... | b7<<7`.
Getting this wrong yields bytes that are bit-reversed - a useful tell: if your output is
garbage but `int('{:08b}'.format(c)[::-1], 2)` of each byte is printable, you had the order
backwards.

### Headers

Many hand-written embedders prefix the payload:

- a 32-bit big-endian length in the first 32 bits,
- a magic such as `STEG`/`\x89PNG`/`PK\x03\x04`,
- a terminator such as `\x00` or the literal string `$$END$$`.

Always check the first 4 bytes of a candidate stream as a big- and little-endian length: if it
is between 1 and the image capacity, you have found the header format.

### Detection statistics

- **Chi-square attack**: in a natural image the counts of value `2i` and `2i+1` differ; LSB
  replacement makes them converge. A chi-square test over pairs-of-values flags embedding.
- **Sample pairs / RS analysis**: estimates the embedding rate rather than just presence.
- Practical shortcut: histogram the low bit per channel. A natural photo is near 50/50 but
  *correlated spatially*; embedded regions look like white noise with zero spatial correlation.

## Attack

```bash
# 1. let zsteg do the standard grid first
zsteg -a chal.png

# 2. extract a specific candidate to a file
zsteg -E 'b1,rgb,lsb,xy' chal.png > payload.bin
file payload.bin

# 3. all bit planes as images (Stegsolve does this interactively)
java -jar stegsolve.jar chal.png    # arrow keys cycle planes

# 4. ImageMagick: isolate bit 0 of the blue channel and stretch it
convert chal.png -channel B -separate -depth 8 -fx '(u*255)%2' -normalize b0.png

# 5. brute the whole space with the Python below when zsteg finds nothing
python3 lsb_bruteforce.py chal.png --min-run 8
```

## Code

```python
#!/usr/bin/env python3
"""Exhaustive LSB extractor: every channel / bit / bit-order / pixel-order combo.

Scores each candidate byte stream by its longest printable run and by whether it
starts with a known file magic, then prints the best hits.

Usage: python3 lsb_bruteforce.py image.png [--min-run 12] [--bits 1]
"""
from __future__ import annotations

import argparse
import itertools
import re
import sys

from PIL import Image

MAGICS = {
    b"PK\x03\x04": "zip",
    b"\x89PNG": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF8": "gif",
    b"%PDF": "pdf",
    b"\x1f\x8b\x08": "gzip",
    b"7z\xbc\xaf": "7z",
    b"Rar!": "rar",
    b"BZh": "bzip2",
    b"flag": "flag",
    b"CTF": "ctf",
}

PRINTABLE = set(range(32, 127)) | {9, 10, 13}


def pixel_iter(w: int, h: int, order: str):
    """Yield (x, y) in the requested traversal order."""
    if order == "xy":  # row-major, left to right
        for y in range(h):
            for x in range(w):
                yield x, y
    elif order == "yx":  # column-major, top to bottom
        for x in range(w):
            for y in range(h):
                yield x, y
    elif order == "snake":  # boustrophedon rows
        for y in range(h):
            rng = range(w) if y % 2 == 0 else range(w - 1, -1, -1)
            for x in rng:
                yield x, y
    else:
        raise ValueError(f"unknown order {order}")


def collect_bits(px, w: int, h: int, channels: tuple[int, ...], bit: int,
                 order: str, nchan: int, limit: int) -> list[int]:
    """Gather one bit from each selected channel of each pixel, in `order`."""
    bits: list[int] = []
    mask = 1 << bit
    for x, y in pixel_iter(w, h, order):
        p = px[x, y]
        if nchan == 1:
            vals = (p,)
        else:
            vals = p
        for c in channels:
            if c < len(vals):
                bits.append(1 if vals[c] & mask else 0)
        if len(bits) >= limit:
            return bits
    return bits


def pack(bits: list[int], msb_first: bool) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        v = 0
        if msb_first:
            for b in chunk:
                v = (v << 1) | b
        else:
            for j, b in enumerate(chunk):
                v |= b << j
        out.append(v)
    return bytes(out)


def longest_printable_run(data: bytes) -> tuple[int, bytes]:
    best = 0
    best_s = b""
    cur = 0
    start = 0
    for i, c in enumerate(data):
        if c in PRINTABLE:
            if cur == 0:
                start = i
            cur += 1
            if cur > best:
                best = cur
                best_s = data[start:i + 1]
        else:
            cur = 0
    return best, best_s


def score(data: bytes) -> tuple[int, str]:
    for magic, name in MAGICS.items():
        if data[:16].find(magic) != -1:
            return 10_000, f"magic:{name}"
    run, s = longest_printable_run(data)
    note = s[:80].decode("latin1") if run else ""
    return run, note


CHANNEL_SETS = {
    "r": (0,), "g": (1,), "b": (2,), "a": (3,),
    "rgb": (0, 1, 2), "bgr": (2, 1, 0),
    "rgba": (0, 1, 2, 3), "abgr": (3, 2, 1, 0),
    "gray": (0,),
}


def brute(path: str, min_run: int = 10, bits_to_try=(0, 1, 2, 7), max_bytes: int = 4096):
    im = Image.open(path)
    if im.mode == "P":
        print(f"[i] palette image: also run zsteg for palette-index LSB ({len(im.getpalette() or [])//3} colours)")
        im = im.convert("RGB")
    if im.mode not in ("RGB", "RGBA", "L"):
        im = im.convert("RGB")
    nchan = len(im.getbands())
    w, h = im.size
    px = im.load()
    print(f"[i] {path}: {w}x{h} mode={im.mode} bands={im.getbands()}")

    names = ["gray"] if nchan == 1 else [n for n, c in CHANNEL_SETS.items()
                                         if n != "gray" and max(c) < nchan]
    results = []
    limit = max_bytes * 8
    for cname, bit, order, msb in itertools.product(names, bits_to_try, ("xy", "yx", "snake"), (True, False)):
        chans = CHANNEL_SETS[cname]
        bits = collect_bits(px, w, h, chans, bit, order, nchan, limit)
        data = pack(bits, msb)
        sc, note = score(data)
        if sc >= min_run:
            tag = f"b{bit},{cname},{'msb' if msb else 'lsb'},{order}"
            results.append((sc, tag, note, data))
    results.sort(key=lambda r: -r[0])
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--min-run", type=int, default=10)
    ap.add_argument("--dump", metavar="PREFIX", help="write the top 5 candidates to PREFIX_N.bin")
    args = ap.parse_args()

    results = brute(args.image, args.min_run)
    if not results:
        print("[-] nothing scored above the threshold; lower --min-run or try zsteg -a")
        return 1
    for sc, tag, note, _data in results[:25]:
        print(f"{sc:>6}  {tag:<22} {note!r}")
    if args.dump:
        for i, (_sc, tag, _note, data) in enumerate(results[:5]):
            p = f"{args.dump}_{i}_{tag.replace(',', '_')}.bin"
            with open(p, "wb") as fh:
                fh.write(data)
            print(f"[+] wrote {p}")
    return 0


def embed(path_in: str, path_out: str, message: bytes, bit: int = 0,
          channels: tuple[int, ...] = (0, 1, 2), order: str = "xy", msb_first: bool = True) -> None:
    """Reference embedder, used by the self-test (and handy for building your own challenges)."""
    im = Image.open(path_in).convert("RGB")
    w, h = im.size
    px = im.load()
    bits: list[int] = []
    for byte in message:
        if msb_first:
            bits.extend((byte >> (7 - i)) & 1 for i in range(8))
        else:
            bits.extend((byte >> i) & 1 for i in range(8))
    it = iter(bits)
    mask = 1 << bit
    done = False
    for x, y in pixel_iter(w, h, order):
        if done:
            break
        vals = list(px[x, y])
        for c in channels:
            try:
                b = next(it)
            except StopIteration:
                done = True
                break
            vals[c] = (vals[c] & ~mask) | (b << bit)
        px[x, y] = tuple(vals)
    im.save(path_out)


def _selftest() -> None:
    import os
    import tempfile

    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "cover.png")
    dst = os.path.join(tmp, "stego.png")
    im = Image.new("RGB", (64, 64))
    p = im.load()
    for y in range(64):
        for x in range(64):
            p[x, y] = ((x * 5) % 256, (y * 3) % 256, ((x + y) * 7) % 256)
    im.save(src)

    secret = b"flag{lsb_is_everywhere_and_nowhere}"
    embed(src, dst, secret, bit=0, channels=(0, 1, 2), order="xy", msb_first=True)

    results = brute(dst, min_run=8)
    assert results, "brute force found nothing"
    top_tag = results[0][1]
    joined = b"".join(r[3] for r in results[:3])
    assert secret in joined, f"secret not in top candidates; best tag was {top_tag}"
    assert re.search(r"b0,(rgb|r|g|b),msb,xy", top_tag), f"unexpected winning tag {top_tag}"
    print(f"selftest ok: recovered payload with {top_tag}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        sys.exit(main())
```

## Variants and pitfalls

- **JPEG has no usable pixel LSB.** If the challenge file is a JPEG, stop and go to
  `jpeg-structure-attacks`.
- **Palette (mode `P`) PNGs**: the LSB may be in the *palette index* or in the *palette entries*
  themselves. `zsteg` checks both; converting to RGB in Python destroys the index information,
  so handle `im.getpalette()` separately.
- **Alpha-only payloads** are invisible in every viewer that flattens onto white. Check
  `im.getchannel("A").getextrema()`.
- **2 or 4 bits per sample** (`b2`, `b4` in zsteg) doubles/quadruples capacity and still looks
  clean. If `b1` gives nothing, try them.
- **Length prefix confusion**: if the first four bytes decode to a plausible length, drop them
  and re-read. If the stream starts with `\x00\x00\x0d\x2a` that is a 32-bit length of 3370.
- **Sparse embedding** (every Nth pixel, or PRNG-seeded positions) defeats linear extraction.
  A seed derived from a password means you need the password - that is `stego-bruteforce`.
- **Scaled/resaved images lose everything.** Confirm you have the original bytes.
- **Do not trust one tool.** `zsteg` misses column-major and snake orders; the script above
  covers them.
- **Grayscale (`L`) images** have one band; the loop above handles `nchan == 1` specially
  because `px[x, y]` returns an int, not a tuple.

## Tools

`zsteg` (PNG/BMP, the reference implementation of the parameter grid), `stegsolve` (visual
plane browser plus "Data Extract" which exposes the same options in a GUI), `stegoveritas`,
Python `Pillow` + `numpy`, ImageMagick for plane rendering.

## References

- `zsteg --help` documents the exact channel/bit/order selector syntax used above.
- Stegsolve's "Analyse -> Data Extract" dialog exposes bit planes, bit order and row/column order.
- Westfeld and Pfitzmann, "Attacks on Steganographic Systems" - origin of the chi-square attack.
