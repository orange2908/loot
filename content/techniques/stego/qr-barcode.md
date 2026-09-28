---
title: "QR Codes and Barcodes - Repair, Decode, Read by Hand"
category: stego
subcategory: barcode
type: technique
tags: [qr, qr-code, barcode, datamatrix, aztec, pdf417, code128, ean13, zbar, zbarimg, pyzbar, opencv, reed-solomon, mask-pattern, finder-pattern, repair, stego]
difficulty: medium
summary: "Decode with zbar/OpenCV; if that fails, repair the quiet zone, finders and contrast, and as a last resort read the modules by hand."
when_to_use:
  - "An image contains a QR/barcode that no reader will decode"
  - "The code is inverted, rotated, cut into pieces, or missing its finder patterns"
  - "Only part of the code survives and you need to know if error correction can save it"
  - "You must extract a payload that a phone app refuses to show you raw"
tools: [zbarimg, zbar-tools, python3, pyzbar, opencv, qrcode, PIL, gimp, convert]
related: [image-triage, other-image-formats, video-stego, stego-cheatsheet, image-forensics-cheatsheet]
---

## TL;DR

Try `zbarimg --raw` first, then OpenCV's `QRCodeDetector`, then fix the image (invert, upscale
with nearest-neighbour, add a 4-module quiet zone, threshold to pure black/white) and retry.
Only when all of that fails do you read the module grid by hand - which is entirely doable
because the format information and the first data codewords are in fixed positions.

## Recognise it

- A black-and-white square with three large square "finder" patterns at the corners -> QR.
- Same but with one solid L edge and a dashed edge -> Data Matrix.
- Square with a bullseye in the middle -> Aztec.
- A rectangle of stacked narrow bars -> PDF417.
- Parallel bars with digits underneath -> a 1D symbology (EAN-13, UPC, Code128, Code39).
- A QR whose colours are inverted, or whose modules are red-on-green, or whose finders were
  deliberately erased.

## Theory

### QR anatomy

| Element | Where | Purpose |
| --- | --- | --- |
| Finder patterns | 7x7 at three corners | locate and orient |
| Separators | 1-module white border round each finder | |
| Timing patterns | row/column 6 | establish the module pitch |
| Alignment patterns | 5x5, version >= 2, positions from a table | correct perspective |
| Format information | 15 bits, twice, beside the finders | EC level (2 bits) + mask (3 bits) + BCH |
| Version information | 18 bits, twice, version >= 7 | |
| Data + EC codewords | the rest, zig-zag from bottom-right upward in 2-module columns | |

Version `v` has `17 + 4v` modules per side (v1 = 21x21, v2 = 25x25, ... v40 = 177x177).

Error correction levels and their recovery capacity:

| Level | Bits in format info | Recovers up to |
| --- | --- | --- |
| L | 01 | ~7% of codewords |
| M | 00 | ~15% |
| Q | 11 | ~25% |
| H | 10 | ~30% |

Reed-Solomon works on **codewords (bytes)**, not modules, and it corrects up to `t = (n-k)/2`
erroneous codewords, or twice as many if you know which are missing (erasures). Practically: a
version-1 QR at level H has 26 total codewords, 9 data and 17 EC, so up to 8 wrong codewords
are recoverable - which is why a QR with a corner torn off often still scans.

### Masking

After placing data, one of eight masks is XORed over the data region so no large uniform areas
appear. Mask `i` flips module `(r, c)` when its condition holds:

```text
0: (r + c) % 2 == 0
1: r % 2 == 0
2: c % 3 == 0
3: (r + c) % 3 == 0
4: (r // 2 + c // 3) % 2 == 0
5: (r * c) % 2 + (r * c) % 3 == 0
6: ((r * c) % 2 + (r * c) % 3) % 2 == 0
7: ((r + c) % 2 + (r * c) % 3) % 2 == 0
```

The mask index is in the format information, which is itself protected by a BCH(15,5) code and
XORed with the constant `0x5412` - so you can brute-force all 32 valid format strings and pick
the closest match by Hamming distance.

### Data encoding

After unmasking and de-interleaving, the bit stream starts with a 4-bit **mode indicator**:

| Mode | Bits | Character count bits (v1-9) |
| --- | --- | --- |
| Numeric | 0001 | 10 |
| Alphanumeric | 0010 | 9 |
| Byte | 0100 | 8 |
| Kanji | 1000 | 8 |
| ECI | 0111 | - |
| Terminator | 0000 | - |

Then the character count, then the data, then a terminator. For Byte mode the data is simply
8 bits per character, so once you have the unmasked bit stream you can read a flag off by hand.

## Attack

```bash
# 1. the standard decoders
zbarimg --raw -q chal.png
zbarimg --raw -q --set '*.enable=1' chal.png       # enable every symbology, not just the defaults
python3 -c "import cv2;print(cv2.QRCodeDetector().detectAndDecode(cv2.imread('chal.png'))[0])"

# 2. fix the image, then retry
convert chal.png -negate inv.png                    # inverted codes are extremely common
convert chal.png -bordercolor white -border 40 pad.png   # missing quiet zone
convert chal.png -resize 800x800 -filter point big.png   # nearest-neighbour upscale, never blur
convert chal.png -colorspace Gray -threshold 50% bw.png  # kill antialiasing / colour
convert chal.png -rotate 90 rot.png
convert chal.png -flop mirror.png                   # mirrored codes decode after flipping

# 3. per-channel: the code may only exist in one colour channel
convert chal.png -channel R -separate r.png
convert chal.png -channel G -separate g.png
convert chal.png -channel B -separate b.png

# 4. frames of a video/GIF, one QR per frame
ffmpeg -i chal.gif -vsync 0 f/%04d.png
for f in f/*.png; do zbarimg --raw -q "$f"; done

# 5. reassemble a jigsaw / stitch pieces, then decode
montage piece*.png -tile 3x3 -geometry +0+0 joined.png
```

## Code

```python
#!/usr/bin/env python3
"""QR toolkit: normalise and decode with available libraries, or read the modules by hand.

The manual reader implements: grid sampling, format-info recovery by BCH brute force,
mask removal, zig-zag codeword ordering and byte/numeric/alphanumeric mode decoding.
It handles version 1-6 codes without alignment-pattern interference in the data path
(version 1) and reports what it can for larger ones.

Usage:
  python3 qr_tool.py decode chal.png
  python3 qr_tool.py grid   chal.png 21      # print the module matrix as 0/1
  python3 qr_tool.py --selftest
"""
from __future__ import annotations

import sys

ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

MASKS = {
    0: lambda r, c: (r + c) % 2 == 0,
    1: lambda r, c: r % 2 == 0,
    2: lambda r, c: c % 3 == 0,
    3: lambda r, c: (r + c) % 3 == 0,
    4: lambda r, c: (r // 2 + c // 3) % 2 == 0,
    5: lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    6: lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    7: lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
}

FORMAT_MASK = 0x5412
EC_BITS = {0b01: "L", 0b00: "M", 0b11: "Q", 0b10: "H"}


def bch_format(data5: int) -> int:
    """Encode 5 format bits into the 15-bit BCH(15,5) word used by QR."""
    d = data5 << 10
    g = 0b10100110111
    for i in range(4, -1, -1):
        if d & (1 << (i + 10)):
            d ^= g << i
    return ((data5 << 10) | d) ^ FORMAT_MASK


ALL_FORMATS = {bch_format(i): i for i in range(32)}


def popcount(x: int) -> int:
    return bin(x).count("1")


def best_format(bits15: int) -> tuple[int, int, int]:
    """Return (ec_level_bits, mask_index, hamming_distance) for the closest valid format word."""
    best = (None, None, 99)
    for word, raw in ALL_FORMATS.items():
        d = popcount(word ^ bits15)
        if d < best[2]:
            best = (raw >> 3, raw & 0b111, d)
    return best


def unmask(matrix: list[list[int]], mask_index: int) -> list[list[int]]:
    n = len(matrix)
    fn = MASKS[mask_index]
    out = [row[:] for row in matrix]
    for r in range(n):
        for c in range(n):
            if is_function_module(r, c, n):
                continue
            if fn(r, c):
                out[r][c] ^= 1
    return out


def is_function_module(r: int, c: int, n: int) -> bool:
    """True for finders, separators, timing, format and (v>=7) version areas."""
    if r < 9 and c < 9:
        return True
    if r < 9 and c >= n - 8:
        return True
    if r >= n - 8 and c < 9:
        return True
    if r == 6 or c == 6:
        return True
    version = (n - 17) // 4
    if version >= 2:  # single alignment pattern at (n-7, n-7) for versions 2..6
        ar = ac = n - 7
        if abs(r - ar) <= 2 and abs(c - ac) <= 2:
            return True
    return False


def read_codewords(matrix: list[list[int]]) -> list[int]:
    """Zig-zag from the bottom-right, two columns at a time, skipping function modules."""
    n = len(matrix)
    bits: list[int] = []
    col = n - 1
    upward = True
    while col > 0:
        if col == 6:  # the vertical timing pattern column is skipped entirely
            col -= 1
        rows = range(n - 1, -1, -1) if upward else range(n)
        for r in rows:
            for c in (col, col - 1):
                if not is_function_module(r, c, n):
                    bits.append(matrix[r][c])
        upward = not upward
        col -= 2
    return [int("".join(str(b) for b in bits[i:i + 8]), 2)
            for i in range(0, len(bits) - 7, 8)]


def decode_payload(codewords: list[int], version: int = 1) -> str:
    """Decode the data codeword stream (post error correction) into text."""
    bits = "".join(f"{cw:08b}" for cw in codewords)
    out: list[str] = []
    i = 0
    while i + 4 <= len(bits):
        mode = int(bits[i:i + 4], 2)
        i += 4
        if mode == 0:
            break
        if mode == 0b0100:      # byte
            cc_len = 8 if version <= 9 else 16
            count = int(bits[i:i + cc_len], 2)
            i += cc_len
            for _ in range(count):
                if i + 8 > len(bits):
                    break
                out.append(chr(int(bits[i:i + 8], 2)))
                i += 8
        elif mode == 0b0010:    # alphanumeric
            cc_len = 9 if version <= 9 else 11
            count = int(bits[i:i + cc_len], 2)
            i += cc_len
            while count >= 2 and i + 11 <= len(bits):
                v = int(bits[i:i + 11], 2)
                out.append(ALNUM[v // 45])
                out.append(ALNUM[v % 45])
                i += 11
                count -= 2
            if count == 1 and i + 6 <= len(bits):
                out.append(ALNUM[int(bits[i:i + 6], 2)])
                i += 6
        elif mode == 0b0001:    # numeric
            cc_len = 10 if version <= 9 else 12
            count = int(bits[i:i + cc_len], 2)
            i += cc_len
            while count >= 3 and i + 10 <= len(bits):
                out.append(f"{int(bits[i:i + 10], 2):03d}")
                i += 10
                count -= 3
            if count == 2 and i + 7 <= len(bits):
                out.append(f"{int(bits[i:i + 7], 2):02d}")
                i += 7
            elif count == 1 and i + 4 <= len(bits):
                out.append(str(int(bits[i:i + 4], 2)))
                i += 4
        else:
            break
    return "".join(out)


def format_bits_from_matrix(matrix: list[list[int]]) -> int:
    """Read the 15 format bits from the copy beside the top-left finder."""
    n = len(matrix)
    coords = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
              (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    val = 0
    for r, c in coords:
        val = (val << 1) | matrix[r][c]
    del n
    return val


def manual_decode(matrix: list[list[int]]) -> dict:
    n = len(matrix)
    version = (n - 17) // 4
    fmt = format_bits_from_matrix(matrix)
    ec, mask, dist = best_format(fmt)
    unmasked = unmask(matrix, mask)
    cws = read_codewords(unmasked)
    return {
        "size": n,
        "version": version,
        "ec_level": EC_BITS.get(ec, "?"),
        "mask": mask,
        "format_hamming": dist,
        "codewords": cws,
        "text": decode_payload(cws, version),
    }


def matrix_from_image(path: str, modules: int | None = None) -> list[list[int]]:
    """Sample an image down to a module matrix (1 = dark). Requires Pillow."""
    from PIL import Image

    im = Image.open(path).convert("L")
    w, h = im.size
    if modules is None:
        modules = guess_modules(im)
    cell_w = w / modules
    cell_h = h / modules
    px = im.load()
    out = []
    for r in range(modules):
        row = []
        for c in range(modules):
            x = int((c + 0.5) * cell_w)
            y = int((r + 0.5) * cell_h)
            row.append(1 if px[min(x, w - 1), min(y, h - 1)] < 128 else 0)
        out.append(row)
    return out


def guess_modules(im) -> int:
    """Estimate the module count from the width of the top-left finder pattern (7 modules)."""
    px = im.load()
    w, h = im.size
    run = 0
    y = h // 14 if h > 14 else 0
    for x in range(w):
        if px[x, y] < 128:
            run += 1
        elif run:
            break
    if run == 0:
        return 21
    module_px = run / 7.0
    n = round(w / module_px)
    n = max(21, n)
    return n if (n - 17) % 4 == 0 else 21


def library_decode(path: str) -> list[str]:
    """Try pyzbar then OpenCV; return every payload found."""
    found: list[str] = []
    try:
        from pyzbar.pyzbar import decode as zdecode
        from PIL import Image
        for sym in zdecode(Image.open(path)):
            found.append(f"{sym.type}: {sym.data.decode('utf-8', 'replace')}")
    except ImportError:
        pass
    try:
        import cv2
        img = cv2.imread(path)
        if img is not None:
            txt, _pts, _st = cv2.QRCodeDetector().detectAndDecode(img)
            if txt:
                found.append(f"QRCODE(cv2): {txt}")
    except ImportError:
        pass
    return found


def print_grid(matrix: list[list[int]]) -> None:
    for row in matrix:
        print("".join("##" if v else "  " for v in row))


def main() -> int:
    cmd = sys.argv[1]
    if cmd == "decode":
        hits = library_decode(sys.argv[2])
        for h in hits:
            print(h)
        if not hits:
            print("[-] no library decode; falling back to manual module reading")
            m = matrix_from_image(sys.argv[2])
            info = manual_decode(m)
            for k, v in info.items():
                if k != "codewords":
                    print(f"  {k}: {v}")
    elif cmd == "grid":
        mods = int(sys.argv[3]) if len(sys.argv) > 3 else None
        print_grid(matrix_from_image(sys.argv[2], mods))
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    # Format information round trip: encode, corrupt 2 bits, recover.
    for ec, mask in ((0b01, 3), (0b10, 7), (0b00, 0)):
        raw = (ec << 3) | mask
        word = bch_format(raw)
        got_ec, got_mask, dist = best_format(word)
        assert (got_ec, got_mask, dist) == (ec, mask, 0), (ec, mask, got_ec, got_mask, dist)
        corrupted = word ^ 0b000000000000101
        got_ec, got_mask, dist = best_format(corrupted)
        assert (got_ec, got_mask) == (ec, mask), "BCH should absorb 2 bit errors"
        assert dist == 2

    # Mask functions match the specification for a few sample coordinates.
    assert MASKS[0](0, 0) and not MASKS[0](0, 1)
    assert MASKS[1](2, 5) and not MASKS[1](3, 5)
    assert MASKS[2](7, 3) and not MASKS[2](7, 4)

    # Function-module map for a version-1 (21x21) code.
    n = 21
    assert is_function_module(0, 0, n) and is_function_module(6, 10, n)
    assert is_function_module(20, 0, n) and is_function_module(0, 20, n)
    assert not is_function_module(10, 10, n)
    data_modules = sum(1 for r in range(n) for c in range(n) if not is_function_module(r, c, n))
    assert data_modules == 208, data_modules   # 26 codewords * 8 bits

    # Codeword ordering visits every data module exactly once.
    empty = [[0] * n for _ in range(n)]
    cws = read_codewords(empty)
    assert len(cws) == 26, len(cws)

    # Byte-mode payload decoding from raw codewords.
    msg = b"flag{qr}"
    bits = "0100" + f"{len(msg):08b}" + "".join(f"{b:08b}" for b in msg) + "0000"
    bits += "0" * (-len(bits) % 8)
    codewords = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]
    assert decode_payload(codewords, 1) == "flag{qr}"

    # Alphanumeric mode.
    text = "CTF 2026"
    pairs = [(ALNUM.index(text[i]) * 45 + ALNUM.index(text[i + 1])) for i in range(0, len(text) - 1, 2)]
    ab = "0010" + f"{len(text):09b}" + "".join(f"{v:011b}" for v in pairs) + "0000"
    ab += "0" * (-len(ab) % 8)
    acw = [int(ab[i:i + 8], 2) for i in range(0, len(ab), 8)]
    assert decode_payload(acw, 1) == text, decode_payload(acw, 1)

    # Numeric mode.
    num = "1234567"
    nb = "0001" + f"{len(num):010b}"
    nb += "".join(f"{int(num[i:i + 3]):010b}" for i in range(0, 6, 3))
    nb += f"{int(num[6]):04b}" + "0000"
    nb += "0" * (-len(nb) % 8)
    ncw = [int(nb[i:i + 8], 2) for i in range(0, len(nb), 8)]
    assert decode_payload(ncw, 1) == num, decode_payload(ncw, 1)

    print("selftest ok: BCH format recovery, masks, function map (208 data modules), "
          "byte/alnum/numeric decoding")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--selftest":
        sys.exit(main())
    _selftest()
```

## Other symbologies

| Symbology | Shape | Decoder |
| --- | --- | --- |
| Data Matrix | square, solid L finder | `zbarimg` (build with DM support), `dmtxread` (libdmtx) |
| Aztec | central bullseye | `zxing` based tools; ZBar does not decode Aztec |
| PDF417 | stacked rows of bars | `zxing`, `pdf417decoder` |
| Code 128 / Code 39 | 1D bars | `zbarimg` decodes by default |
| EAN-13 / UPC-A | 1D with digits | `zbarimg`; the last digit is a mod-10 check digit |
| MaxiCode | hexagons + bullseye | `zxing` |

For 1D codes that will not scan, measure the bar widths by hand: every symbology is a fixed
pattern of narrow/wide bars and spaces, and a table lookup recovers the digits.

## Variants and pitfalls

- **Inverted colours** are the number one cause of "it will not scan". Always try `-negate`.
- **No quiet zone**: the spec requires 4 modules of white around a QR. Adding a white border
  fixes a huge fraction of stubborn codes.
- **Antialiased upscaling destroys modules.** Use nearest neighbour (`-filter point`).
- **Micro QR** (11x11 to 17x17) uses a different format-info layout and one finder pattern;
  `zbarimg` will not read it - use a ZXing-based tool.
- **Colour-separated QR**: three independent QRs in the R, G and B channels of one image.
- **Jigsaw QR**: pieces shuffled; the three finder patterns tell you which pieces are corners
  and their orientation.
- **The payload may not be the flag.** A QR that decodes to a URL or to base64 is one step,
  not the answer.
- **Manual reading**: de-interleaving is only trivial for version 1 (one block). For versions
  with multiple EC blocks you must de-interleave the codewords before reading them, or the
  stream will look like noise even though every module is correct.
- **Reed-Solomon decoding by hand is rarely needed.** If more than a few codewords are damaged,
  it is almost always faster to repair the *image* than to implement RS correction.

## Tools

`zbarimg`/`zbarcam` (ZBar), `libdmtx` (`dmtxread`), Python `pyzbar`, `opencv-python`
(`cv2.QRCodeDetector`, `cv2.barcode.BarcodeDetector`), `qrcode` (generation),
`segno` (generation), ImageMagick, GIMP for manual pixel repair.

## References

- ISO/IEC 18004 specifies QR symbol structure, the eight mask patterns, the BCH(15,5) format
  information code and its `0x5412` mask constant, and the codeword placement order.
- ZBar project documentation for the `--set '*.enable=1'` symbology switch.
- ISO/IEC 16022 (Data Matrix), ISO/IEC 15438 (PDF417), ISO/IEC 24778 (Aztec).
