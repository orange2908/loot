---
title: "Tool - Stegsolve / zsteg"
category: stego
subcategory: image-stego
type: tool
tags: [stegsolve, zsteg, lsb, bit-plane, png, bmp, steganography, colour-channel, image-analysis, stegoveritas, stego, extract, palette, alpha-channel]
summary: "The two tools for lossless-image steganography: zsteg brute-forces LSB encodings on the CLI, Stegsolve lets you eyeball every bit plane."
related: [stego-triage, exiftool, binwalk, aperisolve]
---

## What it is

- **zsteg** brute-forces the common LSB encodings in PNG and BMP files: every bit depth, every channel order, every scan direction, plus PNG-specific tricks (extra data after IEND, zlib-compressed chunks, palette abuse). It is the single highest-yield command on a lossless image.
- **Stegsolve** is a small Java GUI that displays one colour/bit plane at a time so you can see hidden text, and includes a data extractor, a stereogram viewer and an image combiner (XOR/AND/ADD two images).

They complement each other: zsteg finds machine-readable payloads, Stegsolve finds things drawn for the eye.

## Install

```sh
# zsteg is a Ruby gem
gem install zsteg
# Debian/Kali
sudo apt install zsteg      # or: gem install zsteg
zsteg --help

# Stegsolve is a single JAR; get it from the author's page, then:
chmod +x stegsolve.jar
java -jar stegsolve.jar
# Kali packages a launcher
sudo apt install stegsolve  2>/dev/null || true

# headless alternative that covers both
pipx install stegoveritas && stegoveritas_install_deps
```

## The invocations that matter

```sh
F=chal.png

# 1. zsteg: the default scan
zsteg "$F"

# 2. zsteg: try EVERYTHING (all bit depths, orders, directions). Always use -a.
zsteg -a "$F"

# 3. zsteg: extract a specific finding it reported
zsteg -E 'b1,rgb,lsb,xy' "$F" > out.bin
zsteg -E 'b1,r,lsb,xy'   "$F" > out.bin
zsteg -E 'extradata:0'   "$F" > out.bin

# 4. zsteg: show more context per hit, and limit the output length
zsteg -a -v "$F"
zsteg -a --limit 4096 "$F"

# 5. zsteg: only look for printable strings of a minimum length (cuts noise)
zsteg -a --min-str-len 8 "$F"

# 6. Stegsolve, GUI workflow:
java -jar stegsolve.jar
#   - arrow keys cycle through ~40 planes/filters. Watch for text appearing.
#   - Analyse -> File Format      : chunk listing, appended data
#   - Analyse -> Data Extract     : pick bit planes + channels, preview, Save Bin
#   - Analyse -> Image Combiner   : XOR/ADD/SUB two images (for paired-image challenges)
#   - Analyse -> Stereogram Solver

# 7. headless bit-plane extraction (when you have no GUI)
python3 - <<'PY'
from PIL import Image
im = Image.open("chal.png").convert("RGB")
w, h = im.size
px = im.load()
for ci, name in enumerate("rgb"):
    for bit in range(8):
        out = Image.new("1", (w, h))
        o = out.load()
        for y in range(h):
            for x in range(w):
                o[x, y] = (px[x, y][ci] >> bit) & 1
        out.save(f"plane_{name}{bit}.png")
print("wrote plane_*.png - open them and look for text")
PY

# 8. the alpha channel (fully transparent pixels can still carry colour)
python3 -c "
from PIL import Image
im = Image.open('chal.png').convert('RGBA'); im.putalpha(255); im.save('opaque.png')"

# 9. PNG structure check (finds cropped images and bad chunks)
pngcheck -v "$F"

# 10. the all-in-one runner
stegoveritas "$F"        # writes results into ./results/
```

Reading zsteg output: each line is `<params> .. <what it found>`. `b1,rgb,lsb,xy` means 1 bit per channel, RGB order, LSB first, scanned x-then-y. A line ending in `text: "flag{...}"` is your answer; `file: gzip compressed data` means extract it with `-E` and then decompress.

## Gotchas

- **zsteg only works on PNG and BMP.** On a JPEG, spatial LSB does not survive DCT compression - use `steghide`/`stegseek`/`outguess` instead (`ctfbrain search stego-triage`).
- Always pass `-a`. The default scan misses most encodings.
- zsteg produces a lot of false-positive "text" from natural image noise. Real payloads are usually long, printable and start at the beginning of a plane. Use `--min-str-len`.
- `zsteg -E` takes the parameter string **exactly** as printed, including the commas.
- Stegsolve's Data Extract dialog has separate bit checkboxes per channel plus a Row/Column order toggle - the combination that works is the one zsteg named.
- Stegsolve is an old Java app; it needs a JRE and does not handle very large images gracefully.
- A PNG whose IHDR height was reduced hides the bottom of the image. `pngcheck` reports a CRC error on IHDR - fix the height and recompute the CRC.
- Palette (indexed) PNGs store indices, not colours: LSB operates on the index. zsteg handles this, manual scripts usually do not.
- If the image was re-saved by a viewer, LSB data is destroyed. Always work on the original file.
- `gem install zsteg` needs Ruby dev headers on some systems (`ruby-dev`, `build-essential`).

## If it fails, use instead

| Situation | Alternative |
|---|---|
| JPEG instead of PNG | `steghide extract -sf f.jpg -p ''`, `stegseek f.jpg rockyou.txt`, `outguess -r` |
| Everything at once | `aperisolve` (`ctfbrain search aperisolve`), `stegoveritas` |
| Appended/embedded files | `binwalk -e`, `foremost` |
| Metadata payloads | `exiftool -a -u -G1` |
| PNG chunk-level tricks | `pngcheck -v`, `pngtools`, a manual chunk parser |
| Audio or video | `sox`/`ffmpeg` spectrogram, `ctfbrain search stego-triage` |
| A custom encoding zsteg does not model | write the extractor in Python with PIL (pattern 7 above) |
| Two images given | Stegsolve's Image Combiner, or `ImageChops.difference` in PIL |
