---
title: "Tool - Aperi'Solve"
category: stego
subcategory: image-stego
type: tool
tags: [aperisolve, stego, image-analysis, zsteg, steghide, outguess, exiftool, binwalk, bit-planes, aggregator, one-shot, docker, stegoveritas]
summary: "Runs the whole image-steganography toolchain at once (zsteg, steghide, outguess, exiftool, binwalk, foremost, bit planes) and shows every result on one page."
related: [stego-triage, stegsolve-zsteg, exiftool, binwalk]
---

## What it is

Aperi'Solve is a layer-analysis platform for images: you give it a file and it runs the standard stego toolchain in parallel - zsteg, steghide, outguess, exiftool, binwalk, foremost, strings, and per-channel/per-bit-plane renders - then presents everything on one page. It saves you from typing the same eight commands on every stego challenge.

There is a hosted web version and a self-hostable Docker image; for CTF, self-hosting is preferable (no upload of challenge files, and it works offline).

## Install / run

```sh
# self-host with Docker (the offline-friendly option)
docker pull zeecka/aperisolve
docker run -d -p 5000:5000 --name aperisolve zeecka/aperisolve
# then open http://127.0.0.1:5000

# or clone and run with compose
git clone --depth 1 https://github.com/Zeecka/AperiSolve
cd AperiSolve && docker compose up -d

# the hosted instance exists at aperisolve.com - do not upload anything sensitive there
```

If Docker is not available, run the equivalent locally with `stegoveritas`:
```sh
pipx install stegoveritas
stegoveritas_install_deps        # pulls exiftool, steghide, foremost, binwalk, etc.
stegoveritas chal.png            # results land in ./results/
```

## What it runs for you

| Stage | Equivalent command |
|---|---|
| File identification | `file chal.png` |
| Metadata | `exiftool -a -u -G1 chal.png` |
| Strings | `strings -a chal.png` |
| Embedded file scan | `binwalk chal.png` |
| Carving | `foremost -i chal.png` |
| LSB brute force | `zsteg -a chal.png` |
| JPEG stego | `steghide info` / `steghide extract -p ''` |
| JPEG stego (DCT) | `outguess -r chal.jpg out.txt` |
| Bit planes | per-channel, per-bit renders (the Stegsolve view) |
| Colour maps | inverted, grayscale, per-channel isolations |
| Superimposed layers | combinations of planes |
| Zlib / trailing data | appended-data detection |

The value is not that it does anything you could not do yourself - it is that it does all of it in ten seconds and shows the bit planes as images you can scan with your eye.

## Using it well

1. Upload (or point it at) the image, and optionally supply passwords to try for `steghide`/`outguess`.
2. **Look at the bit-plane grid first.** Hidden text drawn into a plane is instantly visible and no automated tool would report it.
3. Read the zsteg section for anything that says `text:` or `file:`.
4. Read the exiftool section for `Comment`, `UserComment`, `Artist`, `ThumbnailImage`.
5. Check the "trailing data" / binwalk section for an appended archive.
6. Then, whatever it found, **reproduce it on the CLI** so you can script the extraction:
   ```sh
   zsteg -E 'b1,rgb,lsb,xy' chal.png > out.bin
   steghide extract -sf chal.jpg -p 'thepassword'
   binwalk -e chal.png
   ```

## Gotchas

- **Do not upload challenge files to the public instance during an active CTF** unless the rules clearly permit it. Some competitions treat that as leaking the challenge; and you are handing your work to a third party. Self-host.
- It is an image tool. Audio, video, archives and documents are out of scope - see `ctfbrain search stego-triage` for those branches.
- It will not find anything that needs a password unless you supply the password; feed it the challenge-specific candidates (`ctfbrain search stego-triage` section 6).
- JPEG results from `zsteg` are meaningless (zsteg is PNG/BMP only); ignore that panel on JPEGs and look at the steghide/outguess panels instead.
- False positives from `zsteg -a` and `binwalk` appear here too. Judge by whether the output is long, printable and starts at a plane boundary.
- It does not understand custom encodings. If the payload is XOR'd or uses a non-standard bit order, you still need to write the extractor yourself.
- The hosted instance has file-size limits and can be slow under load.
- It runs a fixed toolchain: if the challenge needs `jsteg`, `mp3stego`, `bkcrack` or a PNG chunk parser, you are on your own.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Offline, no Docker | `stegoveritas`, or run the commands by hand from `ctfbrain search stego-triage` |
| You need control over parameters | `zsteg -a`, `stegsolve` (`ctfbrain search stegsolve-zsteg`) |
| JPEG specifically | `stegseek chal.jpg rockyou.txt`, `outguess -r`, `jsteg reveal` |
| Appended archives | `binwalk -e`, `7z x`, `bkcrack` for encrypted ones |
| Audio | `sox ... spectrogram`, Sonic Visualiser, `ffmpeg showspectrumpic` |
| PNG structure damage | `pngcheck -v` |
| A custom LSB scheme | a PIL script; see `ctfbrain search stegsolve-zsteg` pattern 7 |
