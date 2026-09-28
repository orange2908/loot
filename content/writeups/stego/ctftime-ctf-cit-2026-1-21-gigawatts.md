---
title: "1.21 Gigawatts - CTF@CIT 2026"
category: "stego"
subcategory: "audio"
type: "writeup"
tags: ["stego", "sstv", "qr-code", "base64", "gigawatts", "audio", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Category: Misc · Points: 1000"
source:
  name: "CTFtime writeup #40746"
  url: "https://ctftime.org/writeup/40746"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "1.21 Gigawatts"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** 1.21 Gigawatts
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40746>

---
# 1.21 Gigawatts — Writeup

\- **Category:** Misc · **Points:** 1000  
\- **Flag:** `CIT{fl0ppy_d1sk_fluX_c4p4c1tor}`

Back to the Future reference ("1.21 gigawatts" / flux capacitor) → the final payload is a KryoFlux **flux** capture of a FAT12 **floppy disk**. Five transforms stacked:

```text  
WAV ─► SSTV(Martin 1) ×5 ─► QR ─► base64 ─► gzip ─► KryoFlux stream ─► FAT12 floppy ─► FLAG.TXT  
```

## 1. SSTV in the WAV

The WAV is 582 s at 44.1 kHz mono. Instantaneous frequency lives in 1100–2300 Hz with strong peaks at 2297 Hz — the signature of Martin-1 SSTV (1500 Hz black, 2300 Hz white, 1200 Hz sync). `sstv -d 121gigawatts.wav` auto-detects `Martin 1`, one frame ≈ 114 s, so 5 frames cover ~570 s.

Decode each frame by re-running with `-s <skip>`:

```sh  
sstv -d 121gigawatts.wav -s 0 -o qr_1of5.png  
sstv -d 121gigawatts.wav -s 114 -o qr_2of5.png  
sstv -d 121gigawatts.wav -s 228 -o qr_3of5.png  
sstv -d 121gigawatts.wav -s 342 -o qr_4of5.png  
sstv -d 121gigawatts.wav -s 456 -o qr_5of5.png  
```

## 2. QR → base64 → gzip

Each decoded image is a QR code whose payload begins `N/5:` followed by base64 text. Concatenating the 5 chunks yields a base64 blob starting `H4sI…` (gzip magic `1f 8b` in base64).

```sh  
for i in 1 2 3 4 5; do  
zbarimg -q --raw qr_${i}of5.png  
done | awk -F: '{print $2}' | tr -d '\n' | base64 -d | gunzip > stream.raw  
```

Result: 47 081 bytes.

## 3. Identifying the KryoFlux stream

First 42 bytes decode to plain text:

```text  
sck=24027428.5714286, ick=3003428.5714286  
```

These are the exact [KryoFlux](<https://www.kryoflux.com/>) sample-clock and index-clock constants. The surrounding `\x0d <type> <len:LE16> <data>` blocks are KryoFlux OOB (Out Of Band) records. The remaining ~47 KB is flux-transition data — mostly bytes `0x60` (96), `0x90` (144), `0xc0` (192). The 2 : 3 : 4 ratio is the hallmark of **MFM at 500 kbit/s on a 3.5" HD/DD floppy** (2T/3T/4T cells at 24.027 MHz sample clock = 4 µs / 6 µs / 8 µs). 46 985 flux events in 200.01 ms = exactly one revolution at 300 RPM. One track of a floppy.

## 4. KryoFlux → FAT12

The [Greaseweazle](<https://github.com/keirf/greaseweazle>) toolkit reads KryoFlux streams. It expects files named `trackCC.H.raw`; copy the stream to `track00.0.raw`, then convert to a 720 KB IBM-MFM image:

```sh  
gw convert track00.0.raw floppy.img --format ibm.720  
# T0.0: IBM MFM (9/9 sectors) from Raw Flux — 100%  
```

## 5. Reading the flag off the disk

The image is a valid FAT12 volume, OEM `MSDOS5.0`, label `CAPACITOR`. Sector 3 (root directory) contains `FLAG.TXT`; sector 4 (first data sector) starts with:

```text  
CIT{fl0ppy_d1sk_fluX_c4p4c1tor}  
```

Easy grep:

```sh  
strings floppy.img | grep -o 'CIT{[^}]*}'  
# CIT{fl0ppy_d1sk_fluX_c4p4c1tor}  
```

## Reproduce

```sh  
pip3 install --user pysstv git+<https://github.com/colaclanth/sstv> git+<https://github.com/keirf/greaseweazle>  
brew install zbar libsndfile  
bash scripts/[solve.sh](http://solve.sh)  
```

## Chain-of-stego recap

| Layer | Tool | Clue |  
|---|---|---|  
| SSTV Martin-1 | `sstv` | ~15 kHz FFT peak, 1100–2300 Hz range |  
| 5 QR codes | `zbarimg` | image is clearly a QR |  
| base64 + gzip | `base64 -d \| gunzip` | `H4sI…` magic |  
| KryoFlux stream | `gw convert` | `sck=…, ick=…` constants |  
| FAT12 image | `strings` / mount | `CIT{…}` |
