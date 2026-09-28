---
title: "Tool - binwalk"
category: forensics
subcategory: carving
type: tool
tags: [binwalk, carving, firmware, embedded-files, signature-scan, entropy, extract, squashfs, appended-data, polyglot, unknown-file, stego, forensics]
summary: "Scan any file for embedded file signatures and extract them; the default second command after `file` on an unknown blob."
related: [unknown-file, stego-triage, forensics-triage, exiftool]
---

## What it is

`binwalk` scans a file for known magic signatures at every offset (not just offset 0), reports what it finds, and can extract each embedded object. It was written for firmware images but in CTF it is the standard way to find a ZIP appended to a JPEG, a filesystem inside a blob, or a compressed payload hidden mid-file.

## Install

```sh
# Debian/Ubuntu/Kali
sudo apt install binwalk
# macOS
brew install binwalk
# from source (gets the newest signatures)
pipx install binwalk
# extraction depends on external tools - install them or -e silently does nothing
sudo apt install p7zip-full unzip zlib1g-dev liblzma-dev lzop srecord \
                 squashfs-tools cabextract cramfsswap
# verify
binwalk --help | head -3
```

## The invocations that matter

```sh
# 1. signature scan - what is inside this file, and at what offset
binwalk chal.png

# 2. extract everything it recognises (creates _chal.png.extracted/)
binwalk -e chal.png

# 3. extract recursively - for nested archives and firmware
binwalk -Me chal.bin

# 4. carve every signature match, even ones binwalk cannot decompress
binwalk --dd='.*' chal.bin

# 5. entropy analysis - finds encrypted/compressed regions and their boundaries
binwalk -E chal.bin            # produces a PNG plot
binwalk -EJ chal.bin           # save the plot to a file

# 6. opcode scan - identifies the CPU architecture of a raw blob
binwalk -A chal.bin

# 7. raw string/byte search at every offset
binwalk -R '\x50\x4b\x03\x04' chal.bin      # find every ZIP local header

# 8. limit the extraction size (binwalk loves to explode on false positives)
binwalk -e --size=10000000 chal.bin

# 9. scan but skip the noisy false-positive signatures
binwalk --exclude='Unix path' --exclude='Copyright' chal.bin

# 10. compare two files' signature layouts
binwalk -W a.bin b.bin          # hexdump diff
```

Follow-up you will always want:
```sh
# once binwalk reports an offset, carve it yourself for exact control
binwalk chal.png
# e.g. "1234  0x4D2  Zip archive data"
dd if=chal.png bs=1 skip=1234 of=embedded.zip
unzip -l embedded.zip
# the tail of a file, when the payload is simply appended
tail -c +1235 chal.png > embedded.zip
```

## Gotchas

- **`-e` without external tools installed silently extracts nothing.** If the scan shows a squashfs/LZMA/JFFS2 image but `_extracted/` is empty, you are missing `squashfs-tools`/`liblzma`/etc.
- **False positives are constant** on high-entropy data. A "LZMA compressed data" hit with a 1-byte or nonsensical size on a JPEG is noise. Trust hits whose offsets line up with structure.
- binwalk reports the signature offset; the actual file often starts there, but for some formats there is a header you must include or skip. Verify with `xxd` before trusting the carve.
- Newer binwalk (v3, written in Rust) has different flags from v2. If a flag in a tutorial does not exist, check `binwalk --help` for your version.
- Extraction writes into `_<filename>.extracted/` in the current directory and can fill a disk with `-Me` on a hostile file. Use `--size` and run it in a scratch directory.
- binwalk does not find data that has no signature - XOR-obfuscated or encrypted payloads will not show up. Use entropy (`-E`) to locate them, then decode first.
- It does not understand PNG chunk structure; use `pngcheck -v` alongside it for PNGs.
- Running binwalk on untrusted firmware has had path-traversal extraction CVEs in the past. Extract in a container or a throwaway directory.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| binwalk finds nothing but the file is suspicious | `foremost -i f -o out/`, `scalpel`, `photorec` (better recovery heuristics) |
| You need broad artefact extraction | `bulk_extractor -o be/ f` |
| Format identification only | `file`, `trid` (much larger signature DB) |
| PNG-specific structure | `pngcheck -v`, `zsteg` |
| ZIP/archive specifics | `7z l -slt`, `zipinfo -v` |
| Firmware unpacking | `unblob` (modern binwalk alternative, better format coverage), `firmware-mod-kit` |
| You know the offset already | `dd` / `tail -c` |
| Encrypted/XOR'd payload | `xortool`, then binwalk the decoded output |
