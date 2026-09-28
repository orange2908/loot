---
title: "Tool - bkcrack"
category: crypto
subcategory: zip
type: tool
tags: [bkcrack, zipcrypto, zip, known-plaintext, biham-kocher, archive, password, decrypt, crypto, stego, forensics, pkzip]
summary: "Breaks legacy ZipCrypto ZIP encryption with a known-plaintext attack: 12 known bytes of any file in the archive recovers the internal keys."
related: [stego-triage, john, hashcat, unknown-file]
---

## What it is

`bkcrack` implements the Biham-Kocher known-plaintext attack against the legacy **ZipCrypto** (PKZIP) stream cipher. Given at least 12 contiguous known plaintext bytes from **any one file** in the archive, it recovers the three internal 32-bit keys in minutes, then decrypts every file in the archive - and can optionally recover the password itself.

This matters because in CTF, an encrypted ZIP almost always contains a file whose first bytes you can predict: a PNG header, a PDF header, a known `.docx` structure, or a file you already have an unencrypted copy of.

## Install

```sh
# Prebuilt binaries are published on the project's GitHub releases page; download and unzip.
# Or build from source:
git clone --depth 1 https://github.com/kimci86/bkcrack
cd bkcrack && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
./build/bkcrack -h
# macOS
brew install bkcrack        # if the formula is available; otherwise build from source
```

## The invocations that matter

```sh
Z=secret.zip

# 1. list the archive and check the encryption method (ZipCrypto vs AES)
bkcrack -L "$Z"
7z l -slt "$Z" | grep -i 'method\|encrypted'
#   "ZipCrypto"  -> bkcrack works
#   "AES-256"    -> bkcrack does NOT work; crack the password instead

# 2. the attack with a known-plaintext FILE (you have the exact original)
bkcrack -C "$Z" -c secret.png -p original.png

# 3. the attack with a known PREFIX only (the usual case)
#    build a file containing just the expected first bytes
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' > prefix.bin
bkcrack -C "$Z" -c secret.png -p prefix.bin

# 4. plaintext at a known offset inside the file
bkcrack -C "$Z" -c secret.bin -p known.bin -o 100        # known.bin starts at offset 100

# 5. plaintext from another zip entry (a file you have both encrypted and plain)
bkcrack -C "$Z" -c encrypted.txt -P plain.zip -p plain.txt

# 6. once you have the keys, decrypt one file
bkcrack -C "$Z" -c secret.png -k 12345678 9abcdef0 13579bdf -d secret_decrypted.png

# 7. or rewrite the whole archive with a new password you choose
bkcrack -C "$Z" -k 12345678 9abcdef0 13579bdf -U unlocked.zip newpassword
unzip -P newpassword unlocked.zip

# 8. recover the original password from the keys (bounded length + charset)
bkcrack -k 12345678 9abcdef0 13579bdf -r 10 '?p'          # up to 10 printable chars
bkcrack -k 12345678 9abcdef0 13579bdf -r 8 'abcdefghijklmnopqrstuvwxyz0123456789'

# 9. speed: use more threads and narrow the search
bkcrack -C "$Z" -c secret.png -p prefix.bin -e            # exhaustive
OMP_NUM_THREADS=8 bkcrack -C "$Z" -c secret.png -p prefix.bin

# 10. save/resume the intermediate state on a long run
bkcrack -C "$Z" -c secret.png -p prefix.bin --continue-attack 1234567
```

Known-plaintext prefixes you can always build:

| Target file type | First bytes |
|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52` |
| JPEG (JFIF) | `FF D8 FF E0 00 10 4A 46 49 46 00 01` |
| PDF | `25 50 44 46 2D 31 2E` (`%PDF-1.`) |
| GIF | `47 49 46 38 39 61` |
| ZIP / docx / xlsx | `50 4B 03 04 14 00 06 00` |
| ELF | `7F 45 4C 46 02 01 01 00` |
| A known text header | e.g. `#!/usr/bin/env python3\n` |
| `.docx` `[Content_Types].xml` | the ZIP local header plus that filename |

```sh
# generate a prefix file quickly
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' > prefix.bin
xxd prefix.bin
# or take the first 32 bytes of any file you already have of the same type
head -c 32 sample.png > prefix.bin
```

## Gotchas

- **ZipCrypto only.** If `7z l -slt` says `AES-256` (WinZip AES), bkcrack cannot help - crack the password with `zip2john`+`john` or `hashcat -m 13600`.
- You need **12 contiguous known bytes minimum**; more is much faster. 8 bytes is not enough.
- The known plaintext must correspond to the **uncompressed** data if the entry is stored, but to the **deflate-compressed** data if it is deflated. bkcrack handles this when you give it `-p` a plain file and the entry is deflated, but a hand-built prefix must match the compressed stream - which is why a prefix from a **stored** (uncompressed) entry is far more reliable. Check the method per entry with `bkcrack -L`.
- If the archive has several files, pick the one whose content you can predict best; the recovered keys decrypt **all** entries (they share the archive password).
- Runtime is typically seconds to minutes with a good prefix; with exactly 12 bytes it can be much longer. More known bytes is the single biggest speedup.
- The keys are internal state, not the password. `-r` recovers a password only if it is short and within the charset you give.
- The tool operates on the archive as-is: do not re-zip or modify the file first.
- Very old "PKZIP 2.0" and modern "ZipCrypto" are the same cipher; both are in scope.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| AES-encrypted ZIP | `zip2john f.zip > h; john h --wordlist=rockyou.txt`, or `hashcat -m 13600` |
| No known plaintext at all | password cracking, or find the password in the challenge text |
| RAR archive | `rar2john` + `john`, or `hashcat -m 13000` (RAR5) |
| 7z archive | `7z2john.pl` + `john`, or `hashcat -m 11600` |
| The ZIP is corrupted | `zip -FF broken.zip --out fixed.zip`, or repair the headers by hand |
| Only the filenames are hidden | ZipCrypto does not encrypt filenames; `unzip -l` already shows them |
| You just need to know if it is worth trying | `7z l -slt f.zip \| grep Method` decides it in one second |
