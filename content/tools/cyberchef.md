---
title: "Tool - CyberChef"
category: misc
subcategory: encoding
type: tool
tags: [cyberchef, encoding, decoding, magic, recipe, base64, xor, hex, offline, gchq, data-transformation, cyberchef-recipe, node, quick-analysis]
summary: "The browser-based 'cyber swiss army knife': chain encoding, decoding, crypto and parsing operations into a recipe, with a Magic auto-detector."
related: [encoding-detection, crypto-triage, unknown-file, flag-formats]
---

## What it is

CyberChef is a client-side web application that applies a chain ("recipe") of ~400 operations to an input: base64/hex/URL/HTML encoding, XOR, AES/DES/RC4, hashes, compression, character encoding conversion, regex extraction, JWT decoding, image manipulation, and more. Its **Magic** operation tries thousands of decode chains automatically and reports what produced sensible output.

For CTF it is the fastest path from "weird blob" to "readable text", and it runs entirely offline once downloaded.

## Install (offline use)

```sh
# Download the release archive from the official GCHQ/CyberChef GitHub releases page,
# unzip it, and open the single HTML file in a browser. No server needed.
unzip CyberChef_v*.zip -d cyberchef && open cyberchef/CyberChef_v*.html
# Debian/Kali package
sudo apt install cyberchef        # then open /usr/share/cyberchef/index.html
# Docker (self-hosted)
docker run -d -p 8000:80 mpepping/cyberchef
# Node library, for scripting the same operations
npm install cyberchef
```
It is fully client-side, so an offline copy behaves identically to the hosted one and never sends your data anywhere.

## The operations that matter

| Operation | Use |
|---|---|
| **Magic** (with "Intensive mode" and a depth of 3-5) | auto-detect the encoding chain. Always your first move |
| From Base64 / To Base64 | with an **Alphabet** field - set a custom alphabet here |
| From Hex / To Hex | delimiter-aware |
| From Base32 / From Base58 / From Base85 | the other bases |
| URL Decode / HTML Entity Decode | web payloads |
| XOR | key as hex/UTF8/base64; `Null preserving` option |
| **XOR Brute Force** | tries all single-byte keys and shows the results - solves a lot of challenges alone |
| ROT13 / ROT47 / **Rotate left/right** | classical shifts (ROT13 has an "amount" slider: that is your Caesar brute force) |
| Vigenere Decode / Bifid / Affine / Rail Fence / Atbash | classical ciphers |
| AES/DES/Triple DES/RC4/Blowfish Decrypt | with mode, key and IV fields |
| RSA Decrypt / RSA Verify | PEM input |
| Derive PBKDF2 key / Derive EVP key | KDFs |
| MD5 / SHA1 / SHA2 / CRC-32 | hashing |
| **JWT Decode** / JWT Verify / JWT Sign | tokens |
| Raw Inflate / Gunzip / Zlib Inflate / Bzip2 Decompress | compression (Raw Inflate handles headerless deflate) |
| Detect File Type / Extract Files | magic-byte identification and carving inside CyberChef |
| **Regular expression** | extract with a regex, with "List matches" output |
| Extract IP addresses / URLs / Email addresses | quick IOC pulls |
| Strings | like the CLI tool, with a length filter |
| Character Encoding / Remove Diacritics | UTF-16, code pages, unicode tricks |
| To/From Morse Code | audio and text Morse |
| From Binary / From Decimal / From Charcode | ordinal encodings |
| Parse QR Code | decode a QR image |
| Render Image | view a carved image inline |
| Fork / Merge / Subsection | apply a recipe to each line, or to only part of the input |
| Label / Jump / Conditional Jump | loops in a recipe (for iterative decoding) |

Recipes worth saving (use "Save recipe" and paste the JSON back later):

```
# peel arbitrary nested encodings
Magic (depth 5, intensive)

# repeated base64 until it stops being base64
Label('top') -> From Base64 -> Conditional Jump(regex '^[A-Za-z0-9+/=]+$', to 'top', max 20)

# per-line decode
Fork(split '\n') -> From Base64 -> Merge

# single-byte XOR sweep
XOR Brute Force (key length 1, sample 100, print key, crib 'flag')

# extract then decode
Regular expression('[A-Za-z0-9+/]{20,}={0,2}', list matches) -> Fork('\n') -> From Base64
```

## Gotchas

- **Magic is a starting point, not an oracle.** It scores by entropy and dictionary hits; a custom-alphabet base64 or a XOR with a multi-byte key will not be found. Read the chain it suggests and then reason.
- The input pane treats content as text by default. For binary work, use the "Input character encoding" selector, or paste hex and start the recipe with `From Hex`.
- Large files (tens of MB) make the browser tab unresponsive. Use CLI tools for those.
- The hosted instance is client-side, but if the data is genuinely sensitive, use the offline copy - it is one HTML file.
- `From Base64` silently ignores invalid characters by default; that can hide a wrong guess. Turn off "Remove non-alphabet chars" to see the failure.
- XOR key fields default to UTF-8 interpretation; switch the dropdown to HEX when your key is bytes.
- Some operations are lossy or reorder bytes (e.g. "Remove whitespace"); when a decode fails unexpectedly, check for an earlier cleanup step eating real data.
- CyberChef's AES needs the key and IV in the right format (hex vs UTF8 vs base64) - mismatches produce garbage rather than an error.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Large files | `python3` with `base64`/`binascii`, or `xxd`, `base64`, `openssl` on the CLI |
| Automated multi-layer peeling | `ciphey` (`pipx install ciphey`), or the peeler script in `ctfbrain search encoding-detection` |
| Classical cipher solving | `ctfbrain search cipher-identification`, `quipqiup` for substitution ciphers |
| Scriptable, repeatable transforms | write the 5 lines of Python; you will need them in the exploit anyway |
| Binary structure | `binwalk`, `xxd`, `010 Editor`/`ImHex` templates |
| Crypto with real key material | `openssl`, `pycryptodome`, SageMath |
