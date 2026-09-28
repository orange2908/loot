---
title: "Playbook - I Have an Unknown File"
category: misc
subcategory: triage
type: playbook
tags: [unknown-file, what-is-this-file, file-identification, magic-bytes, file-command, binwalk, strings, where-to-start, stuck, triage, entropy, hexdump, carving, foremost, trid, blob, no-extension, corrupted-header]
summary: "Decision tree from a mystery blob to a category: file -> magic bytes -> entropy -> container vs executable vs archive vs ciphertext."
when_to_use:
  - "The challenge gave you a file with no extension or a wrong extension"
  - "`file` says 'data' and you do not know what to do next"
  - "You suspect something is embedded inside another file"
  - "You have a blob of bytes from a pcap, a memory dump, or a decoded payload"
related: [stego-triage, forensics-triage, rev-triage, encoding-detection]
---

## TL;DR

Run the four commands below in order. Every branch in this document is decided by their output.

```sh
# 1. libmagic identification - the single highest-value command
file -b unknown.bin
# 2. first 64 bytes in hex + ascii; the magic number lives here
xxd -l 64 unknown.bin
# 3. size and entropy - tells you compressed/encrypted vs plaintext/code
ls -l unknown.bin; ent unknown.bin 2>/dev/null || python3 -c "import sys,math,collections;d=open(sys.argv[1],'rb').read();c=collections.Counter(d);print('entropy',round(-sum(v/len(d)*math.log2(v/len(d)) for v in c.values()),4),'bytes',len(d))" unknown.bin
# 4. embedded files / appended data
binwalk -e unknown.bin
```

---

## Step 0 - Normalise the input first

| Observation | Action |
|---|---|
| File is pure `[A-Za-z0-9+/=]` text | `base64 -d unknown.bin > out.bin` then restart. See `ctfbrain search encoding-detection` |
| File is pure `[0-9a-fA-F]` text, even length | `xxd -r -p unknown.bin > out.bin` then restart |
| File starts with `\x1f\x8b` but named `.txt` | `gunzip -c unknown.bin > out.bin`, restart |
| File is a hexdump/`xxd` output pasted as text | `xxd -r unknown.bin > out.bin` |
| File is a Base64 that fails to decode | Strip whitespace: `tr -d ' \n\r\t' < f \| base64 -d` ; try `base64 -d -i` to ignore garbage; try base32/base58 |
| File is `.txt` with `0x` prefixes or `\x` escapes | `python3 -c "import sys;print(open(sys.argv[1]).read())"` then `bytes.fromhex` / `codecs.decode(s,'unicode_escape')` |

`ctfbrain search encoding-detection`

---

## Step 1 - Branch on `file` output

### 1.1 `file` says ELF / PE / Mach-O
It is an executable. Decide pwn vs rev:

```sh
# Is it stripped? dynamically linked? what protections?
file unknown.bin; checksec --file=unknown.bin; nm -D unknown.bin 2>/dev/null | head -40
```

| Signal | Go to |
|---|---|
| Ships with a `libc.so.6` / `ld-*.so` and an `nc host port` | pwn. `ctfbrain search pwn-triage` |
| No remote, challenge says "find the flag / key / password" | rev. `ctfbrain search rev-triage` |
| Imports `ptrace`, `IsDebuggerPresent`, huge `.rodata`, UPX magic | packed/anti-debug rev. `ctfbrain search upx-unpacking anti-debug` |

### 1.2 `file` says a known archive/container
```sh
# generic: list before extracting, so you see path traversal / zip-slip entries
7z l unknown.bin
7z x unknown.bin -oout/
```

| Magic (`xxd -l 4`) | Type | Command |
|---|---|---|
| `50 4b 03 04` | ZIP / JAR / APK / DOCX / XLSX / ODF | `unzip -l f`; if encrypted -> `ctfbrain search bkcrack zip-known-plaintext` |
| `52 61 72 21` | RAR | `unrar x f` |
| `37 7a bc af` | 7z | `7z x f` |
| `1f 8b` | gzip | `gunzip -c f > out` |
| `42 5a 68` | bzip2 | `bunzip2 -c f > out` |
| `fd 37 7a 58 5a` | xz | `xz -dc f > out` |
| `04 22 4d 18` | lz4 | `lz4 -d f out` |
| `28 b5 2f fd` | zstd | `zstd -d f -o out` |
| `75 73 74 61 72` at 0x101 | tar | `tar xvf f` |
| `21 3c 61 72 63 68 3e` | ar / .deb / static lib | `ar x f` ; `dpkg-deb -R f out/` |
| `ed ab ee db` | RPM | `rpm2cpio f \| cpio -idmv` |
| `d0 cf 11 e0` | OLE2 (legacy doc/xls/msi) | `oledump.py f` ; `ctfbrain search forensics-triage maldoc` |
| `25 50 44 46` | PDF | `ctfbrain search pdf-forensics` |
| `4d 5a` | PE/DLL | rev |
| `ca fe ba be` | Java class OR Mach-O fat | `javap -c -p f` ; `lipo -info f` |
| `ca fe d0 0d` | Java pack200 | `unpack200 f out.jar` |
| `de d0 0d ff`/`0a 70 61 78` | Android dex is `64 65 78 0a` | `jadx -d out f` |
| `53 51 4c 69 74 65` | SQLite3 | `sqlite3 f .dump` |
| `4f 67 67 53` | Ogg | media -> stego |
| `52 49 46 46` | RIFF (WAV/AVI/WEBP) | check bytes 8-12 |
| `89 50 4e 47` | PNG | `ctfbrain search stego-triage` |
| `ff d8 ff` | JPEG | `ctfbrain search stego-triage` |
| `47 49 46 38` | GIF | frames: `convert f out%03d.png` |
| `42 4d` | BMP | LSB stego is common |
| `49 49 2a 00` / `4d 4d 00 2a` | TIFF (LE/BE) | `exiftool f` |
| `1a 45 df a3` | Matroska/WebM | `mkvextract`/`ffmpeg` |
| `00 00 01 ba`/`00 00 01 b3` | MPEG | `ffmpeg -i f` |
| `d4 c3 b2 a1` / `a1 b2 c3 d4` | pcap (LE/BE) | `ctfbrain search forensics-triage pcap` |
| `0a 0d 0d 0a` | pcapng | same |
| `45 4d 55 4c`/`EMiL` etc | check with `trid` | `trid f` |
| `4b 44 4d` | VMDK | `ctfbrain search disk-image` |
| `63 6f 6e 65 63 74 69 78` | VHD | `qemu-img info f` |
| `51 46 49 fb` | QCOW2 | `qemu-nbd` |
| `7f 45 4c 46` | ELF | pwn/rev |
| `23 21` (`#!`) | script | just read it |

Full magic tables: `ctfbrain search file-magic-bytes`

### 1.3 `file` says "ASCII text" / "UTF-8 text"
```sh
head -c 400 unknown.bin; wc -lc unknown.bin
grep -aoiE '[a-z0-9_]+\{[^}]{4,}\}' unknown.bin   # flag-shaped strings
```
- Looks like source code -> `ctfbrain search source-code-given`
- Looks like a ciphertext blob (uniform alphabet, no spaces) -> `ctfbrain search crypto-triage cipher-identification`
- Looks like JSON/YAML/XML config -> hunt for keys, tokens, hashes; `ctfbrain search regex-recipes`
- Three dot-separated base64url segments starting `eyJ` -> JWT. `ctfbrain search jwt-tool`
- `-----BEGIN` -> PEM key/cert. `openssl asn1parse -in f`; `ctfbrain search rsa-decision-tree`

### 1.4 `file` says "data" (the hard case)
Go to Step 2.

---

## Step 2 - `file` says "data": use entropy

Compute entropy (command 3 above). Bits/byte:

| Entropy | Meaning | Next command |
|---|---|---|
| < 1.0 | mostly one byte value; padding, sparse image, or a bitmap | `xxd f \| uniq -f1 -c \| head` |
| 1.0 - 4.5 | structured binary, text-ish, a custom format, or a weak cipher | `strings -n 6 f \| head -50` ; `binwalk f` |
| 4.5 - 6.5 | mixed: an executable, a serialized object, a raw image | `binwalk -A f` (opcode scan) ; `xxd f \| head -40` |
| 6.5 - 7.5 | compressed, or media (jpeg/png/mp3) | `binwalk -e f`; check for a header at a nonzero offset |
| > 7.9 | encrypted, or /dev/urandom, or already-compressed | It is ciphertext -> `ctfbrain search crypto-triage` |

### 2.1 Header may be stripped or the file may start at an offset
```sh
# search the whole file for embedded signatures, not just offset 0
binwalk f
# carve everything binwalk finds
binwalk --dd='.*' f
# aggressive carving of known types when binwalk misses it
foremost -i f -o carved/
scalpel -c /etc/scalpel/scalpel.conf f -o carved/
```
If `binwalk` shows a signature at offset N: `dd if=f bs=1 skip=N of=out.bin`.

### 2.2 Maybe the magic bytes were corrupted on purpose
Classic CTF trick: first 4-8 bytes are zeroed or swapped.
```sh
# compare your header to the expected one and patch it back
xxd -l 16 f
printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a' | dd of=f bs=1 seek=0 conv=notrunc   # restore PNG magic
```
For PNG specifically, `pngcheck -v f` names the broken chunk. `ctfbrain search png-repair`

### 2.3 Maybe it is XOR-obfuscated
```sh
# single-byte XOR brute force + look for a magic number or 'flag'
python3 - <<'PY'
data=open('f','rb').read()
for k in range(256):
    d=bytes(b^k for b in data[:64])
    if d[:4] in (b'\x89PNG', b'PK\x03\x04', b'\x7fELF', b'MZ\x90\x00', b'MZ\x00\x00', b'%PDF') or b'flag' in bytes(b^k for b in data).lower():
        print(hex(k), d[:16])
PY
# multi-byte repeating key
xortool f
xortool f -c 00      # if you expect long runs of null bytes
```
`ctfbrain search xor-cryptanalysis xortool`

### 2.4 Still nothing
```sh
# TrID uses a much bigger signature DB than libmagic
trid f
# look for a repeating block size -> block cipher / a record format
python3 -c "d=open('f','rb').read();print([len(d)%n for n in (8,16,32,64,128,256)])"
# visualise it - structure is obvious to the eye
binvis / veles / `python3 -c "..."` or simply: convert -size 256x256 -depth 8 gray:f out.png
```

---

## Step 3 - Once identified, jump

| Identified as | Go |
|---|---|
| Executable | `ctfbrain search rev-triage` / `ctfbrain search pwn-triage` |
| Image / audio / video | `ctfbrain search stego-triage` |
| pcap / memory dump / disk image / office doc | `ctfbrain search forensics-triage` |
| Archive (possibly encrypted) | `ctfbrain search bkcrack zip-crack` |
| Ciphertext / keys / numbers | `ctfbrain search crypto-triage` |
| Source code | `ctfbrain search source-code-given` |
| Nothing works after 30 min | `ctfbrain search stuck` |

## Pitfalls
- `file` reads only the first bytes: a ZIP appended to a JPEG still reports JPEG. Always also run `binwalk`.
- `binwalk -e` false-positives constantly on high-entropy data. Ignore 1-byte "LZMA compressed data" hits.
- Polyglots are real: a file can legitimately be a valid PDF and a valid ZIP. Try both.
- A file ending in `PK\x05\x06` (EOCD) has ZIP data even if it starts with something else: `unzip f` often just works.
- Never delete the original. Work on copies; some tools write in place.
