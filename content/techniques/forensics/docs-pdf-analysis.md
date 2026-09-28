---
title: "PDF Forensics - Objects, JavaScript, Embedded Files and Incremental Updates"
category: forensics
subcategory: documents
type: technique
tags: [pdf, pdfid, pdf-parser, peepdf, qpdf, mutool, pdftotext, pdfimages, pdfdetach, exiftool, javascript, openaction, embeddedfile, incremental-update, redaction, flatedecode, maldoc, dfir]
difficulty: medium
summary: "Map a PDF's object graph, extract JavaScript and embedded files, and recover redacted text from earlier incremental revisions."
when_to_use:
  - "The challenge ships a .pdf and says 'redacted', 'classified' or 'attachment'"
  - "pdfid reports a nonzero /JS, /OpenAction, /Launch or /EmbeddedFile count"
  - "Text is visible on screen but pdftotext returns nothing (or vice versa)"
  - "The file size does not match the visible content"
tools: [pdfid, pdf-parser, peepdf, qpdf, mutool, poppler-utils, exiftool, binwalk, python3, john, hashcat]
related: [docs-office-macros, docs-email-forensics, disk-file-carving, docs-sqlite-forensics]
---

## TL;DR

`pdfid` tells you which dangerous keywords exist, `pdf-parser` shows and extracts the objects,
`qpdf --qdf` makes the whole file human-readable, and a `%%EOF` count greater than one means
there are earlier revisions that may still contain what was "redacted".

## Structure you need to know

```
%PDF-1.7                          <- header (bytes 0-8; must be within the first 1024 bytes)
1 0 obj                           <- object number, generation
<< /Type /Catalog /Pages 2 0 R >>
endobj
...
4 0 obj
<< /Length 128 /Filter /FlateDecode >>
stream
....binary....
endstream
endobj
xref                              <- cross-reference table (or an xref stream in 1.5+)
0 12
0000000000 65535 f
0000000015 00000 n
trailer
<< /Size 12 /Root 1 0 R /Info 3 0 R /ID [<..><..>] /Prev 45678 /Encrypt 9 0 R >>
startxref
56789
%%EOF                             <- end of THIS revision
```

Key points:

- `/Prev` in a trailer points at the **previous** xref table. Following the chain walks backwards
  through every incremental update.
- Each incremental update appends a new body + xref + trailer + `%%EOF`. Nothing is deleted.
- `/Length` may be an indirect reference, so you cannot always trust it when carving by hand.
- Object streams (`/Type /ObjStm`) pack many objects into one compressed stream; `qpdf
  --object-streams=disable` unpacks them.

## Triage

```sh
# keyword counts: the one-line risk assessment
pdfid.py suspicious.pdf
# also scan for the keywords inside object streams (they hide there)
pdfid.py -e suspicious.pdf
# force it to look everywhere, not just the header region
pdfid.py -a suspicious.pdf
# make the whole file readable: uncompress streams, one object per block
qpdf --qdf --object-streams=disable suspicious.pdf readable.pdf
less readable.pdf
# structural sanity check and repair
qpdf --check suspicious.pdf
qpdf --replace-input --qdf suspicious.pdf   # in-place normalisation (keep a copy!)
# page count and basic info
qpdf --show-npages suspicious.pdf
pdfinfo suspicious.pdf
mutool info suspicious.pdf
# full metadata including XMP and hidden fields
exiftool -a -u -g1 suspicious.pdf
pdftk suspicious.pdf dump_data
# how many revisions are in here?
grep -c '%%EOF' suspicious.pdf
grep -abo '%%EOF' suspicious.pdf
grep -abo 'startxref' suspicious.pdf
# anything appended after the last %%EOF is a polyglot / hidden payload
binwalk suspicious.pdf
binwalk -e suspicious.pdf
```

What `pdfid` counters mean:

| Keyword | Why it matters |
| --- | --- |
| `/JS`, `/JavaScript` | Embedded script |
| `/AA`, `/OpenAction` | Runs something automatically on open or on an event |
| `/Launch` | Launches an external application |
| `/EmbeddedFile` | A file is stored inside the PDF |
| `/URI` | External link (exfil / phishing) |
| `/AcroForm`, `/XFA` | Forms; XFA is a whole XML app surface |
| `/RichMedia` | Flash / embedded media |
| `/GoToR`, `/SubmitForm` | Remote navigation / data submission |
| `/ObjStm` | Object streams -- keywords may be hidden inside, rerun with `-e` |
| `/Encrypt` | The document is encrypted |
| `/AcroForm` + `/JS` | Classic malicious combination |

## Walking the objects

```sh
# statistics: which object types exist and how many
pdf-parser.py -a suspicious.pdf
# print every object (huge output, pipe it)
pdf-parser.py suspicious.pdf | less
# show object 12, and follow it
pdf-parser.py -o 12 suspicious.pdf
# decode the stream in object 12 (applies /Filter) and dump raw bytes to a file
pdf-parser.py -o 12 -f -d out.bin suspicious.pdf
# raw (undecoded) stream instead
pdf-parser.py -o 12 -d raw.bin suspicious.pdf
# find every object mentioning a keyword
pdf-parser.py --search JavaScript suspicious.pdf
pdf-parser.py --search OpenAction suspicious.pdf
pdf-parser.py --search EmbeddedFile suspicious.pdf
# show objects of a given type
pdf-parser.py -t /Page suspicious.pdf
# resolve references and print the object that a name points to
pdf-parser.py -r 12 suspicious.pdf
# peepdf: interactive object browser with JS analysis
peepdf -i suspicious.pdf
peepdf -f -l suspicious.pdf         # force parsing of a malformed file, verbose
# inside the peepdf shell:
#   tree              show the object tree
#   object 12         print object 12
#   stream 12         print the decoded stream
#   js_analyse object 12
#   extract js
# qpdf per-object inspection
qpdf --show-object=12 suspicious.pdf
qpdf --show-object=12 --raw-stream-data suspicious.pdf > raw.bin
qpdf --show-object=12 --filtered-stream-data suspicious.pdf > decoded.bin
# mutool: fast and scriptable
mutool show suspicious.pdf trailer
mutool show suspicious.pdf xref
mutool show suspicious.pdf grep | grep -i javascript
mutool show suspicious.pdf 12
```

## Getting the content out

```sh
# text, preserving layout (the fastest way to beat a bad redaction)
pdftotext -layout suspicious.pdf - | less
# text with no layout heuristics - sometimes reveals hidden/overlapped text
pdftotext -raw suspicious.pdf -
# per-page
pdftotext -f 3 -l 3 -layout suspicious.pdf page3.txt
# mutool's text extractor, for when poppler chokes
mutool draw -F txt -o - suspicious.pdf
mutool draw -F stext -o out.xml suspicious.pdf   # text with coordinates
# every image, in its native format, with JPEG kept as JPEG
pdfimages -all -j suspicious.pdf img
pdfimages -list suspicious.pdf                   # inventory first
# embedded (attached) files
pdfdetach -list suspicious.pdf
pdfdetach -saveall -o ./attachments suspicious.pdf
# mutool extracts images AND fonts AND embedded files
mutool extract suspicious.pdf
# render pages to PNG so you can see what the text extractor missed
pdftoppm -r 150 -png suspicious.pdf page
mutool draw -r 150 -o page%d.png suspicious.pdf
# brute force
strings -a suspicious.pdf | grep -aoiE '[a-z0-9_]{2,16}\{[^}]{4,120}\}'
strings -a suspicious.pdf | grep -aiE '(http|javascript|eval|unescape|%u[0-9a-f]{4})'
```

## JavaScript

```sh
# find it
pdfid.py suspicious.pdf | grep -iE '/JS|/JavaScript|/OpenAction|/AA'
pdf-parser.py --search javascript suspicious.pdf
# extract the JS object's stream
pdf-parser.py -o 9 -f -d js.txt suspicious.pdf
# peepdf's dedicated extractor
peepdf -i suspicious.pdf   # then: extract js > js.txt
# make it readable
npx js-beautify js.txt > js_pretty.js
python3 -m jsbeautifier js.txt > js_pretty.js
# common obfuscation to unwind by hand
grep -oE 'unescape\("[^"]+"\)' js.txt
grep -oE '%u[0-9a-fA-F]{4}' js.txt | head
# decode a %uXXXX heap-spray string
python3 -c "import re,sys;s=open('js.txt').read();print(''.join(chr(int(x,16)) for x in re.findall(r'%u([0-9a-fA-F]{4})',s))[:400])"
# decode a String.fromCharCode list
python3 -c "import re;s=open('js.txt').read();print(''.join(chr(int(n)) for n in re.findall(r'\d+',re.search(r'fromCharCode\(([^)]*)\)',s).group(1))))"
```

Never run extracted PDF JavaScript in a browser. If you must execute it, use a JS engine with no
DOM (`node --input-type=module` with a stubbed `app`/`this` object) inside a disposable VM.

## Incremental updates and broken redaction

This is the classic CTF PDF challenge. A "redacted" PDF is usually one of:

1. A black rectangle **drawn over** live text. `pdftotext` prints the text anyway.
2. Text removed in a **new revision** while the old revision is still appended in the same file.
3. An image of a redacted page, with the original page still present as an earlier object.
4. Text set to white, rendered at zero size, or clipped outside the page box.

```sh
# 1) does the text survive extraction?
pdftotext -layout suspicious.pdf - | less
# 2) how many revisions?
grep -c '%%EOF' suspicious.pdf
# split the file at each %%EOF; each prefix is a valid standalone PDF
python3 pdf_revisions.py suspicious.pdf revisions/
for f in revisions/*.pdf; do echo "== $f"; pdftotext -layout "$f" - | head -20; done
# 3) follow the /Prev chain to enumerate the xref generations
qpdf --show-xref suspicious.pdf | head -40
grep -aob 'startxref' suspicious.pdf
# 4) compare what qpdf considers reachable against every object in the file
qpdf --qdf --object-streams=disable suspicious.pdf all.pdf
grep -c ' 0 obj' all.pdf
# 5) look for text drawn in white or with a zero-size font in the content stream
pdf-parser.py -o 5 -f -d content.txt suspicious.pdf
grep -nE '(1 1 1 rg|1 g|Tf 0 |Tz 0)' content.txt
# 6) dump every content stream and grep them all
qpdf --qdf --object-streams=disable suspicious.pdf - | strings | grep -i 'secret'
```

## Filters

| Filter | Decode |
| --- | --- |
| `/FlateDecode` | zlib (`zlib.decompress`) |
| `/LZWDecode` | LZW, `pdf-parser -f` handles it |
| `/ASCIIHexDecode` | hex digits until `>` |
| `/ASCII85Decode` | base85, `base64.a85decode(..., adobe=True)` |
| `/RunLengthDecode` | simple RLE |
| `/DCTDecode` | it is a JPEG -- rename and open |
| `/JPXDecode` | JPEG 2000 |
| `/CCITTFaxDecode` | fax group 3/4, extract with `pdfimages -all` |
| `/Crypt` | encrypted, needs the document key |

Filters cascade: `/Filter [/ASCII85Decode /FlateDecode]` means base85 first, then inflate.

## Encryption

```sh
# is it encrypted, and how?
qpdf --show-encryption suspicious.pdf
pdfinfo suspicious.pdf | grep -i encrypt
# many "protected" PDFs have an EMPTY user password - just strip the owner password
qpdf --decrypt suspicious.pdf plain.pdf
qpdf --password='' --decrypt suspicious.pdf plain.pdf
# with a known password
qpdf --password='Passw0rd' --decrypt suspicious.pdf plain.pdf
# crack it
pdf2john.py suspicious.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash
hashcat -m 10500 pdf.hash rockyou.txt   # PDF 1.4-1.6 (Acrobat 5-8)
hashcat -m 10700 pdf.hash rockyou.txt   # PDF 1.7 Level 8 (Acrobat 10-11, AES-256)
hashcat -m 10400/10410/10420 pdf.hash rockyou.txt  # PDF 1.1-1.3
```

## Code

```python
#!/usr/bin/env python3
"""Split a PDF into its successive incremental revisions.

Every incremental update appends body + xref + trailer + %%EOF. The bytes from
offset 0 up to and including each %%EOF form a valid standalone PDF representing
the document as it looked at that point - which is how "redacted" text survives.

    python3 pdf_revisions.py suspicious.pdf revisions/
    for f in revisions/*.pdf; do pdftotext -layout "$f" - ; done
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

EOF = b"%%EOF"


def find_eofs(data: bytes) -> list[int]:
    """Byte offsets one past each %%EOF marker (plus any trailing newline)."""
    ends: list[int] = []
    pos = 0
    while True:
        idx = data.find(EOF, pos)
        if idx < 0:
            break
        end = idx + len(EOF)
        while end < len(data) and data[end] in (0x0D, 0x0A):
            end += 1
        ends.append(end)
        pos = idx + 1
    return ends


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pdf")
    ap.add_argument("outdir", nargs="?", default="revisions")
    args = ap.parse_args()

    try:
        with open(args.pdf, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        print(f"no such file: {args.pdf}", file=sys.stderr)
        return 1

    if not data.lstrip()[:5].startswith(b"%PDF-"):
        off = data.find(b"%PDF-")
        if off < 0:
            print("no %PDF- header found; is this really a PDF?", file=sys.stderr)
            return 1
        print(f"[!] %PDF- header is at offset {off}, not 0 (polyglot / prepended data)")

    ends = find_eofs(data)
    if not ends:
        print("no %%EOF found; the file is truncated or the trailer is corrupt",
              file=sys.stderr)
        return 1

    print(f"{len(ends)} revision(s) found in {len(data)} bytes")
    os.makedirs(args.outdir, exist_ok=True)
    for i, end in enumerate(ends, 1):
        chunk = data[:end]
        out = os.path.join(args.outdir, f"rev{i:02d}.pdf")
        with open(out, "wb") as fh:
            fh.write(chunk)
        digest = hashlib.sha256(chunk).hexdigest()[:16]
        print(f"  rev{i:02d}  {end:>10} bytes  sha256:{digest}  -> {out}")

    if len(data) > ends[-1]:
        trailing = data[ends[-1]:]
        out = os.path.join(args.outdir, "trailing.bin")
        with open(out, "wb") as fh:
            fh.write(trailing)
        print(f"\n[!] {len(trailing)} bytes AFTER the final %%EOF -> {out}")
        print("    run `file` and `binwalk` on it; polyglots hide there")

    if len(ends) > 1:
        print("\nnext:  for f in %s/rev*.pdf; do echo \"== $f\"; "
              "pdftotext -layout \"$f\" - | head -40; done" % args.outdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Inflate every FlateDecode stream in a PDF and grep the decompressed content.

Pure stdlib: does not need pdf-parser, qpdf or mutool. Handles cascaded
ASCIIHex/ASCII85 + Flate filters and truncated /Length values by inflating
as much as possible.

    python3 pdf_streams.py suspicious.pdf --grep 'flag\\{'
    python3 pdf_streams.py suspicious.pdf --dump streams/
"""
from __future__ import annotations

import argparse
import base64
import binascii
import os
import re
import sys
import zlib

OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
STREAM_RE = re.compile(rb"stream\r?\n?")
FILTER_RE = re.compile(rb"/Filter\s*(\[[^\]]*\]|/\w+)")


def owning_object(data: bytes, pos: int) -> tuple[int, int, bytes]:
    """Find the `N G obj` header preceding `pos` and return (num, gen, dict_bytes)."""
    start = data.rfind(b" obj", 0, pos)
    if start < 0:
        return (-1, -1, b"")
    line_start = max(0, data.rfind(b"\n", 0, max(0, start - 24)))
    m = None
    for m in OBJ_RE.finditer(data, line_start, start + 4):
        pass
    if not m:
        return (-1, -1, b"")
    return (int(m.group(1)), int(m.group(2)), data[m.end():pos])


def apply_filters(raw: bytes, filters: list[bytes]) -> bytes:
    out = raw
    for f in filters:
        if f in (b"/FlateDecode", b"/Fl"):
            try:
                out = zlib.decompress(out)
            except zlib.error:
                # truncated or wrong /Length: inflate what we can
                d = zlib.decompressobj()
                try:
                    out = d.decompress(out)
                except zlib.error:
                    return out
        elif f in (b"/ASCIIHexDecode", b"/AHx"):
            hexpart = out.split(b">")[0]
            hexpart = re.sub(rb"[^0-9A-Fa-f]", b"", hexpart)
            if len(hexpart) % 2:
                hexpart += b"0"
            try:
                out = binascii.unhexlify(hexpart)
            except binascii.Error:
                return out
        elif f in (b"/ASCII85Decode", b"/A85"):
            try:
                out = base64.a85decode(out, adobe=True, ignorechars=b" \t\r\n\v\f")
            except (ValueError, binascii.Error):
                return out
        elif f in (b"/RunLengthDecode", b"/RL"):
            out = run_length_decode(out)
        else:
            # DCTDecode/JPXDecode/CCITTFaxDecode: leave the bytes as-is
            return out
    return out


def run_length_decode(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        n = data[i]
        i += 1
        if n == 128:
            break
        if n < 128:
            out.extend(data[i:i + n + 1])
            i += n + 1
        else:
            if i >= len(data):
                break
            out.extend(bytes([data[i]]) * (257 - n))
            i += 1
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pdf")
    ap.add_argument("--grep", help="regex to search in decoded streams")
    ap.add_argument("--dump", help="write each decoded stream into this directory")
    ap.add_argument("--preview", type=int, default=120,
                    help="bytes of preview to print per stream")
    args = ap.parse_args()

    try:
        with open(args.pdf, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        print(f"no such file: {args.pdf}", file=sys.stderr)
        return 1

    needle = re.compile(args.grep.encode(), re.I) if args.grep else None
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)

    count = 0
    hits = 0
    for m in STREAM_RE.finditer(data):
        body_start = m.end()
        end = data.find(b"endstream", body_start)
        if end < 0:
            continue
        raw = data[body_start:end].rstrip(b"\r\n")
        num, gen, header = owning_object(data, m.start())
        fm = FILTER_RE.search(header)
        filters: list[bytes] = []
        if fm:
            filters = re.findall(rb"/\w+", fm.group(1))
        decoded = apply_filters(raw, filters)
        count += 1

        label = f"obj {num} {gen}" if num >= 0 else f"stream@{m.start()}"
        flt = b",".join(filters).decode("latin-1") or "none"
        if args.dump:
            out = os.path.join(args.dump,
                               f"obj_{num if num >= 0 else m.start()}_{gen if gen >= 0 else 0}.bin")
            with open(out, "wb") as fh:
                fh.write(decoded)

        if needle:
            for hit in needle.findall(decoded):
                hits += 1
                print(f"[{label}] filter={flt} -> {hit.decode('latin-1', 'replace')}")
        else:
            preview = decoded[:args.preview]
            printable = "".join(chr(c) if 32 <= c < 127 else "." for c in preview)
            print(f"[{label}] filter={flt} raw={len(raw)} decoded={len(decoded)}")
            print(f"    {printable}")

    print(f"\n[+] {count} streams processed"
          + (f", {hits} regex hits" if needle else "")
          + (f", dumped to {args.dump}/" if args.dump else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **A PDF is a polyglot magnet.** The header only has to appear within the first 1024 bytes, and
  anything after the final `%%EOF` is ignored by readers. Always `binwalk` and check
  `grep -abo '%PDF-'`.
- `pdfid` only counts keywords in the **raw** file by default; keywords inside object streams need
  `-e`. A clean `pdfid` report on a 1.5+ PDF proves nothing.
- `/Length` lying about the stream size is a standard evasion. Carve to `endstream`, not to
  `/Length`, which is what the script above does.
- **Text that renders but does not extract** is drawn with a custom encoding or as vector paths.
  Render to PNG and OCR it (`pdftoppm` + `tesseract`).
- **Text that extracts but does not render** is the redaction failure you are looking for.
- `qpdf --decrypt` with an empty password works on a large share of "password protected" PDFs,
  because only the *owner* password was set.
- Objects can be **free** (`f` in the xref) yet still physically present in the file. `pdf-parser`
  without `--search` shows them; qpdf's normalised output may not.
- XFA forms are XML inside a stream -- extract them and read them as XML, not as PDF objects.

## Tools

`pdfid.py`, `pdf-parser.py`, `peepdf`, `qpdf`, `mutool` (mupdf-tools), poppler-utils
(`pdftotext`, `pdfimages`, `pdfdetach`, `pdfinfo`, `pdftoppm`), `pdftk`, `exiftool`,
`binwalk`, `js-beautify`, `pdf2john.py`, `hashcat`, `john`, `tesseract` for OCR.

## References

- `pdfid.py -h`, `pdf-parser.py -h`, `qpdf --help`, `mutool` with no arguments list every option.
- The PDF specification's sections on incremental updates and cross-reference streams explain the
  `/Prev` chain used above.
