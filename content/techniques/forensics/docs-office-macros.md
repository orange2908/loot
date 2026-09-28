---
title: "Office Documents - OLE vs OOXML, Macros, DDE and RTF"
category: forensics
subcategory: documents
type: technique
tags: [oletools, olevba, oledump, oleid, rtfobj, msodde, mraptor, pcodedmp, vba, macro, xlm, excel4, ooxml, ole2, docx, doc, rtf, maldoc, template-injection, dfir]
difficulty: medium
summary: "Identify an Office file's real container, pull the VBA or XLM macro out, and deobfuscate it down to the URL or command it runs."
when_to_use:
  - "The challenge ships a .doc/.docm/.xls/.xlsm/.ppt/.rtf and says 'phishing attachment'"
  - "file says 'Composite Document File V2' or 'Microsoft Word 2007+'"
  - "You need the C2 URL, the dropped filename, or a flag hidden inside a macro"
  - "A document opened something and you must prove what"
tools: [oletools, olevba, oledump, oleid, rtfobj, msodde, mraptor, pcodedmp, xlmmacrodeobfuscator, msoffcrypto-tool, john, hashcat]
related: [docs-pdf-analysis, docs-email-forensics, disk-file-carving, network-c2-analysis]
---

## TL;DR

Two containers: **OLE2/CFB** (`.doc`, `.xls`, `.ppt`, `.msg`, magic `D0CF11E0A1B11AE1`) and
**OOXML** (`.docx`, `.xlsm`, `.pptx`, which are ZIP files starting `PK\x03\x04`). `oleid` tells
you which and whether there is a macro; `olevba --decode --deobf` usually prints the payload in
one shot. When `olevba` finds nothing, look for XLM macros, DDE fields, a remote template, or an
embedded OLE object.

## Recognise it

```sh
# the single most useful first command
file suspicious.doc
# OLE2: "Composite Document File V2 Document"        -> D0 CF 11 E0 A1 B1 1A E1
# OOXML: "Microsoft Word 2007+" / "Zip archive data" -> 50 4B 03 04
# RTF:   "Rich Text Format data"                     -> 7B 5C 72 74 66 31  ({\rtf1)
xxd suspicious.doc | head -2
# the extension lies constantly: a .doc that is really a ZIP, or an .rtf that is really OLE
unzip -l suspicious.docx 2>/dev/null | head
7z l suspicious.doc 2>/dev/null | head
```

Red flags before you even parse anything:

- A `.docx` that Word opens but `unzip -l` shows `word/vbaProject.bin` -> should have been `.docm`.
- A `.rtf` containing `\objdata` or `\objupdate`.
- A `.xls` with a very small body and one hidden sheet.
- A file whose name ends `.doc` but whose magic is `PK` (or vice versa).

## oletools - the whole workflow

```sh
# install once
pip install -U oletools
# 1) triage: container type, macro presence, encryption, ole objects, flash
oleid suspicious.doc
# 2) the big one: extract VBA, analyse it, and show decoded strings
olevba suspicious.doc
# analysis only, with IOC extraction and suspicious-keyword table
olevba -a suspicious.doc
# decode hex/base64/dridex strings and attempt deobfuscation
olevba --decode --deobf suspicious.doc
# just the VBA source, nothing else - pipe this into a file
olevba -c suspicious.doc > macro.vba
# reveal: substitutes the deobfuscated values back into the source
olevba --reveal suspicious.doc
# recurse into a directory or a zip of samples
olevba -r 'samples/*.doc'
# 3) macro triage: does it auto-execute, write files, or spawn processes?
mraptor suspicious.doc
# 4) metadata: author, company, creation/modification times, template
olemeta suspicious.doc
oletimes suspicious.doc
# 5) the OLE stream map - shows unused space where data can hide
olemap suspicious.doc
# 6) embedded OLE objects (packager payloads, linked files)
oleobj -d ./objs suspicious.doc
# 7) DDE / DDEAUTO fields - macro-less code execution
msodde suspicious.docx
msodde --json suspicious.rtf
# 8) RTF embedded objects
rtfobj suspicious.rtf
rtfobj -s all -d ./objs suspicious.rtf
```

## oledump - when you need the raw streams

```sh
# list every stream with its size; M marks a stream containing VBA macros
oledump.py suspicious.doc
# dump stream 3 (the raw bytes)
oledump.py -s 3 suspicious.doc
# decompress the VBA in stream 3 (this is the one you want)
oledump.py -s 3 -v suspicious.doc
# strings of a stream
oledump.py -s 3 -S suspicious.doc
# every stream's VBA at once
oledump.py -s a -v suspicious.doc
# run a plugin: HTTP heuristics finds URLs even in obfuscated code
oledump.py -p plugin_http_heuristics suspicious.doc
# dump the BIFF records of an .xls (Excel 4.0 macro hunting)
oledump.py -p plugin_biff --pluginoptions "-x" book.xls
# hex/ascii dump of a stream with an offset
oledump.py -s 4 -x suspicious.doc | head -40
# pipe a stream into another tool
oledump.py -s 3 -d suspicious.doc | xxd | head
```

## OOXML internals

An OOXML file is just a ZIP. Unzip it and read the XML.

```sh
# unpack
mkdir doc_x && unzip -o suspicious.docx -d doc_x && find doc_x -type f
# the parts that matter
#   [Content_Types].xml        - declares every part type
#   word/document.xml          - the visible text
#   word/vbaProject.bin        - an OLE2 container holding the VBA (feed it to oledump)
#   word/_rels/document.xml.rels - RELATIONSHIPS, including EXTERNAL ones
#   word/settings.xml          - attachedTemplate reference (remote template injection)
#   docProps/core.xml          - author, lastModifiedBy, created, modified
#   docProps/app.xml           - application, template, total edit time
#   word/embeddings/*          - embedded OLE objects
# every external relationship target - this is where template injection shows up
grep -ro 'Target="[^"]*"' doc_x --include='*.rels' | grep -i 'http\|file:\|\\\\'
# the attached template
grep -o 'attachedTemplate[^/]*' doc_x/word/settings.xml
# any URL anywhere in the package
grep -rioE 'https?://[^"<> ]{6,200}' doc_x | sort -u
# the vbaProject is itself an OLE file
oledump.py doc_x/word/vbaProject.bin
olevba doc_x/word/vbaProject.bin
# metadata without unzipping
unzip -p suspicious.docx docProps/core.xml
exiftool -a -u -g1 suspicious.docx
```

## VBA deobfuscation patterns

What obfuscated maldoc VBA looks like, and how to unwind it:

```vb
' character-by-character construction
s = Chr(104) & Chr(116) & Chr(116) & Chr(112)          ' -> "http"
s = ChrW(&H68) & ChrW(&H74)                            ' hex form
' reversed strings
s = StrReverse("ptth//:")                              ' -> "//:http" reversed
' split/join with a junk delimiter
s = Join(Split("h!t!t!p", "!"), "")                    ' -> "http"
' Mid/Replace shuffling
s = Replace("hXXp", "X", "t")
' environment-based paths
p = Environ("TEMP") & "\a.exe"
' the payload
Set o = CreateObject("WScript.Shell")
o.Run s, 0, False
Set x = CreateObject("MSXML2.XMLHTTP")
x.Open "GET", url, False
```

Auto-execution entry points to grep for:

| Application | Entry points |
| --- | --- |
| Word | `AutoOpen`, `AutoExec`, `AutoNew`, `AutoClose`, `Document_Open`, `Document_Close`, `Document_New` |
| Excel | `Auto_Open`, `Auto_Close`, `Workbook_Open`, `Workbook_BeforeClose`, `Workbook_Activate` |
| PowerPoint | `Auto_Open`, `OnSlideShowPageChange`, action buttons |
| Any | `Class_Initialize` on a class module, `Application_Startup` |

```sh
# grep the extracted source
grep -inE '(AutoOpen|AutoExec|Document_Open|Workbook_Open|Auto_Open|Class_Initialize)' macro.vba
grep -inE '(Shell|CreateObject|WScript|powershell|cmd\.exe|URLDownloadToFile|XMLHTTP|ADODB\.Stream|SaveToFile|Environ|Chr\(|ChrW\(|StrReverse|Base64)' macro.vba
```

## Excel 4.0 (XLM) macros and VBA stomping

XLM macros live in a hidden or very-hidden sheet, not in a VBA project, so `olevba` may report
"no macros found" on a live maldoc.

```sh
# olevba does detect XLM in recent versions
olevba --deobf book.xls
# the dedicated deobfuscator emulates the macro sheet
pip install XLMMacroDeobfuscator
xlmdeobfuscator --file book.xls
xlmdeobfuscator --file book.xlsm --output-formula-format '[[INT-FORMULA]]'
# raw BIFF record dump of the macro sheet
oledump.py -p plugin_biff --pluginoptions "-x -s" book.xls
# hidden sheet states in an OOXML workbook
unzip -p book.xlsm xl/workbook.xml | grep -o 'state="[^"]*"'
```

**VBA stomping**: the attacker removes the VBA source but leaves the compiled p-code, so
`olevba` shows harmless (or empty) source while Office executes the real thing.

```sh
# dump and disassemble the p-code
pip install pcodedmp
pcodedmp -d suspicious.doc
# a mismatch between the p-code and the source text is the tell
pcodedmp suspicious.doc | head -60
# olevba flags it too
olevba --show-pcode suspicious.doc
```

## Encrypted / password-protected documents

```sh
# is it encrypted? OLE with an EncryptedPackage stream, or "Encrypted" from oleid
oleid protected.docx
oledump.py protected.docx 2>/dev/null | grep -i encrypt
# the default "VelvetSweatshop" password used by Excel for auto-decrypting files
msoffcrypto-tool -p VelvetSweatshop protected.xls out.xls
# decrypt with a known password
pip install msoffcrypto-tool
msoffcrypto-tool -p 'Passw0rd!' protected.docx plain.docx
# crack it
office2john.py protected.docx > office.hash
john --wordlist=rockyou.txt office.hash
hashcat -m 9600 office.hash rockyou.txt     # Office 2013+ (AES-256, SHA-512)
hashcat -m 9500 office.hash rockyou.txt     # Office 2010
hashcat -m 9400 office.hash rockyou.txt     # Office 2007
hashcat -m 9700/9800 office.hash rockyou.txt  # Office 97-2003 (RC4)
# the "protect sheet" password in xlsx is not encryption at all - just delete the element
unzip -p book.xlsx xl/worksheets/sheet1.xml | grep -o '<sheetProtection[^>]*>'
```

## Code

```python
#!/usr/bin/env python3
"""Static triage of an OOXML (docx/xlsx/pptx/docm/xlsm) file.

Lists every part, dumps external relationship targets (template injection / remote
payloads), prints docProps metadata, and greps every part for URLs and base64 blobs.

    python3 ooxml_triage.py suspicious.docm
    python3 ooxml_triage.py suspicious.xlsm --dump-part word/vbaProject.bin
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import re
import sys
import zipfile
from xml.etree import ElementTree

URL_RE = re.compile(rb"(?:https?|ftp|file)://[^\s\"'<>)]{6,300}", re.I)
UNC_RE = re.compile(rb"\\\\[A-Za-z0-9._-]{2,64}\\[^\s\"'<>]{1,200}")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{80,}={0,2}")
INTERESTING_PARTS = (
    "vbaProject.bin", "vbaData.xml", "settings.xml", "document.xml",
    "workbook.xml", "oleObject", "activeX", "embeddings/", "media/",
)
SUSPICIOUS_STRINGS = (
    b"AutoOpen", b"Auto_Open", b"Document_Open", b"Workbook_Open", b"AutoExec",
    b"Shell", b"CreateObject", b"WScript", b"powershell", b"cmd.exe",
    b"URLDownloadToFile", b"XMLHTTP", b"ADODB.Stream", b"SaveToFile",
    b"DDEAUTO", b"DDE ", b"mshta", b"regsvr32", b"rundll32", b"certutil",
)


def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def relationships(zf: zipfile.ZipFile) -> list[tuple[str, str, str, str]]:
    """Return (part, rel_id, type, target) for every External relationship."""
    out = []
    for name in zf.namelist():
        if not name.endswith(".rels"):
            continue
        try:
            root = ElementTree.fromstring(zf.read(name))
        except ElementTree.ParseError:
            continue
        for rel in root:
            if strip_ns(rel.tag) != "Relationship":
                continue
            mode = rel.attrib.get("TargetMode", "Internal")
            target = rel.attrib.get("Target", "")
            rtype = rel.attrib.get("Type", "").rsplit("/", 1)[-1]
            if mode == "External" or target.lower().startswith(("http", "ftp", "file:", "\\\\")):
                out.append((name, rel.attrib.get("Id", ""), rtype, target))
    return out


def metadata(zf: zipfile.ZipFile) -> dict[str, str]:
    props: dict[str, str] = {}
    for part in ("docProps/core.xml", "docProps/app.xml"):
        if part not in zf.namelist():
            continue
        try:
            root = ElementTree.fromstring(zf.read(part))
        except ElementTree.ParseError:
            continue
        for child in root.iter():
            tag = strip_ns(child.tag)
            if child.text and child.text.strip() and tag not in ("coreProperties", "Properties"):
                props[tag] = child.text.strip()
    return props


def looks_printable(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for c in data if 32 <= c < 127 or c in (9, 10, 13))
    return printable / len(data) > 0.85


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path")
    ap.add_argument("--dump-part", help="write this part to ./<basename>")
    ap.add_argument("--min-b64", type=int, default=120,
                    help="minimum base64 run length to report")
    args = ap.parse_args()

    try:
        zf = zipfile.ZipFile(args.path)
    except FileNotFoundError:
        print(f"no such file: {args.path}", file=sys.stderr)
        return 1
    except zipfile.BadZipFile:
        with open(args.path, "rb") as fh:
            magic = fh.read(8)
        if magic.startswith(b"\xd0\xcf\x11\xe0"):
            print("this is an OLE2 (CFB) file, not OOXML.\n"
                  "  use:  oleid FILE ; olevba --decode --deobf FILE ; oledump.py FILE",
                  file=sys.stderr)
        elif magic.startswith(b"{\\rtf"):
            print("this is RTF.\n  use:  rtfobj -s all -d ./objs FILE ; msodde FILE",
                  file=sys.stderr)
        else:
            print(f"not a zip and not a recognised Office container (magic {magic.hex()})",
                  file=sys.stderr)
        return 1

    with zf:
        print(f"== parts ({len(zf.namelist())})")
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            mark = "  <-- interesting" if any(k in info.filename for k in INTERESTING_PARTS) else ""
            print(f"  {info.file_size:>9}  {info.filename}{mark}")

        if args.dump_part:
            try:
                data = zf.read(args.dump_part)
            except KeyError:
                print(f"no such part: {args.dump_part}", file=sys.stderr)
                return 1
            out = args.dump_part.rsplit("/", 1)[-1]
            with open(out, "wb") as fh:
                fh.write(data)
            print(f"\n[+] wrote {out} ({len(data)} bytes, "
                  f"sha256 {hashlib.sha256(data).hexdigest()[:16]}...)")
            return 0

        props = metadata(zf)
        if props:
            print("\n== metadata")
            for k in ("creator", "lastModifiedBy", "created", "modified", "revision",
                      "Application", "AppVersion", "Template", "TotalTime", "Company"):
                if k in props:
                    print(f"  {k:<16} {props[k]}")

        rels = relationships(zf)
        if rels:
            print("\n== EXTERNAL relationships (template injection / remote payloads)")
            for part, rid, rtype, target in rels:
                print(f"  [{rtype}] {target}")
                print(f"      from {part} ({rid})")
        else:
            print("\n== no external relationships")

        urls: set[str] = set()
        uncs: set[str] = set()
        hits: dict[str, list[str]] = {}
        b64: list[tuple[str, str]] = []
        for name in zf.namelist():
            try:
                data = zf.read(name)
            except (KeyError, RuntimeError, zipfile.BadZipFile):
                continue
            for m in URL_RE.findall(data):
                urls.add(m.decode("latin-1"))
            for m in UNC_RE.findall(data):
                uncs.add(m.decode("latin-1"))
            found = [s.decode("latin-1") for s in SUSPICIOUS_STRINGS if s in data]
            if found:
                hits[name] = found
            for m in B64_RE.findall(data):
                if len(m) < args.min_b64:
                    continue
                try:
                    dec = base64.b64decode(m + b"=" * (-len(m) % 4), validate=False)
                except (binascii.Error, ValueError):
                    continue
                if looks_printable(dec) or dec[:2] in (b"MZ", b"PK", b"\x1f\x8b"):
                    b64.append((name, dec[:160].decode("latin-1", "replace")))

        if urls:
            print("\n== urls")
            for u in sorted(urls):
                print(f"  {u}")
        if uncs:
            print("\n== unc paths")
            for u in sorted(uncs):
                print(f"  {u}")
        if hits:
            print("\n== suspicious strings by part")
            for name, found in hits.items():
                print(f"  {name}: {', '.join(sorted(set(found)))}")
        if b64:
            print("\n== decodable base64 blobs")
            for name, preview in b64[:20]:
                print(f"  {name}: {preview!r}")
        if not (urls or uncs or hits or b64 or rels):
            print("\n[!] nothing obviously malicious in the package; check for XLM macros "
                  "(xlmdeobfuscator), DDE fields (msodde) and VBA stomping (pcodedmp)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Deobfuscate common VBA string-building tricks in extracted macro source.

Handles Chr(n)/ChrW(n) concatenation chains, StrReverse("..."), simple string
concatenation with &, and Replace("x","a","b") with literal arguments. Applies
repeatedly until nothing changes.

    olevba -c sample.doc > macro.vba && python3 vba_deobf.py macro.vba
    python3 vba_deobf.py --selftest
"""
from __future__ import annotations

import argparse
import re
import sys

NUM = r"(?:&[Hh][0-9A-Fa-f]+|\d+)"
CHR_CALL = re.compile(rf"\bChrW?\$?\s*\(\s*({NUM})\s*\)", re.I)
STR_LIT = re.compile(r'"((?:[^"]|"")*)"')
CONCAT = re.compile(r'"((?:[^"]|"")*)"\s*&\s*"((?:[^"]|"")*)"')
STRREVERSE = re.compile(r'\bStrReverse\s*\(\s*"((?:[^"]|"")*)"\s*\)', re.I)
REPLACE = re.compile(r'\bReplace\s*\(\s*"((?:[^"]|"")*)"\s*,\s*"((?:[^"]|"")*)"\s*,'
                     r'\s*"((?:[^"]|"")*)"\s*\)', re.I)
JOIN_SPLIT = re.compile(r'\bJoin\s*\(\s*Split\s*\(\s*"((?:[^"]|"")*)"\s*,\s*'
                        r'"((?:[^"]|"")*)"\s*\)\s*,\s*"((?:[^"]|"")*)"\s*\)', re.I)
MID = re.compile(r'\bMid\$?\s*\(\s*"((?:[^"]|"")*)"\s*,\s*(\d+)\s*(?:,\s*(\d+)\s*)?\)', re.I)


def num(token: str) -> int:
    token = token.strip()
    if token.lower().startswith("&h"):
        return int(token[2:], 16)
    return int(token)


def vba_escape(text: str) -> str:
    return '"' + text.replace('"', '""') + '"'


def vba_unescape(text: str) -> str:
    return text.replace('""', '"')


def _chr(m: re.Match[str]) -> str:
    try:
        code = num(m.group(1))
    except ValueError:
        return m.group(0)
    if 0 <= code <= 0x10FFFF:
        try:
            return vba_escape(chr(code))
        except ValueError:
            return m.group(0)
    return m.group(0)


def _concat(m: re.Match[str]) -> str:
    return vba_escape(vba_unescape(m.group(1)) + vba_unescape(m.group(2)))


def _reverse(m: re.Match[str]) -> str:
    return vba_escape(vba_unescape(m.group(1))[::-1])


def _replace(m: re.Match[str]) -> str:
    src, old, new = (vba_unescape(m.group(i)) for i in (1, 2, 3))
    return vba_escape(src.replace(old, new) if old else src)


def _join_split(m: re.Match[str]) -> str:
    src, sep, glue = (vba_unescape(m.group(i)) for i in (1, 2, 3))
    return vba_escape(glue.join(src.split(sep)) if sep else src)


def _mid(m: re.Match[str]) -> str:
    src = vba_unescape(m.group(1))
    start = max(1, int(m.group(2)))
    if m.group(3) is not None:
        return vba_escape(src[start - 1:start - 1 + int(m.group(3))])
    return vba_escape(src[start - 1:])


PASSES = [
    (CHR_CALL, _chr),
    (JOIN_SPLIT, _join_split),
    (REPLACE, _replace),
    (STRREVERSE, _reverse),
    (MID, _mid),
    (CONCAT, _concat),
]


def deobfuscate(source: str, max_rounds: int = 60) -> str:
    text = source
    for _ in range(max_rounds):
        before = text
        for pat, fn in PASSES:
            text = pat.sub(fn, text)
        if text == before:
            break
    return text


def extract_strings(source: str, min_len: int = 6) -> list[str]:
    out = []
    for m in STR_LIT.finditer(source):
        s = vba_unescape(m.group(1))
        if len(s) >= min_len:
            out.append(s)
    return out


def selftest() -> int:
    src = 'u = Chr(104) & Chr(116) & Chr(116) & Chr(112)'
    assert deobfuscate(src) == 'u = "http"', deobfuscate(src)
    src = 'a = StrReverse("cba")'
    assert deobfuscate(src) == 'a = "abc"', deobfuscate(src)
    src = 'b = Replace("hXXp", "X", "t")'
    assert deobfuscate(src) == 'b = "http"', deobfuscate(src)
    src = 'c = Join(Split("h!t!t!p", "!"), "")'
    assert deobfuscate(src) == 'c = "http"', deobfuscate(src)
    src = 'd = ChrW(&H48) & ChrW(&H69)'
    assert deobfuscate(src) == 'd = "Hi"', deobfuscate(src)
    src = 'e = Mid("XXhttpXX", 3, 4)'
    assert deobfuscate(src) == 'e = "http"', deobfuscate(src)
    big = ('Sub AutoOpen()\n'
           '  u = Chr(104)&Chr(116)&Chr(116)&Chr(112)&Chr(58)&Chr(47)&Chr(47)\n'
           '  Shell StrReverse("exe.dab/") \n'
           'End Sub\n')
    out = deobfuscate(big)
    assert '"http://"' in out, out
    assert '"/bad.exe"' in out, out
    assert "http://" in extract_strings(out)
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("vbafile", nargs="?")
    ap.add_argument("--strings-only", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.vbafile:
        return selftest()
    with open(args.vbafile, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    out = deobfuscate(source)
    if args.strings_only:
        for s in dict.fromkeys(extract_strings(out)):
            print(s)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **"No macros found" is not a clean bill of health.** Check XLM (`xlmdeobfuscator`), DDE
  (`msodde`), remote templates (external relationships), embedded OLE objects (`oleobj`,
  `rtfobj`), and VBA stomping (`pcodedmp`).
- **RTF is not OLE and not ZIP.** It is text with `\objdata` hex blobs. `rtfobj` extracts them;
  a malformed RTF that Word still opens is a deliberate parser-confusion trick, so always try
  `rtfdump.py` as well.
- **Never open the document.** Static analysis only, or a disposable VM with no network.
- `olevba` prints a "suspicious keywords" table -- read it, but a benign document can trip it and
  a malicious one can avoid every keyword.
- **Excel's `VelvetSweatshop`** is the hardcoded password Excel tries silently; encrypted-but-
  auto-opening workbooks use it to defeat scanners.
- OOXML parts can be **stored with a wrong extension or an extra `../` path**; check
  `[Content_Types].xml` against the actual part names for zip-slip style tricks.
- The **`docProps` metadata lies** as easily as any other field, but `lastModifiedBy` and
  `TotalTime` are often left untouched and identify the builder.
- A ZIP with a **prepended blob** (polyglot) still opens in Word. Run `binwalk` on any Office file
  whose size does not match its part sizes.

## Tools

`oletools` (`oleid`, `olevba`, `olemeta`, `oletimes`, `olemap`, `oleobj`, `rtfobj`, `msodde`,
`mraptor`), `oledump.py` + plugins, `pcodedmp`, `XLMMacroDeobfuscator`, `msoffcrypto-tool`,
`office2john.py`, `hashcat`, `john`, `exiftool`, `binwalk`, `7z`, `ViperMonkey` (VBA emulation).

## References

- `olevba -h`, `oledump.py -h`, `rtfobj -h` document every flag used above.
- The oletools wiki (shipped with the package as documentation) describes each tool's output.
