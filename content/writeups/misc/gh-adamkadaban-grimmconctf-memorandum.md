---
title: "Memorandum - GrimmConCTF"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "memorandum", "miscellaneous", "grimmconctf", "adamkadaban", "ctfs"]
summary: "misc writeup for \"Memorandum\" from GrimmConCTF - techniques: memorandum, miscellaneous, grimmconctf, adamkadaban, ctfs."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/GrimmConCTF/Memorandum/README.md"
ctf:
  name: "GrimmConCTF"
  challenge: "Memorandum"
---

## Source

- **CTF:** GrimmConCTF
- **Challenge:** Memorandum
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/GrimmConCTF/Memorandum/README.md>

---
* I just kind did `strings memorandum.bin | grep -i "flag"` and happened to stop it from printing at the correct time
* I saw the flag in:
```
flag\{e701f9290e2cd553be981461f8ea08e5\}\lang9\f1\par
flag
flagno
_FLAGS
GetTraceEnableFlags
flag\{e701f9290e2cd553be981461f8ea08e5\}\lang9\f1\par
%s - AsyncRecoSetFlags failed.
%s - AsyncRecoBackgroundSetFlags failed.
flag\{e701f9290e2cd553be981461f8ea08e5\}\lang9\f1\par
EtwGetTraceEnableFlags
Windows\CurrentVersion\Internet Settings\Cache!DebugFlag
```
* The flag is `flag{e701f9290e2cd553be981461f8ea08e5}`
