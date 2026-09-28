---
title: "Volatility Commands (Forensics)"
category: "forensics"
subcategory: "memory"
type: "technique"
tags: ["my-notes", "personal", "volatility", "commands", "forensics"]
summary: "Personal note: Volatility Commands (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Volatility Commands.md"
---

```bash
py vol.py -o __OUT -f dumped windows.memmap --pid 5380 --dump
```

```bash
python3 vol.py -f ~/Desktop/Evidence/memdump.mem -o ~/Desktop windows.dumpfiles --virtaddr 0xbc0ca7eb88c0
```

```bash
vol -f memdump.elf --filters "ImageFileName,chrome.exe" windows.pslist
```

```bash
vol -f memdump.elf windows.filescan | rg -Fi "desktop\\"
```

```bash
vol -f memdump.elf windows.filescan | rg -Fi "\\Default\\Local Extension Settings\\"
```

---

*From your own notes: `Forensics/Volatility Commands.md`*
