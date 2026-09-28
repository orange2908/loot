---
title: "Evtx Extract (Forensics)"
category: "forensics"
subcategory: "windows"
type: "technique"
tags: ["my-notes", "personal", "evtx", "extract", "forensics"]
summary: "Personal note: Evtx Extract (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Evtx Extract.md"
---

```
pip3 install evtxtract

#one big file
evtxtract [file] > output

#split the records individually
evtxtract -s -o [output_dir] [file]
```

or

```
evtx_dump
```

---

*From your own notes: `Forensics/Evtx Extract.md`*
