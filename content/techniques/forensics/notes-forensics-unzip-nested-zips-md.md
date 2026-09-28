---
title: "Unzip Nested Zips (Forensics)"
category: "forensics"
type: "technique"
tags: ["my-notes", "personal", "unzip", "nested", "zips", "forensics"]
summary: "Personal note: Unzip Nested Zips (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/unzip nested zips.md"
---

```bash
while [ "`find . -type f -name '*.zip' | wc -l`" -gt 0 ]; do find -type f -name "*.zip" -exec unzip -- '{}' \; -exec rm -- '{}' \;; done >
```

---

*From your own notes: `Forensics/unzip nested zips.md`*
