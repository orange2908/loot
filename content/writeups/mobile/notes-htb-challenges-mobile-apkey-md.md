---
title: "APKey (Mobile)"
category: "mobile"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "apktool", "apkey", "mobile", "htb-challenges"]
summary: "Personal note: APKey (Mobile)."
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Mobile/APKey.md"
---

- change the `MainActivity$a.samli` so `p1` has the value of `const/4 p1, 0x1`
- recompile using

```bash
apktool b [decompiled folder] -o [final APK file name]
```

- done

---

*From your own notes: `HTB Challenges/Mobile/APKey.md`*
