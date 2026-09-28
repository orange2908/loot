---
title: "Logcat (Mobile)"
category: "mobile"
subcategory: "runtime"
type: "technique"
tags: ["my-notes", "personal", "frida", "adb", "logcat", "mobile"]
summary: "Personal note: Logcat (Mobile)."
source:
  name: "Personal notes"
origin_path: "Mobile/logcat.md"
---

# Get PID number
```bash
$ frida-ps -U | rg kitty
```
# Start logcat
```bash
$ adb logcat --pid=1896 -v color
```

---

*From your own notes: `Mobile/logcat.md`*
