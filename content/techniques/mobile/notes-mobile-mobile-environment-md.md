---
title: "Mobile environment (Mobile)"
category: "mobile"
subcategory: "number-theory"
type: "technique"
tags: ["my-notes", "personal", "chinese-remainder", "frida", "adb", "mobile"]
summary: "Personal note: Mobile environment (Mobile)."
source:
  name: "Personal notes"
origin_path: "Mobile/Mobile environment.md"
---

```bash
frida-ps -Uai
```

```bash
adb devices -l
```

```bash
adb push frida-server-16.2.1-android-x86 /data/local/tmp/frida-server
```

```bash
adb shell "chmod 755 /data/local/tmp/frida-server"
```

```bash
adb shell "/data/local/tmp/frida-server &"
```
# SLL PINNING BYPASS
```bash
adb shell "cp /system/etc/security/cacerts/9a5ba575.0 /data/local/tmp/cert-der.crt"
```

```bash
adb shell "chmod 755 /data/local/tmp/cert-der.crt"
```

```bash
frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f com.example.pinned
```

---

*From your own notes: `Mobile/Mobile environment.md`*
