---
title: "Decompilation (Mobile)"
category: "mobile"
type: "technique"
tags: ["my-notes", "personal", "decompilation", "mobile"]
summary: "Personal note: Decompilation (Mobile)."
source:
  name: "Personal notes"
origin_path: "Mobile/Decompilation.md"
---

```bash
d2j-dex2jar.sh CampusConnect.apk -o CampusConnect.jar
```

```bash
sudo apt install procyon-decompiler # Ubuntu/Debian install via APT
```

```bash
procyon CampusConnect.jar -o CampusConnect.java
find -name MainActivity.java
```

---

*From your own notes: `Mobile/Decompilation.md`*
