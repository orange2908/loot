---
title: "Intercept sqlmap requests with burp (Web)"
category: "web"
type: "technique"
tags: ["my-notes", "personal", "sqlmap", "intercept", "requests", "burp", "web"]
summary: "Personal note: Intercept sqlmap requests with burp (Web)."
source:
  name: "Personal notes"
origin_path: "Web/Intercept sqlmap requests with burp.md"
---

```bash
sqlmap http://142.93.33.226:31880/view/1 --current-db --proxy http://127.0.0.1:8080 --all --batch
```

---

*From your own notes: `Web/Intercept sqlmap requests with burp.md`*
