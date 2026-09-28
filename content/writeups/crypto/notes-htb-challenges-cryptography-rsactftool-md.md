---
title: "RSACtfTool (Cryptography)"
category: "crypto"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "rsa", "rsactftool", "cryptography", "crypto", "htb-challenges"]
summary: "Personal note: RSACtfTool (Cryptography)."
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Cryptography/RSACtfTool.md"
---

### Decrypt publickey

```bash
openssl rsa -inform PEM -text -noout -pubin -in pubkey.pem
```

---

*From your own notes: `HTB Challenges/Cryptography/RSACtfTool.md`*
