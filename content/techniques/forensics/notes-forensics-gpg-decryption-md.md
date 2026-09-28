---
title: "GPG Decryption (Forensics)"
category: "forensics"
type: "technique"
tags: ["my-notes", "personal", "gpg", "decryption", "forensics"]
summary: "Personal note: GPG Decryption (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/GPG Decryption.md"
---

```
gpg --list-keys
```

```
gpg --keyring [path-to-keyring-file] --decrypt [file-to-decrypt]
```

```
gpg --keyring /path/to/keyring/mykeyring.kbx --decrypt secret.txt.gpg > secret.txt
```

```
gpg --no-default-keyring --keyring /path/to/keyring/mykeyring.kbx --decrypt secret.txt.gpg > secret.txt
```

**Decrypt**

```
gpg --decrypt [encrypted-file]
```

---

*From your own notes: `Forensics/GPG Decryption.md`*
