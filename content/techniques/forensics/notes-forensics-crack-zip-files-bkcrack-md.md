---
title: "Bkcrack (Crack Zip files)"
category: "forensics"
subcategory: "crack-zip-files"
type: "technique"
tags: ["my-notes", "personal", "bkcrack", "crack", "zip", "files", "forensics"]
summary: "https://mariuszbartosik.com/buckeye-ctf-2024-reducerecycle-write-up/"
source:
  name: "Personal notes"
origin_path: "Forensics/Crack Zip files/bkcrack.md"
---

```
https://github.com/kimci86/bkcrack
```

> Example

```
./bkcrack -C ingredients.zip -c tmp/4296197df38573eb43a4147bf1d24b8c/ingredients.txt -p plain_text.txt
```

https://mariuszbartosik.com/buckeye-ctf-2024-reduce_recycle-write-up/

```bash
➜  forensics ~/tools/forensics/bkcrack/bkcrack -C files.zip -c notsus.exe -x 0 4d5a90000300000004000000ffff0000
bkcrack 1.7.0 - 2024-05-26
[16:38:14] Z reduction using 9 bytes of known plaintext
100.0 % (9 / 9)
[16:38:15] Attack on 721104 Z values at index 6
Keys: d1608c35 d11d350a 4bc3da9c
91.2 % (657301 / 721104)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 657301
[17:06:45] Keys
d1608c35 d11d350a 4bc3da9c
```

```
➜  forensics ~/tools/forensics/bkcrack/bkcrack -C files.zip -k d1608c35 d11d350a 4bc3da9c -D no_password.zip
bkcrack 1.7.0 - 2024-05-26
[17:16:41] Writing decrypted archive no_password.zip
100.0 % (2 / 2)
```

---

*From your own notes: `Forensics/Crack Zip files/bkcrack.md`*
