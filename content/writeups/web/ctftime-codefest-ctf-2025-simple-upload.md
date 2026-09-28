---
title: "Simple Upload - Codefest CTF 2025"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "simple", "upload", "lfi", "codefest-ctf", "codefest-ctf-2025", "2025", "ctf-writeup"]
summary: "After we published the file, we can access it by following link: http://codefest-ctf.iitbhu.tech:10192/download?file=uploads/{filename}"
source:
  name: "CTFtime writeup #39839"
  url: "https://ctftime.org/writeup/39839"
ctf:
  name: "Codefest CTF 2025"
  year: 2025
  challenge: "Simple Upload"
---

## Metadata

- **CTF:** Codefest CTF 2025
- **Task:** Simple Upload
- **Author team:** DIONLABS
- **CTFtime:** <https://ctftime.org/writeup/39839>

---
### Explanation

After we published the file, we can access it by following link: http://codefest-ctf.iitbhu.tech:10192/download?file=uploads/{file_name}

Because of "uploads/" in the link, it hints us that **Path Traversal Exploit** works here, so we can access parent directories (e.g. http://codefest-ctf.iitbhu.tech:10192/download?file=../../upload.png).

So, our goal is to find flag.txt in parent directories.

### Solution

All we need is to download the file from parent directory of "uploads" by following link: http://codefest-ctf.iitbhu.tech:10192/download?file=../flag.txt
