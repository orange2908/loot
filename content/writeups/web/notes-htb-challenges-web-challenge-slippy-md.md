---
title: "Challenge - Slippy (Web)"
category: "web"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "zip-slip", "slippy", "web", "htb-challenges"]
summary: "Personal note: Challenge - Slippy (Web)."
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Web/Challenge - Slippy.md"
---

- make a tar archive

```
tar -czvf test.tar.gz test.txt
```

- start looking at the `docker` file first
- zip slip vulnerability : the application doesn’t check for absolute path in file name

```
tar -czvf pwn.tar-gz
```

### references

- [https://www.youtube.com/watch?v=8eXutSxYhOQ&t=70s&ab_channel=0xbro](https://www.youtube.com/watch?v=8eXutSxYhOQ&t=70s&ab_channel=0xbro)
- [https://www.youtube.com/watch?v=ADkjeCPz4TI&ab_channel=JohnHammond](https://www.youtube.com/watch?v=ADkjeCPz4TI&ab_channel=JohnHammond)
- [https://www.youtube.com/watch?v=Ry_yb5Oipq0&ab_channel=LiveOverflow](https://www.youtube.com/watch?v=Ry_yb5Oipq0&ab_channel=LiveOverflow)
- [https://maoutis.github.io/writeups/Web Hacking/Exploit Zip Slip vulnerability in python tarfile/](https://maoutis.github.io/writeups/Web%20Hacking/Exploit%20Zip%20Slip%20vulnerability%20in%20python%20tarfile/)

---

*From your own notes: `HTB Challenges/Web/Challenge - Slippy.md`*
