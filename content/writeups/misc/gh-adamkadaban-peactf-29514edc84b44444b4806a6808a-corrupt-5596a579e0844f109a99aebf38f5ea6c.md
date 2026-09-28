---
title: "Corrupt 5596a579e0844f109a99aebf38f5ea6c - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "corrupt", "a579e0844f109a99aebf38f5ea6c", "miscellaneous", "corrupt-5596a579e0844f109a99aebf38f5ea6c", "peactf-29514edc84b44444b4806a6808a"]
summary: "misc writeup for \"Corrupt 5596a579e0844f109a99aebf38f5ea6c\" from PeaCTF 29514edc84b44444b4806a6808a3fc68 - techniques: corrupt, a579e0844f109a99aebf38f5ea6c, miscellaneous, corrupt-5596a579e0844f109a9"
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Corrupt%205596a579e0844f109a99aebf38f5ea6c.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "Corrupt 5596a579e0844f109a99aebf38f5ea6c"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** Corrupt 5596a579e0844f109a99aebf38f5ea6c
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Corrupt%205596a579e0844f109a99aebf38f5ea6c.md>

---
# Corrupt

> Sometimes files can be disguised with a different file format! Find the password within this file.
No flag formatting required.

1. Let's run the file command on the file

    ```bash
    file filetype.txt
    ```

    - It says the file is a png
2. Rename the file

    ```bash
    mv filetype.txt filetype.png
    ```

3. Open the image

    ```bash
    eog filetype.png
    ```

4. Luckily, the problem says we don't need any flag formatting

    ![Corrupt%205596a579e0844f109a99aebf38f5ea6c/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Corrupt%205596a579e0844f109a99aebf38f5ea6c/Untitled.png)

5. The flag is REDACTED
