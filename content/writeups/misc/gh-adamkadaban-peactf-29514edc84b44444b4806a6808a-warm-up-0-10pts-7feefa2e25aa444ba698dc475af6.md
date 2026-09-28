---
title: "Warm up 0 (10pts) 7feefa2e25aa444ba698dc475af663fd - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "warm", "pts", "feefa2e25aa444ba698dc475af663fd", "miscellaneous", "warm-up-0-10pts-7feefa2e25aa444ba698dc47"]
summary: "Log into the ssh service with username peactf and password peactf2020."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%200%20%2810pts%29%207feefa2e25aa444ba698dc475af663fd.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "Warm up 0 (10pts) 7feefa2e25aa444ba698dc475af663fd"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** Warm up 0 (10pts) 7feefa2e25aa444ba698dc475af663fd
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%200%20%2810pts%29%207feefa2e25aa444ba698dc475af663fd.md>

---
# Warm-up 0 (10pts)

> These are a series of introductory problems on basic Linux skills.
Log into the ssh service with username peactf and password peactf2020. What's on the server?

1. Log in with the ip and port they give:

    ```bash
    ssh peactf@45.32.128.108 -p 28083
    # then type in the password (peactf2020)
    ```

2. We see a directory... lets cd into it

    ![Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled.png)

3. There's too many directories to even hope to look through
    - All of them have even more subdirectories

        ![Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled%201.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled%201.png)

4. Let's recursively look through the folders and cat out any files

    ```bash
    ls -LR | cat | grep peaCTF
    ```

5. The flag is peaCTF{67f7b551-159b-49ef-b39e-6ddc2031bb1c}
