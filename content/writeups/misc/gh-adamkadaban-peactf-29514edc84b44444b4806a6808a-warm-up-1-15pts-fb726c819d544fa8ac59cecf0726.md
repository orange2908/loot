---
title: "Warm up 1 (15pts) fb726c819d544fa8ac59cecf0726abd7 - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "warm", "pts", "fb726c819d544fa8ac59cecf0726abd7", "miscellaneous", "warm-up-1-15pts-fb726c819d544fa8ac59cecf"]
summary: "Hmm... how to I search for a string recursively on Linux?"
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%201%20%2815pts%29%20fb726c819d544fa8ac59cecf0726abd7.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "Warm up 1 (15pts) fb726c819d544fa8ac59cecf0726abd7"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** Warm up 1 (15pts) fb726c819d544fa8ac59cecf0726abd7
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%201%20%2815pts%29%20fb726c819d544fa8ac59cecf0726abd7.md>

---
# Warm-up 1 (15pts)

> Log into the ssh service with username peactf and password peactf2020.
Hmm... how to I search for a string recursively on Linux?

1. Log in with the ip and port they give:

    ```bash
    ssh peactf@45.32.128.108 -p 28083
    # then type in the password (peactf2020)
    ```

2. We see a directory... lets cd into it

    ![Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled.png)

3. There's too many directories to even hope to look through
    - All of them have even more subdirectories

        ![Warm-up%201%20(15pts)%20fb726c819d544fa8ac59cecf0726abd7/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%201%20(15pts)%20fb726c819d544fa8ac59cecf0726abd7/Untitled.png)

4. Let's recursively look through the folders and cat out any files

    ```bash
    # ls -LR | cat | grep peaCTF
    # for some reason, the above command didn't work, so i used this:
    find  -exec cat {} \; | cat | grep pea
    ```

5. After some errors, the flag is highlighted

    ![Warm-up%201%20(15pts)%20fb726c819d544fa8ac59cecf0726abd7/Untitled%201.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%201%20(15pts)%20fb726c819d544fa8ac59cecf0726abd7/Untitled%201.png)

6. The flag is peaCTF{51e1de7c-6606-42c2-8621-96c62f56bd83}
