---
title: "Warm up 2 (30pts) b61b240391db46189aacb240afb7b83f - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "warm", "pts", "b61b240391db46189aacb240afb7b83f", "miscellaneous", "warm-up-2-30pts-b61b240391db46189aacb240"]
summary: "It's a little bit dramatic this time."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%202%20%2830pts%29%20b61b240391db46189aacb240afb7b83f.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "Warm up 2 (30pts) b61b240391db46189aacb240afb7b83f"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** Warm up 2 (30pts) b61b240391db46189aacb240afb7b83f
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%202%20%2830pts%29%20b61b240391db46189aacb240afb7b83f.md>

---
# Warm-up 2 (30pts)

> Log into the ssh service with username peactf and password peactf2020.
It's a little bit dramatic this time.

1. Log in with the ip and port they give:

    ```
    ssh peactf@45.32.128.108 -p 28095
    # then type in the password (peactf2020)

    ```

2. We see a readme... lets cat it

    ![Warm-up%202%20(30pts)%20b61b240391db46189aacb240afb7b83f/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%202%20(30pts)%20b61b240391db46189aacb240afb7b83f/Untitled.png)

    - Good to know
3. Now, lets cd into the directory
4. There's too many directories to even hope to look through
    - All of them have even more subdirectories

        ![Warm-up%202%20(30pts)%20b61b240391db46189aacb240afb7b83f/Untitled%201.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%202%20(30pts)%20b61b240391db46189aacb240afb7b83f/Untitled%201.png)

5. Let's recursively look through the folders and cat out any files

    ```bash
    grep -r peaCTF{.*}
    # This recursively looks through and cats anything that matches the regex
    ```

6. We see a lot of flags, but only the last one has closing bracket

    ![Warm-up%202%20(30pts)%20b61b240391db46189aacb240afb7b83f/Untitled%202.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Warm-up%202%20(30pts)%20b61b240391db46189aacb240afb7b83f/Untitled%202.png)

    - If we want to, we can refine the output a bit like this:

    ```sql
    grep -r -o peaCTF{.*} | cut -d " " -f 43
    ```

7. The flag is peaCTF{3991868c-12f7-4ca8-9d56-5385e5905036}
