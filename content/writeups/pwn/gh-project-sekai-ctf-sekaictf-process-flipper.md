---
title: "process flipper - sekaictf 2024"
category: "pwn"
subcategory: "privesc"
type: "writeup"
tags: ["pwn", "privesc", "process", "flipper", "binary-exploitation", "process-flipper"]
summary: "Inspired from a certain anti-cheat used in gacha games."
source:
  name: "project-sekai-ctf/sekaictf-2024"
  url: "https://github.com/project-sekai-ctf/sekaictf-2024/blob/e7c9183860a846dd2c4e0d1fd5d5a1fe468e1244/pwn/process-flipper/README.md"
ctf:
  name: "sekaictf"
  year: 2024
  challenge: "process flipper"
---

## Source

- **CTF:** sekaictf 2024
- **Challenge:** process flipper
- **Repository:** [project-sekai-ctf/sekaictf-2024](https://github.com/project-sekai-ctf/sekaictf-2024)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2024/blob/e7c9183860a846dd2c4e0d1fd5d5a1fe468e1244/pwn/process-flipper/README.md>

---
## Process Flipper

| Author      | Difficulty | Points | Solves | First Blood | Time to Blood |
| ----------- | ---------- | ------ | ------ | ----------- | ------------- |
| nyancat0131 | Expert (4) | 458    | 3      | r4kapig     | 11 hours      |

---

### Description

Tags: `Windows`

<blockquote>

Inspired from a certain anti-cheat used in _gacha_ games.

> ❖ **Note**
>
> - This challenge runs on Windows 11 build 26100.1150.
> - Your exploit is expected to perform privilege escalation to `NT AUTHORITY\SYSTEM`, then show the content of `C:\flag.txt` to the screen.
> - A screenshot of the machine will be returned to you after your exploit finishes (the timeout is 30 seconds).
> - Please submit **statically linked binaries** only since there are no runtimes installed.
> - Your exploit could be blocked by Windows Defender.

<!-- <details closed>
<summary><b>Hint(s)</b>:</summary>

1. Hint 1
2. Hint 2

</details> -->
</blockquote>

### Challenge Files

- [processflipper.zip](https://raw.githubusercontent.com/project-sekai-ctf/sekaictf-2024/e7c9183860a846dd2c4e0d1fd5d5a1fe468e1244/pwn/process-flipper/dist)
