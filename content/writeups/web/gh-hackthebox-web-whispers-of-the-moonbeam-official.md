---
title: "official - web whispers of the moonbeam 2025"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["web", "command-injection", "official", "rce", "web-exploitation", "web-whispers-of-the-moonbeam"]
summary: "web writeup for \"official\" from web whispers of the moonbeam - techniques: command-injection, official, rce, web-exploitation, web-whispers-of-the-moonbeam."
source:
  name: "hackthebox/cyber-apocalypse-2025"
  url: "https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/web/web_whispers_of_the_moonbeam/official_writeup.md"
ctf:
  name: "web whispers of the moonbeam"
  year: 2025
  challenge: "official"
---

## Source

- **CTF:** web whispers of the moonbeam 2025
- **Challenge:** official
- **Repository:** [hackthebox/cyber-apocalypse-2025](https://github.com/hackthebox/cyber-apocalypse-2025)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/web/web_whispers_of_the_moonbeam/official_writeup.md>

---
![img](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2025/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/assets/banner.png)

<img src='https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2025/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Whispers of the Moonbeam</font>


24<sup>th</sup> March 2025

Prepared By: makelaris

Challenge Author: makelaris

Difficulty: <font color='green'>Very Easy</font>


# Synopsis

Whispers of the Moonbeam is a very easy web challenge. Players will determine that terminal commands are system commands and execute command injection in order to get the flag.

## Skills Required

- Knowledge of Linux commands

## Skills Learned

- Performing command injection

# Solution

When we visit the site, we're greeted with a terminal application that accepts comamnds.

![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2025/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/web/web_whispers_of_the_moonbeam/assets/preview.png)

Typing commands like `gossip`, `observe` and `examine` will seemingly provide us linux command outputs, indicating it's running system commands. There's also a hint to use `;` for command injection.

![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2025/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/web/web_whispers_of_the_moonbeam/assets/command_output.png)

We see the `flag.txt` on the `gossip` command, we can use command injection to `cat flag.txt`, using this payload:

```sh
observe; cat flag.txt
```

And we get the flag!
![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2025/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/web/web_whispers_of_the_moonbeam/assets/flag.png)
