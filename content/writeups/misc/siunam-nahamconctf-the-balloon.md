---
title: "The-Balloon - nahamconctf 2022"
category: "misc"
subcategory: "classical"
type: "writeup"
tags: ["misc", "caesar", "cyberchef", "the-balloon", "classical", "miscellaneous"]
summary: "As usual, let's download the theballoon file and see what it is."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/nahamconctf2022/Miscellaneous/The-Balloon/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/nahamconctf2022/Miscellaneous/The-Balloon/README.md"
ctf:
  name: "nahamconctf"
  year: 2022
  challenge: "The-Balloon"
---

## Source

- **CTF:** nahamconctf 2022
- **Challenge:** The-Balloon
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/nahamconctf2022/Miscellaneous/The-Balloon/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/nahamconctf2022/Miscellaneous/The-Balloon/README.md>

---
# Background
![background](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/background.png)

As usual, let's download the `theballoon` file and see what it is.

![question](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/question.png)

It's said it's **defalted balloon(Compressed data)**, `spin it around`, `_inflate_ it`. Then, I saw a string that's rotated, and it reminds me Cicada 3301 stuff, as it looks a `HTTPS scheme`. Hmm... Let's use [CyberChef](https://gchq.github.io/CyberChef/) to rotate that string. I'll use `Rot13` recipe and manually change the `amount`.

![solution1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/solution1.png)

Oh... It's a pastebin link. Let's check that out.

![solution2](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/solution2.png)

Weird string... Let's throw that into [CyberChef](https://gchq.github.io/CyberChef/) again with the `Raw Inflate` recipe, as the `theballoon` file tells us to **inflate it(Decompress).**

![flag](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Miscellaneous/The-Balloon/images/flag.png)

And voila!! That's the flag!
