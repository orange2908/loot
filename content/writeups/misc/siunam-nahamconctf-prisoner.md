---
title: "Prisoner - nahamconctf 2022"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "os-system", "prisoner", "miscellaneous", "nahamconctf", "siunam321"]
summary: "In this challenge, you have to exit the python script."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/nahamconctf2022/Warmups/Prisoner/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/nahamconctf2022/Warmups/Prisoner/README.md"
ctf:
  name: "nahamconctf"
  year: 2022
  challenge: "Prisoner"
---

## Source

- **CTF:** nahamconctf 2022
- **Challenge:** Prisoner
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/nahamconctf2022/Warmups/Prisoner/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/nahamconctf2022/Warmups/Prisoner/README.md>

---
# Background
![background](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Warmups/Prisoner/images/background.png)

![question](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Warmups/Prisoner/images/question.png)

In this challenge, you have to exit the python script. At that time I was asking myself, if I'm inside a python editor, how do I exit? So I pressed `Ctrl+D` to exit that script.

![question](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Warmups/Prisoner/images/question1.png)

And yes! I've successfully escape that python script!

Next, since the flag is in ./flag.txt, so I was googling `How to cat a file inside the python editor`, and I found this:
```
import os

os.system("command")
```

![question](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/Warmups/Prisoner/images/flag.png)

Finally!! We've the flag, let's submit it.
