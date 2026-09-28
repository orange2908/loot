---
title: "Compressor - cactf 2022"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "gtfobins", "compressor", "miscellaneous", "cactf", "siunam321"]
summary: "In this challenge, pretty much just like one of the challenge in NahamCon CTF 2022!"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/cactf2022/Misc/Compressor/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/cactf2022/Misc/Compressor/README.md"
ctf:
  name: "cactf"
  year: 2022
  challenge: "Compressor"
---

## Source

- **CTF:** cactf 2022
- **Challenge:** Compressor
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/cactf2022/Misc/Compressor/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/cactf2022/Misc/Compressor/README.md>

---
# Background
![background1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-CTF-2022/Misc/Compressor/images/background1.png)

![background2](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-CTF-2022/Misc/Compressor/images/background2.png)

In this challenge, pretty much just like [one of the challenge in NahamCon CTF 2022](https://github.com/siunam321/CTF-Writeups/tree/main/NahamCon-CTF-2022/Warmups/Prisoner)! **Breaking out of the shell!**

# Solution
![solution1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-CTF-2022/Misc/Compressor/images/solution1.png)

First, as usual, netcat into the docker instance. Then we can see there are 4 components. Let's choose one of them.

Next, there are 7 actions we can choose!
```
1. Create artifact (Create a file)
2. List directory (pwd; ls -la)
3. Read artifact (cat ./<name>)
4. Compress artifact (zip <name>.zip <name> <options>)
5. Change directory (cd <dirname>)
6. Clean directory (rm -rf ./*)
7. Exit
```

Let's create a file then.

After the process of overthinking, I found maybe we can do something peculiar to this machine via **zip**! As it can parse an argument!

![solution3](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-CTF-2022/Misc/Compressor/images/solution3.png)

Hmm... According to [GTFOBins](https://gtfobins.github.io/gtfobins/zip/#shell), we can break out the shell via `-T -TT 'sh #'`! Let's try this!

![solution2](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-CTF-2022/Misc/Compressor/images/solution2.png)

Yes!!! It works! Let's find and cat the flag!

![flag](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-CTF-2022/Misc/Compressor/images/flag.png)

# Flag
`HTB{GTFO_4nd_m4k3_th3_b35t_4rt1f4ct5}`
