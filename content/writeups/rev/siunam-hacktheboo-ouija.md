---
title: "Ouija - hacktheboo"
category: "rev"
subcategory: "classical"
type: "writeup"
tags: ["rev", "caesar", "pie", "lsb", "ouija", "classical"]
difficulty: "easy"
summary: "In this challenge, we can download a file:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/hacktheboo/Reversing/Ouija/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/hacktheboo/Reversing/Ouija/README.md"
ctf:
  name: "hacktheboo"
  challenge: "Ouija"
---

## Source

- **CTF:** hacktheboo
- **Challenge:** Ouija
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/hacktheboo/Reversing/Ouija/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/hacktheboo/Reversing/Ouija/README.md>

---
# Ouija

## Background

> You've made contact with a spirit from beyond the grave! Unfortunately, they speak in an ancient tongue of flags, so you can't understand a word. You've enlisted a medium who can translate it, but they like to take their time...

> Difficulty: Easy

- Overall difficulty for me: Very easy

**In this challenge, we can [download a file](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/HackTheBoo/Reversing/Ouija/rev_ouija.zip):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/HackTheBoo/Reversing/Ouija/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Ouija]
└─# unzip rev_ouija.zip         
Archive:  rev_ouija.zip
   creating: rev_ouija/
  inflating: rev_ouija/ouija

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Ouija]
└─# file rev_ouija/ouija 
rev_ouija/ouija: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2cace162c306a34dcfc4837d648d047e2ea339fe, for GNU/Linux 3.2.0, not stripped
```

It's an ELF 64-bit LSB pie executable!

## Find the flag

**Let's use `strings` to list all the strings in the executable!** 
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Reversing/Ouija/rev_ouija]
└─# strings ouija
[...]
ZLT{Svvafy_kdwwhk_lg_qgmj_ugvw_escwk_al_wskq_lg_ghlaearw_dslwj!}
Retrieving key.
     
 done!
Hmm, I don't like that one. Let's pick a new one.
Yes, 18 will do nicely.
Let's get ready to start. This might take a while!
This one's a lowercase letter
Wrapping it round...
This one's an uppercase letter!
We can leave this one alone.
Okay, let's write down this letter! This is a pretty complex operation, you might want to check back later.
You're still here?
[...]
```

Oh! That looks like a flag, and it's being **rotated**??

**For the sake of simplicity, I'll use a caesar cipher decoder from [dcode.fr](https://www.dcode.fr/caesar-cipher):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/HackTheBoo/Reversing/Ouija/images/a2.png)

We found the flag!

# Conclusion

What we've learned:

1. Decrypting Caesar Cipher
