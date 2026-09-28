---
title: "Special - picoCTF 2023"
category: "crypto"
subcategory: "ecc"
type: "writeup"
tags: ["crypto", "ed25519", "special", "ecc", "cryptography", "picoctf"]
summary: "crypto writeup for \"Special\" from picoCTF - techniques: ed25519, special, ecc, cryptography, picoctf."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/picoCTF-2023/General-Skills/Special/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/picoCTF-2023/General-Skills/Special/README.md"
ctf:
  name: "picoCTF"
  year: 2023
  challenge: "Special"
---

## Source

- **CTF:** picoCTF 2023
- **Challenge:** Special
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/picoCTF-2023/General-Skills/Special/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/picoCTF-2023/General-Skills/Special/README.md>

---
# Special

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Author: LT 'syreal' Jones

#### Description

Don't power users get tired of making spelling mistakes in the shell? Not anymore! Enter Special, the Spell Checked Interface for Affecting Linux. Now, every word is properly spelled and capitalized... automatically and behind-the-scenes! Be the first to test Special in beta, and feel free to tell us all about how Special streamlines every development process that you face. When your co-workers see your amazing shell interface, just tell them: That's Special (TM) Start your instance to see connection details. 

`ssh -p 61464 ctf-player@saturn.picoctf.net`

The password is `d8819d45`

## Find the flag

**In this challenge, we can SSH into the instance machine:**
```shell
┌[siunam♥earth]-(~/ctf/picoCTF-2023)-[2023.03.16|22:30:34(HKT)]
└> ssh -p 61464 ctf-player@saturn.picoctf.net
The authenticity of host '[saturn.picoctf.net]:61464 ([13.59.203.175]:61464)' can't be established.
ED25519 key fingerprint is SHA256:tJ0wuU5yBvNO/FrkHmR9iY36VJClMhKV+Hq2sxqKFmg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[saturn.picoctf.net]:61464' (ED25519) to the list of known hosts.
ctf-player@saturn.picoctf.net's password: 
[...]
Special$ 
```

```shell
Special$ whoami    
Whom 
sh: 1: Whom: not found
```

Hmm... Looks like we're inside a **Bash jail environment**!

As you can see, it ***capitalized*** the first character of our commands.

Hmm... Can we spawn another shell?

```shell
Special$ /bin/bash
Why go back to an inferior shell?
```

Oh... We can't.

**Based on my experience, we can use `$(<command>)` to execute OS commands:**
```shell
Special$ $(id)
$(id) 
sh: 1: uid=1000(ctf-player): not found
```

Hmm... Weird. We see some outputs.

**After some testing, I found the `*` is doing weird stuff:**
```shell
Special$ *
* 
sh: 1: blargh: not found
```

`blargh : not found`??

The `*` is the wildcard character, which reads everything in the current directory.

That being said, **there's a file/directory called `blargh`.**

Now, we can also use another trick to read the output:
```shell
<1&<command_here>
```

**The `<1&` is redirecting the command's output standard output (`1`).**

**Armed with above information, we can try to read the flag!**
```shell
<1&cat * 
sh: 1: cannot open 1: No such file
cat: blargh: Is a directory
```

Hmm... The `blargh` is a directory.

**We can use `cat blargh/*` to read everything inside that directory:**
```shell
Special$ <1&cat blargh/*
<1&cat blargh/* 
sh: 1: cannot open 1: No such file
picoCTF{5p311ch3ck_15_7h3_w0r57_0c61d335}Special$ 
```

Boom! We got the flag!

- **Flag: `picoCTF{5p311ch3ck_15_7h3_w0r57_0c61d335}`**

## Conclusion

What we've learned:

1. Bash Jail Escape
