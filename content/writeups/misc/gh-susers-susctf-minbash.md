---
title: "minBash - SUSCTF 2018"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "minbash", "miscellaneous", "susctf", "susers", "writeups"]
summary: "misc writeup for \"minBash\" from SUSCTF - techniques: minbash, miscellaneous, susctf, susers, writeups."
source:
  name: "susers/Writeups"
  url: "https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2018/SUSCTF/Misc/minBash/Writeup.md"
ctf:
  name: "SUSCTF"
  year: 2018
  challenge: "minBash"
---

## Source

- **CTF:** SUSCTF 2018
- **Challenge:** minBash
- **Repository:** [susers/Writeups](https://github.com/susers/Writeups)
- **File:** <https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2018/SUSCTF/Misc/minBash/Writeup.md>

---
##  minBash

##  Tools

- ssh 

##  Steps

```sh
ctf@7ec56ab12af0:~$ ls
-rbash: ls: command not found

ctf@7ec56ab12af0:~$ python
Python 2.7.12 (default, Dec  4 2017, 14:50:18) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.listdir('.')
['.bashrc', '.bash_logout', '.profile', 'bin', 'c8049f64c8080af25f414b15cb6f80c3']
>>> os.path.isfile('c8049f64c8080af25f414b15cb6f80c3')
True
>>> 
ctf@7ec56ab12af0:~$ strings c8049f64c8080af25f414b15cb6f80c3
SUSCTF{e6b729cdf8885b16e7b949e85772e340}

ctf@7ec56ab12af0:~$ grep sus -i c8049f64c8080af25f414b15cb6f80c3
SUSCTF{e6b729cdf8885b16e7b949e85772e340}
ctf@7ec56ab12af0:~$ 

```
