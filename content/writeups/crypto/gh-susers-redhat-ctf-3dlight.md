---
title: "3dlight - RedHat CTF 2018"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "dlight", "cryptography", "3dlight", "redhat-ctf", "susers"]
summary: "crypto writeup for \"3dlight\" from RedHat CTF - techniques: dlight, cryptography, 3dlight, redhat-ctf, susers."
source:
  name: "susers/Writeups"
  url: "https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2018/RedHat%20CTF/Crypto/3dlight/writeup.md"
ctf:
  name: "RedHat CTF"
  year: 2018
  challenge: "3dlight"
---

## Source

- **CTF:** RedHat CTF 2018
- **Challenge:** 3dlight
- **Repository:** [susers/Writeups](https://github.com/susers/Writeups)
- **File:** <https://github.com/susers/Writeups/blob/2b7977525e55889777895ac24b38ec87ca923d70/2018/RedHat%20CTF/Crypto/3dlight/writeup.md>

---
##  Title
3dlight

##  Tools


## Steps

这题自己也是莫名其妙做出来了，感觉方法可能不科学…
先把得到的密文转回三维列表lights，用ans暂存要还原的三维列表，初始值是2表示还没还原；
首先检查lights中的0，只要有0，自己和与它直接相连的都不会发光；
随后检查有没有8，有就代表它自己和它直接相连的都会发光；
再检查有没有在面上的7，有就代表它自己和它直接相连的都会发光；
最后检查有没有在棱上的6，有就代表它自己和它直接相连的都会发光；
然后就是无科学性地循环排除，简单来说检查已经找到（ans=0或1）并熄灭的灯的周围有没有大于2且没找到（ans = 2）的灯，如果正好等于中间的数值，就说明这些灯都是发光的；
在这些查找中，如果lights小于等于1且对应ans=2，那它肯定不发光并置ans=0；

[脚本](https://raw.githubusercontent.com/susers/Writeups/2b7977525e55889777895ac24b38ec87ca923d70/2018/RedHat%20CTF/Crypto/3dlight/files_for_writeups/exp.py)：
