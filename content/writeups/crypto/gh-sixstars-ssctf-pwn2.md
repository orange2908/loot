---
title: "pwn2 - SSCTF 2016"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "xor", "pwn2", "cryptography", "ssctf", "sixstars"]
summary: "crypto writeup for \"pwn2\" from SSCTF - techniques: xor, pwn2, cryptography, ssctf, sixstars."
source:
  name: "sixstars/ctf"
  url: "https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2016/SSCTF/pwn2/writeup/README.md"
ctf:
  name: "SSCTF"
  year: 2016
  challenge: "pwn2"
---

## Source

- **CTF:** SSCTF 2016
- **Challenge:** pwn2
- **Repository:** [sixstars/ctf](https://github.com/sixstars/ctf)
- **File:** <https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2016/SSCTF/pwn2/writeup/README.md>

---
这题的程序和前面一题大致一样，连洞都一样，不过对数列长度用个随机数做了校验，于是要修改数列长度必须同时修改后面那个数，使得 xor 结果不变。

由于我们只能越界一位，于是我们不能直接修改数列长度，那我们尝试修改某个 history 结构体，
然后由于显示 history 的时候，也做了那个 xor 的校验，于是我们刚开始还不能随便伪造，因为不知道随机数的值，
但我们可以选择改成那个随机数存的位置，而那个数后面正好又是 0，这样就可以过掉 xor 判断。
过掉判断之后，我们利用 history 就可以泄漏此随机数，以及堆地址神马的。
但这里我们不能直接 reload 这个结构体，因为几乎 size 都会超过限制，于是 out of memory 跪掉。
但由于信息已经泄漏了许多，我们就可以在堆上伪造这样一个数列了，
然后再修改另一个 history 结构体指向这个伪造的数列，然后 reload，就拿到了一个可以越界很多的数列了，接下来就和前一题一样做了。
