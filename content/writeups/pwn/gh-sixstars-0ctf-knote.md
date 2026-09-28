---
title: "knote - 0ctf 2017"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "stack-pivot", "aslr", "kernel-pwn", "binary-exploitation"]
summary: "pwn writeup for \"knote\" from 0ctf - techniques: rop, stack-pivot, aslr, kernel-pwn, binary-exploitation."
source:
  name: "sixstars/ctf"
  url: "https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2017/0ctf/pwn/knote/writeup.md"
ctf:
  name: "0ctf"
  year: 2017
  challenge: "knote"
---

## Source

- **CTF:** 0ctf 2017
- **Challenge:** knote
- **Repository:** [sixstars/ctf](https://github.com/sixstars/ctf)
- **File:** <https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2017/0ctf/pwn/knote/writeup.md>

---
首先 add note 分配的 content 没有初始化，add note 的时候传入空内容可以在 read note 时 leak 残留数据，
这里 `tty_struct` 在 kmalloc-1024，可以用来被泄漏，`const struct tty_operations *ops` 字段有 kernel 指针，kASLR passed。

然后当 add note 的长度过长时，调用 `put_note`，其中会对 hash 表 unlink，
而 next、prev 都没有初始化，通过 sendmmsg spray 可以控制 next、prev，实现一次有限制的写入。
这里还是使用 `tty_struct`，通过前面的写入可以将 `tty_operations` 的 `ops` 字段伪造，控制函数指针劫持控制流。
stack pivot 后 ROP 首先 disable SMEP/SMAP，然后 `commit_creds(prepare_kernel_cred(0))` 提权，最后返回 user mode execve 得 root shell。
