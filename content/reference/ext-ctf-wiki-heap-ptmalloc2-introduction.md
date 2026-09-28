---
title: "Introduction - 堆利用 (CTF Wiki)"
category: "pwn"
subcategory: "ptmalloc2"
type: "reference"
tags: ["ctf-wiki", "pwn", "heap", "wordpress", "introduction", "ptmalloc2", "chinese", "zh"]
summary: "对于不同的应用来说，由于内存的需求各不相同等特性，因此目前堆的实现有很多种，具体如下"
source:
  name: "CTF Wiki"
  url: "https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/pwn/linux/user-mode/heap/ptmalloc2/introduction.md"
license: "CC BY-NC-SA 4.0"
---

# 堆利用

在该章节中，我们会按照如下的步骤进行介绍

1. 介绍我们所熟知的动态内存分配的堆的宏观操作
2. 介绍为了达到这些操作所使用的数据结构
3. 介绍利用这些数据结构实现堆的分配与回收的具体操作
4. 由浅入深地介绍堆的各种利用技巧。

对于不同的应用来说，由于内存的需求各不相同等特性，因此目前堆的实现有很多种，具体如下
```text
dlmalloc  – General purpose allocator
ptmalloc2 – glibc
jemalloc  – FreeBSD and Firefox
tcmalloc  – Google
libumem   – Solaris
```

这里我们主要以 glibc 中堆的实现为主进行介绍。如果后续有时间，会继续介绍其它堆的实现及其利用。

该部分主要参考的资料如下，文中有很多内容会和参考资料中一致，以后就不一一说明了。

- [black hat heap exploitation](https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf)
- [github heap exploition](https://heap-exploitation.dhavalkapil.com/)
- [sploitfun](https://sploitfun.wordpress.com/archives/)
- glibc 源码
- 更多的参考文献请看ref目录下的文件

---

## Source

CTF Wiki - <https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/pwn/linux/user-mode/heap/ptmalloc2/introduction.md>

Mirrored into CTF-Brain at commit `e225ddfcd420`. Licence: CC BY-NC-SA 4.0. The text is the original authors' work.
