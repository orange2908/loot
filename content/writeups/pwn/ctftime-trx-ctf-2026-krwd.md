---
title: "krwd - TRX CTF 2026"
category: "pwn"
type: "writeup"
tags: ["pwn", "kernel", "krwd", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "This challenge is a Linux kernel pwnable built around a custom character device, /dev/chall."
source:
  name: "CTFtime writeup #40711"
  url: "https://ctftime.org/writeup/40711"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-kwrd-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "krwd"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** krwd
- **Author team:** rawpayload
- **CTFtime tags:** kernel
- **CTFtime:** <https://ctftime.org/writeup/40711>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-kwrd-writeup>

---
This challenge is a Linux kernel pwnable built around a custom character device, /dev/chall. The bug is a classic delayed user-pointer bug: the module stores a __user pointer in a global request and later dereferences it from a kernel workqueue thread. Because the copy runs in a kworker instead of the process that submitted the ioctl, the user address is interpreted in whichever userspace address space the kworker is borrowing at that moment.

On this VM, QEMU is single CPU (-smp 1). By repeatedly waking PID 1 (/init, BusyBox ash) and scheduling delayed work, the kworker can be made to perform copy_from_user() and copy_to_user() against PID 1's active_mm. That gives a probabilistic arbitrary read/write primitive into PID 1 userspace.
