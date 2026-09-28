---
title: "Coin Jam - CTF@CIT 2026"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "base64", "coin", "jam", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The clean .text logic makes the puzzle impossible on purpose."
source:
  name: "CTFtime writeup #40740"
  url: "https://ctftime.org/writeup/40740"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Coin Jam"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Coin Jam
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40740>

---
# Coin Jam — Writeup

\- Category: Game  
\- Value: 950  
\- Author: by **ronnie**

## Challenge

> Can you collect all the coins?  
>  
> Flag Format:  
> CIT{example_flag}

## Recon

The clean `.text` logic makes the puzzle impossible on purpose. The renderer and collision code only reference seven visible coins in the array at `0x1400114a0`, but the exit gate in `0x1400029cc` requires `coin_count >= 10` before it jumps into the protected `.vlizer` block at `0x1400b8ce0`.

Jumping straight into the protected block only triggers the fake integrity path. The missing piece is startup state: the virtualized code expects globals that are normally populated by the program's constructor and window setup, not just the visible coin counters.

## Solve

I solved it on `dev-box-cpu` with a Unicorn-based Windows stub.

The working replay needs four parts:

1\. Run the security-cookie initializer at `0x140004258`.  
2\. Seed the static-constructor globals:  
\- `0x14001dbd8` -> pointer to a copied 0x754-byte base64 buffer from `0x140011aa0`  
\- `0x14001dbe8` -> `0x754`  
\- `0x14001dbf0` -> `0x75f`  
\- `0x14001dbd0` -> fake nonzero `HWND`  
3\. Seed game state so the player is already overlapping the exit with 10 coins.  
4\. Call the real update function at `0x140002560`, not the deeper protected jump directly.

Once those globals exist, the protected path returns cleanly and allocates a 0x20-byte heap buffer containing the flag. The recovered heap bytes are stored in [other/heap-dump.txt](other/heap-dump.txt), and the solver in [scripts/[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py)) reproduces the same result.

## Flag

```text  
CIT{5x4W28cLIbUq}  
```

## Files

\- [scripts/[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py))  
\- [solution/flag.txt](solution/flag.txt)  
\- [other/heap-dump.txt](other/heap-dump.txt)
