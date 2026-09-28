---
title: "Booking Key - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "booking", "key", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "We are given a python script chall.py and a remote service."
source:
  name: "CTFtime writeup #40590"
  url: "https://ctftime.org/writeup/40590"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Booking Key"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Booking Key
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40590>

---
**Challenge Description**:  
We are given a python script `[chall.py](http://chall.py)` and a remote service. The service prints three ciphertext lists (one per round) derived from a book-based cipher and asks us to submit the corresponding 32-character passwords.

**Analysis**:  
The encryption uses a “book pointer” that moves through the text until the next occurrence of each character.  
```python  
while book[current] != char:  
current = (current + 1) % len(book)  
count += 1  
cipher.append(count)  
```  
So each `count` is the distance from the current index to the *first* next occurrence of the character. The secret “key” is just the random starting index.

**Solution**:  
We can recover the password without knowing the start index:  
1\. Precompute the positions of every allowed ASCII letter (`A–Z`, `a–z`) in the book.  
2\. For each possible start index `s`, walk the cipher. Compute `target = (cur + count) % L`, set `char = book[target]`, and ensure `target` is the *first* occurrence of `char` at or after `cur` (via binary search on the positions list).  
3\. If all 32 steps validate, we’ve found the unique password for that round.

This removes all ambiguity; only one start index passes the “first occurrence” constraint.

**Implementation**:  
We wrote a solver that connects to the server, parses the cipher list, reconstructs the password, and replies 3 times.  
[[solve_booking_key.py](http://solve_booking_key.py)](file:///home/mritunjya/ctf/2026/nullcon/crypto/booking_key/[solve_booking_key.py](http://solve_booking_key.py))

**Snippet from Solver**:  
```python  
target = (cur + count) % L  
ch = BOOK[target]  
if next_index(ch, cur) != target:  
break  
```

**Flag**:  
`ENO{y0u_f1nd_m4ny_th1ng5_in_w0nd3r1and}`
