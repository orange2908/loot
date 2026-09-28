---
title: "Seen - Nullcon Goa HackIM 2026 CTF"
category: "misc"
subcategory: "prng"
type: "writeup"
tags: ["misc", "prng", "seen", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40657"
  url: "https://ctftime.org/writeup/40657"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/Seen/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Seen"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Seen
- **Author team:** RootRunners
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/40657>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/Seen/README.md>

---
# Seen

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Misc   
**Points:** 50 

## Overview  
The client-side checker in `index.html` decodes a long string of Unicode Variation Selectors into a byte array `t`, then validates your input with a simple PRNG-like update. Only the second half of `t` is actually compared, so the first half is noise.

## Variation Selectors to Bytes  
The challenge uses the basic Variation Selectors block (`U+FE00...`). Two selectors encode one byte:

```js  
const vs = 0xFE00;  
for (let i = 0; i < s.length; i += 2) {  
t.push(((s.charCodeAt(i) - vs) << 4) | (s.charCodeAt(i + 1) - vs));  
}  
```

So:  
\- Each selector encodes a nibble (`0..15`) with `codepoint - 0xFE00`.  
\- Two nibbles make one byte.

## Length Constraint  
The checker enforces:

```  
if (u.length * 2 != t.length) fail();  
```

So the input length is exactly `t.length / 2`.

## Inversion  
Only the low byte of the PRNG state is used. Reduced modulo 256:  
\- `gen & 0xFF = 0x48`  
\- `c & 0xFF = 0x48`  
\- `k & 0xFF = 0x83`

Let `G[i] = t[n + i]` (the second half of `t`). The per-byte inversion is:

```  
input[i] = prev ^ cc ^ ((G[i] - kk) & 0xFF)  
prev = G[i]  
```

## Minimal Solver (Python)  
```python  
# Extract s from the HTML manually, paste it here:  
s = "PASTE_THE_VARIATION_SELECTOR_STRING_HERE"

vs = 0xFE00

# Decode variation selectors to bytes  
t = []  
for i in range(0, len(s), 2):  
b = ((ord(s[i]) - vs) << 4) | (ord(s[i+1]) - vs)  
t.append(b)

n = len(t) // 2  
G = t[n:]

prev = 0x48  
cc = 0x48  
kk = 0x83

u = []  
for gi in G:  
ui = prev ^ cc ^ ((gi - kk) & 0xFF)  
u.append(ui)  
prev = gi

flag = bytes(u).decode("utf-8")  
print(flag)  
```

## Flag  
`ENO{W0W_1_D1DN'T_533_TH4T_C0M1NG!!!}`
