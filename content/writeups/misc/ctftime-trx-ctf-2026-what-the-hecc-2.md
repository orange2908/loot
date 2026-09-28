---
title: "What the HECC 2 - TRX CTF 2026"
category: "misc"
type: "writeup"
tags: ["misc", "hecc", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "Setup: Mumford reduction of P + Q"
source:
  name: "CTFtime writeup #40722"
  url: "https://ctftime.org/writeup/40722"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-what-the-hecc-2-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "What the HECC 2"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** What the HECC 2
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40722>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-what-the-hecc-2-writeup>

---
Setup: Mumford reduction of P + Q  
P has weight 1, Q has weight 2, so P + Q is a weight-3 divisor that Cantor's algorithm reduces to weight ≤ 2 before printing.

Let the three affine points of the un-reduced divisor be (Px, Py), (α₁, β₁), (α₂, β₂). The semi-reduced Mumford form is (u₃, w) where

u₃(x) = (x − Px)(x − α₁)(x − α₂)  
w(x) = unique quadratic interpolating (Px, Py), (α₁, β₁), (α₂, β₂)  
with the identity F(x) − w(x)² = u₃(x) · u'(x), deg u' = 2. Cantor reduction outputs

v'(x) ≡ −w(x) (mod u'(x))  
and we receive (u', v'). Crucially, u₃ is not directly recoverable from u' alone.
