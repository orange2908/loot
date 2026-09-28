---
title: "Lazy RSA - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "lazy", "cryptography", "lazy-rsa"]
summary: "crypto writeup for \"Lazy RSA\" from AlpacaHack Daily - techniques: alpacahack, rsa, lazy, cryptography, lazy-rsa."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d07_Lazy_RSA/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Lazy RSA"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Lazy RSA
- **Date:** 2026-07-07
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d07_Lazy_RSA>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d07_Lazy_RSA/README.md>

---
# Lazy RSA

## 問題

simple RSA challenge

```py
from Crypto.Util.number import bytes_to_long, getPrime
import os

FLAG = os.getenv("FLAG", "Alpaca{DUMMY}").encode()

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537
m = bytes_to_long(FLAG)
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")

hint = 12345 * p + 6789 * q
print(f"hint = {hint}")
```

## 概要

RSAの問題ですが、この問題では通常の`n`,`e`,`c`の他に`hint = 12345 * p + 6789 * q`が与えられています。

それ以外は通常のRSA暗号なので破ることはできませんが、`hint`をどのように活用すれば復号できるのでしょうか？

## 方針

`hint`を使って`q`を`p`で表し、`n = p * q`とあわせて二次方程式を解き`p`を求める。

## 解法

```
hint == 12345 * p + 6789 * q
```
を変形すると、
```
q == (hint - 12345 * p) / 6789
```
となります。

これを
```
n == p * q
```
にあてはめると、
```
n == p * (hint - 12345 * p) / 6789
p * (hint - 12345 * p) / 6789 - n == 0
```
のような`p`の二次方程式になります。

ここで、二次方程式なので`p`は最大2個の解をもつことと、今回の問題では`p`と`q`が対称ではないのでもう一つの解が`q`ではないことに注意が必要です。

ではさっそくPythonで求めていきます。

```py
from sympy import symbols, solve

# ここにoutput.txtの内容を全てコピペする

p = symbols('p')
expr = p * (hint - 12345 * p) / 6789 - n
ans = solve(expr, p)

print(ans)
```
```
[27461(略)67133/4115, 13141(略)30127]
```
2個の解が求まりましたが、1個目は整数でないようです。

`p`は整数だとわかっているので、2個目が正解ということになります。

`p`がわかったので`q = n // p`により`q`も求めることができます。

あとは通常どおり復号すればフラグを得ることができます。

```py
from sympy import symbols, solve
from Crypto.Util.number import long_to_bytes

（略）

for p1 in ans:
    if p1.is_integer:
        p = int(p1)
        q = n // p
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        flag = long_to_bytes(m)
        print(f"{flag = }")
        break
else:
    print("Solution not found.")
```
