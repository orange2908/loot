---
title: "neighboRhood diStAnce - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "neighborhood", "distance", "cryptography"]
summary: "crypto writeup for \"neighboRhood diStAnce\" from AlpacaHack Daily - techniques: alpacahack, rsa, neighborhood, distance, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d16-18_neighboRhood_diStAnce/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "neighboRhood diStAnce"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** neighboRhood diStAnce
- **Date:** 2026-09-16-18
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d16-18_neighboRhood_diStAnce>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d16-18_neighboRhood_diStAnce/README.md>

---
# neighboRhood_diStAnce

なんか問題タイトルの表記がおかしいと思ったら、RSAが含まれているってことですね。

## 問題

あなたの「隣人との距離」はどれくらいですか？

```py
bits = 1024

FLAG = os.environ.get("FLAG", "Alpaca{*REDACTED*}").encode()

assert len(FLAG) % 3 == 0
L = len(FLAG) // 3

m1 = bytes_to_long(FLAG[0:L])
m2 = bytes_to_long(FLAG[L:2*L])
m3 = bytes_to_long(FLAG[2*L:3*L])

e = 0x10001

p, q, r = [getPrime(bits) for _ in range(3)]
pp = next_prime(p)
qq = next_prime(q)
rr = next_prime(r)

assert (p - 1) % e != 0 and (q - 1) % e != 0 and (r - 1) % e != 0
assert (pp - 1) % e != 0 and (qq - 1) % e != 0 and (rr - 1) % e != 0
assert (pp - p) < 2**16 or (qq - q) < 2**16 or (rr - r) < 2**16

n1 = p * qq
n2 = q * rr
n3 = r * pp
c1 = pow(m1, e, n1)
c2 = pow(m2, e, n2)
c3 = pow(m3, e, n3)
```

## 概要

1024ビットの素数`p`,`q`,`r`と、これらの次の素数`pp`,`qq`,`rr`が生成され、これらを組み合わせた`n1`,`n2`,`n3`と`e=36657`によってフラグの断片`m1`,`m2`,`m3`を暗号化した`c1`,`c2`,`c3`が与えられます。

最初「これFarmat Attackで一発じゃない？」と思いましたが、やってみるとうまくいかず、よーく見てみると、
```py
n1 = p * qq
n2 = q * rr
n3 = r * pp
```
のように掛けられる素数がズレているのでダメでした。

どうすればフラグの断片を得ることができるのでしょうか？

## 方針

`p`と`pp`などのペアとなる素数は割合的にはほぼ等しいことを利用する。

## 解法

数学好きの私の勘がこう言いました。「`n1`,`n2`,`n3`を全部掛けろ」と。

そうすると、

```
n = p * qq * q * rr * r * pp = (p * pp) * (q * qq) * (r * rr)
```
となります。

ここで、`p`と`pp`などのペアとなる素数は隣どうしの素数なので、ほぼ等しいと考えられます。

※素数によっては大きく差が開くかもしれませんが、3つの素数`p`,`q`,`r`が$`2^{1023}`$～$`2^{1024}-1`$の範囲内に散らばっていることを考えたらその差は無いも同然です。

なので、$`n0 = \sqrt{n}`$は`p * q * r`とほぼ同じになります。

さらに、`n1 * n3 = p * qq * r * pp`なので、`p0 = n1 * n3 // n0`は`p`とほぼ同じになります。

この「ほぼ`p`」と正しい`p`や`pp`はほとんど変わらないはずなので、「ほぼ`p`」の付近の前後から`n3`を割り切る奇数を探せば`pp`が求まります。

`pp`さえ求まれば、`n1`,`n2`,`n3`を割ったり、next_prime関数を利用したりして、芋づる式に全ての素数を求めることができます。

あとはそれぞれ通常どおり復号すればフラグの断片が求まり、これらを結合することでフラグを得ることができます。

## ソルバー

```py
from Crypto.Util.number import *
from gmpy2 import iroot

# chal.pyからnext_prime関数の定義をここにコピペする

# output.txtの内容をここに全てコピペする

n0, _ = iroot(n1 * n2 * n3, 2)
p0 = n1 * n3 // int(n0)
if p0 & 1 == 0:
    p0 |= 1 # 偶数の場合は奇数にしておく

for i in range(999999):
    pp = p0 + i * 2
    if n3 % pp == 0:
        break
    pp = p0 - i * 2
    if n3 % pp == 0:
        break
else:
    print("Not found.")
    exit(1)

r = n3 // pp
rr = next_prime(r)
q = n2 // rr
qq = next_prime(q)
p = n1 // qq

phi1 = (p - 1) * (qq - 1)
phi2 = (q - 1) * (rr - 1)
phi3 = (r - 1) * (pp - 1)

d1 = pow(e, -1, phi1)
d2 = pow(e, -1, phi2)
d3 = pow(e, -1, phi3)

m1 = pow(c1, d1, n1)
m2 = pow(c2, d2, n2)
m3 = pow(c3, d3, n3)

flag1 = long_to_bytes(m1)
flag2 = long_to_bytes(m2)
flag3 = long_to_bytes(m3)

flag = flag1 + flag2 + flag3
print(f"{flag = }")
```
