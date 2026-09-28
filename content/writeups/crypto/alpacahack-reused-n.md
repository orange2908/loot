---
title: "reused n - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "gcd", "low-exponent", "reused"]
summary: "crypto writeup for \"reused n\" from AlpacaHack Daily - techniques: alpacahack, rsa, gcd, low-exponent, reused."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d09_reused_n/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "reused n"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** reused n
- **Date:** 2026-05-09
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d09_reused_n>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d09_reused_n/README.md>

---
# reused n

## 問題

n を使い回すと危ないらしいです
```py
assert len(flag) < 100

m = bytes_to_long(flag)

p = getPrime(1024)
q = getPrime(1024)
n = p * q

e1 = 1234
e2 = 5678

c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
```

## 概要

この問題では、$`n`$と、異なる$`e_{1}`$, $`e_{2}`$と、これらで平文$`m`$を暗号化した暗号文$`c_{1}`$, $`c_{2}`$が与えられています。

それぞれ単独でみると正規のRSA暗号なので、破ることはできそうにありません。

この状況で、なんとかして平文$`m`$を得ることはできないでしょうか？

## 方針

拡張ユークリッド互除法を使って $`m^{2}`$ を求め、さらにLow Public Exponent Attackで$`m`$を求める。

## 解法

以降$`a`$と$`b`$の最大公約数を$`GCD(a, b)`$と書くことにします。

拡張ユークリッド互除法を使うと、整数$`a`$, $`b`$について、 $`ax + by = GCD(a, b)`$ を満たすような整数$`x`$, $`y`$を求めることができます。

もし、$`e_{1}`$と$`e_{2}`$が互いに素であれば、$`GCD(e_{1}, e_{2}) = 1`$が成立するので、この$`e_{1}`$と$`e_{2}`$について拡張ユークリッド互除法を使って`x`と`y`を求め、

$`c_{1}^{x} \cdot c_{2}^{y} \equiv m^{e_{1}x} \cdot m^{e_{2}y} \equiv m^{e_{1}x + e_{2}y} \equiv m^{1} \equiv m \pmod{n}`$

から$`m`$を求めることができます。（$`m < n`$であれば。）

しかし、この問題の面白いところは、$`e_{1}`$と$`e_{2}`$が互いに素でないというもうひとひねりがあるところです。

具体的には、$`e_{1} = 1234`$, $`e_{2} = 5678`$なので、$`GCD(e_{1}, e_{2}) = 2`$となり、この方法をそのまま使うことはできません。

この計算によって求められた

$`m_{2} \equiv c_{1}^{x} \cdot c_{2}^{y} \pmod{n}`$

は、$`m_{2} \equiv m^{2} \pmod{n}`$すなわち$`m`$を$`e = 2`$で暗号化したものになります。

$`e = 2`$という小さい$`e`$であったとしても一般には破ることは困難です。

※それ以前に$`e = 2`$だと$`GCD(e, φ(n)) \ne 1`$なので逆元$`d`$が求められず正規の復号すらできないかもしれません。

しかし、この問題について言えば、フラグは100バイト未満であるという制約があります。

この制約により、$`m`$は800ビット未満、$`m^{2}`$は1600ビット未満となります。

一方で、$`n`$は1024ビットの2つの素数の積であり、2047ビットです。

よって、$`m^{2} < n`$が成立するので、この$`m_{2}`$についてLow Public Exponent Attackが使えることになります。

※Low Public Exponent Attack：暗号化に$`\pmod{n}`$が効かないような小さい$`e`$とパディングなしの小さい$`m`$が使われている場合において、単に累乗根を求めるだけで復号できてしまう性質を利用した攻撃

```py
from Crypto.Util.number import long_to_bytes
import gmpy2

# ここにchall.txtの内容を全てコピペする

g, x, y = gmpy2.gcdext(e1, e2)
m2 = pow(c1, x, n) * pow(c2, y, n) % n

m, exact = gmpy2.iroot(m2, 2)
if exact:
    flag = long_to_bytes(m)
    print(f"{flag = }")
```

厳密にいえばこの$`m`$の型は`gmpy2.mpz`なので、`long_to_bytes(int(m))`とするべきなのでしょうか？

でも`long_to_bytes`がちゃんと動作してくれるみたいなのでまあいいかってなりました（笑）
