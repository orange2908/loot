---
title: "✌️✌️✌️ - AlpacaHack Daily"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "alpacahack", "cryptography", "alpacahack-daily", "daily", "2026"]
summary: "crypto writeup for \"✌️✌️✌️\" from AlpacaHack Daily - techniques: alpacahack, cryptography, alpacahack-daily, daily, 2026."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d22_%E2%9C%8C%EF%B8%8F%E2%9C%8C%EF%B8%8F%E2%9C%8C%EF%B8%8F/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "✌️✌️✌️"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** ✌️✌️✌️
- **Date:** 2026-06-22
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d22_%E2%9C%8C%EF%B8%8F%E2%9C%8C%EF%B8%8F%E2%9C%8C%EF%B8%8F>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d22_%E2%9C%8C%EF%B8%8F%E2%9C%8C%EF%B8%8F%E2%9C%8C%EF%B8%8F/README.md>

---
# ✌️✌️✌️

## 問題

人にやさしく

```py
import os, secrets

P = 2**521 - 1
THRESHOLD = 3
SHARES = 4

flag = int.from_bytes(os.getenv("FLAG", "Alpaca{DUMMY}").encode())
assert flag < P

coeffs = [flag] + [secrets.randbelow(P - 1) + 1 for _ in range(THRESHOLD - 1)]

# f(x) = c0 + c1 * x + c2 * x^2 mod P
f = lambda x: sum(c * pow(x, i, P) for i, c in enumerate(coeffs)) % P

# shares = (1, f(1)), ..., (4, f(4))
shares = [(x, f(x)) for x in range(1, SHARES + 1)]

# 3-out-of-4 secret sharing
print(f"{shares[:THRESHOLD] = }")
```

## 概要

素数 $`P = 2^{521} - 1`$ と、整数化したフラグ$`c_{0}`$、1以上P未満のランダムな整数 $`c_{1}`$, $`c_{2}`$、二次関数 $`f(x) \equiv c_{2}x^{2} + c_{1}x + c_{0} \pmod{P}`$ によって計算される $`f(1)`$, $`f(2)`$, $`f(3)`$ が与えられます。

どうすれば $`c_{0}`$ を求めてフラグを得ることができるでしょうか？

## 解法

与えられた$`f(1)`$, $`f(2)`$, $`f(3)`$を、$`c_{0}`$, $`c_{1}`$, $`c_{2}`$を使った式で表してみます。

$`f(1) \equiv c_{2} + c_{1} + c_{0} \pmod{P}`$

$`f(2) \equiv 4c_{2} + 2c_{1} + c_{0} \pmod{P}`$

$`f(3) \equiv 9c_{2} + 3c_{1} + c_{0} \pmod{P}`$

ここで、

$`a \equiv f(2) - f(1) \equiv 3c_{2} + c_{1} \pmod{P}`$

$`b \equiv f(3) - f(2) - a \equiv 2c_{2} \pmod{P}`$

とおくと、

$`c_{2} \equiv b ÷ 2 \pmod{P}`$

$`c_{1} \equiv a - 3c_{2} \pmod{P}`$

$`c_{0} \equiv f(1) - c_{2} - c_{1} \pmod{P}`$

となることから、$`c_{0}`$, $`c_{1}`$, $`c_{2}`$を全て特定することができます。

```py
from Crypto.Util.number import long_to_bytes

P = 2**521 - 1
shares = [output.txtからコピペ]

f1 = shares[0][1]
f2 = shares[1][1]
f3 = shares[2][1]

a = (f2 - f1) % P
b = (f3 - f2 - a) % P

c2 = b * pow(2, -1, P) % P
c1 = (a - 3 * c2) % P
c0 = (f1 - c2 - c1) % P

print(f"{c0 = }")
flag = long_to_bytes(c0)
print(f"{flag = }")
```
※この問題では全て $`\pmod{P}`$ の世界で考えているので、足し算、引き算、掛け算はそのままでいいですが、割り算については逆元 $`2^{-1} \pmod{P}`$ をとる必要があります。（2とPは互いに素なのでこれを求めることができます。）

## 補足

フラグには、「ラグランジュ補完も試してみて」と書いてありました。

調べてみると、k+1個の点 ($`x_{0}`$, $`y_{0}`$), ($`x_{1}`$, $`y_{1}`$), ... , ($`x_{k}`$, $`y_{k}`$) を通るk次式を求める方法のようです。

これには、ある $`x_{i}`$ だけ`1`でほかの $`x_{j} (i \ne j)`$ は`0`になるような関数 $`L_{i}(x)`$ を使うそうです。

具体的にやってみましょう。

$`x_{0} = 1`$, $`x_{1} = 2`$, $`x_{2} = 3`$として考えると、

$`L_{0}(x) \equiv \frac{(x - x_{1})(x - x_{2})}{(x_{0} - x_{1})(x_{0} - x_{2})} \equiv \frac{(x - 2)(x - 3)}{(1 - 2)(1 - 3)} \equiv -\frac{1}{2} (x^{2} - 5x + 6) \pmod{P}`$

$`L_{1}(x) \equiv \frac{(x - x_{0})(x - x_{2})}{(x_{1} - x_{0})(x_{1} - x_{2})} \equiv \frac{(x - 1)(x - 3)}{(2 - 1)(2 - 3)} \equiv - (x^{2} - 4x + 3) \pmod{P}`$

$`L_{2}(x) \equiv \frac{(x - x_{0})(x - x_{1})}{(x_{2} - x_{0})(x_{2} - x_{1})} \equiv \frac{(x - 1)(x - 2)}{(3 - 1)(3 - 2)} \equiv \frac{1}{2} (x^{2} - 3x + 2) \pmod{P}`$

$`f(x) \equiv f(x_{0})L_{0}(x) + f(x_{1})L_{1}(x) + f(x_{2})L_{2}(x) \pmod{P}`$

となります。

今回求めたいのは $`f(0)`$ の値なので、

$`f(0) \equiv 3f(1) - 3f(2) + f(3) \pmod{P}`$

によっても求められたというわけですね。

```py
f1 = shares[0][1]
f2 = shares[1][1]
f3 = shares[2][1]

c0 = (3 * f1 - 3 * f2 + f3) % P
```

## その他

フラグを得てもタイトルと問題文の意味がわからなかったので、「3ピース 人にやさしく」でWeb検索してみました。

すると、むかし「人にやさしく」というドラマがあったらしく、そのドラマの中で「3ピース」は「普通の幸せよりもっと幸せになれる」という意味が込められた特別なピースサインであったことがわかりました。

私はこのドラマを観ていないので結局問題の内容との関連性はわかりませんでしたが、今回秘密情報の断片が3つ与えられているので、3つの欠片(3 pieces)と掛けているということなのでしょうか？
