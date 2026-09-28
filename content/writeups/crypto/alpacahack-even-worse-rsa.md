---
title: "Even Worse RSA - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "gcd", "low-exponent", "cryptography"]
summary: "crypto writeup for \"Even Worse RSA\" from AlpacaHack Daily - techniques: alpacahack, rsa, gcd, low-exponent, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d23_Even_Worse_RSA/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Even Worse RSA"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Even Worse RSA
- **Date:** 2026-05-23
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d23_Even_Worse_RSA>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d23_Even_Worse_RSA/README.md>

---
# Even Worse RSA

## 問題

one-p-rsa がやられたようだな……
```py
m = bytes_to_long(flag)

p = getPrime(512)
e = 65538
c = pow(m, e, p)
assert m < p

print(f"{p = }")
print(f"{e = }")
print(f"{c = }")
```

## 概要

Even Worse RSA「one-p-rsaがやられたようだな……」

Square RSA「フフフ……奴は四天王の中でも最易……」

Safe Prime「baumroll1234ごときに解かれるとはRSA問題の面汚しよ……」

みたいな会話が聞こえてきそうですが、今回はどうすれば平文 $`m`$ を得て四天王を倒せるのでしょうか？

## 解法

さて、そんなザコ勇者baumroll1234はこの問題を見て、「え？こんなの簡単じゃない？`one-p-rsa`と何が違うの？」と思いました。

しかし、実際にソルバーを書いて実行してみると
```py
from Crypto.Util.number import long_to_bytes

# ここにoutput.txtの内容を全てコピペする

phi = p - 1
d = pow(e, -1, phi)
m = pow(c, d, p)
flag = long_to_bytes(m)
print(f"{flag = }")
```
```
Traceback (most recent call last):
  File "c:\ctf\even-worse-rsa\solve.py", line 8, in <module>
    d = pow(e, -1, phi)
ValueError: base is not invertible for the given modulus
```
なぜかエラーになってしまいます。

そこで、配布のソースコードをもう一度よく見ると、公開鍵 $`e`$ がいつもの`65537`ではなく`65538`になっています。

たった1違うだけでうまくいかないのはなぜでしょうか？

通常、秘密鍵 $`d`$ は、$`\phi(p) = p - 1`$（いつもでいう $`\phi(n) = (p - 1)(q - 1)`$ ）を法とする公開鍵 $`e`$ の逆元となります。

法 $`n`$ の世界において $`a`$の逆元 $`b \equiv a^{-1} \pmod{n}`$ が存在する条件は、$`a`$ と $`n`$ が互いに素であることでしたよね。

ですが、この問題では $`e`$ と $`\phi(p)`$ はいずれも偶数であり、互いに素ではないので、逆元 $`d`$ を求めることができません。

詰みました＼(^o^)／

しかし、勇者としては簡単にあきらめるわけにはいきません。

再び立ち上がり、別の方法を考えます。

$`e`$ と $`\phi(p)`$ が互いに素でないということは、これらのGCD(最大公約数)は1より大きいはずです。

とりあえず $`g = GCD(e, \phi(p))`$ で両方を割って互いに素なところに落とし込んでみます。

※この問題においては、$`g = 6`$ でした。

この新しい $`e`$ と $`\phi(p)`$ をそれぞれ

$`e' = \frac{e}{g}`$

$`\phi'(p) = \frac{\phi'(p)}{g}`$

とすると、共通の素因数が排除された $`e'`$ と $`\phi'(p)`$ は互いに素になるので、

$`d' \equiv e'^{-1} \pmod{\phi'(p)}`$

を求めることができます。

この $`d'`$ を使って暗号文 $`c`$ を復号すると、

$`c^{d'} = m^{e d'} = m^{g e' d'}`$

となります。

ここで、$`e'`$ と $`d'`$ は $`\phi'(p)`$を法とする逆元どうしであることから、

$`e'd' \equiv 1 \pmod{\phi'(p)}`$

が成立し、適切な整数 $`k`$ を使って

$`e'd' = k \phi'(p) + 1`$

と表すことができます。これを先ほどの式にあてはめると、

$`m^{g e' d'} = m^{g(k \phi'(p) + 1)} = m^{g k \phi'(p) + g} = m^{k \phi(p) + g} = (m^{\phi(p)})^{k} m^{g}`$

となります。

フェルマーの小定理により、$`p`$を法とする世界における$`\phi(p)`$乗は（$`x \equiv 0 \pmod{p}`$ を満たす $`x`$ 以外は）何でも1にしてしまうので、

$`(m^{\phi(p)})^{k} m^{g} \equiv m^{g} \pmod{p}`$

となります。

ここまでまとめると、

$`c^{d'} \equiv m^{g} \pmod{p}`$

となります。

まずはここまでPythonで求めてみます。

```py
from math import gcd

# output.txtの内容

phi = p - 1
g = gcd(e, phi)

e1 = e // g
phi1 = (p-1) // g

d = pow(e1, -1, phi1)
a = pow(c, d, p)

print(f"{p = }")
print(f"{a = }")
print(f"{g = }")
```

ここで求めた $`a`$ は先ほどでてきた $`c`$ を $`d'`$で復号したものです。

この $`a`$ の$`p`$を法とする世界での $`g`$ 乗根すなわち６乗根を求めれば、$`m`$が求められそうです。

さすがにLow Public Exponent Attackは使えそうにありませんが、SageMathを使えば解けるかもしれません。

```py
# 前記のプログラムの出力結果をコピペ

R = Zmod(p)
P.<x> = PolynomialRing(R)

f = x^g - a
roots = f.roots()

for r, _ in roots:
    print(int(r))
```
このSageMathスクリプトを実行したところ、出力された6つの解の中に1つだけあきらかに小さいものがありました。

ものすごく怪しいです。

違ったら他の5つも試せばいいだけの話なので、とりあえずこれでやってみます。

というわけで、再びPythonに戻り、
```py
from Crypto.Util.number import long_to_bytes

m = 前記SageMathスクリプトの出力からコピペ
flag = long_to_bytes(m)
print(f"{flag = }")
```
を実行すると、フラグを得ることができました。
