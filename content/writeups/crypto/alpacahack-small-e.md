---
title: "Small e - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "low-exponent", "small", "cryptography"]
summary: "crypto writeup for \"Small e\" from AlpacaHack Daily - techniques: alpacahack, rsa, low-exponent, small, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d04_Small_e/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Small e"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Small e
- **Date:** 2026-06-04
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d04_Small_e>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d04_Small_e/README.md>

---
# Small e

初心者だった私ももうDaily AlpacaHack歴６か月ですからね、さすがにRSAのEasyは楽勝でした。

## 問題

eがちいさe

```py
FLAG = os.environ.get("FLAG", "Alpaca{dummy}")
assert len(FLAG) < 50

p = getPrime(1024)
q = getPrime(1024)

n = p * q

e = 5 # what????????

m = bytes_to_long(FLAG.encode())
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
```

## 概要

一見普通のRSA暗号のように見えます。一か所を除いて。

これはどうすれば復号できるのでしょうか？

## 方針

Low Public Exponent Attackを使う。

## 解法

メタ的に言えば、タイトルや問題文からLow Public Exponent Attackを使うのは間違いなさそうですが、まあとりあえず見なかったことにしましょう。

RSA暗号の公開鍵`e`は、理論上は$`\phi(n)`$と互いに素であればなんでも良い（素数である必要すらない）のですが、安全性や計算効率の観点から通常は`e = 65537(=0x10001)`が使われることが多いようです。

しかし、この問題ではとても小さい`e = 5`が使われています。

なぜこれがまずいのでしょうか？

RSA暗号では$`c \equiv m^{e} \pmod{n}`$によって暗号化され、$`m \equiv c^{d} \pmod{n}`$によって復号されます。

公開鍵`e`から秘密鍵`d`を求めるには$`\phi(n) = (p - 1)(q - 1)`$が必要であり、そのために`n`を素因数分解する必要があることから、素因数分解の困難性を根拠に安全性が保障されています。

また、通常$`m^{e}`$は`n`よりはるかに大きい値であり、$`\pmod{n}`$によって切り抜かれるため、`c`から`m`を直接求めることは現実的には不可能です。

しかし、平文`m`がパディングされておらず、かつ`e`が極めて小さい場合、$`m^{e} < n`$に収まってしまい、$`\pmod{n}`$が効かず、$`c = m^{e}`$が成立することから、単に`c`の`e`乗根を計算するだけで効率的に`m`が求められてしまうことがあります。

このように、`e`乗根を求めるだけで復号できてしまう攻撃手法をLow Public Exponent Attackといいます。

さて、この問題ではその攻撃は使えるのでしょうか？

まず、
```py
assert len(FLAG) < 50
```
により、フラグの長さが50バイト、つまり400ビット未満であることが保証されています。（フラグにマルチバイト文字が含まれていなければ。）

よってフラグを数値化した`m`も400ビット未満であり、これを`e(=5)`乗しても2000ビット未満です。

一方、

```py
p = getPrime(1024)
q = getPrime(1024)

n = p * q
```

から、`p`と`q`は1024ビットの素数ですので、`n`は2047ビットまたは2028ビットになります。（この問題では2047ビットでした。）

よって、$`m^{e} < n`$であることがわかるので、Low Public Exponent Attackが成立します。

また、`n`と`c`の10進数の桁数を比較してみると、`c`の方が100桁ほど少ないようです。

そのような小さい`c`になる可能性も全くゼロではありませんが、たまたまそのような小さい値になったと考えるのは明らかに不自然であり、もともと$`m^{e}`$が`n`に届いていなかったと考える方が自然であることからも、攻撃が成立すると考えられます。

そうとわかったら、ソルバーを書いてみます。

```py
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

# ここにoutput.txtの内容を全てコピペする

m, exact = iroot(c, e)
if exact:
    flag = long_to_bytes(m)
    print(f"{flag = }")
```
