---
title: "I cannot decrypt RSA - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "cannot", "decrypt", "cryptography"]
summary: "crypto writeup for \"I cannot decrypt RSA\" from AlpacaHack Daily - techniques: alpacahack, rsa, cannot, decrypt, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d26_I_cannot_decrypt_RSA/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "I cannot decrypt RSA"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** I cannot decrypt RSA
- **Date:** 2026-05-26
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d26_I_cannot_decrypt_RSA>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d26_I_cannot_decrypt_RSA/README.md>

---
# I cannot decrypt RSA

## はじめに

前回のVending Machineにつづき今回もたくさんの方に解いていただけてとても嬉しいCTF初心者baumroll1234です。こんばんは。

今回の私の作成問題第二弾は、私が好きなCryptoジャンルの問題です。

## 問題

RSAのプログラムを実装してみたんだけど、暗号化して復号しても元に戻らないのはなぜだろう？

```py
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537

m = bytes_to_long(FLAG.encode())
assert m < n
c = pow(m, e, n)

phi = (p + 1) * (q + 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)

print(f"{n = }")
print(f"{e = }")
print(f"{phi = }")
print(f"{flag = }")
```

## 概要

`chall.py`を読んでみると、フラグを暗号化してすぐ復号し出力しているように見えますが、`output.txt`をみると、出力の`flag`が`b"Alpaca{...}"`になっておらず、ぐちゃぐちゃに壊れていることがわかります。

正しく暗号化、復号していれば元に戻るはずなので、プログラムのどこかに間違いがあることは明らかです。

どこがどのように間違っているのでしょうか？そしてこの状況で正しいフラグを得るにはどうすればいいのでしょうか？

## 解法

### Step0: 間違いを探す

結論からいうと、間違いはここです。
```py
phi = (p + 1) * (q + 1)
```

RSAでは通常、オイラー関数

$`\phi(n) = (p - 1)(q - 1)`$

を使って公開鍵$`e`$から秘密鍵$`d`$を作り出しますが、ここでは間違って

$`\phi(n) = (p + 1)(q + 1)`$

になっています。

$`\phi(n)`$が間違っているので、これから計算される$`d`$も間違っています。

正しく復号できなくて当然ですね。

### Step1: 正しい$`\phi(n)`$を求める

正しく復号するために、まずは正しい$`\phi(n)`$を求めてみます。

間違った$`\phi(n)`$を$`\phi'(n)`$と書くことにすると、

$`\phi'(n) = (p + 1)(q + 1) = pq + p + q + 1`$

となります。

ここで、$`n = pq`$の値が既に判明しているので、

$`p + q = \phi'(n) - n - 1`$

を求めることができます。

$`q = \phi'(n) - n - 1 - p`$として二次方程式を解き$`p`$, $`q`$を求めても良いですが、ここではもっと直感的で簡単な方法があります。

正しい$`\phi(n)`$は、

$`\phi(n) = (p - 1)(q - 1) = pq - (p + q) + 1`$

ですので、その差は

$`\phi'(n) - \phi(n) = (pq + p + q + 1) - (pq - (p + q) + 1) = 2(p + q)`$

になります。よって$`\phi(n)`$は、

$`\phi(n) = \phi'(n) - 2(p + q) = \phi'(n) - 2(\phi'(n) - n - 1) = 2n - \phi'(n) + 2`$

によって求めることができます。

※いちおう二次方程式を解いて$`p`$, $`q`$を特定する方法も[find_p_and_q.py](https://raw.githubusercontent.com/baumroll0928-spec/myRepository/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d26_I_cannot_decrypt_RSA/find_p_and_q.py)に書いておきます。

これを使って正しい秘密鍵$`d`$を計算すれば暗号文$`c`$を復号することができるようになります。

しかし、この問題では暗号文$`c`$は示されておらず、フラグに関する情報は間違ったフラグだけです。

よって、まず間違った平文$`m'`$から暗号文$`c`$を復元する必要があります。

### Step2: 暗号文$`c`$を求める

間違った平文$`m'`$は、暗号文$`c`$を間違った秘密鍵$`d'`$で復号した結果のようなフリをしていますが、$`d'`$は$`d`$とは全然違う値ですので、$`c`$を$`d'`$で復号することはできません。

これはもはや復号というよりも、$`c`$を更に$`d'`$で暗号化した、と考えた方が都合が良さそうです。

そうすると、$`m'`$から$`c`$を求めるためには、$`d'`$と対をなす鍵$`e'`$によって$`m'`$を復号することになります。

まず、正しい$`e`$と間違った$`\phi'(n)`$を使って、間違った$`d'`$を求めます。

$`d' \equiv e^{-1} \pmod{\phi'(n)}`$

そして、この間違った$`d'`$と正しい$`\phi(n)`$を使って、$`e'`$を求めます。

$`e' \equiv d'^{-1} \pmod{\phi(n)}`$

※初心者向けヒントにも記載しましたが、この暗号化は正規の方法ではないので、$`p`$, $`q`$のとりかたによっては$`d'`$と$`\phi(n)`$が互いに素にならないことから$`e'`$を求められず$`m'`$から$`c`$を容易に復元できないことがあります。とはいえ発生確率は約20～25%とそれほど高くないので、この問題ではそのようにならないような$`p`$, $`q`$が使われています。

あとはこの$`e'`$を使って$`m'`$を復号すると、$`c`$が求まります。

$`c \equiv m'^{e'} \pmod{n}`$

### Step3: 暗号文$`c`$を正しく復号する

必要な情報は全て揃ったので、あとは普通のRSAの復号手順を使って暗号文$`c`$を正しく復号します。

$`d \equiv e^{-1} \pmod{\phi(n)}`$

で正しい$`d`$を求め、この$`d`$を使って、

$`m \equiv c^{d} \pmod{n}`$

で復号すると、正しい平文$`m`$を得ることができます。

```py
from Crypto.Util.number import bytes_to_long, long_to_bytes

# ここにoutput.txtの内容を全てコピペする

phi_ = phi
flag_ = flag

# Step1: 正しいφ(n)を求める
phi = 2 * n - phi_ + 2

# Step2: 暗号文cを求める
m_ = bytes_to_long(flag_)
d_ = pow(e, -1, phi_)
e_ = pow(d_, -1, phi)
c = pow(m_, e_, n)

# Step3: 暗号文cを正しく復号する
d = pow(e, -1, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(f"{flag = }")
```

※他の方のWriteupを見るまで気付かなかったのですが、実は$`c`$は必ずしも求める必要はなく、$`m' \equiv m^{ed'} \pmod{n}`$と表せることから、$`d \equiv (ed')^{-1} \pmod{\phi(n)}`$を使って$`m'`$を復号することで、$`c`$をすっ飛ばして直接$`m`$を求めることもできます。勉強になりました。

## おわりに

「$`\phi(n)`$を間違えて$`(p + 1)(q + 1)`$にしたらどうなるんだろう？」という私の素朴な疑問から生まれた今回の問題、いかがでしたでしょうか？

問題作成の裏話になりますが、シンプルなプログラムながら細かい問題点が多く、出題にあたっていろいろな葛藤がありました。

$`d'`$と$`\phi(n)`$が互いに素にならないケース（以下ダメケース）をassertで弾きたかったのですが、正しい$`\phi(n)`$を使ったassertを入れてしまうと、この問題の大事な最初の段階である「$`\phi(n)`$が間違って$`(p + 1)(q + 1)`$になってる！？」の部分の答えを教えるようなものになってしまうので、入れることができませんでした。

ダメケースが発生する可能性は排除しきれない、かといってあえて確率が低いダメケースのデータにするのもなんかちょっと違うような気がしたので、今回の問題のデータはダメケースではないものでいくことにしました。

しかし、挑戦者にとっては両方の可能性を考慮しなければならず、特に手元で`chall.py`を実行して実験しながら解こうとする人や一般的な解法で解こうとする人にとっては、無駄に惑わせてしまうおそれがありました。（実際、ダメケースであってもほとんどの場合は5/23の過去問`Even Worse RSA`の解法を応用した方法で解くことが可能ですが、難易度が跳ね上がってしまいます。）

最終的に初心者向けヒントに保険としてその旨を記載することに落ち着いたというわけですが、問題作成の難しさを実感しました。

ところで、フラグを取れた方はお気づきかもしれませんが、最近私、長い間放置していたあつ森（あつまれどうぶつの森）を再開しました。

ホテルの客室作りの要素が追加されていたりいろいろ変わっていましたね。

あつ森には実際にアルパカが登場します。リサとカイゾーという名前のアルパカ夫婦で、家具の特殊なリメイクができるお店「Rパーカーズ」を経営しています。

まもなく彼らが主催するジューンブライドのイベントも始まるでしょうし、こっちの方も忙しくなりそうです（笑）

## Solver

### `find_p_and_q.py`

<https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d26_I_cannot_decrypt_RSA/find_p_and_q.py>

```python
from sympy import Symbol, solve

# example
n = 187
phi = 216

x = Symbol('x')
expr = x * (phi - n - 1 - x) - n
ans = solve(expr, x)
p = ans[0]
q = ans[1]

print(f"{p = }") # p = 11
print(f"{q = }") # q = 17
print(f"Correct?", p * q == n) # Correct? True
```
