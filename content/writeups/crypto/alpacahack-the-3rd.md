---
title: "The 3rd - AlpacaHack Daily"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "alpacahack", "aes", "ecc", "sage", "chinese-remainder"]
summary: "crypto writeup for \"The 3rd\" from AlpacaHack Daily - techniques: alpacahack, aes, ecc, sage, chinese-remainder."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d22-24_The_3rd/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "The 3rd"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** The 3rd
- **Date:** 2026-09-22-24
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d22-24_The_3rd>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202609/d22-24_The_3rd/README.md>

---
# The 3rd

## 問題

3つめの素数

```sage
flag = os.environ["FLAG"].encode()

assert len(flag) == 14
assert flag.startswith(b"Alpaca{") and flag.endswith(b"}")

p = 577131489751
q = 604663433347
r = Integer(os.environ["SECRET_PRIME"])
assert all(s.is_prime() for s in [p, q, r])
assert len({p, q, r}) == 3

E = EllipticCurve(Zmod(p * q * r), [2, 3])
S = E(47472880544948864957374958450616147, 15718905651315016723553161697283736)
T = int.from_bytes(flag) * S
print(f"T = ({T[0]}, {T[1]})")
```

## 概要

楕円曲線 $`y^{2} \equiv x^{3} + 2x + 3 \pmod{pqr}`$ 上の点`S`と、フラグを整数化したもの（ここでは`m`とします）をこれにかけた`T = mS`が与えられます。

素数`p`,`q`,`r`のうち3つめの素数`r`は教えてもらえないようですが、どうすれば`m`を得ることができるのでしょうか？

## 楕円曲線暗号について

楕円曲線暗号(ECC)は、楕円曲線 $`y^{2} \equiv x^{3} + ax + b \pmod{p}`$ 上の点を使って暗号化や復号を行う方法です。

`P = kQ`を満たす楕円曲線上の点`P`,`Q`がわかっていても整数`k`を求めるのが極めて困難であることが安全性の根拠になっています。

※ただ、ECCはその性質上、楕円曲線上の点しか暗号化できないので、実用的にはECDH(秘密情報の共有) + KDF(鍵生成) + AES(暗号化)が使われるのが一般的のようですね。

この問題ではそれとはちょっと違うようですが、`S`と`T = mS`からフラグ`m`を求めるのは同様に無理なように見えます。

## 解法

### `r`を求める

$`y^{2} \equiv x^{3} + 2x + 3 \pmod{pqr}`$ より、$`y^{2} - (x^{3} + 2x + 3)`$ は`pqr`の倍数です。

もしこの式に`S`の座標を代入した値を素因数分解することができたら、`r`の候補をいくつかに絞れそうな気がします。

```sage
x = 47472880544948864957374958450616147
y = 15718905651315016723553161697283736
z = y^2 - (x^3 + 2*x + 3)
if z < 0:
    z = -z
p = 577131489751
q = 604663433347
assert z % p == 0 and z % q == 0
z = z // p // q
print(factor(z))
```
```
2^2 * 227 * 12786471977 * 1091632154029 * 24189972666792725751913915818784289411539630036825220903
```

できましたー！というわけで、秘密の素数`r`は
```
2, 227, 12786471977, 1091632154029, 24189972666792725751913915818784289411539630036825220903
```
のどれかだということがわかりました！

Hard問題だけど意外と楽勝？`r`も5つに絞れたしあとちょっと・・・かと思ったら、全然そんなことはありませんでしたね。

`r`がわかったところで`m`を求めるのが困難であることに変わりありません。ぬか喜びでした。

### `m`を求める。

通常の楕円曲線暗号では、法は1つの素数です。

この問題ではなぜか3つの素数がかけられているので、そこが突破口（脆弱性）になるのではないかと考えました。

こういうときは過去の経験上、`p`,`q`,`r`を別々に考えてあとで結合してあげるのがいい気がしました。

まずは`p`について解いてみます。

```sage
from sage.all import *

p = 577131489751
Tx = 299503460090901935082824843431273729
Ty = 5022588709750132765941314121276972
Sx = 47472880544948864957374958450616147
Sy = 15718905651315016723553161697283736

Ep = EllipticCurve(GF(p), [2, 3])
Sp = Ep(Sx % p, Sy % p)
Tp = Ep(Tx % p, Ty % p)
o_p = Sp.order()
m_p = discrete_log(Tp, Sp, operation='+')

print(f"{o_p = }")
print(f"{m_p = }")
```
```
o_p = 288566009096
m_p = 223318757821
```
できました。pが割と小さめ（40ビット）なのですぐに求まりました。

※`S.order()`は`S`の「位数」で、雑に言えば`S`を何個たすと1周するかということです。

一応ちゃんと求まっているか検証してみます。
```sage
略
T0 = o_p * Sp
T1 = (o_p + 1) * Sp
Tm = m_p * Sp
print(T0)
print(T1)
print(Sp)
assert T1 == Sp
print(Tm)
print(Tp)
assert Tm == Tp
print("OK")
```
```
(0 : 1 : 0)
(142996162678 : 492275424648 : 1)
(142996162678 : 492275424648 : 1)
(507854588098 : 386530613847 : 1)
(507854588098 : 386530613847 : 1)
OK
```
大丈夫そうです。

同様に`q`についても求めてみると、
```
o_q = 302331052781
m_q = 247372533797
```
となりました。

つづいて`r`ですが、さすがに2や227ではない気がするので、その次の`12786471977`で試してみます。すると、
```
TypeError: Coordinates [8674421802, 11808087553, 1] do not define a point on Elliptic Curve defined by y^2 = x^3 + 2*x + 3 over Finite Field of size 12786471977
```
エラーになってしまいました。「そんな点は楕円曲線上に無いよ」と言っているのですね、たぶん。

なるほど、誤った`r`を使って縮小したために壊れてしまったようです。それでエラーを吐いてくれるならむしろ好都合です。

気を取り直してその次の`1091632154029`で試してみます。
```
o_r = 1091633088668
m_r = 590892949289
```
よし、ちゃんと出ました。今度は間違いなさそうです。

これらの数値が意味することは、

- $`m \equiv m_{p} \pmod{o_{p}}`$
- $`m \equiv m_{q} \pmod{o_{q}}`$
- $`m \equiv m_{r} \pmod{o_{r}}`$

です。

この形まで持ち込んだら、あとはCRT（中国剰余定理）で求められそうですが、`m`が`lcm([o_p,o_q,o_r])`すなわち結合後の位数より大きいとちょっと厄介になりそうですね。

ですが、
```sage
from sage.all import *

o_p = 288566009096
o_q = 302331052781
o_r = 1091633088668
print(lcm([o_p, o_q, o_r]))

m_max = int.from_bytes('Alpaca{~~~~~~}'.encode())
print(m_max)
```
```
23809190471927841985027273763499992
1326948045845116133951641388744317
```
その点は大丈夫そうです。

というわけで、最終的に下記を実行するとフラグを得ることができました。
```sage
from sage.all import *

略

m = crt([m_p, m_q, m_r], [o_p, o_q, o_r])
flag = m.to_bytes(14, 'big')
print(f"{flag = }")
```

## おまけ: DockerでSageMath

備忘録も兼ねて・・・。

SageMathについてはAlpacaHackの[解説ページ](https://github.com/alpacahack/resources/blob/main/resources/SageMath.md)に詳しく書いてあるので省きます。

さて、この解説ページに書いてあるとおり、Powershellで
```
docker run -it sagemath/sagemath:latest
```
を実行すると、実行が始まります。（初回はイメージのダウンロードのため時間がかかります。）
```
PS C:\ctf> docker run -it sagemath/sagemath:latest
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 10.9, Release Date: 2026-05-04                    │
│ Using Python 3.12.3. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage:
```
しかし、ここはDockerのコンテナ内の世界なので、ホスト側とは隔離されてしまい、このままではホスト側のソースコードを実行することができません。

そこであわせて覚えておきたいのが、
```
docker run -it -v C:\ctf:/home/sage/work sagemath/sagemath:latest
```
です。

このように`-v`でフォルダを指定して実行すると、ホスト側にマウントすることができるようです。

実行したいときは
```
sage: cd work
/home/sage/work
sage: run solve.sage
flag = b'Alpaca{******}'
```
のように、`run <ファイル名>`で実行できます。

あとは、
```
docker run -it -e FLAG="Alpaca{sample_flag}" sagemath/sagemath:latest
```
のように`-e`で環境変数を設定することもできます。
