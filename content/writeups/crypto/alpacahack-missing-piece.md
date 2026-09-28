---
title: "missing Piece - AlpacaHack Daily"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "alpacahack", "missing", "piece", "cryptography", "missing-piece"]
summary: "crypto writeup for \"missing Piece\" from AlpacaHack Daily - techniques: alpacahack, missing, piece, cryptography, missing-piece."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/b01-05_missing_Piece/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "missing Piece"
---

## Source

- **CTF:** AlpacaHack Daily (bonus challenge)
- **Challenge:** missing Piece
- **Date:** 2026-07-01-05
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/b01-05_missing_Piece>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/b01-05_missing_Piece/README.md>

---
# missing ✌️

「俺のフラグか？欲しけりゃくれてやるぜ…　探してみろ　この世の全てをそこ（環境変数）に置いてきた」

「だってよ…!!!ジャ○グズ!!!　Pが!!!」

「安いもんだ　Pの一つくらい…　無事でよかった」

♪ありったけのsharesをかき集め～捜し物を探しに行くのさ～１✌

✌✌✌（3ピース）に続いて✌っていうのは、こういうことでしょうか？（すみません初めてB-Sideが解けたので無駄にテンション上がってしまいました。）

# 問題

P も share みたいになりたいってさ

```py
P = getPrime(512)
THRESHOLD = 3
SHARES = 10

flag = int.from_bytes(os.getenv("FLAG", "Alpaca{DUMMY}").encode())
assert flag < P

coeffs = [flag] + [secrets.randbelow(P - 1) + 1 for _ in range(THRESHOLD - 1)]

# f(x) = c0 + c1 * x + c2 * x^2 mod P
f = lambda x: sum(c * pow(x, i, P) for i, c in enumerate(coeffs)) % P

# shares = (1, f(1)), ..., (10, f(10))
shares = [(x, f(x)) for x in range(1, SHARES + 1)]

# 3-out-of-10 secret sharing?
# NOTE: The intended solution works with only the first 4 shares. 10 just avoids edge cases.
print(f"{shares = }")
```

## 概要

6月22日のDailyの過去問「✌✌✌」の応用問題のようです。

今回、 $`f(1)`$ ～ $`f(10)`$ が与えられていますが、`P`については512ビットの素数であることしかわかっていません。

どうすれば $`c_{0} = f(0)`$を求めることができるのでしょうか？

## 解法

フー○ャ村を出たばかりのザコ海賊baumroll1234は、この問題をみて、「✌✌✌とどう違うんだろう？」と思いました。

答えにPは出てこないし、そのままでいけるのではないのかな？と。

「Crypto王に、俺はなる!!!」といわんばかりに意気込んで駆け出しましたが、壁にぶつかるまでにそれほどかかりはしませんでした。

[✌✌✌の解法](https://github.com/baumroll0928-spec/myRepository/tree/main/Daily_AlpacaHack/m202606/d22_%E2%9C%8C%EF%B8%8F%E2%9C%8C%EF%B8%8F%E2%9C%8C%EF%B8%8F#%E8%A7%A3%E6%B3%95)で逆元を使っていたのを思い出します。

逆元の計算って`pow(2, -1, P)`のようになるので`P`を使いますよね。

じゃあ、逆元をとらなくてもいいように係数が`1`になるように調整すればいいでしょうか？

いや、そもそも$`\pmod{P}`$の世界での引き算`a - b`は`(a - b) % P`なので、`P`がわからないと引き算すらできません。

「何が…Crypto王だ…!!!!　俺は!!!!弱いっ!!!!」

「無いものは無い!!!　確認せい!!お前にまだ残っておるものは何じゃ!!!」

「sharesがいる゛よ…!!!!」

…はい、というわけで、`P`を求めないことにはどうにもしようがなさそうです。

そこで、もし $`x \ne 0`$ かつ $`x \equiv 0 \pmod{P}`$ なる $`x`$ を見つけることができれば、`P`を求める手がかりになるのではないかと考えました。

まず、$`f(1)`$～$`f(4)`$はこんな感じです。

$`f(1) \equiv c_{0} + c_{1} + c_{2} \pmod{P}`$

$`f(2) \equiv c_{0} + 2c_{1} + 4c_{2} \pmod{P}`$

$`f(3) \equiv c_{0} + 3c_{1} + 9c_{2} \pmod{P}`$

$`f(4) \equiv c_{0} + 4c_{1} + 16c_{2} \pmod{P}`$

この隣同士の差分をとってみます。

$`f_{1}(1) = f(2) - f(1) \equiv c_{1} + 3c_{2} \pmod{P}`$

$`f_{1}(2) = f(3) - f(2) \equiv c_{1} + 5c_{2} \pmod{P}`$

$`f_{1}(3) = f(4) - f(3) \equiv c_{1} + 7c_{2} \pmod{P}`$

$`c_{0}`$ が消え、 $`c_{1}`$ が揃いました。

もう一度差分をとってみます。

$`f_{2}(1) = f_{1}(2) - f_{1}(1) \equiv 2c_{2} \pmod{P}`$

$`f_{2}(2) = f_{1}(3) - f_{1}(2) \equiv 2c_{2} \pmod{P}`$

$`c_{1}`$ も消え、 $`c_{2}`$ が揃いました。

さらにもう一度差分をとってみます。

$`f_{3}(1) = f_{2}(2) - f_{2}(1) \equiv 0 \pmod{P}`$

全て消えました。

よって、 $`f_{3}(1)`$ は`P`の倍数であることがわかるので、もしこの $`f_{3}(1)`$ が`0`でなければ $`f_{3}(1) = kP`$ なる`0`でない整数 $`k`$ が存在するはずです。

`0`になる以外にもうひとつ不安なのが、この`k`がSageMathでも素因数分解できないくらいめちゃくちゃでかい素因数をもつのではないかということです。

$`f_{3}(1)`$ を $`f(1)`$～$`f(4)`$ を使って表すと

$`f_{3}(1) = f(4) - 3f(3) + 3f(2) - f(1)`$

となります。

$`f(x)`$の最大値は`P-1`、最小値は`0`です。

よって、$`kP = f_{3}(1)`$の最大値は$`4P - 4`$、最小値は$`-4P + 4`$となり、`k`は、`-3`,`-2`,`-1`,`1`,`2`,`3`のどれかということになります。

これなら素因数分解しなくても全て試せばよさそうです。

では、実際にPythonで求めてみます。
```py
shares = [output.txtからコピペ]

f1 = shares[0][1]
f2 = shares[1][1]
f3 = shares[2][1]
f4 = shares[3][1]
f11 = f2 - f1
f12 = f3 - f2
f13 = f4 - f3
f21 = f12 - f11
f22 = f13 - f12
f31 = f22 - f21
print(f"{f31 = }")
print("bit length:", f31.bit_length())
```
これで`0`になってしまうようであれば組み合わせを変えて再試行しないといけませんが、
```
f31 = 15695(略)38206
bit length: 513
```
ちゃんと`0`以外になったようです。

そして513ビットであり`P`から1ビットしか増えていないので、やはり`P`にかけられた数`k`は`2`または`3`であったことがわかります。

`2`と`3`で割ってみます。
```py
from Crypto.Util.number import isPrime

kP = 15695(略)38206
for k in range(1, 4):
    print(f"{k}:", isPrime(kP // k), kP % k)
```
`1`～`3`で割ってみて、商が素数か、余りが`0`かを調べています。
```
1: False 0
2: True 0
3: False 2
```
`k`は`2`であることがわかりました。

これにより、`P = kP // 2`から`P`を求めることができるので、あとは✌✌✌と同じ方法で解くことができます。
