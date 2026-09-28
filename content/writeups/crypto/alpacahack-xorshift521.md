---
title: "xorshift521 - AlpacaHack Daily"
category: "crypto"
subcategory: "prng"
type: "writeup"
tags: ["crypto", "alpacahack", "sage", "xor", "xorshift", "xorshift521"]
summary: "crypto writeup for \"xorshift521\" from AlpacaHack Daily - techniques: alpacahack, sage, xor, xorshift, xorshift521."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d20_xorshift521/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "xorshift521"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** xorshift521
- **Date:** 2026-06-20
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d20_xorshift521>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d20_xorshift521/README.md>

---
# xorshift521

こういうときの「有限時間」って、「理論上は可能」＝「現実的には不可能」って意味ですよね？

## 問題

銀河級のフラグチェッカーが入力した文字列が正しいフラグかどうかを有限時間で判定します！

```py
n = 521
mask = (1 << n) - 1
expected = bytes.fromhex("01dadc95cc4ad53980f0bfa25eb55bbea8590cc11c12f9922fd3783e0b4ba33846cd11520a0a3fb8b4905c996d")

def next(state):
    state ^= state << (5*21) & mask
    state ^= state >> (52+1)
    state ^= state << (0o521) & mask
    return state

def main():
    flag = input("flag > ").strip().encode()

    if len(flag) != len(expected):
        print("Incorrect...")
        exit(1)

    state = 521
    for i in range((521**521)**521):
        state = next(state)

    for i in range(len(expected)):
        if (flag[i] ^ (state & 0xFF)) != expected[i]:
            print("Incorrect...")
            exit(1)
        state = next(state)

    print("Correct!")
```

## 概要

`state = 521`を`next`関数によって $`r = (521^{521})^{521}`$ 回(!?)変換した初期値を使って暗号化された暗号文のフラグチェッカーのようです。

※6/22 表記に誤りがあったため修正しました。誤： $`r = 521^{(521^{521})}`$ 正： $`r = (521^{521})^{521}`$ 

この`r`、logを使った概算によると、$`log_{10}r = (log_{10}512)×512^{2} = 737461.14845...`$なので、10進数で737462桁にもなってしまいます。

普通に実行することはできそうにありませんが、どうすれば暗号文を復号してフラグを得ることができるのでしょうか？

## 方針

SageMathを使い、stateを0/1のベクトルで、next()変換を0/1の正方行列との積で表し、next変換の周期を利用することで、stateの初期値を効率よく計算する。

## 解法

### 解法概要

stateをビットに分解した0/1の長さ521のベクトルで表します。

そうすると、XORもビットシフトも線形変換なので、state=next(state)そのものも１つの線形変換になります。

ベクトル`v`の線形変換は、適切な正方行列`M`を左から掛ける $`v' = Mv`$ で表すことができます。

ベクトルや行列で表せると何が嬉しいのでしょうか？

stateの初期値を求めるとき、素直にnext()で変換すると`r`回繰り返す必要があります。

しかし、ベクトルと行列を使った場合は、$`M^{r}v`$ を求めるだけで済みます。

SageMathなら効率よく $`M^{r}`$ を求めることがDekiMathが、さすがに今回の`r`は大きすぎる気がします。

そこで、$`M^{i}`$の周期を利用して`r`を縮小して求めます。

stateの初期値が求まれば、あとは復号するだけです。

### ステップ1: next変換を表す行列$`M`$を作る

ここで使うのは521×521の0/1の正方行列なので、これを使う準備をします。
```sage
n = 521
MS = MatrixSpace(GF(2), n, n)
```

まず、105ビット左シフトする変換行列を作ります。

左シフトは、その分だけ上位ビットにスライドする変換です。

イメージとして、7×7の行列で2ビット左シフトする行列を考えるとわかりやすいでしょう。
```
[0 0 0 0 0 0 0]
[0 0 0 0 0 0 0]
[1 0 0 0 0 0 0]
[0 1 0 0 0 0 0]
[0 0 1 0 0 0 0]
[0 0 0 1 0 0 0]
[0 0 0 0 1 0 0]
```
こんな感じですね。対角線からシフトする分だけ下にズラした位置を1にします。

```sage
M1 = MS([[(1 if (i == j + 105) else 0) for j in range(n)] for i in range(n)])
```

次に、もとのベクトルとXORをとります。

0/1の世界なので、XORは足し算になります。

単位行列（対角成分が全て1でそれ以外は0の行列で、行列やベクトルに掛けても変わらない）を`E`とすると、$`v + M_{1}v = (E + M_{1})v`$となることから、さきほどの行列に単位行列を足せばいいですね。
```
[1 0 0 0 0 0 0]
[0 1 0 0 0 0 0]
[1 0 1 0 0 0 0]
[0 1 0 1 0 0 0]
[0 0 1 0 1 0 0]
[0 0 0 1 0 1 0]
[0 0 0 0 1 0 1]
```
こんな感じになります。
```sage
M1 = MS([[(1 if (i == j or i == j + 105) else 0) for j in range(n)] for i in range(n)])
```

同じように、53ビット右シフトと337ビット左シフトの分の行列も作ります。
```sage
M2 = MS([[(1 if (i == j or i == j - 53) else 0) for j in range(n)] for i in range(n)])
M3 = MS([[(1 if (i == j or i == j + 337) else 0) for j in range(n)] for i in range(n)])
```

この $`M_{1}`$, $`M_{2}`$, $`M_{3}`$ を掛け合わせれば next変換の $`M`$ になりますが、ここで気を付けなければいけないことがあります。（私はここで少しつまずきました。）

行列の掛け算は一般的に**交換則が成立しない**ので、一部の例外を除いてAB=BAは成立しません。

ここでは、ベクトルに $`M_{1}`$,  $`M_{2}`$,  $`M_{3}`$ の順に掛けるので、 $`v' = Mv = M_{3}M_{2}M_{1}v`$ とする必要があります。

よって、$`M = M_{1}M_{2}M_{3}`$ ではなく、$`M = M_{3}M_{2}M_{1}`$ としなければいけません。

```sage
M = M3 * M2 * M1
```

### ステップ2: 行列$`M`$の周期を使って$`M^{r}`$を求める

作った行列 $`M`$ の変換を`r`回繰り返す $`M^{r}`$ は、
```sage
Mr = M ** r
```
で求めることができます。

これは単純な繰り返しではなく、Pythonのpow関数のように工夫して高速に計算されます。

しかし、そのまま`M ** r`を計算してみましたが、さすがに今回の`r`は大きすぎるため時間がかかりすぎて無理でした。

※ちなみに、なんとビックリ、`r`の値そのものはSageMathで737462桁全て求めることができました！
```sage
n = 521
r = (n ** n) ** n
print(r)
```

そこで、$`M^{i}`$ の周期を利用して`r`を縮小します。

長さ521のベクトルは $`2^{521}`$ 種類であり、ゼロベクトルは不動なので、周期は最大 $`2^{521} - 1`$ になります。

もしゼロベクトル以外が全てつながってループするなら、周期は最大の $`2^{521} - 1`$ になります。

なんとなくそんな気はしますが、試しに $`M`$ の $`2^{521} - 1`$ 乗が単位行列になるか確認してみましょう。
```sage
r = (1 << n) - 1
Mr = M ** r
print(Mr == MS.identity_matrix())
```
```
True
```

よって、周期が $`2^{521} - 1`$ の約数であることがわかりました。

さすがにこの数の素因数分解は無理だと思いますが、素数判定ならすぐにできるでしょう。
```sage
n = 521
r = (1 << n) - 1
print(r.is_prime())
```
```
True
```
素数でした。

よって周期の候補が`1`と $`2^{521} - 1`$ に絞られましたが、`1`はあきらかに違うので、 $`2^{521} - 1`$ だとわかりました。

$`2^{521} - 1`$ 回ごとに元に戻ってくるので、`r`ではなく`r`を $`2^{521} - 1`$ で割ったあまりで計算しても同じ値になりそうです。

これは、 $`521^{521}`$ の段階で$`\pmod{(2^{521} - 1)}`$ をとり、さらに521乗して再度$`\pmod{(2^{521} - 1)}`$ をとるのが良さそうです。
```sage
r = pow(n, n, (1<<n)-1)
r = pow(r, n, (1<<n)-1)
Mr = M ** r
```

### ステップ3: stateの初期値を求めて暗号文を復号する

求めた $`M^{r}`$ を使ってstateの初期値を求めます。

これは、521を表すベクトルに $`M^{r}`$ を左から掛けることで求めることができます。
```sage
state = vector(GF(2), [(521 >> i) & 1 for i in range(n)])
state = Mr * state
```

そして、ソースコードで与えられた暗号文を復号し、フラグを出力します。
```sage
expected = bytes.fromhex("01dadc95cc4ad53980f0bfa25eb55bbea8590cc11c12f9922fd3783e0b4ba33846cd11520a0a3fb8b4905c996d")
flag_list = []
for i in range(len(expected)):
    key = sum(int(state[j])<<j for j in range(8))
    flag_list.append(key ^^ expected[i])
    state = M * state
print(bytes(flag_list))
```

これでやっとフラグを出力することができました。

### ソルバーまとめ(SageMathスクリプト)
```sage
n = 521
MS = MatrixSpace(GF(2), n, n)

M1 = MS([[(1 if i == j or (i == j + 105) else 0) for j in range(n)] for i in range(n)])
M2 = MS([[(1 if i == j or (i == j - 53) else 0) for j in range(n)] for i in range(n)])
M3 = MS([[(1 if i == j or (i == j + 337) else 0) for j in range(n)] for i in range(n)])
M = M3 * M2 * M1

r = pow(n, n, (1<<n)-1)
r = pow(r, n, (1<<n)-1)
Mr = M ** r

state = vector(GF(2), [(521 >> i) & 1 for i in range(n)])
state = Mr * state

expected = bytes.fromhex("01dadc95cc4ad53980f0bfa25eb55bbea8590cc11c12f9922fd3783e0b4ba33846cd11520a0a3fb8b4905c996d")
flag_list = []
for i in range(len(expected)):
    key = sum(int(state[j])<<j for j in range(8))
    flag_list.append(key ^^ expected[i])
    state = M * state
print(bytes(flag_list))
```

## その他

今回の問題は、nozokareさんの第4作目でした。順調に出題されているようです。

Hard難易度なだけにかなり難しかったですが、試行錯誤を繰り返し無事フラグをゲットできたときはかなりの達成感がありました。

今回の問題も見た瞬間にわかるインパクトがあり、驚きや学びを与えてくれる良い問題だと思いました。

私もそろそろ新作を出したいところですね。
